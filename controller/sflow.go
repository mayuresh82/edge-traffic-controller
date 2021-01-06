package main

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var WINDOW_SIZE = 2 * time.Minute

type RouterIP string
type IfIndex int
type Prefix string

// FlowSample represents a single flow sample
type FlowSample struct {
	AgentIP         net.IP
	SampleRate      int
	InputInterface  IfIndex
	OutputInterface IfIndex
	PacketSizeBytes int
	SrcIP           net.IP
	DstIP           net.IP
	BgpNextHop      net.IP
	BgpPeerAS       int
	SrcMask         int
	DstMask         int
	Ts              time.Time
}

func (s FlowSample) DstPrefix() *net.IPNet {
	cidr := fmt.Sprintf("%s/%d", s.DstIP.String(), s.DstMask)
	_, ipnet, _ := net.ParseCIDR(cidr)
	return ipnet
}

type FlowSamples []FlowSample

// Rate returns aggregate bps of all samples in the slice
func (f FlowSamples) Rate(sampleRate int, aggInterval time.Duration) int {
	if len(f) == 0 {
		return 0
	}
	var samplesInInterval FlowSamples
	firstTs := f[len(f)-1].Ts
	for i := len(f) - 1; i >= 0; i-- {
		if f[i].Ts.Sub(firstTs) <= aggInterval {
			samplesInInterval = append(samplesInInterval, f[i])
		}
	}
	sumBytes := 0
	for _, fs := range samplesInInterval {
		sumBytes += fs.PacketSizeBytes
	}
	sumScaledBytes := sumBytes * sampleRate
	bps := sumScaledBytes * 8 / int(aggInterval/time.Second)
	return bps
}

type CounterSample struct {
	AgentIP   net.IP
	IfIndex   IfIndex
	InOctets  int
	OutOctets int
	Speed     int
	OutBps    int
	Ts        time.Time
}

type CounterSamples []CounterSample

func (c CounterSamples) Rate(aggInterval time.Duration) int {
	if len(c) == 0 {
		return 0
	}
	var samplesInInterval CounterSamples
	firstTs := c[len(c)-1].Ts
	for i := len(c) - 1; i >= 0; i-- {
		if c[i].Ts.Sub(firstTs) <= aggInterval {
			samplesInInterval = append(samplesInInterval, c[i])
		}
	}
	sumBps := 0
	for _, cs := range samplesInInterval {
		sumBps += cs.OutBps
	}
	return sumBps / len(samplesInInterval)
}

type PrefixRate struct {
	Prefix  *net.IPNet
	RateBps int
}

func (p *PrefixRate) MarshalJSON() ([]byte, error) {
	tmp := struct {
		Prefix  string
		RateBps int
	}{
		Prefix:  p.Prefix.String(),
		RateBps: p.RateBps,
	}
	return json.Marshal(tmp)
}

type SflowServer struct {
	// buffer of flow samples per destination prefix per interface per router
	samplesPerPrefix map[RouterIP]map[IfIndex]map[Prefix]FlowSamples
	// moving out-bps traffic rates per interface per router
	ratesPerIntf        map[RouterIP]map[IfIndex]CounterSamples
	fsChan              chan FlowSample
	csChan              chan CounterSample
	pktChan             chan *layers.SFlowDatagram
	sampleRate          int
	counterPollInterval time.Duration
	mu                  sync.Mutex
}

func NewSflowServer(conf SflowConfig) *SflowServer {
	// start udp server
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", conf.ListenPort))
	if err != nil {
		glog.Exitf("Failed to bind UDP %d: %v", conf.ListenPort, err)
	}
	sampleMap := make(map[RouterIP]map[IfIndex]map[Prefix]FlowSamples)
	ratesMap := make(map[RouterIP]map[IfIndex]CounterSamples)
	s := &SflowServer{
		samplesPerPrefix:    sampleMap,
		ratesPerIntf:        ratesMap,
		sampleRate:          conf.SampleRate,
		counterPollInterval: conf.CounterPollInterval,
		fsChan:              make(chan FlowSample),
		csChan:              make(chan CounterSample),
		pktChan:             make(chan *layers.SFlowDatagram),
	}
	go s.processPacket()
	go func() {
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			n, _, _ := conn.ReadFrom(buf)
			sflowDGram := &layers.SFlowDatagram{}
			if err := sflowDGram.DecodeFromBytes(buf[:n], gopacket.NilDecodeFeedback); err != nil {
				glog.Errorf("Failed to decode sflow packet: %v", err)
				continue
			}
			s.pktChan <- sflowDGram
		}
	}()
	return s
}

func (s *SflowServer) processSamples() {
	var lastFsTs time.Time
	var lastCsTs time.Time
	for {
		select {
		case sample := <-s.fsChan:
			s.mu.Lock()
			routerIP := RouterIP(sample.AgentIP.String())
			ifIndex := sample.OutputInterface
			prefix := Prefix(sample.DstPrefix().String())
			perRtrMap := s.samplesPerPrefix[routerIP]
			if perRtrMap == nil {
				perRtrMap = make(map[IfIndex]map[Prefix]FlowSamples)
			}
			perIntfMap := perRtrMap[ifIndex]
			if perIntfMap == nil {
				perIntfMap = make(map[Prefix]FlowSamples)
			}
			samplesPerPrefix := perIntfMap[prefix]
			if len(samplesPerPrefix) == 0 {
				lastFsTs = sample.Ts
			}
			if len(samplesPerPrefix) > 0 {
				if sample.Ts.Sub(lastFsTs) >= WINDOW_SIZE*2 {
					// truncate the window by half
					truncIdx := 0
					for i, sm := range samplesPerPrefix {
						if sm.Ts.Sub(lastFsTs) >= WINDOW_SIZE {
							truncIdx = i
							break
						}
					}
					samplesPerPrefix = samplesPerPrefix[truncIdx:]
					lastFsTs = sample.Ts
				}
			}
			glog.V(4).Infof("Adding flow sample: %+v", sample)
			samplesPerPrefix = append(samplesPerPrefix, sample)
			perIntfMap[prefix] = samplesPerPrefix
			perRtrMap[ifIndex] = perIntfMap
			s.samplesPerPrefix[routerIP] = perRtrMap
			s.mu.Unlock()
		case sample := <-s.csChan:
			s.mu.Lock()
			routerIP := RouterIP(sample.AgentIP.String())
			ifIndex := sample.IfIndex
			perRtrMap := s.ratesPerIntf[routerIP]
			if perRtrMap == nil {
				perRtrMap = make(map[IfIndex]CounterSamples)
			}
			samplesPerIntf := perRtrMap[ifIndex]
			if len(samplesPerIntf) == 0 {
				lastCsTs = sample.Ts
			}
			if len(samplesPerIntf) > 0 {
				if sample.Ts.Sub(lastCsTs) >= WINDOW_SIZE*2 {
					// truncate the window by half
					truncIdx := 0
					for i, sm := range samplesPerIntf {
						if sm.Ts.Sub(lastCsTs) >= WINDOW_SIZE {
							truncIdx = i
							break
						}
					}
					samplesPerIntf = samplesPerIntf[truncIdx:]
					lastCsTs = sample.Ts
				}
				prevSample := samplesPerIntf[len(samplesPerIntf)-1]
				rate := (sample.OutOctets - prevSample.OutOctets) * 8 / int(s.counterPollInterval/time.Second)
				sample.OutBps = rate
			}
			glog.V(4).Infof("Adding counter sample: %+v", sample)
			samplesPerIntf = append(samplesPerIntf, sample)
			perRtrMap[ifIndex] = samplesPerIntf
			s.ratesPerIntf[routerIP] = perRtrMap
			s.mu.Unlock()
		}
	}
}

func (s *SflowServer) processPacket() {
	go s.processSamples()
	for dgram := range s.pktChan {
		for _, fs := range dgram.FlowSamples {
			sample := FlowSample{
				AgentIP:         dgram.AgentAddress,
				SampleRate:      int(fs.SamplingRate),
				InputInterface:  IfIndex(fs.InputInterface),
				OutputInterface: IfIndex(fs.OutputInterface),
				Ts:              time.Now(),
			}
			for _, r := range fs.Records {
				switch fr := r.(type) {
				case layers.SFlowIpv4Record:
					sample.SrcIP = fr.IPSrc
					sample.DstIP = fr.IPDst
				case layers.SFlowExtendedRouterFlowRecord:
					sample.SrcMask = int(fr.NextHopSourceMask)
					sample.DstMask = int(fr.NextHopDestinationMask)
				case layers.SFlowExtendedGatewayFlowRecord:
					sample.BgpNextHop = fr.NextHop
					sample.BgpPeerAS = int(fr.PeerAS)
				case layers.SFlowRawPacketFlowRecord:
					if ipLayer := fr.Header.Layer(layers.LayerTypeIPv4); ipLayer != nil {
						ipHdr, _ := ipLayer.(*layers.IPv4)
						sample.SrcIP = ipHdr.SrcIP
						sample.DstIP = ipHdr.DstIP
						sample.PacketSizeBytes = int(ipHdr.Length)
					}
				}
			}
			s.fsChan <- sample
		}
		for _, cs := range dgram.CounterSamples {
			sample := CounterSample{
				AgentIP: dgram.AgentAddress, Ts: time.Now(),
			}
			for _, r := range cs.Records {
				switch fr := r.(type) {
				case layers.SFlowGenericInterfaceCounters:
					sample.IfIndex = IfIndex(fr.IfIndex)
					sample.OutOctets = int(fr.IfOutOctets)
					sample.InOctets = int(fr.IfInOctets)
					sample.Speed = int(fr.IfSpeed)
				}
			}
			s.csChan <- sample
		}
	}
}

func (s *SflowServer) TopNPrefixesByRate(n int, routerIP RouterIP, ifIndex IfIndex, interval time.Duration) []PrefixRate {
	s.mu.Lock()
	defer s.mu.Unlock()
	prefixRates := []PrefixRate{}
	intfSamples, ok := s.samplesPerPrefix[routerIP][ifIndex]
	if !ok {
		glog.V(2).Infof("No samples found for %s / %d", routerIP, ifIndex)
		return prefixRates
	}
	for prefix, samples := range intfSamples {
		_, ipnet, _ := net.ParseCIDR(string(prefix))
		prefixRate := PrefixRate{Prefix: ipnet, RateBps: samples.Rate(s.sampleRate, interval)}
		prefixRates = append(prefixRates, prefixRate)
	}
	sort.Slice(prefixRates, func(i, j int) bool {
		return prefixRates[i].RateBps > prefixRates[j].RateBps
	})
	if len(prefixRates) <= n {
		return prefixRates
	}
	return prefixRates[:n]
}

// ChildPrefixRates returns prefix rates for the children of a given parent prefix
func (s *SflowServer) ChildPrefixRates(
	routerIP RouterIP,
	ifIndex IfIndex,
	parent Prefix,
	children []Prefix,
	interval time.Duration,
) []PrefixRate {
	s.mu.Lock()
	defer s.mu.Unlock()
	prefixRates := []PrefixRate{}
	prefixSamples, ok := s.samplesPerPrefix[routerIP][ifIndex][parent]
	if !ok {
		glog.V(2).Infof("No samples found for %s / %d / %s", routerIP, ifIndex, parent)
		return prefixRates
	}
	for _, c := range children {
		_, ipnet, _ := net.ParseCIDR(string(c))
		var samplesForChild FlowSamples
		for _, sample := range prefixSamples {
			if ipnet.Contains(sample.DstIP) {
				samplesForChild = append(samplesForChild, sample)
			}
		}
		prefixRate := PrefixRate{Prefix: ipnet, RateBps: samplesForChild.Rate(s.sampleRate, interval)}
		prefixRates = append(prefixRates, prefixRate)
	}
	return prefixRates
}

// GetInterfaceUtil gets the out-bps of a given interface averaged over the given interval
func (s *SflowServer) InterfaceUtil(routerIP RouterIP, ifIndex IfIndex, interval time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	samplesPerIntf, ok := s.ratesPerIntf[routerIP][ifIndex]
	if !ok {
		return 0
	}
	return samplesPerIntf.Rate(interval)
}
