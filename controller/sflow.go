package main

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var WINDOW_SIZE = 1 * time.Minute
var CLEANUP_INTERVAL = 1 * time.Minute

type SflowServer struct {
	// buffer of flow samples per destination prefix per interface per router
	samplesPerPrefix map[RouterIP]map[IfIndex]map[Prefix]FsBuf
	// moving out-bps traffic rates per interface per router
	ratesPerIntf        map[RouterIP]map[IfIndex]CsBuf
	fsChan              chan FlowSample
	csChan              chan CounterSample
	pktChan             chan *layers.SFlowDatagram
	counterPollInterval time.Duration
	mu                  sync.Mutex
}

func NewSflowServer(conf SflowConfig) *SflowServer {
	// start udp server
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", conf.ListenPort))
	if err != nil {
		glog.Exitf("Failed to bind UDP %d: %v", conf.ListenPort, err)
	}
	sampleMap := make(map[RouterIP]map[IfIndex]map[Prefix]FsBuf)
	ratesMap := make(map[RouterIP]map[IfIndex]CsBuf)
	s := &SflowServer{
		samplesPerPrefix:    sampleMap,
		ratesPerIntf:        ratesMap,
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
	cleanUpTicker := time.NewTicker(CLEANUP_INTERVAL)
	for {
		select {
		case sample := <-s.fsChan:
			s.mu.Lock()
			routerIP := RouterIP(sample.AgentIP.String())
			ifIndex := sample.OutputInterface
			prefix := Prefix(sample.DstPrefix().String())
			perRtrMap := s.samplesPerPrefix[routerIP]
			if perRtrMap == nil {
				perRtrMap = make(map[IfIndex]map[Prefix]FsBuf)
			}
			perIntfMap := perRtrMap[ifIndex]
			if perIntfMap == nil {
				perIntfMap = make(map[Prefix]FsBuf)
			}
			buf := perIntfMap[prefix]
			if len(buf.samples) == 0 {
				buf.lastFsTs = sample.Ts
			}
			if len(buf.samples) > 0 {
				if sample.Ts.Sub(buf.lastFsTs) >= WINDOW_SIZE*2 {
					// truncate the window by half
					glog.V(6).Infof("Pre Trunc: %d samples", len(buf.samples))
					truncIdx := 0
					for i, sm := range buf.samples {
						if sm.Ts.Sub(buf.lastFsTs) >= WINDOW_SIZE {
							truncIdx = i
							break
						}
					}
					glog.V(6).Infof("Trunc FS: sampleTS: %v, lastFsTs: %v, truncIdx: %d",
						sample.Ts, buf.lastFsTs, truncIdx)
					buf.samples = buf.samples[truncIdx:]
					glog.V(6).Infof("Post Trunc: %d samples", len(buf.samples))
					buf.lastFsTs = sample.Ts
				}
			}
			glog.V(6).Infof("Adding flow sample: %+v", sample)
			buf.samples = append(buf.samples, sample)
			perIntfMap[prefix] = buf
			perRtrMap[ifIndex] = perIntfMap
			s.samplesPerPrefix[routerIP] = perRtrMap
			s.mu.Unlock()
		case sample := <-s.csChan:
			s.mu.Lock()
			routerIP := RouterIP(sample.AgentIP.String())
			ifIndex := sample.IfIndex
			perRtrMap := s.ratesPerIntf[routerIP]
			if perRtrMap == nil {
				perRtrMap = make(map[IfIndex]CsBuf)
			}
			buf := perRtrMap[ifIndex]
			if len(buf.samples) == 0 {
				buf.lastCsTs = sample.Ts
			}
			if len(buf.samples) > 0 {
				if sample.Ts.Sub(buf.lastCsTs) >= WINDOW_SIZE*2 {
					// truncate the window by half
					truncIdx := 0
					for i, sm := range buf.samples {
						if sm.Ts.Sub(buf.lastCsTs) >= WINDOW_SIZE {
							truncIdx = i
							break
						}
					}
					buf.samples = buf.samples[truncIdx:]
					buf.lastCsTs = sample.Ts
				}
				prevSample := buf.samples[len(buf.samples)-1]
				rate := (sample.OutOctets - prevSample.OutOctets) * 8 / int(s.counterPollInterval/time.Second)
				sample.OutBps = rate
			}
			glog.V(6).Infof("Adding counter sample: %+v", sample)
			buf.samples = append(buf.samples, sample)
			perRtrMap[ifIndex] = buf
			s.ratesPerIntf[routerIP] = perRtrMap
			s.mu.Unlock()
		case <-cleanUpTicker.C:
			s.mu.Lock()
			for rip, ifs := range s.samplesPerPrefix {
				for ifindex, prefixSamples := range ifs {
					for prfx, buf := range prefixSamples {
						if len(buf.samples) == 0 {
							continue
						}
						// if the last sample is older than cleanup interval, clear them out
						if time.Now().Sub(buf.samples[len(buf.samples)-1].Ts) >= CLEANUP_INTERVAL {
							glog.V(2).Infof("Clean up samples for %v / %v / %v", rip, ifindex, prfx)
							delete(s.samplesPerPrefix[rip][ifindex], prfx)
							continue
						}
					}
				}
			}
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
				SrcMask:         24,
				DstMask:         24,
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
					sample.PacketSizeBytes = int(fr.FrameLength)
					if err := fr.Header.ErrorLayer(); err != nil {
						glog.Errorf("Error decoding some part of the packet: %v", err)
					}
					if ipLayer := fr.Header.Layer(layers.LayerTypeIPv4); ipLayer != nil {
						ipHdr, _ := ipLayer.(*layers.IPv4)
						sample.SrcIP = ipHdr.SrcIP
						sample.DstIP = ipHdr.DstIP
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
	for prefix, buf := range intfSamples {
		_, ipnet, _ := net.ParseCIDR(string(prefix))
		prefixRate := PrefixRate{Prefix: ipnet, RateBps: buf.samples.Rate(interval)}
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

func (s *SflowServer) PrefixUtil(routerIP RouterIP, ifIndex IfIndex, prefix Prefix, interval time.Duration) PrefixRate {
	s.mu.Lock()
	defer s.mu.Unlock()
	intfSamples, ok := s.samplesPerPrefix[routerIP][ifIndex]
	if !ok {
		glog.V(2).Infof("No samples found for %s / %d", routerIP, ifIndex)
		return PrefixRate{}
	}
	prefixSamples := intfSamples[prefix]
	_, ipnet, _ := net.ParseCIDR(string(prefix))
	return PrefixRate{Prefix: ipnet, RateBps: prefixSamples.samples.Rate(interval)}
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
	buf, ok := s.samplesPerPrefix[routerIP][ifIndex][parent]
	if !ok {
		glog.V(2).Infof("No samples found for %s / %d / %s", routerIP, ifIndex, parent)
		return prefixRates
	}
	for _, c := range children {
		_, ipnet, _ := net.ParseCIDR(string(c))
		var samplesForChild FlowSamples
		for _, sample := range buf.samples {
			if ipnet.Contains(sample.DstIP) {
				samplesForChild = append(samplesForChild, sample)
			}
		}
		prefixRate := PrefixRate{Prefix: ipnet, RateBps: samplesForChild.Rate(interval)}
		prefixRates = append(prefixRates, prefixRate)
	}
	return prefixRates
}

// GetInterfaceUtil gets the out-bps of a given interface averaged over the given interval
func (s *SflowServer) InterfaceUtil(routerIP RouterIP, ifIndex IfIndex, interval time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	samplesBuf, ok := s.ratesPerIntf[routerIP][ifIndex]
	if !ok {
		glog.Infof("No samples found for router %s, ifindex %d", routerIP, ifIndex)
		return 0
	}
	return samplesBuf.samples.Rate(interval)
}
