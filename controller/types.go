package main

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/golang/glog"
)

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
func (f FlowSamples) Rate(aggInterval time.Duration) int {
	if len(f) == 0 {
		return 0
	}
	var samplesInInterval FlowSamples
	firstTs := f[len(f)-1].Ts
	for i := len(f) - 1; i >= 0; i-- {
		if firstTs.Sub(f[i].Ts) <= aggInterval {
			samplesInInterval = append(samplesInInterval, f[i])
		}
	}
	glog.V(4).Infof("%d samples in this interval", len(samplesInInterval))
	sumBytes := 0
	for _, fs := range samplesInInterval {
		sumBytes += fs.PacketSizeBytes
	}
	sumScaledBytes := sumBytes * samplesInInterval[0].SampleRate
	bps := sumScaledBytes * 8 / int(aggInterval/time.Second)
	return bps
}

// Flow sample buffer
type FsBuf struct {
	samples  FlowSamples
	lastFsTs time.Time
}

// CounterSample represents a single counter sample
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

// Counter sample buffer
type CsBuf struct {
	samples  CounterSamples
	lastCsTs time.Time
}

// Prefixrate is used to store a prefix and its associated traffic rate
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

// Override is a route override for a prefix
type Override struct {
	Prefix       string
	RateBps      int    `json:"rate"`
	ParentPrefix string `json:"parent_prefix"`
	Route        BgpRoute
	OutIfIndex   IfIndex `json:"out_ifindex"`
}
