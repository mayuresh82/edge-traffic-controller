package main

import (
	"io/ioutil"
	"net"
	"path/filepath"
	"time"

	"github.com/golang/glog"
	"gopkg.in/yaml.v2"
)

type SflowConfig struct {
	ListenPort          int           `yaml:"listen_port"`
	SampleRate          int           `yaml:"sample_rate"`
	CounterPollInterval time.Duration `yaml:"counter_poll_interval"`
}

type BgpConfig struct {
	LocalAS int    `yaml:"local_as"`
	LocalIP net.IP `yaml:"local_ip"`
}

type InterfaceConfig struct {
	Name               string
	IfIndex            int `yaml:"ifindex"`
	Speed              int
	HighWaterMark      int  `yaml:"high_watermark"`
	LowWaterMark       int  `yaml:"low_watermark"`
	PerPrefixThreshold int  `yaml:"per_prefix_threshold"`
	DryRun             bool `yaml:"dry_run"`
}

type DeviceConfig struct {
	Name       string
	IP         net.IP `yaml:"ip"`
	ASN        int    `yaml:"asn"`
	Interfaces []InterfaceConfig
}

type Config struct {
	Sflow   SflowConfig
	Bgp     BgpConfig
	Devices []DeviceConfig
}

func GetConfig(file string) *Config {
	absPath, _ := filepath.Abs(file)
	data, err := ioutil.ReadFile(absPath)
	if err != nil {
		glog.Exitf("FATAL: Unable to read config file: %v", err)
	}
	config := &Config{}
	if err := yaml.Unmarshal(data, config); err != nil {
		glog.Exitf("FATAL: Unable to decode yaml: %v", err)
	}
	return config
}
