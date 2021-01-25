package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/golang/glog"

	"github.com/giantswarm/ipam"
	"github.com/gorilla/mux"
	api "github.com/osrg/gobgp/api"
	gobgp "github.com/osrg/gobgp/pkg/server"
)

var (
	configFile       = flag.String("config", "", "Path to config file")
	httpAddr         = flag.String("http_addr", ":8080", "HTTP Server Addr")
	MONITOR_INTERVAL = 2 * time.Minute
)

type Device struct {
	Name         string
	IP           net.IP
	Interfaces   map[string]*Interface
	Peered       bool
	BgpCommunity string
}

type Interface struct {
	Name      string
	SpeedBps  int
	Nets      []*net.IPNet
	IfIndex   int
	Overrides []PrefixRate
}

type Controller struct {
	SflowServer       *SflowServer
	BgpServer         *gobgp.BgpServer
	ControlledDevices map[string]*Device
	Config            *Config
	wg                sync.WaitGroup
}

func NewController(config *Config) *Controller {
	s := gobgp.NewBgpServer()
	go s.Serve()
	ctx := context.Background()
	glog.Infof("Starting GoBGP Server")
	if err := s.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{
			As:       uint32(config.Bgp.LocalAS),
			RouterId: config.Bgp.LocalIP.String(),
		},
	}); err != nil {
		glog.Exitf("Unable to start bgp: %v", err)
	}

	glog.Infof("Starting Sflow server on :%d", config.Sflow.ListenPort)
	sflow := NewSflowServer(config.Sflow)
	c := &Controller{Config: config, BgpServer: s, SflowServer: sflow}
	c.ControlledDevices = make(map[string]*Device)
	peerState := func(p *api.Peer) {
		for _, d := range c.ControlledDevices {
			if p.Conf.NeighborAddress == d.IP.String() {
				d.Peered = true
				break
			}
		}
	}
	if err := s.MonitorPeer(ctx, &api.MonitorPeerRequest{}, peerState); err != nil {
		glog.Exit(err)
	}
	for _, d := range config.Devices {
		dev := &Device{
			Name: d.Name, IP: d.IP, Interfaces: make(map[string]*Interface),
			BgpCommunity: d.BgpCommunity,
		}
		n := &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: d.IP.String(),
				PeerAs:          uint32(d.ASN),
			},
			ApplyPolicy: &api.ApplyPolicy{
				ImportPolicy: &api.PolicyAssignment{
					DefaultAction: api.RouteAction_ACCEPT,
				},
				ExportPolicy: &api.PolicyAssignment{
					Policies:      []*api.Policy{neighborPolicy(dev)},
					DefaultAction: api.RouteAction_REJECT,
				},
			},
			AfiSafis: []*api.AfiSafi{
				&api.AfiSafi{
					Config: &api.AfiSafiConfig{Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}},
					AddPaths: &api.AddPaths{
						Config: &api.AddPathsConfig{Receive: true},
					},
				},
			},
			EbgpMultihop: &api.EbgpMultihop{Enabled: true, MultihopTtl: uint32(255)},
		}
		if err := s.AddPeer(ctx, &api.AddPeerRequest{Peer: n}); err != nil {
			glog.Exitf("Failed to add peer %v", d.IP)
			continue
		}
		for _, ds := range neighborDefinedSets(dev) {
			if err := s.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: ds}); err != nil {
				glog.Exitf("Failed to add defined set: %v", err)
			}
		}
		c.ControlledDevices[dev.Name] = dev
	}
	return c
}

func (c *Controller) Start() {
	for _, devConf := range c.Config.Devices {
		for _, intConf := range devConf.Interfaces {
			intf := &Interface{
				Name: intConf.Name, SpeedBps: intConf.Speed, IfIndex: intConf.IfIndex,
			}
			_, ipnet, err := net.ParseCIDR(intConf.Address)
			if err != nil {
				glog.Errorf("Invalid address: %s", intConf.Address)
				continue
			}
			intf.Nets = append(intf.Nets, ipnet)
			dev := c.ControlledDevices[devConf.Name]
			dev.Interfaces[intf.Name] = intf
			go c.monitorLoop(dev, intConf)
		}
	}
	glog.Infof("Starting http server on %s", *httpAddr)
	router := mux.NewRouter()
	router.HandleFunc("/sflow/{query}/", c.handleSflowQuery).Methods("GET")
	srv := &http.Server{Addr: *httpAddr, Handler: router, WriteTimeout: 10 * time.Second,
		ReadTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		glog.Errorf("HTTP server ListenAndServe Error: %v", err)
	}
}

func (c *Controller) monitorLoop(d *Device, intfConf InterfaceConfig) {
	for {
		glog.Infof("Starting monitoring for Interface %s on %s", intfConf.Name, d.Name)
		time.Sleep(MONITOR_INTERVAL)
		// wait for peering
		if !d.Peered {
			glog.Infof("%s is not peered, skipping cycle", d.Name)
			continue
		}
		devIntf, ok := d.Interfaces[intfConf.Name]
		if !ok {
			glog.Errorf("Failed to find interface %s on %s", intfConf.Name, d.Name)
			return
		}
		rip := RouterIP(d.IP.String())
		ifindex := IfIndex(devIntf.IfIndex)
		utilBps := c.SflowServer.InterfaceUtil(rip, ifindex, 1*time.Minute)
		speedBps := devIntf.SpeedBps
		percentUtil := utilBps / speedBps * 100
		glog.Infof("%s/%s (Util: %d, speed: %d) is at %d%% utilization",
			d.Name, intfConf.Name, utilBps, speedBps, percentUtil)

		// check if interface already has previous overrides that should be removed
		// This might occur if interface util has fallen below the low watermark
		if utilBps <= intfConf.LowWaterMark/100*speedBps {
			glog.Infof("Low WM reached for %s/%s", d.Name, intfConf.Name)
			var overridesToRemove []PrefixRate
			totBpsAdded := 0
			for _, o := range devIntf.Overrides {
				if totBpsAdded+o.RateBps >= intfConf.HighWaterMark/100*speedBps {
					break
				}
				// recompute prefixRate for old override since that may have changed
				newPrefixRate := c.SflowServer.PrefixUtil(rip, ifindex, Prefix(o.Prefix.String()), 1*time.Minute)
				totBpsAdded += newPrefixRate.RateBps
				glog.V(2).Infof("Removing previous override: %v", newPrefixRate)
				overridesToRemove = append(overridesToRemove, newPrefixRate)
			}
			if len(overridesToRemove) > 0 {
				glog.Infof("Adding back total %d bps", totBpsAdded)
				if err := c.RemoveOverrides(overridesToRemove); err != nil {
					glog.Errorf("Failed to remove overrides: %v", err)
				} else {
					utilBps += totBpsAdded
				}
			}
		}

		if percentUtil <= intfConf.HighWaterMark {
			// util is below high wm so no detour needed
			continue
		}
		topNPrefixes := c.SflowServer.TopNPrefixesByRate(5, rip, ifindex, 1*time.Minute)
		if len(topNPrefixes) == 0 {
			glog.Errorf("Failed to get top 5 prefixes from sflow")
			continue
		}

		var finalPrefixes []PrefixRate
		var totalBpsDetoured int

		// figure out if any of the prefixes needs to be split due to threshold limit
		for _, pr := range topNPrefixes {
			c.SplitPrefixes(rip, ifindex, intfConf.PerPrefixThreshold, pr, &finalPrefixes)
		}
		glog.V(2).Infof("Final Prefixes: %v", finalPrefixes)
		for _, pr := range finalPrefixes {
			totalBpsDetoured += pr.RateBps
			glog.V(2).Infof("Will detour Prefix: %v", pr)
			if !intfConf.DryRun {
				devIntf.Overrides = append(devIntf.Overrides, pr)
			}
			if (utilBps - totalBpsDetoured) < (intfConf.HighWaterMark / 100 * speedBps) {
				glog.Infof("Detouring total of %d bps off interface %s:%s (util %d, hwm %d)",
					totalBpsDetoured,
					d.Name,
					devIntf.Name,
					utilBps,
					intfConf.HighWaterMark,
				)
				break
			}
		}
		if intfConf.DryRun {
			glog.Info("Dry-run mode, skipping actual detour")
			continue
		}
		c.AddOverrides(d, intfConf, devIntf.Overrides)
	}
}

// SplitPrefixes recursively splits the given prefix into smaller chunks
// if its over a threshold. For e.g, it split a /24 into two /25s
func (c *Controller) SplitPrefixes(
	rip RouterIP,
	i IfIndex,
	thres int,
	pr PrefixRate,
	finalPrefixes *[]PrefixRate,
) {
	if pr.RateBps <= thres {
		*finalPrefixes = append(*finalPrefixes, pr)
		return
	}
	subnets, err := ipam.Split(*pr.Prefix, 2)
	if err != nil {
		glog.Error(err)
		return
	}
	var children []Prefix
	for _, s := range subnets {
		children = append(children, Prefix(s.String()))
	}
	for _, childPr := range c.SflowServer.ChildPrefixRates(
		rip, i, Prefix(pr.Prefix.String()), children, 1*time.Minute) {
		c.SplitPrefixes(rip, i, thres, childPr, finalPrefixes)
	}
}

// AddOverrides sends bgp overrides to the devices to detour prefixes
func (c *Controller) AddOverrides(d *Device, conf InterfaceConfig, overrides []PrefixRate) {
	// get all available routes for the prefix. This depends on bgp add-path
	// to be enabled
	glog.V(2).Infof("Adding overrides for device: %s, intf: %s", d.Name, conf.Name)
	rip := RouterIP(d.IP.String())
	for _, o := range overrides {
		pfxStr := o.Prefix.String()
		paths, err := c.getBgpPaths(pfxStr)
		if err != nil {
			glog.Errorf("Failed to get paths for prefix: %s: %v", pfxStr, err)
			continue
		}
		sorted := SortPaths(paths, false, false)
		// need at least one more path to detour to !
		if len(sorted) < 2 {
			glog.Errorf("Found no detour paths for prefix %s", pfxStr)
			continue
		}
		glog.Infof("Found %d total paths for prefix %s", len(sorted), pfxStr)
		for _, p := range sorted {
			for _, intf := range d.Interfaces {
				var found bool
				for _, n := range intf.Nets {
					if n.Contains(net.ParseIP(p.nh)) {
						found = true
						break
					}
				}
				if !found {
					continue
				}
				if intf.IfIndex == conf.IfIndex {
					continue
				}
				// make sure the detour interface has enough capacity
				bps := c.SflowServer.InterfaceUtil(rip, IfIndex(intf.IfIndex), 1*time.Minute)
				if int(bps/intf.SpeedBps*100) >= conf.HighWaterMark {
					glog.Warningf("Detour candidate %s has no capacity", intf.Name)
					continue
				}
				glog.Infof("Detouring %d bps for prefix %s to interface %s (nh %s)", o.RateBps, pfxStr, intf.Name, p.nh)
				p.lp = 500 // inject with a high LP
				p.origin = ORIGIN_IGP
				if _, err := c.BgpServer.AddPath(context.Background(), &api.AddPathRequest{Path: apiPath(p)}); err != nil {
					glog.Error(err)
				}
				break
			}
		}

	}
}

func (c *Controller) RemoveOverrides(overrides []PrefixRate) error {
	for _, o := range overrides {
		paths, err := c.getBgpPaths(o.Prefix.String())
		if err != nil {
			return err
		}
		if len(paths) == 0 {
			return fmt.Errorf("No paths found for override: %v", o.Prefix.String())
		}
		best := SortPaths(paths, false, true)
		best[0].lp = 500
		best[0].origin = ORIGIN_IGP
		if err := c.BgpServer.DeletePath(context.Background(), &api.DeletePathRequest{Path: apiPath(best[0])}); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) getBgpPaths(prefix string) ([]BgpRoute, error) {
	prefixes := []*api.TableLookupPrefix{&api.TableLookupPrefix{Prefix: prefix}}
	lpr := &api.ListPathRequest{
		TableType: api.TableType_GLOBAL,
		Family:    &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
		Prefixes:  prefixes,
	}
	var routes []BgpRoute
	var err error
	err = c.BgpServer.ListPath(context.Background(), lpr, func(d *api.Destination) {
		for _, path := range d.Paths {
			route, errr := apiPathToBgpRoute(path)
			if errr != nil {
				err = errr
				return
			}
			if route.prefix == "" {
				route.prefix = d.Prefix
			}
			routes = append(routes, route)
		}
	})
	return routes, err
}

func (c *Controller) handleSflowQuery(w http.ResponseWriter, r *http.Request) {
	queries := r.URL.Query()
	router, _ := queries["router"]
	dev, ok := c.ControlledDevices[router[0]]
	if !ok {
		http.Error(w, "Router not found", http.StatusNotFound)
		return
	}
	intf, _ := queries["interface"]
	var ifIndex int
	for _, i := range dev.Interfaces {
		if i.Name == intf[0] {
			ifIndex = i.IfIndex
			break
		}
	}
	if ifIndex == 0 {
		http.Error(w, "Interface not found", http.StatusNotFound)
		return
	}
	interval := "1m"
	intervals, ok := queries["interval"]
	if ok {
		interval = intervals[0]
	}
	dur, _ := time.ParseDuration(interval)
	vars := mux.Vars(r)
	switch vars["query"] {
	case "util":
		resp := make(map[string]interface{})
		util := c.SflowServer.InterfaceUtil(RouterIP(dev.IP.String()), IfIndex(ifIndex), dur)
		resp["util"] = util
		json.NewEncoder(w).Encode(resp)
	case "topK":
		k := "5"
		ks, ok := queries["k"]
		if ok {
			k = ks[0]
		}
		n, _ := strconv.Atoi(k)
		topK := c.SflowServer.TopNPrefixesByRate(n, RouterIP(dev.IP.String()), IfIndex(ifIndex), dur)
		json.NewEncoder(w).Encode(topK)
	}
}

func main() {
	flag.Parse()
	config := GetConfig(*configFile)
	controller := NewController(config)
	controller.Start()
}
