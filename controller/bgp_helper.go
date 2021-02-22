package main

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	api "github.com/osrg/gobgp/api"
)

type Origin int

const (
	ORIGIN_EGP Origin = iota
	ORIGIN_IGP
	ORIGIN_UNKNOWN
)

type BgpType int

const (
	EBGP BgpType = iota
	IBGP
)

type BgpRoute struct {
	Prefix      string
	Nh          string
	Lp          int
	AsPath      []int `json:"as_path"`
	Origin      Origin
	Med         int
	BgpType     BgpType `json:"bgp_type"`
	Communities []string
	MpCandidate bool `json:"mp_candidate"`
}

// stripped down version of BGP bestpath algorithm
func SortPaths(paths []BgpRoute, multiPath bool, bestPath bool) []BgpRoute {
	sort.Slice(paths, func(i, j int) bool {
		_, n1, _ := net.ParseCIDR(paths[i].Prefix)
		_, n2, _ := net.ParseCIDR(paths[j].Prefix)
		s1, _ := n1.Mask.Size()
		s2, _ := n2.Mask.Size()
		if s1 > s2 {
			return true
		}
		if paths[i].Lp > paths[j].Lp {
			return true
		}
		if len(paths[i].AsPath) < len(paths[j].AsPath) {
			return true
		}
		if paths[i].Origin < paths[j].Origin {
			return true
		}
		if paths[i].Med < paths[j].Med {
			return true
		}
		if multiPath {
			paths[i].MpCandidate = true
			paths[j].MpCandidate = true
		}
		return false
	})
	if !bestPath {
		return paths
	}
	var bestPaths []BgpRoute
	for _, p := range paths {
		if multiPath && p.MpCandidate {
			bestPaths = append(bestPaths, p)
			continue
		}
		bestPaths = append(bestPaths, p)
		break
	}
	return bestPaths
}

func apiPathToBgpRoute(p *api.Path) (BgpRoute, error) {
	var r BgpRoute
	var value ptypes.DynamicAny
	if err := ptypes.UnmarshalAny(p.Nlri, &value); err != nil {
		return r, fmt.Errorf("failed to unmarshal nlri: %s", err)
	}
	switch v := value.Message.(type) {
	case *api.IPAddressPrefix:
		r.Prefix = fmt.Sprintf("%s/%d", v.Prefix, v.PrefixLen)
	default:
		return r, fmt.Errorf("Unsupported NLRI: %v", v)
	}
	for _, a := range p.Pattrs {
		var val ptypes.DynamicAny
		if err := ptypes.UnmarshalAny(a, &val); err != nil {
			return r, fmt.Errorf("failed to unmarshal attr: %v", err)
		}
		switch v := val.Message.(type) {
		case *api.NextHopAttribute:
			r.Nh = v.NextHop
		case *api.OriginAttribute:
			r.Origin = Origin(v.Origin)
		case *api.MultiExitDiscAttribute:
			r.Med = int(v.Med)
		case *api.LocalPrefAttribute:
			r.Lp = int(v.LocalPref)
		case *api.AsPathAttribute:
			for _, seg := range v.Segments {
				// as-sequence
				if seg.Type != 2 {
					continue
				}
				for _, num := range seg.Numbers {
					r.AsPath = append(r.AsPath, int(num))
				}
			}
		case *api.CommunitiesAttribute:
			for _, c := range v.Communities {
				strComm := fmt.Sprintf("%v:%v", c>>16, c&65535)
				r.Communities = append(r.Communities, strComm)
			}
		}
	}
	return r, nil
}

func bgpRouteToApiPath(route BgpRoute) *api.Path {
	_, ipnet, _ := net.ParseCIDR(route.Prefix)
	afi := api.Family_AFI_IP
	if ipnet.IP.To4() == nil {
		afi = api.Family_AFI_IP6
	}
	prefixlen, _ := ipnet.Mask.Size()
	nlri, _ := ptypes.MarshalAny(&api.IPAddressPrefix{
		Prefix:    ipnet.IP.String(),
		PrefixLen: uint32(prefixlen),
	})
	a1, _ := ptypes.MarshalAny(&api.OriginAttribute{
		Origin: uint32(route.Origin),
	})
	a2, _ := ptypes.MarshalAny(&api.NextHopAttribute{
		NextHop: route.Nh,
	})
	a3, _ := ptypes.MarshalAny(&api.LocalPrefAttribute{
		LocalPref: uint32(route.Lp),
	})
	var communities []uint32
	for _, comm := range route.Communities {
		communities = append(communities, convertCommunity(comm))
	}
	a4, _ := ptypes.MarshalAny(&api.CommunitiesAttribute{
		Communities: communities,
	})
	attrs := []*any.Any{a1, a2, a3, a4}
	return &api.Path{
		Family: &api.Family{Afi: afi, Safi: api.Family_SAFI_UNICAST},
		Nlri:   nlri,
		Pattrs: attrs,
	}
}

func neighborPolicy(d *Device) *api.Policy {
	p := &api.Policy{Name: fmt.Sprintf("Conditional Announce policy for %s", d.Name)}
	stmnt := &api.Statement{
		Name: "Match community and announce",
		Conditions: &api.Conditions{
			NeighborSet: &api.MatchSet{
				MatchType: api.MatchType_ANY,
				Name:      d.Name,
			},
			CommunitySet: &api.MatchSet{
				MatchType: api.MatchType_ALL,
				Name:      d.BgpCommunity,
			},
		},
		Actions: &api.Actions{
			RouteAction: api.RouteAction_ACCEPT,
		},
	}
	p.Statements = append(p.Statements, stmnt)
	return p
}

func neighborDefinedSets(d *Device) []*api.DefinedSet {
	dsList := []*api.DefinedSet{}
	ds1 := &api.DefinedSet{DefinedType: api.DefinedType_NEIGHBOR}
	ds1.Name = d.Name
	ds1.List = []string{d.IP.String() + "/32"}
	ds2 := &api.DefinedSet{DefinedType: api.DefinedType_COMMUNITY}
	ds2.Name = d.BgpCommunity
	ds2.List = []string{d.BgpCommunity}
	dsList = append(dsList, ds1, ds2)
	return dsList
}

func convertCommunity(comm string) uint32 {
	parts := strings.Split(comm, ":")
	first, _ := strconv.ParseUint(parts[0], 10, 32)
	second, _ := strconv.ParseUint(parts[1], 10, 32)
	return uint32(first)<<16 | uint32(second)
}
