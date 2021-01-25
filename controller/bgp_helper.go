package main

import (
	"fmt"
	"net"
	"sort"

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
	prefix      string
	nh          string
	lp          int
	asPath      []int
	origin      Origin
	med         int
	bgpType     BgpType
	mpCandidate bool
}

// stripped down version of BGP bestpath algorithm
func SortPaths(paths []BgpRoute, multiPath bool, bestPath bool) []BgpRoute {
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].lp > paths[j].lp {
			return true
		}
		if len(paths[i].asPath) < len(paths[j].asPath) {
			return true
		}
		if paths[i].origin < paths[j].origin {
			return true
		}
		if paths[i].med < paths[j].med {
			return true
		}
		if multiPath {
			paths[i].mpCandidate = true
			paths[j].mpCandidate = true
			return true
		}
		return false
	})
	if !bestPath {
		return paths
	}
	var bestPaths []BgpRoute
	for _, p := range paths {
		if multiPath && p.mpCandidate {
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
		r.prefix = fmt.Sprintf("%s/%d", v.Prefix, v.PrefixLen)
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
			r.nh = v.NextHop
		case *api.OriginAttribute:
			r.origin = Origin(v.Origin)
		case *api.MultiExitDiscAttribute:
			r.med = int(v.Med)
		case *api.LocalPrefAttribute:
			r.lp = int(v.LocalPref)
		case *api.AsPathAttribute:
			for _, seg := range v.Segments {
				// as-sequence
				if seg.Type != 2 {
					continue
				}
				for _, num := range seg.Numbers {
					r.asPath = append(r.asPath, int(num))
				}
			}
		}
	}
	return r, nil
}

func apiPath(route BgpRoute) *api.Path {
	_, ipnet, _ := net.ParseCIDR(route.prefix)
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
		Origin: uint32(route.origin),
	})
	a2, _ := ptypes.MarshalAny(&api.NextHopAttribute{
		NextHop: route.nh,
	})
	a3, _ := ptypes.MarshalAny(&api.LocalPrefAttribute{
		LocalPref: uint32(route.lp),
	})
	attrs := []*any.Any{a1, a2, a3}
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
				MatchType: api.MatchType_ALL,
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
	ds1.List = []string{d.IP.String()}
	ds2 := &api.DefinedSet{DefinedType: api.DefinedType_COMMUNITY}
	ds2.Name = d.BgpCommunity
	ds2.List = []string{d.BgpCommunity}
	dsList = append(dsList, ds1, ds2)
	return dsList
}
