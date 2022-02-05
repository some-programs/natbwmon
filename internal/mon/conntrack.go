package mon

import (
	"bytes"
	"fmt"
	"net"
	"sort"

	ct "github.com/florianl/go-conntrack"
)

type FlowSlice []Flow

type Flow struct {
	Original Subflow
	Reply    Subflow
	TTL      uint64
}

func (flow Flow) isSNAT() bool {
	// SNATed flows should reply to our WAN IP, not a LAN IP.
	if flow.Original.Source.Equal(flow.Reply.Destination) {
		return false
	}

	if !flow.Original.Destination.Equal(flow.Reply.Source) {
		return false
	}

	return true
}

func (flow Flow) isDNAT() bool {
	// Reply must go back to the source; Reply mustn't come from the WAN IP
	if flow.Original.Source.Equal(flow.Reply.Destination) && !flow.Original.Destination.Equal(flow.Reply.Source) {
		return true
	}

	// Taken straight from original netstat-nat, labelled "DNAT (1 interface)"
	if !flow.Original.Source.Equal(flow.Reply.Source) && !flow.Original.Source.Equal(flow.Reply.Destination) && !flow.Original.Destination.Equal(flow.Reply.Source) && flow.Original.Destination.Equal(flow.Reply.Destination) {
		return true
	}

	return false
}

func (flow Flow) isLocal() bool {
	// no NAT
	if flow.Original.Source.Equal(flow.Reply.Destination) && flow.Original.Destination.Equal(flow.Reply.Source) {
		// At least one local address
		if isLocalIP(flow.Original.Source) || isLocalIP(flow.Original.Destination) || isLocalIP(flow.Reply.Source) || isLocalIP(flow.Reply.Destination) {
			return true
		}
	}

	return false
}

// isInternet returns true where
func (flow Flow) isInternet() bool {
	for _, ip := range []net.IP{
		flow.Original.Source,
		flow.Original.Destination,
		flow.Reply.Source,
		flow.Reply.Destination,
	} {
		if !(ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || isLocalIP(ip)) {
			return true
		}
	}
	return false
}

func (flow Flow) isRouted() bool {
	// no NAT
	if flow.Original.Source.Equal(flow.Reply.Destination) && flow.Original.Destination.Equal(flow.Reply.Source) {
		// No local addresses
		if !isLocalIP(flow.Original.Source) && !isLocalIP(flow.Original.Destination) && !isLocalIP(flow.Reply.Source) && !isLocalIP(flow.Reply.Destination) {
			return true
		}
	}

	return false
}

type Subflow struct {
	Source      net.IP
	Destination net.IP
	SPort       int
	DPort       int
	Bytes       uint64
	Packets     uint64
}

func newSubFlow(ipt *ct.IPTuple, counter *ct.Counter) Subflow {
	var sf Subflow
	if ipt != nil {
		if ipt.Src != nil {
			sf.Source = *ipt.Src
		}
		if ipt.Dst != nil {
			sf.Destination = *ipt.Dst
		}
		if ipt.Proto != nil {
			if ipt.Proto.SrcPort != nil {
				sf.DPort = int(*ipt.Proto.SrcPort)
			}
			if ipt.Proto.DstPort != nil {
				sf.DPort = int(*ipt.Proto.DstPort)
			}
		}
	}
	if counter != nil {
		if counter.Bytes != nil {
			sf.Bytes = *counter.Bytes
		}
		if counter.Packets != nil {
			sf.Packets = *counter.Packets
		}
	}
	return sf
}

func Flows() (FlowSlice, error) {
	nfct, err := ct.Open(&ct.Config{})
	if err != nil {
		return nil, fmt.Errorf("could not create nfct: %w", err)
	}
	defer nfct.Close()
	var fs FlowSlice
	{
		sessions, err := nfct.Dump(ct.Conntrack, ct.IPv4)
		if err != nil {
			return nil, fmt.Errorf("could not dump sessions: %w", err)
		}

		for _, s := range sessions {
			f := Flow{
				Original: newSubFlow(s.Origin, s.CounterOrigin),
				Reply:    newSubFlow(s.Reply, s.CounterReply),
				TTL:      uint64(*s.Timeout),
			}

			if f.isInternet() {
				fs = append(fs, f)
			}

		}
	}
	{
		sessions, err := nfct.Dump(ct.Conntrack, ct.IPv6)
		if err != nil {
			return nil, fmt.Errorf("could not dump sessions: %w", err)
		}

		for _, s := range sessions {
			f := Flow{
				Original: newSubFlow(s.Origin, s.CounterOrigin),
				Reply:    newSubFlow(s.Reply, s.CounterReply),
				TTL:      uint64(*s.Timeout),
			}
			if f.isInternet() {
				fs = append(fs, f)
			}

		}
	}
	return fs, nil
}

func (fs FlowSlice) FilterByIP(ip net.IP) FlowSlice {
	res := fs.Filter(func(f Flow) bool {
		if f.Original.Source.Equal(ip) {
			return true
		}
		if f.Original.Destination.Equal(ip) {
			return true
		}
		if f.Reply.Source.Equal(ip) {
			return true
		}
		if f.Reply.Destination.Equal(ip) {
			return true
		}
		return false
	})
	return FlowSlice(res)
}

func (fs FlowSlice) OrderByTTL() {
	sort.SliceStable(fs, func(i, j int) bool {
		return fs[i].TTL > fs[j].TTL
	})
}

func (fs FlowSlice) OrderByOriginalSPort() {
	sort.SliceStable(fs, func(i, j int) bool {
		return fs[i].Original.SPort < fs[j].Original.SPort
	})
}

func (fs FlowSlice) OrderByOriginalSource() {
	sort.SliceStable(fs, func(i, j int) bool {
		return bytes.Compare(fs[i].Original.Source, fs[j].Original.Source) < 0
	})
}

func (fs FlowSlice) OrderByOriginalDPort() {
	sort.SliceStable(fs, func(i, j int) bool {
		return fs[i].Original.DPort < fs[j].Original.DPort
	})
}

func (fs FlowSlice) OrderByOriginalDestination() {
	sort.SliceStable(fs, func(i, j int) bool {
		return bytes.Compare(fs[i].Original.Destination, fs[j].Original.Destination) < 0
	})
}

func (fs FlowSlice) OrderByReplySPort() {
	sort.SliceStable(fs, func(i, j int) bool {
		return fs[i].Reply.SPort < fs[j].Reply.SPort
	})
}

func (fs FlowSlice) OrderByReplySource() {
	sort.SliceStable(fs, func(i, j int) bool {
		return bytes.Compare(fs[i].Reply.Source, fs[j].Reply.Source) < 0
	})
}

func (fs FlowSlice) OrderByReplyDPort() {
	sort.SliceStable(fs, func(i, j int) bool {
		return fs[i].Reply.DPort < fs[j].Reply.DPort
	})
}

func (fs FlowSlice) OrderByReplyDestination() {
	sort.SliceStable(fs, func(i, j int) bool {
		return bytes.Compare(fs[i].Reply.Destination, fs[j].Reply.Destination) < 0
	})
}

type TypeFilter uint8

const (
	SNATFilter TypeFilter = 1 << iota
	DNATFilter
	RoutedFilter
	LocalFilter
)

var localIPs = make([]*net.IPNet, 0)

func isLocalIP(ip net.IP) bool {
	for _, localIP := range localIPs {
		if localIP.IP.Equal(ip) {
			return true
		}
	}
	return false
}

func init() {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		panic(err)
	}
	for _, address := range addresses {
		localIPs = append(localIPs, address.(*net.IPNet))
	}
}

func (flows FlowSlice) Filter(filter func(flow Flow) bool) FlowSlice {
	filtered := make(FlowSlice, 0, len(flows))

	for _, flow := range flows {
		if filter(flow) {
			filtered = append(filtered, flow)
		}
	}

	return filtered
}

func (flows FlowSlice) FilterByType(which TypeFilter) FlowSlice {
	snat := (which & SNATFilter) > 0
	dnat := (which & DNATFilter) > 0
	local := (which & LocalFilter) > 0
	routed := (which & RoutedFilter) > 0

	return flows.Filter(func(flow Flow) bool {
		return ((snat && flow.isSNAT()) ||
			(dnat && flow.isDNAT()) ||
			(local && flow.isLocal()) ||
			(routed && flow.isRouted()))
	})
}
