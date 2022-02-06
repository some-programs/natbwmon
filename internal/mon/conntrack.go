package mon

import (
	"bytes"
	"fmt"
	"net"
	"sort"

	ct "github.com/florianl/go-conntrack"
)

type Flow struct {
	Orig Subflow
	Reply    Subflow
	TTL      uint64
}

func newFlow(s ct.Con) Flow {
	fl := Flow{
		Orig: newSubFlow(s.Origin, s.CounterOrigin),
		Reply:    newSubFlow(s.Reply, s.CounterReply),
	}
	if s.Timeout != nil {
		fl.TTL = uint64(*s.Timeout)
	}
	return fl
}

// isInteresting returns false if all the ends of the connections is the router
// itself or some similarily uninteresting item. Keeping multicast stuff.
func (flow Flow) isInteresting() bool {
	for _, ip := range []net.IP{
		flow.Orig.Source,
		flow.Orig.Destination,
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
	if flow.Orig.Source.Equal(flow.Reply.Destination) &&
		flow.Orig.Destination.Equal(flow.Reply.Source) {
		if !isLocalIP(flow.Orig.Source) &&
			!isLocalIP(flow.Orig.Destination) &&
			!isLocalIP(flow.Reply.Source) &&
			!isLocalIP(flow.Reply.Destination) {
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
	fs := make(FlowSlice, 0, 1024)
	{
		cons, err := nfct.Dump(ct.Conntrack, ct.IPv4)
		if err != nil {
			return nil, fmt.Errorf("could not dump sessions: %w", err)
		}
		for _, s := range cons {
			f := newFlow(s)
			if f.isInteresting() {
				fs = append(fs, f)
			}
		}
	}
	{
		cons, err := nfct.Dump(ct.Conntrack, ct.IPv6)
		if err != nil {
			return nil, fmt.Errorf("could not dump sessions: %w", err)
		}
		for _, s := range cons {
			f := newFlow(s)
			if f.isInteresting() {
				fs = append(fs, f)
			}
		}
	}
	return fs, nil
}

type FlowSlice []Flow

func (fs FlowSlice) FilterByIP(ip net.IP) FlowSlice {
	res := make(FlowSlice, 0, len(fs))
	for _, f := range fs {
		if f.Orig.Source.Equal(ip) ||
			f.Orig.Destination.Equal(ip) ||
			f.Reply.Source.Equal(ip) ||
			f.Reply.Destination.Equal(ip) {
			res = append(res, f)
		}
	}
	return res
}

func (fs FlowSlice) OrderByTTL() {
	sort.SliceStable(fs, func(i, j int) bool {
		return fs[i].TTL > fs[j].TTL
	})
}

func (fs FlowSlice) OrderByOriginalSPort() {
	sort.SliceStable(fs, func(i, j int) bool {
		return fs[i].Orig.SPort < fs[j].Orig.SPort
	})
}

func (fs FlowSlice) OrderByOriginalSource() {
	sort.SliceStable(fs, func(i, j int) bool {
		return bytes.Compare(fs[i].Orig.Source, fs[j].Orig.Source) < 0
	})
}

func (fs FlowSlice) OrderByOriginalDPort() {
	sort.SliceStable(fs, func(i, j int) bool {
		return fs[i].Orig.DPort < fs[j].Orig.DPort
	})
}

func (fs FlowSlice) OrderByOriginalDestination() {
	sort.SliceStable(fs, func(i, j int) bool {
		return bytes.Compare(fs[i].Orig.Destination, fs[j].Orig.Destination) < 0
	})
}

func (fs FlowSlice) OrderByOriginalBytes() {
	sort.SliceStable(fs, func(i, j int) bool {
		return fs[i].Orig.Bytes > fs[j].Orig.Bytes
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

func (fs FlowSlice) OrderByReplyBytes() {
	sort.SliceStable(fs, func(i, j int) bool {
		return fs[i].Reply.Bytes > fs[j].Reply.Bytes
	})
}
