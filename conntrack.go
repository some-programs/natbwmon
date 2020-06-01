package main

import (
	"bytes"
	"net"
	"sort"

	"honnef.co/go/conntrack"
)

func Flows() (FlowSlice, error) {
	fs, err := conntrack.Flows()
	return FlowSlice(fs), err
}

type FlowSlice conntrack.FlowSlice

func (fs FlowSlice) FilterByIP(ip net.IP) FlowSlice {
	res := conntrack.FlowSlice(fs).Filter(func(f conntrack.Flow) bool {
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

func (fs FlowSlice) OrderByProtoName() {
	sort.SliceStable(fs, func(i, j int) bool {
		in := fs[i].Protocol == nil
		jn := fs[j].Protocol == nil
		if in && jn {
			return false
		}
		if in {
			return true
		}
		if jn {
			return false
		}
		return fs[i].Protocol.Name > fs[j].Protocol.Name
	})
}

func (fs FlowSlice) OrderByState() {
	sort.SliceStable(fs, func(i, j int) bool {
		return fs[i].State > fs[j].State
	})
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
