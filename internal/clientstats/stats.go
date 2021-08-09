package clientstats

import (
	"bytes"
	"net"
	"sort"
)

type Stats []Stat

func (s Stats) OrderByIP() {
	sort.SliceStable(s, func(i, j int) bool {
		return bytes.Compare(net.ParseIP(s[i].IP), net.ParseIP(s[j].IP)) < 0
	})
}

func (s Stats) OrderByInRate() {
	sort.SliceStable(s, func(i, j int) bool { return s[i].InRate > s[j].InRate })
}

func (s Stats) OrderByOutRate() {
	sort.SliceStable(s, func(i, j int) bool { return s[i].OutRate > s[j].OutRate })
}

func (s Stats) OrderByHWAddr() {
	sort.SliceStable(s, func(i, j int) bool { return s[i].HWAddr < s[j].HWAddr })
}

func (s Stats) OrderByName() {
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].Name == "" && s[j].Name != "" {
			return false
		}
		if s[i].Name != "" && s[j].Name == "" {
			return true
		}
		return s[i].Name < s[j].Name
	})
}

func (s Stats) OrderByManufacturer() {
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].Manufacturer == "" && s[j].Manufacturer != "" {
			return false
		}
		if s[i].Manufacturer != "" && s[j].Manufacturer == "" {
			return true
		}
		return s[i].Manufacturer < s[j].Manufacturer
	})
}
