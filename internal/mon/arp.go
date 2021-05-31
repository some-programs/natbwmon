package mon

import (
	parp "github.com/ItsJimi/go-arp"
)

type ArpList []parp.Entry

func Arps() (ArpList, error) {
	all, err := parp.GetEntries()
	if err != nil {
		return nil, err
	}

	return all, nil
}

func (all ArpList) FilterDeviceName(name string) ArpList {
	var filtered ArpList
	for _, v := range all {
		if v.Device == name {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func (all ArpList) HWAddrByIP() map[string]string {
	m := make(map[string]string, len(all))
	for _, v := range all {
		m[v.IPAddress] = v.HWAddress
	}
	return m
}
