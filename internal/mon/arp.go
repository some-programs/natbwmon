package mon

import (
	parp "github.com/ItsJimi/go-arp"
)

type Arps []parp.Entry

func ReadArps() (Arps, error) {
	all, err := parp.GetEntries()
	if err != nil {
		return nil, err
	}

	return all, nil
}

func (as Arps) FilterDeviceName(name string) Arps {
	filtered := make(Arps, 0, len(as))
	for _, v := range as {
		if v.Device == name {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func (as Arps) HWAddrByIP() map[string]string {
	m := make(map[string]string, len(as))
	for _, v := range as {
		m[v.IPAddress] = v.HWAddress
	}
	return m
}
