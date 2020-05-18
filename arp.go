package main

import (
	parp "github.com/ItsJimi/go-arp"
)

func arps() ([]parp.Entry, error) {
	all, err := parp.GetEntries()
	if err != nil {
		return nil, err
	}

	var filtered []parp.Entry

	for _, v := range all {
		if v.Device == flags.LANIface {
			filtered = append(filtered, v)
		}
	}

	return filtered, nil
}

func arpsHWAddrByIP() (map[string]string, error) {
	as, err := arps()
	if err != nil {
		return nil, err
	}

	m := make(map[string]string, len(as))
	for _, v := range as {
		m[v.IPAddress] = v.HWAddress
	}
	return m, nil
}
