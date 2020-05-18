package main

import (
	"fmt"
	"log"
	"time"

	"github.com/coreos/go-iptables/iptables"
)

// IPTables .
type IPTables struct {
	ipt *iptables.IPTables
}

func NewIPTables() (*IPTables, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}
	return &IPTables{
		ipt: ipt,
	}, nil
}

func (i *IPTables) Stats() (IPTStats, error) {
	stats, err := i.ipt.StructuredStats("filter", flags.chain)
	if err != nil {
		return IPTStats{}, err
	}
	return IPTStats{
		CreatedAt: time.Now(),
		Stats:     stats,
	}, nil
}

// ClearChain clears and
func (i *IPTables) ClearChain() error {
	return i.ipt.ClearChain("filter", flags.chain)
}

// Update updates natbw rules according to the system arp list
func (i *IPTables) Update() error {
	as, err := arps()
	if err != nil {
		return err
	}

	ok, err := i.ipt.Exists("filter", "FORWARD", "-j", flags.chain)
	if err != nil {
		return err
	}
	if !ok {
		err = i.ipt.Insert("filter", "FORWARD", 1, "-j", flags.chain)
		if err != nil {
			return err
		}
	}
aloop:
	for _, a := range as {
		if err := i.ipt.AppendUnique("filter", flags.chain, "-d", a.IPAddress, "-j", "RETURN"); err != nil {
			log.Println(err)
			continue aloop
		}
		if err := i.ipt.AppendUnique("filter", flags.chain, "-s", a.IPAddress, "-j", "RETURN"); err != nil {
			log.Println(err)
		}
	}
	return nil
}

// Delete removes all rules related to natbwmon
func (i *IPTables) Delete() error {
	err := i.ClearChain()
	if err != nil {
		log.Fatal(err)
	}

	for {
		ok, err := i.ipt.Exists("filter", "FORWARD", "-j", flags.chain)
		if err != nil {
			return err
		}
		if !ok {
			break
		}

		err = i.ipt.Delete("filter", "FORWARD", "-j", flags.chain)
		if err != nil {
			return err
		}
	}

	err = i.ipt.DeleteChain("filter", flags.chain)
	if err != nil {
		return err
	}

	return nil
}

func getLocalIP(s iptables.Stat) (string, error) {
	su := s.Source.IP.IsUnspecified()
	du := s.Destination.IP.IsUnspecified()
	if su && du {
		return "", fmt.Errorf("expected source or destination to be unspecified: %v", s)
	}
	if !su {
		return s.Source.IP.String(), nil
	}
	if !du {
		return s.Destination.IP.String(), nil
	}
	return "", fmt.Errorf("unexpected stat: %v", s)
}

// IPTStats .
type IPTStats struct {
	CreatedAt time.Time
	Stats     []iptables.Stat
}
