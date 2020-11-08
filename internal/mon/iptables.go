package mon

import (
	"fmt"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/some-programs/natbwmon/internal/log"
)

// IPTables .
type IPTables struct {
	ipt   *iptables.IPTables
	chain string
	netif string
}

func NewIPTables(chain string, netif string) (*IPTables, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}
	return &IPTables{
		ipt:   ipt,
		chain: chain,
		netif: netif,
	}, nil
}

func (i *IPTables) Stats() (IPTStats, error) {
	stats, err := i.ipt.StructuredStats("filter", i.chain)
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
	return i.ipt.ClearChain("filter", i.chain)
}

// Update updates natbw rules according to the system arp list
func (i *IPTables) Update() error {
	as, err := Arps()
	if err != nil {
		return err
	}
	as = as.FilterDeviceName(i.netif)

	ok, err := i.ipt.Exists("filter", "FORWARD", "-j", i.chain)
	if err != nil {
		return err
	}
	if !ok {
		err = i.ipt.Insert("filter", "FORWARD", 1, "-j", i.chain)
		if err != nil {
			return err
		}
	}
aloop:
	for _, a := range as {
		if err := i.ipt.AppendUnique("filter", i.chain, "-d", a.IPAddress, "-j", "RETURN"); err != nil {
			log.Error().Err(err).Msg("")
			continue aloop
		}
		if err := i.ipt.AppendUnique("filter", i.chain, "-s", a.IPAddress, "-j", "RETURN"); err != nil {
			log.Error().Err(err).Msg("")
		}
	}
	return nil
}

// Delete removes all rules related to natbwmon
func (i *IPTables) Delete() error {
	err := i.ClearChain()
	if err != nil {
		log.Fatal().Err(err).Msg("clear iptables chain failed")
	}

	for {
		ok, err := i.ipt.Exists("filter", "FORWARD", "-j", i.chain)
		if err != nil {
			return err
		}
		if !ok {
			break
		}

		err = i.ipt.Delete("filter", "FORWARD", "-j", i.chain)
		if err != nil {
			return err
		}
	}

	err = i.ipt.DeleteChain("filter", i.chain)
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
