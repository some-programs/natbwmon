package mon

import (
	"fmt"
	"sync"
	"time"

	parp "github.com/ItsJimi/go-arp"
	"github.com/coreos/go-iptables/iptables"
	"github.com/mxmCherry/movavg"
	"github.com/some-programs/natbwmon/internal/clientstats"
	"github.com/some-programs/natbwmon/internal/log"
)

type Client struct {
	in        *counter
	out       *counter
	CreatedAt time.Time
	UpdatedAt time.Time
	IP        string
	HWAddr    string
	Name      string
}

func NewClient(ip string, avgSamples int) *Client {
	now := time.Now()
	name, err := ResolveHostname(ip)
	if err != nil {
		log.Warn().Err(err).Msg("")
	}

	return &Client{
		in: &counter{
			avg: movavg.NewSMA(avgSamples),
		},
		out: &counter{
			avg: movavg.NewSMA(avgSamples),
		},
		CreatedAt: now,
		UpdatedAt: now,
		IP:        ip,
		Name:      name,
	}
}

func (c *Client) Stat() clientstats.Stat {
	or := c.out.avg.Avg()
	if or < 0.0001 {
		or = 0
	}
	ir := c.in.avg.Avg()
	if ir < 0.0001 {
		ir = 0
	}

	return clientstats.Stat{
		IP:      c.IP,
		HWAddr:  c.HWAddr,
		Name:    c.Name,
		OutRate: or,
		InRate:  ir,
	}
}

func (c *Client) UpdateIPTables(s iptables.Stat, timestamp time.Time) {
	var count *counter
	if !s.Source.IP.IsUnspecified() {
		count = c.out
	} else {
		count = c.in
	}
	db := s.Bytes - count.bytes
	if count.bytes > s.Bytes {
		log.Warn().Msgf("resetting due to overflow: %v %v", s, count)
		db = 0
	}
	dur := float64(timestamp.Sub(count.updatedAt))
	if dur > 0 {
		perSecond := float64(time.Second) / dur
		count.avg.Add(float64(db) * perSecond)
		count.bytes = s.Bytes
		count.updatedAt = timestamp
	} else {
		log.Warn().Msgf("no time difference, skipping updating rate counter %v %v", dur, db)
	}
	c.UpdatedAt = time.Now()
}

func (c *Client) UpdateArp(a parp.Entry) {
	c.UpdatedAt = time.Now()
	c.HWAddr = a.HWAddress
}

func (c *Client) UpdateName(name string) {
	c.UpdatedAt = time.Now()
	c.Name = name
}

// Clients hold the recorded data of all known clients data.
//
// Access to the data is protected by a single mutex because it is expected
// that it is enough for this use case.
type Clients struct {
	cs map[string]*Client
	mu sync.Mutex

	avgSamples  int
	hostAliases map[string]string
}

func NewClients(avgSamples int, hostAliases map[string]string) *Clients {
	return &Clients{
		cs:          make(map[string]*Client, 0),
		avgSamples:  avgSamples,
		hostAliases: hostAliases,
	}
}

func (c *Clients) UpdateIPTables(stats IPTStats) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, s := range stats.Stats {
		ip, err := getLocalIP(s)
		if err != nil {
			return err
		}
		client, ok := c.cs[ip]
		if ok {
			client.UpdateIPTables(s, stats.CreatedAt)
		} else {
			client = NewClient(ip, c.avgSamples)
			client.UpdateIPTables(s, stats.CreatedAt)
			c.cs[ip] = client
		}
	}
	return nil
}

func (c *Clients) UpdateArp(as []parp.Entry) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, a := range as {
		ip := a.IPAddress
		client, ok := c.cs[ip]
		if ok {
			client.UpdateArp(a)
		} else {
			client = NewClient(ip, c.avgSamples)
			client.UpdateArp(a)
			c.cs[ip] = client
		}
	}
	return nil
}

func (c *Clients) UpdateNames(names map[string]string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for k, v := range names {
		client, ok := c.cs[k]
		if ok {
			client.UpdateName(v)
		} else {
			log.Warn().Msgf("no client registerd for %v %v", k, v)
		}
	}
	return nil
}

func (c *Clients) Stats() clientstats.Stats {
	c.mu.Lock()
	defer c.mu.Unlock()

	ss := make([]clientstats.Stat, 0, len(c.cs))
	for _, client := range c.cs {
		stat := client.Stat()
		if alias, ok := c.hostAliases[stat.HWAddr]; ok {
			stat.Name = alias
		}
		ss = append(ss, stat)
	}
	return ss
}

type counter struct {
	updatedAt time.Time
	bytes     uint64
	avg       movavg.MA
}

func (c counter) String() string {
	return fmt.Sprintf("bytes:%v avg:%.2f updatedAt:%v", c.bytes, c.avg.Avg(), c.updatedAt)
}
