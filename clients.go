package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	parp "github.com/ItsJimi/go-arp"
	"github.com/coreos/go-iptables/iptables"
	"github.com/mxmCherry/movavg"
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

func NewClient(ip string) *Client {
	now := time.Now()
	name, err := resolveHostname(ip)
	if err != nil {
		log.Println(err)
	}

	return &Client{
		in: &counter{
			avg: movavg.NewSMA(flags.avgSamples),
		},
		out: &counter{
			avg: movavg.NewSMA(flags.avgSamples),
		},
		CreatedAt: now,
		UpdatedAt: now,
		IP:        ip,
		Name:      name,
	}
}

func (c *Client) Stat() Stat {
	or := c.out.avg.Avg()
	if or < 0.0001 {
		or = 0
	}
	ir := c.in.avg.Avg()
	if ir < 0.0001 {
		ir = 0
	}

	alias := aliasesMap[c.HWAddr]
	name := c.Name
	if alias != "" {
		name = alias
	}
	return Stat{
		IP:      c.IP,
		HWAddr:  c.HWAddr,
		Name:    name,
		OutRate: or,
		InRate:  ir,
	}
}

func (c *Client) UpdateIPTables(s iptables.Stat, timestamp time.Time) error {
	var count *counter
	if !s.Source.IP.IsUnspecified() {
		count = c.out
	} else {
		count = c.in
	}
	db := s.Bytes - count.bytes
	if db < 0 {
		// supress negative rate numbers, could potentially be caused by
		// external reset of iptables counters, a single 0 value won't cause
		// significant display errors.
		log.Println("got negative bytes count", s, count)
		db = 0
	}
	perSecond := float64(time.Second) / float64(timestamp.Sub(count.updatedAt))
	count.bytes = s.Bytes
	count.avg.Add(float64(db) * perSecond)
	count.updatedAt = timestamp
	c.UpdatedAt = time.Now()
	return nil
}

func (c *Client) UpdateArp(a parp.Entry) error {
	c.UpdatedAt = time.Now()
	c.HWAddr = a.HWAddress
	return nil
}

func (c *Client) UpdateName(name string) error {
	c.UpdatedAt = time.Now()
	c.Name = name
	return nil
}

type Clients struct {
	cs map[string]*Client
	mu sync.Mutex
}

func NewClients() *Clients {
	return &Clients{
		cs: make(map[string]*Client, 0),
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
			client = NewClient(ip)
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
			client = NewClient(ip)
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
			log.Println("no client registerd for", k, v)
		}
	}
	return nil
}

func (c *Clients) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()

	var ss []Stat
	for _, client := range c.cs {
		ss = append(ss, client.Stat())
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

// Stat
type Stat struct {
	IP      string  `json:"ip"`
	Name    string  `json:"name"`
	HWAddr  string  `json:"hwaddr"`
	InRate  float64 `json:"in_rate"`
	OutRate float64 `json:"out_rate"`
}

func (s Stat) InKb() string {
	return fmtRate(s.InRate)
}

func (s Stat) OutKb() string {
	return fmtRate(s.OutRate)
}

func fmtRate(b float64) string {
	if b < 0.01 {
		return ""
	}
	const unit = 1024.0
	if b < unit {
		return fmt.Sprintf("%.2f B/s", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB/s",
		float64(b)/float64(div), "KMGTPE"[exp])
}

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
