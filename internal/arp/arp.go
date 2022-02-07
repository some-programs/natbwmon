// Package arp parse ARP file from /proc/net/arp
package arp

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Entry define the list available in /proc/net/arp
type Entry struct {
	IPAddress string
	HWType    string
	Flags     string
	HWAddress string
	Mask      string
	Device    string
}

// ReadAll parses ARP entries from reader.
func ReadAll(r io.Reader) (Entries, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	entries := make(Entries, 0, len(lines))
	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}
		rows := strings.Fields(line)
		if len(rows) < 6 {
			return nil, fmt.Errorf("line contains less than 6 rows: '%s'", line)
		}
		entries = append(entries,
			Entry{
				IPAddress: rows[0],
				HWType:    rows[1],
				Flags:     rows[2],
				HWAddress: rows[3],
				Mask:      rows[4],
				Device:    rows[5],
			})
	}
	return entries, nil
}

// Get list ARP entries in /proc/net/arp
func Get() (Entries, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadAll(f)
}

type Entries []Entry

func (as Entries) FilterDeviceName(name string) Entries {
	filtered := make(Entries, 0, len(as))
	for _, v := range as {
		if v.Device == name {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func (as Entries) HWAddrByIP() map[string]string {
	m := make(map[string]string, len(as))
	for _, v := range as {
		m[v.IPAddress] = v.HWAddress
	}
	return m
}
