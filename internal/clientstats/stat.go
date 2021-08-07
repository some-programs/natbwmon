package clientstats

import (
	"fmt"
)

// Stat
type Stat struct {
	IP           string  `json:"ip"`
	Name         string  `json:"name"`
	HWAddr       string  `json:"hwaddr"`
	InRate       float64 `json:"in_rate"`
	OutRate      float64 `json:"out_rate"`
	Manufacturer string  `json:"manufacturer"`
}

func (s Stat) HWAddrPrefix() string {
	if len(s.HWAddr) >= len("xx:xx:xx") {
		return s.HWAddr[0:8]
	}
	return ""
}

func (s Stat) InFmt() string {
	return fmtRate(s.InRate)
}

func (s Stat) OutFmt() string {
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
