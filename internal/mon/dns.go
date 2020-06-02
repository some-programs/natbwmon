package mon

import (
	"errors"
	"net"
	"strings"
)

func ResolveHostname(ip string) (string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		var e *net.DNSError
		if errors.As(err, &e) {
			if !e.IsNotFound {
				return "", err
			}
		} else {
			return "", err
		}
	}
	if len(names) > 0 {
		return strings.TrimSuffix(names[0], "."), nil
	}

	return "", nil
}
