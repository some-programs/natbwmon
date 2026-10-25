package mon

import (
	"errors"
	"net"
	"strings"
)

func ResolveHostname(ip string) (string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		if e, ok := errors.AsType[*net.DNSError](err); ok {
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
