package mon

import "net"

var localIPs = make([]*net.IPNet, 0)

func isLocalIP(ip net.IP) bool {
	for _, localIP := range localIPs {
		if localIP.IP.Equal(ip) {
			return true
		}
	}
	return false
}

func init() {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		panic(err)
	}
	for _, address := range addresses {
		localIPs = append(localIPs, address.(*net.IPNet))
	}
}
