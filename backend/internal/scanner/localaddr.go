package scanner

import (
	"net"
	"sync"
)

// Raw SYN scans (-sS) of this machine's own addresses miss Docker-published ports: the
// hand-made SYN is DNAT-ed to the container but the answer never reaches nmap, so every
// published port shows as "filtered" (seen on the jury lab VM: 10.0.0.5:8787 filtered with
// -sS, open with -sT). Chunks that contain a local address therefore use connect scans.

var (
	localAddrsOnce sync.Once
	localAddrs     map[string]bool
)

// isLocalAddress reports whether ip is a loopback address or an address of one of this
// machine's interfaces.
func isLocalAddress(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() {
		return true
	}
	localAddrsOnce.Do(func() {
		localAddrs = map[string]bool{}
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				localAddrs[n.IP.String()] = true
			}
		}
	})
	return localAddrs[parsed.String()]
}

// anyLocalAddress reports whether one of ips is local.
func anyLocalAddress(ips []string) bool {
	for _, ip := range ips {
		if isLocalAddress(ip) {
			return true
		}
	}
	return false
}
