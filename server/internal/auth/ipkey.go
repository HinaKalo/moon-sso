package auth

import "net/netip"

// IPKey groups addresses for rate limiting: IPv4 by address, IPv6 by /64
// (one subscriber usually controls a whole /64).
func IPKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "ip:" + ip
	}
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return "ip6:" + p.String()
	}
	return "ip:" + a.String()
}
