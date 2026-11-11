// Package listenpolicy identifies explicitly loopback-only listener addresses.
package listenpolicy

import "net"

// IsLoopback accepts literal loopback IPs only. Wildcards and hostnames are
// not trusted to remain local after name resolution.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
