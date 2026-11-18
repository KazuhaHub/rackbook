// Package clientip names the client a request is attributed to, for rate
// limits: one function for every limiter.
package clientip

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Of is the address a request is attributed to: the connecting address, or,
// when that address is inside one of trusted (the --trusted-proxy CIDRs), the
// CF-Connecting-IP header. The header is never trusted otherwise. IPv6
// addresses are bucketed by /64, because one host controls a whole /64.
func Of(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return host
	}
	addr = addr.Unmap()
	for _, p := range trusted {
		if p.Contains(addr) {
			if h := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); h != "" {
				if ip, err := netip.ParseAddr(h); err == nil {
					addr = ip.Unmap()
				}
			}
			break
		}
	}
	return bucket(addr)
}

func bucket(a netip.Addr) string {
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.String()
		}
	}
	return a.String()
}

// ParseCIDRs parses --trusted-proxy values (CIDRs or single addresses).
func ParseCIDRs(in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, &net.ParseError{Type: "CIDR address", Text: s}
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}
