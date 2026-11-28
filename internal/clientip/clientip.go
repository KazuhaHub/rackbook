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
	return Bucket(r, trusted, 64)
}

// Bucket is Of with the IPv6 prefix length of the bucket chosen by the caller: the sign-in protection
// of local accounts uses /48 (docs/design-local-accounts.md, 8), the rate limits /64. IPv4 is always the
// full address. v6bits outside 1..128 means 64.
func Bucket(r *http.Request, trusted []netip.Prefix, v6bits int) string {
	addr, ok := parse(r, trusted)
	if !ok {
		return rawHost(r)
	}
	return bucket(addr, v6bits)
}

// Addr is the client address by the same trusted-proxy rules, not bucketed: what a CAPTCHA provider is
// told (remoteIP) and what the audit log keeps before its own truncation. An address that does not parse
// is returned as the connection gave it.
func Addr(r *http.Request, trusted []netip.Prefix) string {
	addr, ok := parse(r, trusted)
	if !ok {
		return rawHost(r)
	}
	return addr.String()
}

func rawHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host
}

func parse(r *http.Request, trusted []netip.Prefix) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.Trim(rawHost(r), "[]"))
	if err != nil {
		return netip.Addr{}, false
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
	return addr, true
}

func bucket(a netip.Addr, v6bits int) string {
	if a.Is6() {
		if v6bits < 1 || v6bits > 128 {
			v6bits = 64
		}
		if p, err := a.Prefix(v6bits); err == nil {
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
