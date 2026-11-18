package tokens

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Limiter counts failed token attempts per client address and blocks a client
// that fails too often for a while. State is in memory only.
type Limiter struct {
	Max    int           // failures allowed per Window; default 10
	Window time.Duration // default 1 minute
	Now    func() time.Time

	mu sync.Mutex
	m  map[string]*bucket
}

type bucket struct {
	count int
	start time.Time
}

func (l *Limiter) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

func (l *Limiter) params() (int, time.Duration) {
	max, w := l.Max, l.Window
	if max <= 0 {
		max = 10
	}
	if w <= 0 {
		w = time.Minute
	}
	return max, w
}

// Blocked reports whether ip has used up its failures in the current window,
// and for how many more seconds.
func (l *Limiter) Blocked(ip string) (bool, int) {
	max, w := l.params()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.m[ip]
	if b == nil {
		return false, 0
	}
	now := l.now()
	if now.Sub(b.start) >= w {
		delete(l.m, ip)
		return false, 0
	}
	if b.count >= max {
		return true, int(w.Seconds() - now.Sub(b.start).Seconds() + 1)
	}
	return false, 0
}

// Fail records a failed attempt.
func (l *Limiter) Fail(ip string) {
	_, w := l.params()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]*bucket{}
	}
	now := l.now()
	if len(l.m) > 10000 { // bounded: drop expired windows, then give up on the rest
		for k, b := range l.m {
			if now.Sub(b.start) >= w {
				delete(l.m, k)
			}
		}
		if len(l.m) > 10000 {
			l.m = map[string]*bucket{}
		}
	}
	b := l.m[ip]
	if b == nil || now.Sub(b.start) >= w {
		b = &bucket{start: now}
		l.m[ip] = b
	}
	b.count++
}

// ClientIP is the address a request is attributed to: the connecting address,
// or, when that address is inside one of trusted (the --trusted-proxy CIDRs),
// the CF-Connecting-IP header. The header is never trusted otherwise.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
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
					return ip.Unmap().String()
				}
			}
			break
		}
	}
	return addr.String()
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
