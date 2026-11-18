package login

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// limiter is a small per-client token bucket for the endpoints anyone can
// call without logging in (starting a login, starting a passkey ceremony):
// each call stores state in memory, and the stores are bounded, so without a
// limit a flood could push real logins out.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

const maxBuckets = 10_000

func newLimiter(perMinute, burst int, now func() time.Time) *limiter {
	return &limiter{buckets: map[string]*bucket{}, rate: float64(perMinute) / 60, burst: float64(burst), now: now}
}

func (l *limiter) allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= maxBuckets {
			for k, e := range l.buckets { // drop buckets that have refilled
				if now.Sub(e.last).Seconds()*l.rate >= l.burst {
					delete(l.buckets, k)
				}
			}
			if len(l.buckets) >= maxBuckets {
				return false
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// clientIP is the address a request counts against. Behind a proxy on the
// same host or network (loopback or private remote address) the proxy's
// forwarded header names the real client; from anywhere else the headers are
// ignored, because anyone could set them.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		for _, h := range []string{"CF-Connecting-IP", "X-Forwarded-For"} {
			if v := strings.TrimSpace(strings.Split(r.Header.Get(h), ",")[0]); v != "" && net.ParseIP(v) != nil {
				return v
			}
		}
	}
	return host
}
