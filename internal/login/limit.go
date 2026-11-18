package login

import (
	"sync"
	"time"

	"github.com/kazuhahub/rackbook/internal/lru"
)

// limiter is a small per-client token bucket for the endpoints anyone can
// call without logging in (starting a login, starting a passkey ceremony):
// each call stores state in memory, and the stores are bounded, so without a
// limit a flood could push real logins out.
type limiter struct {
	mu      sync.Mutex
	buckets *lru.Cache[string, *bucket]
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
	return &limiter{buckets: lru.New[string, *bucket](maxBuckets), rate: float64(perMinute) / 60, burst: float64(burst), now: now}
}

func (l *limiter) allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, _ := l.buckets.Get(key)
	if b == nil {
		// The table is bounded; the least recently seen client is forgotten first.
		b = &bucket{tokens: l.burst, last: now}
		l.buckets.Put(key, b)
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
