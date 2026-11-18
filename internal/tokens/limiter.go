package tokens

import (
	"sync"
	"time"

	"github.com/kazuhahub/rackbook/internal/lru"
)

// Limiter counts failed token attempts per client address and blocks a client
// that fails too often for a while. State is in memory only.
type Limiter struct {
	Max    int           // failures allowed per Window; default 10
	Window time.Duration // default 1 minute
	Now    func() time.Time

	mu sync.Mutex
	m  *lru.Cache[string, *bucket]
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
	if l.m == nil {
		return false, 0
	}
	b, _ := l.m.Get(ip)
	if b == nil {
		return false, 0
	}
	now := l.now()
	if now.Sub(b.start) >= w {
		l.m.Delete(ip)
		return false, 0
	}
	if b.count >= max {
		return true, int(w.Seconds() - now.Sub(b.start).Seconds() + 1)
	}
	return false, 0
}

// maxClients bounds the memory of the limiter; the least recently seen clients
// are forgotten first.
const maxClients = 10000

// Fail records a failed attempt.
func (l *Limiter) Fail(ip string) {
	_, w := l.params()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = lru.New[string, *bucket](maxClients)
	}
	now := l.now()
	b, _ := l.m.Get(ip)
	if b == nil || now.Sub(b.start) >= w {
		b = &bucket{start: now}
		l.m.Put(ip, b)
	}
	b.count++
}
