package login

import (
	"container/list"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/url"
	"strings"
	"sync"
	"time"

	authoidc "github.com/KazuhaHub/authcore/oidc"
)

// Bounds of the pending-login store.
const (
	pendingTTL      = 10 * time.Minute
	pendingCapacity = 10_000
)

type pendingEntry struct {
	state   authoidc.State
	ret     string
	expires time.Time
	elem    *list.Element
}

// pendingStore keeps OIDC protocol state between /auth/oidc/start and the
// callback: in memory, bounded, one-time and short-lived. A restart only
// makes someone mid-login click again.
type pendingStore struct {
	mu    sync.Mutex
	items map[string]*pendingEntry
	order *list.List
	now   func() time.Time
}

func newPendingStore(now func() time.Time) *pendingStore {
	return &pendingStore{items: map[string]*pendingEntry{}, order: list.New(), now: now}
}

// put stores state and the return path and returns the random id that goes
// into the browser-binding cookie.
func (p *pendingStore) put(st authoidc.State, ret string) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(b[:])
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	// Entries are in insertion order and share one TTL, so the expired ones
	// are at the front.
	for e := p.order.Front(); e != nil; e = p.order.Front() {
		id := e.Value.(string)
		if ent := p.items[id]; ent != nil && now.Before(ent.expires) {
			break
		}
		p.order.Remove(e)
		delete(p.items, id)
	}
	for len(p.items) >= pendingCapacity {
		front := p.order.Front()
		if front == nil {
			break
		}
		p.order.Remove(front)
		delete(p.items, front.Value.(string))
	}
	p.items[id] = &pendingEntry{state: st, ret: ret, expires: now.Add(pendingTTL), elem: p.order.PushBack(id)}
	return id, nil
}

type takeResult int

const (
	takeOK      takeResult = iota
	takeUnknown            // no such id: expired, replayed, or never started here
	takeBinding            // the id exists but the callback's state value is not its state
)

// take returns and removes the entry of id, atomically, if the callback's
// state value is the one stored with it. A state that does not match leaves
// the entry alone (so a forged callback cannot burn someone else's login).
// An expired entry is removed and reported as unknown.
func (p *pendingStore) take(id, state string) (*pendingEntry, takeResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.items[id]
	if !ok {
		return nil, takeUnknown
	}
	if !p.now().Before(e.expires) {
		p.order.Remove(e.elem)
		delete(p.items, id)
		return nil, takeUnknown
	}
	if subtle.ConstantTimeCompare([]byte(state), []byte(e.state.Value)) != 1 {
		return nil, takeBinding
	}
	p.order.Remove(e.elem)
	delete(p.items, id)
	return e, takeOK
}

// drop forgets id (used when the IdP reports an error).
func (p *pendingStore) drop(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.items[id]; ok {
		p.order.Remove(e.elem)
		delete(p.items, id)
	}
}

func (p *pendingStore) len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.items)
}

// SafeReturn turns a user-supplied return path into one that is safe to
// redirect to: a same-origin absolute path ("/c/devices?x=1"), never a URL
// with a scheme or host, never protocol-relative ("//host"), never with a
// backslash or control character (browsers treat "\" like "/" and drop tabs
// and newlines, which would turn "/\t/evil.com" into "//evil.com"). Anything
// else, and the login pages themselves, become "/".
func SafeReturn(s string) string {
	if s == "" || len(s) > 2048 || s[0] != '/' {
		return "/"
	}
	if len(s) > 1 && (s[1] == '/' || s[1] == '\\') {
		return "/"
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '\\' || r == 0x85 || r == 0x2028 || r == 0x2029 {
			return "/"
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	if u.Path == "/auth" || strings.HasPrefix(u.Path, "/auth/") {
		return "/"
	}
	return s
}
