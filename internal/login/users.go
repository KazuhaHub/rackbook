package login

import (
	"sort"
	"sync"
	"time"
)

// SeenUser is someone who logged in or used a session since the server
// started. It lives in memory only; the durable facts (roles, passkeys) are
// in Git.
type SeenUser struct {
	ID        string    `json:"id"`
	Name      string    `json:"name,omitempty"`
	Method    string    `json:"method"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	// Groups are the groups of the last session seen, for evaluating group: entries
	// of auth.roles and auth.auditors in the users list. Memory only, never sent.
	Groups []string `json:"-"`
	// AppRoles are the same for app-role: entries.
	AppRoles []string `json:"-"`
}

type userRegistry struct {
	mu   sync.Mutex
	seen map[string]*SeenUser
}

const maxSeenUsers = 10_000

func newUserRegistry() *userRegistry { return &userRegistry{seen: map[string]*SeenUser{}} }

func (u *userRegistry) touch(id, name, method string, groups, appRoles []string, now time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	e := u.seen[id]
	if e == nil {
		if len(u.seen) >= maxSeenUsers {
			return
		}
		e = &SeenUser{ID: id, FirstSeen: now}
		u.seen[id] = e
	}
	if name != "" {
		e.Name = name
	}
	e.Method, e.LastSeen = method, now
	if method == "oidc" || len(groups) > 0 || len(appRoles) > 0 { // only an OIDC session carries groups and app roles
		e.Groups, e.AppRoles = groups, appRoles
	}
}

func (u *userRegistry) list() []SeenUser {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]SeenUser, 0, len(u.seen))
	for _, e := range u.seen {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
