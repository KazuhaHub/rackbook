package oauthserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/kazuhahub/rackbook/internal/fsutil"
)

// StateFile is the grant file in the state directory.
const StateFile = "oauth-grants.json"

const stateVersion = 1

// Subject is the person a grant acts for, as the console knew them when they
// approved it. The role is never stored: it is evaluated from auth.roles for
// this subject on every request and every refresh.
type Subject struct {
	ID     string   `json:"id"`
	Email  string   `json:"email,omitempty"`
	Name   string   `json:"name,omitempty"`
	Method string   `json:"method"`
	Groups []string `json:"groups,omitempty"`
	// AppRoles is the ID token's roles claim at approval, for app-role: entries.
	AppRoles []string `json:"app_roles,omitempty"`
	// SignedIn is when the session that approved the grant signed in. The claims above
	// are as old as that sign-in, so their bound starts there, or at the grant's creation
	// if that is earlier (Server.effective). Zero (a grant made before it was recorded)
	// means the claims no longer count.
	SignedIn time.Time `json:"signed_in,omitzero"`
}

// Client is a client registered with RFC 7591.
type Client struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	RedirectURIs []string  `json:"redirect_uris"`
	Created      time.Time `json:"created"`
	// LastUsed is when a grant was last created for the client (zero = never).
	LastUsed time.Time `json:"last_used,omitzero"`
}

// Grant is one authorization of one client by one person. It holds the SHA-256
// hashes of the refresh tokens, never the tokens.
type Grant struct {
	ID         string    `json:"id"`
	Subject    Subject   `json:"subject"`
	ClientID   string    `json:"client_id"`
	ClientName string    `json:"client_name"`
	Scopes     []string  `json:"scopes"`
	Resource   string    `json:"resource"`
	Created    time.Time `json:"created"`
	// LastUsed is the last refresh (the creation time until the first one).
	LastUsed time.Time `json:"last_used"`
	// RefreshHash is the SHA-256 of the one refresh token that works now.
	RefreshHash string `json:"refresh_hash"`
	// Approved is when the person approved it (the authorization code was issued): a credentials_valid_after later than that
	// refuses the grant, so one whose code exchange raced with a disable is refused too.
	Approved time.Time `json:"approved,omitempty"`
	// Retired holds the last few replaced tokens, to recognise a reused one.
	Retired []Retired `json:"retired,omitempty"`
}

// Retired is a refresh token that was replaced at At.
type Retired struct {
	Hash string    `json:"hash"`
	At   time.Time `json:"at"`
}

type fileData struct {
	Version int                `json:"version"`
	Clients map[string]*Client `json:"clients"`
	Grants  map[string]*Grant  `json:"grants"`
}

func emptyData() fileData {
	return fileData{Version: stateVersion, Clients: map[string]*Client{}, Grants: map[string]*Grant{}}
}

// store is the grant file with its in-process lock. The process-level lock on
// rackbook.lock (held by serve) keeps a second server from using the same
// directory.
type store struct {
	path string
	mu   sync.Mutex
	data fileData
	// blocked says a grant is on the revocation list of the local accounts: it is invisible whatever the state file holds.
	blocked func(id, subject string, approved time.Time) bool
}

func openStore(dir string) (*store, error) {
	s := &store{path: filepath.Join(dir, StateFile), data: emptyData()}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var d fileData
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("%s does not parse (%v): fix or delete it; clients then sign in again", s.path, err)
	}
	if d.Version != stateVersion {
		return nil, fmt.Errorf("%s has version %d, this Rackbook reads version %d", s.path, d.Version, stateVersion)
	}
	if d.Clients == nil {
		d.Clients = map[string]*Client{}
	}
	if d.Grants == nil {
		d.Grants = map[string]*Grant{}
	}
	s.data = d
	return s, nil
}

func clone(d fileData) fileData {
	b, _ := json.Marshal(d)
	var c fileData
	_ = json.Unmarshal(b, &c)
	if c.Clients == nil {
		c.Clients = map[string]*Client{}
	}
	if c.Grants == nil {
		c.Grants = map[string]*Grant{}
	}
	return c
}

// mutate applies fn and writes the file (fsync, rename, directory fsync)
// before it returns. If fn or the write fails, nothing changed.
func (s *store) mutate(fn func(d *fileData) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := clone(s.data)
	if err := fn(&s.data); err != nil {
		s.data = before
		return err
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err == nil {
		err = fsutil.WriteFileAtomic(s.path, append(b, '\n'), 0o600)
	}
	if err != nil {
		s.data = before
		return err
	}
	return nil
}

// grant returns a copy of the grant, or nil.
func (s *store) grant(id string) *Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g := s.data.Grants[id]; g != nil && !s.isBlocked(g) {
		c := *g
		return &c
	}
	return nil
}

func (s *store) client(id string) *Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.data.Clients[id]; c != nil {
		cp := *c
		return &cp
	}
	return nil
}

// grants returns copies of the grants for which keep says true, newest first.
func (s *store) grants(keep func(*Grant) bool) []Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Grant
	for _, g := range s.data.Grants {
		if keep(g) && !s.isBlocked(g) {
			out = append(out, *g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

func (s *store) isBlocked(g *Grant) bool {
	if s.blocked == nil || g == nil {
		return false
	}
	at := g.Approved
	if at.IsZero() {
		at = g.Created
	}
	return s.blocked(g.ID, g.Subject.ID, at)
}
