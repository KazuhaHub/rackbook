package tokens

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/fsutil"
	"github.com/kazuhahub/rackbook/internal/gitstore"
)

// Registry reads and changes .rackbook/tokens.yml through the store.
type Registry struct {
	Store *gitstore.Store
	// Now is the clock; nil = time.Now.
	Now func() time.Time
	// UsePath is a JSON file that keeps the last use of each token across
	// restarts (serve --state-dir). Empty = in memory only.
	UsePath string
	// Blocked, when set, says a token is revoked for a local account (design-local-accounts.md, 5.11): it is on the account
	// store's revocation list, or its creator's credentials_valid_after is later than its creation. Lookup refuses it at once,
	// whatever tokens.yml says yet, and List shows it as revoked.
	Blocked func(Token) bool

	mu     sync.Mutex
	raw    []byte
	parsed []Token
	perr   error
	loaded bool
	used   map[string]time.Time
	// usedLoaded is set once UsePath has been read.
	usedLoaded bool
}

func (r *Registry) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// List returns every token in the file, including revoked and expired ones.
// The file is re-read each time (it is small) and parsed again only when it
// changed, so a pull that brings in a revocation applies at once.
func (r *Registry) List() ([]Token, error) {
	b, _, err := r.Store.StateFile(File)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.loaded || !bytes.Equal(b, r.raw) {
		r.raw, r.loaded = b, true
		r.parsed, r.perr = Parse(b)
	}
	return append([]Token(nil), r.parsed...), r.perr
}

// Listed is List for display: a token the local accounts have revoked is shown as revoked ("pending record": its entry in
// tokens.yml has not been revoked yet), so the console does not offer it as active. List stays as the file has it, because the
// record layer must see what is still to be revoked there.
func (r *Registry) Listed() ([]Token, error) {
	ts, err := r.List()
	if err != nil || r.Blocked == nil {
		return ts, err
	}
	for i := range ts {
		if ts[i].Revoked == "" && r.Blocked(ts[i]) {
			ts[i].Revoked = r.now().UTC().Truncate(time.Second).Format(time.RFC3339)
			ts[i].RevokedBy = "rackbook: revoked with its local account (the record in tokens.yml is pending)"
		}
	}
	return ts, nil
}

// Lookup finds the active token for secret. A file that does not parse is an
// error, so every token fails closed.
func (r *Registry) Lookup(secret string) (*Token, error) {
	ts, err := r.List()
	if err != nil {
		return nil, err
	}
	t, err := Match(ts, secret, r.now())
	if err == nil && r.Blocked != nil && r.Blocked(*t) {
		return nil, ErrRevoked // revoked for a local account (design-local-accounts.md, 5.11), whatever tokens.yml says yet
	}
	return t, err
}

// Touch records a use of the token. With UsePath the file is rewritten when
// the token's recorded use is a minute old or more, so a busy token does not
// write on every request.
func (r *Registry) Touch(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loadUsed()
	now := r.now()
	prev, seen := r.used[name]
	r.used[name] = now
	if r.UsePath != "" && (!seen || now.Sub(prev) >= time.Minute) {
		if err := r.saveUsed(); err != nil {
			slog.Warn("token last-use not saved", "file", r.UsePath, "err", err)
		}
	}
}

// LastUsed is when the token was last used: since the server started, or
// across restarts with UsePath.
func (r *Registry) LastUsed(name string) (time.Time, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loadUsed()
	t, ok := r.used[name]
	return t, ok
}

// loadUsed reads UsePath once; a missing or unreadable file starts empty.
func (r *Registry) loadUsed() {
	if r.used == nil {
		r.used = map[string]time.Time{}
	}
	if r.usedLoaded || r.UsePath == "" {
		return
	}
	r.usedLoaded = true
	b, err := os.ReadFile(r.UsePath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("token last-use not read", "file", r.UsePath, "err", err)
		}
		return
	}
	var m map[string]time.Time
	if err := json.Unmarshal(b, &m); err != nil {
		slog.Warn("token last-use not read", "file", r.UsePath, "err", err)
		return
	}
	for k, v := range m {
		if v.After(r.used[k]) {
			r.used[k] = v
		}
	}
}

// saveUsed writes the map to UsePath atomically.
func (r *Registry) saveUsed() error {
	b, err := json.Marshal(r.used)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(r.UsePath, b, 0o600)
}

// CreateParams describes a new token.
type CreateParams struct {
	Name        string
	Scope       string
	Collections []string
	Actions     []string
	WriteMode   string
	ExpiresDays int // 0 = never
}

// Errors from Create and Revoke.
var (
	ErrExists  = errors.New("a token with this name already exists")
	ErrInvalid = errors.New("invalid token request")
	ErrMissing = errors.New("no such token")
)

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Created is the result of Create.
type Created struct {
	Secret string // shown once
	Token  Token
	Result *gitstore.StateResult
}

// Create makes a token on behalf of who, a current administrator.
func (r *Registry) Create(ctx context.Context, p CreateParams, who *auth.Identity) (*Created, error) {
	if who.Anonymous() {
		return nil, bad("tokens need an identified creator (sign in, or start the server with --editor)")
	}
	if p.Scope == "" {
		p.Scope = ScopeRead
	}
	secret, err := Generate()
	if err != nil {
		return nil, err
	}
	now := r.now().UTC().Truncate(time.Second)
	tok := Token{
		Name: p.Name, ShownPrefix: ShownPrefix(secret), Hash: HashSecret(secret), Scope: p.Scope,
		Collections: p.Collections, Actions: p.Actions, WriteMode: p.WriteMode,
		CreatedBy: who.ID, CreatedVia: creatorMethod(who.Method), Created: now.Format(time.RFC3339),
	}
	if tok.WriteMode == ModePR {
		tok.WriteMode = ""
	}
	if p.ExpiresDays > 0 {
		tok.Expires = now.Add(time.Duration(p.ExpiresDays) * 24 * time.Hour).Format(time.RFC3339)
	}
	if err := tok.Validate(); err != nil {
		return nil, bad("%v", err)
	}
	if tok.Scope == ScopeRead && (tok.WriteMode != "" || len(tok.Actions) > 0 || len(tok.Collections) > 0) {
		return nil, bad("collections, actions and write_mode only apply to write tokens")
	}
	if tok.WriteMode == ModePush && len(tok.Collections) == 0 {
		return nil, bad("write_mode push needs an explicit list of collections")
	}
	known := map[string]bool{}
	for _, c := range r.Store.Ledger().Collections {
		known[c.Name] = true
	}
	for _, c := range tok.Collections {
		if !known[c] {
			return nil, bad("unknown collection %q", c)
		}
	}
	res, err := r.Store.MutateStateFile(ctx, File, "rackbook(auth): create token "+tok.Name, who, func(old []byte, _ bool) ([]byte, error) {
		ts, err := Parse(old)
		if err != nil {
			return nil, err
		}
		for _, t := range ts {
			if t.Name == tok.Name {
				return nil, ErrExists
			}
		}
		return Marshal(append(ts, tok))
	})
	if err != nil {
		return nil, err
	}
	return &Created{Secret: secret, Token: tok, Result: res}, nil
}

// ApplyRevoke returns tokens.yml content with the token revoked (the entry
// stays, for the record). Revoking a revoked token returns old unchanged.
func ApplyRevoke(old []byte, name, by string, now time.Time) ([]byte, error) {
	ts, err := Parse(old)
	if err != nil {
		return nil, err
	}
	for i := range ts {
		if ts[i].Name != name {
			continue
		}
		if ts[i].Revoked != "" {
			return old, nil
		}
		ts[i].Revoked = now.UTC().Truncate(time.Second).Format(time.RFC3339)
		ts[i].RevokedBy = by
		return Marshal(ts)
	}
	return nil, ErrMissing
}

// Revoke revokes a token on behalf of who.
func (r *Registry) Revoke(ctx context.Context, name string, who *auth.Identity, opts ...gitstore.StateOption) (*gitstore.StateResult, error) {
	name = strings.TrimSpace(name)
	return r.Store.MutateStateFile(ctx, File, "rackbook(auth): revoke token "+name, who, func(old []byte, _ bool) ([]byte, error) {
		return ApplyRevoke(old, name, who.IDOrEmpty(), r.now())
	}, opts...)
}

// creatorMethod is the login method worth recording: only those whose
// identities match role entries directly.
func creatorMethod(m string) string {
	switch m {
	case auth.MethodOIDC, auth.MethodPasskey, auth.MethodCloudflareAccess, auth.MethodNone, auth.MethodLocal:
		return m
	}
	return ""
}

// SubjectMethod is the method to evaluate the creator with: the recorded one,
// else none (the behaviour of tokens made before it was recorded).
func (t Token) SubjectMethod() string {
	if m := creatorMethod(t.CreatedVia); m != "" {
		return m
	}
	return auth.MethodNone
}
