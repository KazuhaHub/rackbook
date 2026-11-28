package localauth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/internal/accounts"
)

// The commands of the online command line (docs/design-local-accounts.md, 11.2). They run in the server, through the
// admin channel, and the same code runs in the offline command line when the server is stopped, so the behaviour and the
// output are the same. A link is shown to the operator's terminal only; the audit event never holds it.

// AdminRequest is one command.
type AdminRequest struct {
	Cmd      string `json:"cmd"` // invite, reset, unlock, disable, enable, remove, end-sessions, recover
	Username string `json:"username,omitempty"`
	Name     string `json:"name,omitempty"`
	Scope    string `json:"scope,omitempty"`
	All      bool   `json:"all,omitempty"`
	Operator string `json:"operator"`
	// GrantAdmin (recover): also commit local:<username> to auth.roles.admin, online only.
	GrantAdmin bool `json:"grant_admin,omitempty"`
}

// AdminResponse is its result. Links are complete only when the server knows its --base-url.
type AdminResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Code  string `json:"code,omitempty"`
	// Links are the links made, one per account.
	Links []AdminLink `json:"links,omitempty"`
	// Lines are what to tell the operator besides.
	Lines []string `json:"lines,omitempty"`
}

// AdminLink is a link for one account.
type AdminLink struct {
	Username string `json:"username"`
	Kind     string `json:"kind"` // invite or reset
	Scope    string `json:"scope,omitempty"`
	URL      string `json:"url"`
	Expires  string `json:"expires"`
}

// AdminEnv is what the commands need. The server makes one from its settings, the offline command line from flags.
type AdminEnv struct {
	Store *accounts.Store
	// BaseURL is the public https origin; empty makes links start at /auth/local/setup.
	BaseURL   string
	InviteTTL func() time.Duration
	ResetTTL  func() time.Duration
	// Revoker lists and revokes the API tokens and OAuth grants an account owns (5.11). nil: the server is not running (the
	// offline command line): the revocations are recorded as pending, and the server applies them at its next start.
	Revoker Revoker
	// Guard is run inside every disable and remove: it refuses what would leave sso_only without a local administrator.
	Guard func(st *accounts.State, username string) error
	// Unlocked is told an account's counters were cleared, so that the memory tables forget it too.
	Unlocked func(username string)
	// GrantAdmin commits the admin role entry; nil = not available (the offline command line).
	GrantAdmin func(username, operator string) error
	Now        func() time.Time
}

func (e AdminEnv) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e AdminEnv) link(token string) string {
	return strings.TrimRight(e.BaseURL, "/") + "/auth/local/setup#" + token
}

func fail1(err error) AdminResponse {
	r := AdminResponse{Error: err.Error()}
	switch {
	case errors.Is(err, accounts.ErrAuditUnavailable):
		r.Code = "audit_unavailable"
	case errors.Is(err, accounts.ErrUsernameUsed):
		r.Code = "username_used"
	case errors.Is(err, accounts.ErrNoSuchUser):
		r.Code = "no_such_account"
	case errors.Is(err, ErrLastLocalAdmin):
		r.Code = "last_local_admin"
	case errors.Is(err, accounts.ErrBadState):
		r.Code = "bad_state"
	}
	return r
}

// ErrLastLocalAdmin refuses disabling or removing the last active local administrator while sso_only is on (5.9).
var ErrLastLocalAdmin = errors.New("this is the last active local administrator, and sso_only is on: without one nobody could sign in when the identity provider breaks")

// Do runs one command.
func (e AdminEnv) Do(req AdminRequest) AdminResponse {
	by := accounts.CLI(strings.TrimSpace(req.Operator))
	now := e.now()
	user := normalise(req.Username)
	if req.Cmd != "reset" && req.Cmd != "end-sessions" || !req.All {
		if user == "" || !accounts.ValidUsername(user) {
			return fail1(errors.New("a username matches ^[a-z][a-z0-9._-]{0,31}$"))
		}
	}
	check := accounts.Check(nil)
	if e.Guard != nil {
		check = func(st *accounts.State) error { return e.Guard(st, user) }
	}
	switch req.Cmd {
	case "invite":
		tok, err := e.Store.Invite(by, user, req.Name, e.InviteTTL(), now)
		if err != nil {
			return fail1(err)
		}
		return AdminResponse{OK: true, Links: []AdminLink{{Username: user, Kind: accounts.LinkInvite, Scope: accounts.ScopeAll, URL: e.link(tok), Expires: now.Add(e.InviteTTL()).UTC().Format(time.RFC3339)}}}
	case "reset":
		scope := req.Scope
		if scope == "" {
			scope = accounts.ScopeAll
		}
		if !req.All {
			tok, err := e.Store.Reset(by, user, accounts.ResetOptions{Scope: scope, TTL: e.ResetTTL(), Revoke: e.revocation(user)}, now)
			if err != nil {
				return fail1(err)
			}
			out := AdminResponse{OK: true, Links: []AdminLink{e.resetLink(user, scope, tok, now)}}
			e.revoke(by, user, &out)
			return out
		}
		out := AdminResponse{OK: true}
		for _, n := range e.Store.Snapshot().Names() {
			a := e.Store.Lookup(n)
			if a == nil || a.State == accounts.StateRemoved || a.State == accounts.StateDisabled {
				continue
			}
			tok, err := e.Store.Reset(by, n, accounts.ResetOptions{Scope: scope, TTL: e.ResetTTL(), Revoke: e.revocation(n)}, now)
			if err != nil {
				out.Lines = append(out.Lines, fmt.Sprintf("%s: %v", n, err))
				out.OK = false
				continue
			}
			out.Links = append(out.Links, e.resetLink(n, scope, tok, now))
			e.revoke(by, n, &out)
		}
		return out
	case "unlock":
		if err := e.Store.Unlock(by, user, now); err != nil {
			return fail1(err)
		}
		if e.Unlocked != nil {
			e.Unlocked(user)
		}
		return AdminResponse{OK: true, Lines: []string{user + " is unlocked"}}
	case "disable":
		if err := e.Store.Disable(by, user, check, e.revocation(user), now); err != nil {
			return fail1(err)
		}
		out := AdminResponse{OK: true, Lines: []string{user + " is disabled; its sessions ended"}}
		e.revoke(by, user, &out)
		return out
	case "enable":
		if err := e.Store.Enable(by, user, now); err != nil {
			return fail1(err)
		}
		return AdminResponse{OK: true, Lines: []string{user + " is enabled"}}
	case "remove":
		if err := e.Store.Remove(by, user, check, e.revocation(user), now); err != nil {
			return fail1(err)
		}
		out := AdminResponse{OK: true, Lines: []string{user + " is removed; the name stays used"}}
		e.revoke(by, user, &out)
		return out
	case "end-sessions":
		if !req.All {
			if err := e.Store.EndSessions(by, user, "cli", now); err != nil {
				return fail1(err)
			}
			return AdminResponse{OK: true, Lines: []string{"the sessions of " + user + " ended"}}
		}
		out := AdminResponse{OK: true}
		for _, n := range e.Store.Snapshot().Names() {
			if a := e.Store.Lookup(n); a == nil || a.State == accounts.StateRemoved {
				continue
			}
			if err := e.Store.EndSessions(by, n, "cli", now); err != nil {
				out.OK = false
				out.Lines = append(out.Lines, fmt.Sprintf("%s: %v", n, err))
			}
		}
		if out.OK {
			out.Lines = []string{"every session ended"}
		}
		return out
	case "recover":
		tok, created, err := e.Store.Recover(by, user, req.Name, e.InviteTTL(), e.ResetTTL(), e.revocation(user), now)
		if err != nil {
			return fail1(err)
		}
		out := AdminResponse{OK: true}
		if created {
			out.Links = []AdminLink{{Username: user, Kind: accounts.LinkInvite, Scope: accounts.ScopeAll, URL: e.link(tok), Expires: now.Add(e.InviteTTL()).UTC().Format(time.RFC3339)}}
			out.Lines = append(out.Lines, "there was no such account: it is invited")
		} else {
			out.Links = []AdminLink{e.resetLink(user, accounts.ScopeAll, tok, now)}
			out.Lines = append(out.Lines, "a full reset is issued: whoever opens the link takes over the account")
			e.revoke(by, user, &out)
		}
		if req.GrantAdmin {
			switch {
			case e.GrantAdmin == nil:
				out.Lines = append(out.Lines, fmt.Sprintf("add %q to auth.roles.admin in rackbook.yml: the server is not running, so nothing was committed", "local:"+user))
			default:
				if err := e.GrantAdmin(user, req.Operator); err != nil {
					out.Lines = append(out.Lines, fmt.Sprintf("the admin role entry could not be committed (%v): add %q to auth.roles.admin in rackbook.yml", err, "local:"+user))
				} else {
					out.Lines = append(out.Lines, fmt.Sprintf("%q is committed to auth.roles.admin", "local:"+user))
				}
			}
		}
		return out
	}
	return fail1(fmt.Errorf("unknown command %q", req.Cmd))
}

func (e AdminEnv) resetLink(user, scope, tok string, now time.Time) AdminLink {
	return AdminLink{Username: user, Kind: accounts.LinkReset, Scope: scope, URL: e.link(tok), Expires: now.Add(e.ResetTTL()).UTC().Format(time.RFC3339)}
}

// ---- the server's environment

// AdminEnv is the environment of the commands the server runs.
func (s *Service) AdminEnv() AdminEnv {
	return AdminEnv{
		Store: s.store, BaseURL: s.base.String(),
		InviteTTL: func() time.Duration { return s.settings().InviteTTL },
		ResetTTL:  func() time.Duration { return s.settings().ResetTTL },
		Guard:     s.lastAdminGuard,
		Unlocked:  s.tables.ClearName,
		GrantAdmin: func(username, operator string) error {
			if s.o.GrantAdmin == nil {
				return errors.New("not available")
			}
			return s.o.GrantAdmin(contextBackground(), username, operator)
		},
		Now:     s.now,
		Revoker: s.currentRevoker(),
	}
}

func (s *Service) currentRevoker() Revoker {
	s.revMu.Lock()
	defer s.revMu.Unlock()
	return s.revoker
}

// lastAdminGuard refuses to disable or remove the last active local administrator while sso_only is on (5.9, 2.1).
func (s *Service) lastAdminGuard(st *accounts.State, target string) error {
	return LastAdminGuard(func() bool { return s.ssoOnly(s.settings()) }, s.o.IsAdmin)(st, target)
}

// LastAdminGuard is the guard of 5.9: while ssoOnly says sso_only is in force, the last local administrator (an account that is
// live, with a password and a second factor, and holds the admin role by isAdmin) cannot be disabled or removed. The online
// server and the offline command line, which reads rackbook.yml for this, share it.
func LastAdminGuard(ssoOnly func() bool, isAdmin func(string) bool) func(st *accounts.State, target string) error {
	return func(st *accounts.State, target string) error {
		if isAdmin == nil || !ssoOnly() {
			return nil
		}
		admin := func(n string) bool {
			a := st.Accounts[n]
			return a != nil && a.Live() && a.Password != "" && (a.TOTP != nil || len(a.Passkeys) > 0) && isAdmin(n)
		}
		if !admin(target) {
			return nil
		}
		for n := range st.Accounts {
			if n != target && admin(n) {
				return nil
			}
		}
		return ErrLastLocalAdmin
	}
}

// Revoker finds and revokes what an account owns outside the store: the API tokens it created and the OAuth grants it approved.
// A revocation has two layers (5.11). The local one is the store's revocation list, which the token registry and the OAuth server
// consult on every use: it is written first, in the audited change, and does not depend on Git. The record layer follows: the
// token is also revoked in .rackbook/tokens.yml, with a direct commit, which may fail (a pull request, a failed push) and is retried
// in the background; nothing waits for it.
type Revoker interface {
	// Owned lists the names of the active API tokens created by local:<username> and the ids of its OAuth grants.
	Owned(username string) (tokens, grants []string, err error)
	// TokenIDs returns, for each name that is a token, the SHA-256 of its secret: the identity the revocation list uses (a name can
	// be reused by a later token).
	TokenIDs(names []string) (map[string]string, error)
	// RecordTokens revokes in tokens.yml the tokens with these ids that are not revoked there yet.
	RecordTokens(ctx context.Context, ids []string) error
	// RevokeGrant removes a grant from the OAuth server's state file (a local file).
	RevokeGrant(ctx context.Context, id string) error
}

// revocation is what a disable, a remove or a reset records as pending (5.11): every token and grant the account owns when it
// is applied (the AllOwned marker), and, when they can be listed now, their names and ids, which the audit event shows.
func (e AdminEnv) revocation(user string) accounts.Revocations {
	rev := accounts.EverythingOwned()
	if e.Revoker != nil {
		if names, ids, err := e.Revoker.Owned(user); err == nil {
			rev.Tokens, rev.Grants = append(rev.Tokens, names...), append(rev.Grants, ids...)
		}
	}
	return rev
}

// revoke carries out the revocations pending for the account and says what happened. Without a Revoker, or when listing fails,
// they stay pending: the server applies them at its next start and retries every minute. The record in tokens.yml is made in the
// background and nobody waits for it.
func (e AdminEnv) revoke(by accounts.Actor, user string, out *AdminResponse) {
	if e.Revoker == nil {
		out.Lines = append(out.Lines, "the API tokens and app connections of "+user+" are recorded to be revoked: the server does it when it starts")
		return
	}
	n, m, err := ApplyRevocations(context.Background(), e.Store, e.Revoker, by, user)
	if err != nil {
		out.Lines = append(out.Lines, fmt.Sprintf("revoking the API tokens and app connections of %s failed (%v): they stay pending and are retried every minute", user, err))
		return
	}
	out.Lines = append(out.Lines, fmt.Sprintf("revoked %d API tokens and %d app connections of %s: refused from now on", n, m, user))
	go func() { _ = RecordRevoked(context.Background(), e.Store, e.Revoker) }()
}

// ApplyRevocations carries out the pending revocations of one account. It resolves the AllOwned marker and the names, writes the
// local revocation list and clears the pending entries in one audited change (that is what makes them done), and then removes
// the grants from the OAuth server's state file. Whether the record in tokens.yml can be made does not matter here (RecordRevoked).
// It returns how many tokens and grants were revoked.
func ApplyRevocations(ctx context.Context, st *accounts.Store, rv Revoker, by accounts.Actor, user string) (tokens, grants int, err error) {
	a := st.Lookup(user)
	if a == nil || a.PendingRevocations.Empty() {
		return 0, 0, nil
	}
	pend := a.PendingRevocations
	names, ids := pend.Tokens, pend.Grants
	if slices.Contains(pend.Tokens, accounts.AllOwned) || slices.Contains(pend.Grants, accounts.AllOwned) {
		ot, og, err := rv.Owned(user)
		if err != nil {
			return 0, 0, err
		}
		if slices.Contains(pend.Tokens, accounts.AllOwned) {
			names = append(slices.Clone(pend.Tokens), ot...)
		}
		if slices.Contains(pend.Grants, accounts.AllOwned) {
			ids = append(slices.Clone(pend.Grants), og...)
		}
	}
	names = slices.Compact(slices.Sorted(slices.Values(without(names, []string{accounts.AllOwned}))))
	ids = slices.Compact(slices.Sorted(slices.Values(without(ids, []string{accounts.AllOwned}))))
	hashes, err := rv.TokenIDs(names)
	if err != nil {
		return 0, 0, err
	}
	now := time.Now()
	var items []accounts.RevokedItem
	for _, n := range names {
		if h := hashes[n]; h != "" {
			items = append(items, accounts.RevokedItem{Kind: accounts.KindToken, ID: h, Account: user, Time: now.UTC()})
			tokens++
		}
	}
	for _, g := range ids {
		items = append(items, accounts.RevokedItem{Kind: accounts.KindGrant, ID: g, Account: user, Time: now.UTC()})
		grants++
	}
	done := accounts.Revocations{Tokens: slices.Clone(pend.Tokens), Grants: slices.Clone(pend.Grants)}
	done.Tokens, done.Grants = append(done.Tokens, names...), append(done.Grants, ids...)
	if err := st.RevocationsApplied(by, user, done, items); err != nil {
		return 0, 0, err
	}
	// from here on the token and the grant are refused (the list). Taking a grant out of its file is a local write, and the list
	// holds if it fails.
	for _, g := range ids {
		_ = rv.RevokeGrant(ctx, g)
	}
	return tokens, grants, nil
}

// RecordRevoked makes the record layer of every revoked token: it revokes in tokens.yml the tokens on the revocation list that
// are not revoked there. It may fail (a pull request instead of a commit, a push that is refused, no network) without anything
// else depending on it, since the list already blocks the token; it is retried at start and every minute.
func RecordRevoked(ctx context.Context, st *accounts.Store, rv Revoker) error {
	ids := st.RevokedIDs(accounts.KindToken)
	if len(ids) == 0 {
		return nil
	}
	return rv.RecordTokens(ctx, ids)
}

// SetRevoker gives the service what it needs to revoke tokens and grants; call it before ApplyAllRevocations.
func (s *Service) SetRevoker(r Revoker) {
	s.revMu.Lock()
	s.revoker = r
	s.revMu.Unlock()
}

// ApplyAllRevocations carries out every account's pending revocations: at start, before the server serves, and every minute
// after (RunRevocations), so that what could not be done at the time of a disable or a reset, or was recorded by the offline
// command line, is not forgotten.
func (s *Service) ApplyAllRevocations(ctx context.Context) error {
	rv := s.currentRevoker()
	if rv == nil {
		return nil
	}
	var first error
	for _, n := range s.store.Snapshot().Names() {
		if a := s.store.Lookup(n); a == nil || a.PendingRevocations.Empty() {
			continue
		}
		if _, _, err := ApplyRevocations(ctx, s.store, rv, accounts.Actor{Method: "system"}, n); err != nil {
			s.log.Warn("pending revocations of a local account could not be applied; they are retried", "account", n, "err", err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}

// RecordRevoked makes the record in tokens.yml of every revoked token (see the function of that name).
func (s *Service) RecordRevoked(ctx context.Context) error {
	rv := s.currentRevoker()
	if rv == nil {
		return nil
	}
	return RecordRevoked(ctx, s.store, rv)
}

// RunRevocations retries the pending revocations and the record in tokens.yml now and then every minute, until ctx ends. Neither
// blocks sign-in, setup, enable or recover.
func (s *Service) RunRevocations(ctx context.Context) {
	step := func() {
		_ = s.ApplyAllRevocations(ctx)
		if err := s.RecordRevoked(ctx); err != nil {
			s.log.Warn("revoked API tokens could not be recorded in tokens.yml yet; they are refused all the same and the record is retried", "err", err)
		}
	}
	step()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			step()
		}
	}
}

func without(from, remove []string) []string {
	var out []string
	for _, v := range from {
		if !slices.Contains(remove, v) {
			out = append(out, v)
		}
	}
	return out
}
