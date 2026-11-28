package localauth

import (
	"errors"
	"fmt"
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
			tok, err := e.Store.Reset(by, user, accounts.ResetOptions{Scope: scope, TTL: e.ResetTTL()}, now)
			if err != nil {
				return fail1(err)
			}
			return AdminResponse{OK: true, Links: []AdminLink{e.resetLink(user, scope, tok, now)}}
		}
		out := AdminResponse{OK: true}
		for _, n := range e.Store.Snapshot().Names() {
			a := e.Store.Lookup(n)
			if a == nil || a.State == accounts.StateRemoved || a.State == accounts.StateDisabled {
				continue
			}
			tok, err := e.Store.Reset(by, n, accounts.ResetOptions{Scope: scope, TTL: e.ResetTTL()}, now)
			if err != nil {
				out.Lines = append(out.Lines, fmt.Sprintf("%s: %v", n, err))
				out.OK = false
				continue
			}
			out.Links = append(out.Links, e.resetLink(n, scope, tok, now))
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
		if err := e.Store.Disable(by, user, check, now); err != nil {
			return fail1(err)
		}
		return AdminResponse{OK: true, Lines: []string{user + " is disabled; its sessions ended"}}
	case "enable":
		if err := e.Store.Enable(by, user, now); err != nil {
			return fail1(err)
		}
		return AdminResponse{OK: true, Lines: []string{user + " is enabled"}}
	case "remove":
		if err := e.Store.Remove(by, user, check, now); err != nil {
			return fail1(err)
		}
		return AdminResponse{OK: true, Lines: []string{user + " is removed; the name stays used"}}
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
		tok, created, err := e.Store.Recover(by, user, req.Name, e.InviteTTL(), e.ResetTTL(), now)
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
		Now: s.now,
	}
}

// lastAdminGuard refuses to disable or remove the last active local administrator while sso_only is on (5.9, 2.1).
func (s *Service) lastAdminGuard(st *accounts.State, target string) error {
	if !s.ssoOnly(s.settings()) || s.o.IsAdmin == nil {
		return nil
	}
	isAdmin := func(n string) bool {
		a := st.Accounts[n]
		return a != nil && a.State == accounts.StateActive && a.Password != "" && (a.TOTP != nil || len(a.Passkeys) > 0) && s.o.IsAdmin(n)
	}
	if !isAdmin(target) {
		return nil
	}
	for n := range st.Accounts {
		if n != target && isAdmin(n) {
			return nil
		}
	}
	return ErrLastLocalAdmin
}
