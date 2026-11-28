package accounts

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
)

// The account changes of piece 4 (docs/design-local-accounts.md, 5): invite, opening a link, first setup, reset,
// disable, enable, remove, sessions ended, unlock and the recovery fallback. Each is one Store.Change: audited before
// it is made, written once. The sign-in counters are not here; they are counter writes of the sign-in service.

// Link kinds of Pending.Kind.
const (
	LinkInvite = "invite"
	LinkReset  = "reset"
)

// HoldTime is how long an opened link is held for the browser that opened it (5.2).
const HoldTime = 30 * time.Minute

// Link and setup errors. The messages are for operators; HTTP answers use the codes of 10 (invite_invalid,
// invite_expired, invite_claimed).
var (
	ErrLinkInvalid  = errors.New("the link is not valid")
	ErrLinkExpired  = errors.New("the link has expired")
	ErrLinkClaimed  = errors.New("the link is held by another browser")
	ErrNoSuchUser   = errors.New("there is no such account")
	ErrBadState     = errors.New("the account is not in a state that allows this")
	ErrNotYourself  = errors.New("an account cannot do this to itself")
	ErrRevocations  = errors.New("API tokens or app connections of the account are still to be revoked")
	ErrNeedsFactor  = errors.New("a second factor is required")
	ErrBadScope     = errors.New("the reset scope must be password, second_factor or all")
	ErrBadName      = errors.New("the display name is too long or has control characters")
	ErrLinkNotReady = errors.New("no link has been issued for this reset yet")
)

// Actor is who performs a change: an administrator signed in on the console (Method "local") or the command
// line (Method "cli", with Operator). Addr is the client address for the console.
type Actor struct {
	Identity string // local:<username> of an administrator
	Name     string
	Method   string
	Operator string
	Addr     string
}

// CLI is the actor of the command line.
func CLI(operator string) Actor { return Actor{Method: "cli", Operator: operator} }

// Self is the actor of an account acting on itself (opening a link, finishing setup, signing out).
func Self(username, name, addr string) Actor {
	return Actor{Identity: "local:" + username, Name: name, Method: "local", Addr: addr}
}

// IsCLI says the actor is the command line.
func (a Actor) IsCLI() bool { return a.Method == "cli" }

// By is the label recorded in a holder's notice.
func (a Actor) By() string {
	if a.IsCLI() {
		return "cli:" + a.Operator
	}
	return a.Identity
}

func (a Actor) ev(name, target, code string, detail ...string) audit.Event {
	e := audit.Event{Event: name, Method: a.Method, Addr: a.Addr, Code: code}
	if target != "" {
		e.Target = "local:" + target
	}
	if a.IsCLI() {
		e.Detail = append([]string{"operator:" + a.Operator}, detail...)
	} else {
		e.Identity, e.Name = a.Identity, a.Name
		e.Detail = slices.Clone(detail)
	}
	return e
}

// ---- revocations (5.11)

// AllOwned is the marker "every API token (or OAuth grant) of this account, found when it is applied": the pending
// revocation of an account whose tokens and grants nobody listed, such as one made by the offline command line.
const AllOwned = "*"

// EverythingOwned is the pending revocation of every API token and OAuth grant the account owns.
func EverythingOwned() Revocations {
	return Revocations{Tokens: []string{AllOwned}, Grants: []string{AllOwned}}
}

func mergeRevocations(dst *Revocations, add Revocations) {
	dst.Tokens = addUnique(dst.Tokens, add.Tokens...)
	dst.Grants = addUnique(dst.Grants, add.Grants...)
}

// revDetail is the audit detail of a revocation: names and ids, never a secret.
func revDetail(rev Revocations) []string {
	var d []string
	if len(rev.Tokens) > 0 {
		d = append(d, "tokens:"+strings.Join(rev.Tokens, ","))
	}
	if len(rev.Grants) > 0 {
		d = append(d, "grants:"+strings.Join(rev.Grants, ","))
	}
	return d
}

// RevocationsApplied is the local layer of a revocation (5.11): in one audited change it adds the revoked tokens and grants to
// the store's revocation list, which the token registry and the OAuth server consult on every use, and removes them from the
// account's pending revocations. Writing the list is what makes a revocation done: it does not depend on Git, so a token is
// refused at once whatever a pull request or a failed push says. The record in tokens.yml follows (RevokedIDs).
func (s *Store) RevocationsApplied(by Actor, username string, done Revocations, items []RevokedItem) error {
	_, err := s.Change(by.ev("account_revocations_applied", username, "", revDetail(done)...), func(st *State) error {
		a := st.Accounts[username]
		if a == nil {
			return ErrNoSuchUser
		}
		a.PendingRevocations = Revocations{Tokens: without(a.PendingRevocations.Tokens, done.Tokens), Grants: without(a.PendingRevocations.Grants, done.Grants)}
		for _, it := range items {
			if !slices.ContainsFunc(st.Revoked, func(r RevokedItem) bool { return r.Kind == it.Kind && r.ID == it.ID }) {
				st.Revoked = append(st.Revoked, it)
			}
		}
		return nil
	})
	return err
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

// ---- link tokens

// NewLinkToken is a fresh 256-bit link token, base64url without padding.
func NewLinkToken() (token string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), nil
}

// HashToken is the SHA-256 of a link token, the only form the store keeps.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// NewHold is a fresh browser hold secret (kept in a cookie) and its hash (kept in the account).
func NewHold() (secret, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	secret = base64.RawURLEncoding.EncodeToString(b)
	return secret, HoldHash(secret), nil
}

// HoldHash is the hash of a hold secret.
func HoldHash(secret string) string {
	h := sha256.Sum256([]byte("rackbook hold\x00" + secret))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// FindByLink returns the account whose pending link has this token, comparing every account in constant time.
func FindByLink(st *State, token string) *Account {
	want := HashToken(token)
	var found *Account
	for _, n := range st.Names() { // sorted: the same work for every token
		a := st.Accounts[n]
		if a.Pending != nil && len(a.Pending.TokenHash) == len(want) && subtle.ConstantTimeCompare(a.Pending.TokenHash, want) == 1 {
			found = a
		}
	}
	return found
}

// LinkExpiry is when the pending link of a stops working: its expiry, or the end of the hold when it has been opened,
// whichever is first (5.2).
func (p *Pending) LinkExpiry() time.Time {
	if !p.HeldUntil.IsZero() && p.HeldUntil.Before(p.Expires) {
		return p.HeldUntil
	}
	return p.Expires
}

// CheckLink says whether the link of a can be used now by the browser with hold hash holder ("" when it has not been
// opened yet): the account must be waiting for it, the link not expired, and during a hold only its browser.
func (a *Account) CheckLink(kind string, holder string, now time.Time) error {
	p := a.Pending
	if p == nil || len(p.TokenHash) == 0 || p.Kind != kind {
		return ErrLinkInvalid
	}
	if kind == LinkInvite && a.State != StateInvited || kind == LinkReset && a.State != StateResetPending && a.State != StateInvited {
		return ErrLinkInvalid
	}
	if !now.Before(p.LinkExpiry()) {
		return ErrLinkExpired
	}
	if !p.HeldUntil.IsZero() && now.Before(p.HeldUntil) && (holder == "" || subtle.ConstantTimeCompare([]byte(holder), []byte(p.HeldBy)) != 1) {
		return ErrLinkClaimed
	}
	return nil
}

func cleanName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if len([]rune(name)) > 100 {
		return "", ErrBadName
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", ErrBadName
		}
	}
	return name, nil
}

func validTTL(d time.Duration) bool { return d >= time.Hour && d <= 14*24*time.Hour }

// ---- invite (5.1)

// Invite makes an invited account with a pending invite and returns the token, which is shown once. ttl is
// auth.local.invite_ttl.
func (s *Store) Invite(by Actor, username, name string, ttl time.Duration, now time.Time) (string, error) {
	if !validTTL(ttl) {
		return "", errors.New("the invite lifetime must be between one hour and 14 days")
	}
	name, err := cleanName(name)
	if err != nil {
		return "", err
	}
	token, hash, err := NewLinkToken()
	if err != nil {
		return "", err
	}
	expires := now.Add(ttl).UTC()
	_, err = s.Change(by.ev("account_invited", username, "", "expires:"+expires.Format(time.RFC3339)), func(st *State) error {
		if st.Accounts[username] != nil || s.UsernameUsed(username) {
			return ErrUsernameUsed
		}
		a, err := NewAccount(username, name, by.By(), now)
		if err != nil {
			return err
		}
		a.Pending = &Pending{Kind: LinkInvite, TokenHash: hash, Expires: expires, IssuedBy: by.By()}
		st.Accounts[username] = a
		return nil
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// ---- opening a link (5.2)

// OpenLink holds the link with this token for the browser with hold hash holderHash (30 minutes) and returns the
// account's username and the kind of link. The same browser may open it again. A token that is no account's, an
// expired link and one held by another browser give ErrLinkInvalid, ErrLinkExpired and ErrLinkClaimed.
func (s *Store) OpenLink(token, holderHash, addr string, now time.Time) (username, kind string, err error) {
	snap := s.Snapshot()
	a := FindByLink(snap, token)
	if a == nil {
		return "", "", ErrLinkInvalid
	}
	username, kind = a.Username, a.Pending.Kind
	if err := a.CheckLink(kind, holderHash, now); err != nil {
		return username, kind, err
	}
	if p := a.Pending; !p.HeldUntil.IsZero() && subtle.ConstantTimeCompare([]byte(p.HeldBy), []byte(holderHash)) == 1 && now.Before(p.HeldUntil) {
		// the same browser opens it again: the hold is the one it already has, never longer than the first 30 minutes
		return username, kind, nil
	}
	_, err = s.Change(Self(username, a.Name, addr).ev("account_link_opened", "", kind), func(st *State) error {
		cur := st.Accounts[username]
		if cur.Pending == nil || string(cur.Pending.TokenHash) != string(a.Pending.TokenHash) {
			return ErrLinkInvalid
		}
		if err := cur.CheckLink(kind, holderHash, now); err != nil {
			return err
		}
		cur.Pending.HeldUntil, cur.Pending.HeldBy = now.Add(HoldTime).UTC(), holderHash
		return nil
	})
	return username, kind, err
}

// ---- first setup, and the setup a reset leads to (5.3, 5.8)

// Setup is the finished setup of an opened link. The password was hashed and the second factor verified before
// it is written, outside the writer: what is left to do here is to check the link once more and write.
type Setup struct {
	Token  string
	Holder string // hold hash of the browser
	Addr   string
	// Password is the PHC string of the new password; empty when the scope keeps the old one.
	Password string
	// TOTP or Passkey is the new second factor; both nil when the scope keeps the old one.
	TOTP    *TOTP
	Passkey *Passkey
	// Factor is "totp" or "passkey": the factor the person used or enrolled, for the event.
	Factor string
}

// CompleteSetup writes a finished setup: the account becomes active, the link is consumed, the session id and
// secret are renewed. It returns the account's username. Refused while token or grant revocations are pending.
func (s *Store) CompleteSetup(in Setup, now time.Time) (string, error) {
	snap := s.Snapshot()
	a := FindByLink(snap, in.Token)
	if a == nil {
		return "", ErrLinkInvalid
	}
	username, kind, scope := a.Username, a.Pending.Kind, a.Pending.Scope
	if kind == LinkInvite || scope == "" {
		scope = ScopeAll
	}
	if err := a.CheckLink(kind, in.Holder, now); err != nil {
		return username, err
	}
	if a.Pending.HeldBy == "" {
		return username, ErrLinkInvalid // the link was never opened: nothing is held for this browser
	}
	if !a.PendingRevocations.Empty() {
		return username, ErrRevocations
	}
	ev := Self(username, a.Name, in.Addr).ev("account_setup_completed", "", kind, "factor:"+in.Factor, "scope:"+scope)
	_, err := s.Change(ev, func(st *State) error {
		cur := st.Accounts[username]
		if cur.Pending == nil || string(cur.Pending.TokenHash) != string(a.Pending.TokenHash) {
			return ErrLinkInvalid
		}
		if err := cur.CheckLink(kind, in.Holder, now); err != nil {
			return err
		}
		if !cur.PendingRevocations.Empty() {
			return ErrRevocations
		}
		if in.Password != "" {
			cur.Password = in.Password
		}
		switch {
		case in.TOTP != nil:
			cur.TOTP, cur.Passkeys = in.TOTP, nil
		case in.Passkey != nil:
			cur.TOTP, cur.Passkeys = nil, []Passkey{*in.Passkey}
		}
		if cur.Password == "" || cur.TOTP == nil && len(cur.Passkeys) == 0 {
			return ErrNeedsFactor // never active without a password and a second factor (2.2)
		}
		cur.State, cur.Pending = StateActive, nil
		clearCounters(cur)
		return cur.RenewSessions()
	})
	return username, err
}

func clearCounters(a *Account) {
	a.ConsecutiveFailures, a.TOTPFailures, a.PasskeyPathFailures, a.ReauthFailures = 0, 0, 0, 0
	a.TOTPWindowStart, a.PasskeyWindowStart = time.Time{}, time.Time{}
	a.Locks, a.GoodBuckets = nil, nil
}

// ---- reset (5.8)

// ResetOptions are the checks the caller wants made inside the change.
type ResetOptions struct {
	Scope string
	TTL   time.Duration
	// Revoke is added to the account's pending revocations in the same change (5.11); the event lists it.
	Revoke Revocations
	// Check, when set, is called with the state the change starts from; an error refuses the change.
	Check func(st *State) error
}

// Reset issues a reset link for username and returns the token. At issuance, whatever the scope: the account is
// reset_pending (no role), its session id and secret are renewed, counters, locks and known networks are cleared, and
// what the scope names is deleted. An invited account gets a new invite instead (its link may have died).
func (s *Store) Reset(by Actor, username string, o ResetOptions, now time.Time) (string, error) {
	switch o.Scope {
	case ScopePassword, ScopeSecondFactor, ScopeAll:
	default:
		return "", ErrBadScope
	}
	if o.TTL < time.Hour || o.TTL > 14*24*time.Hour {
		return "", errors.New("the link lifetime must be between one hour and 14 days")
	}
	token, hash, err := NewLinkToken()
	if err != nil {
		return "", err
	}
	expires := now.Add(o.TTL).UTC()
	_, err = s.Change(by.ev("account_reset_issued", username, o.Scope, append([]string{"expires:" + expires.Format(time.RFC3339)}, revDetail(o.Revoke)...)...), func(st *State) error {
		a := st.Accounts[username]
		if a == nil {
			return ErrNoSuchUser
		}
		if o.Check != nil {
			if err := o.Check(st); err != nil {
				return err
			}
		}
		switch a.State {
		case StateRemoved, StateDisabled:
			return fmt.Errorf("%w: the account is %s", ErrBadState, a.State)
		}
		if a.State == StateInvited {
			// no credentials yet: the new link is a new invite
			a.Pending = &Pending{Kind: LinkInvite, TokenHash: hash, Expires: expires, IssuedBy: by.By()}
		} else {
			a.State = StateResetPending
			a.Pending = &Pending{Kind: LinkReset, Scope: o.Scope, TokenHash: hash, Expires: expires, IssuedBy: by.By()}
			switch o.Scope {
			case ScopePassword:
				a.Password = ""
			case ScopeSecondFactor:
				a.TOTP, a.Passkeys = nil, nil
			case ScopeAll:
				a.Password, a.TOTP, a.Passkeys = "", nil, nil
			}
		}
		clearCounters(a)
		mergeRevocations(&a.PendingRevocations, o.Revoke)
		a.Notices = append(a.Notices, Notice{Time: now.UTC(), Kind: "reset:" + o.Scope, By: by.By()})
		return a.RenewSessions()
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// Recover is the lockout fallback of 11.2: it creates the account (an invite) when there is none, and issues a full
// reset when there is. created says which.
func (s *Store) Recover(by Actor, username, name string, inviteTTL, resetTTL time.Duration, rev Revocations, now time.Time) (token string, created bool, err error) {
	if st := s.Snapshot(); st.Accounts[username] == nil {
		token, err = s.Invite(by, username, name, inviteTTL, now)
		return token, true, err
	}
	token, err = s.Reset(by, username, ResetOptions{Scope: ScopeAll, TTL: resetTTL, Revoke: rev}, now)
	return token, false, err
}

// ---- disable, enable, remove, end sessions, unlock (5.9)

// Check is a guard run inside a change against the state it starts from.
type Check func(st *State) error

func (s *Store) changeOne(by Actor, event, code, username string, check Check, fn func(a *Account) error, detail ...string) error {
	_, err := s.Change(by.ev(event, username, code, detail...), func(st *State) error {
		a := st.Accounts[username]
		if a == nil {
			return ErrNoSuchUser
		}
		if check != nil {
			if err := check(st); err != nil {
				return err
			}
		}
		return fn(a)
	})
	return err
}

// Disable sets the account disabled: its session id and secret are renewed (so a later enable does not bring old
// cookies back) and its known networks cleared; sessions end at once and local:<username> has no role.
func (s *Store) Disable(by Actor, username string, check Check, rev Revocations, now time.Time) error {
	return s.changeOne(by, "account_disabled", "", username, check, func(a *Account) error {
		if a.State == StateDisabled || a.State == StateRemoved {
			return fmt.Errorf("%w: the account is %s", ErrBadState, a.State)
		}
		a.State, a.GoodBuckets = StateDisabled, nil
		mergeRevocations(&a.PendingRevocations, rev)
		a.Notices = append(a.Notices, Notice{Time: now.UTC(), Kind: "disabled", By: by.By()})
		return a.RenewSessions()
	}, revDetail(rev)...)
}

// Enable reverses a disable. It is refused while revocations are pending.
func (s *Store) Enable(by Actor, username string, now time.Time) error {
	return s.changeOne(by, "account_enabled", "", username, nil, func(a *Account) error {
		if a.State != StateDisabled {
			return fmt.Errorf("%w: the account is %s", ErrBadState, a.State)
		}
		if !a.PendingRevocations.Empty() {
			return ErrRevocations
		}
		switch {
		case a.Password != "" && (a.TOTP != nil || len(a.Passkeys) > 0):
			a.State = StateActive
		case a.Pending != nil && a.Pending.Kind == LinkReset:
			a.State = StateResetPending
		default:
			a.State = StateInvited
		}
		clearCounters(a)
		a.Notices = append(a.Notices, Notice{Time: now.UTC(), Kind: "enabled", By: by.By()})
		return a.RenewSessions()
	})
}

// Remove deletes the account's credentials and leaves a tombstone: the name stays used (4.5).
func (s *Store) Remove(by Actor, username string, check Check, rev Revocations, now time.Time) error {
	return s.changeOne(by, "account_removed", "", username, check, func(a *Account) error {
		if a.State == StateRemoved {
			return fmt.Errorf("%w: the account is already removed", ErrBadState)
		}
		a.State = StateRemoved
		a.Password, a.TOTP, a.Passkeys, a.Pending, a.Notices, a.LastLogin, a.LastSecondFactorFailure = "", nil, nil, nil, nil, nil, nil
		clearCounters(a)
		mergeRevocations(&a.PendingRevocations, rev)
		return a.RenewSessions()
	}, revDetail(rev)...)
}

// EndSessions renews the account's session id and secret, which ends every session, and clears its known networks.
// reason is cli, self or reauth_failed.
func (s *Store) EndSessions(by Actor, username, reason string, now time.Time) error {
	ev := by.ev("sessions_ended", username, "")
	ev.Reason = reason
	if !by.IsCLI() && by.Identity == "local:"+username {
		ev.Target = "" // the account acting on itself
	}
	_, err := s.Change(ev, func(st *State) error {
		a := st.Accounts[username]
		if a == nil {
			return ErrNoSuchUser
		}
		if a.State == StateRemoved {
			return fmt.Errorf("%w: the account is removed", ErrBadState)
		}
		a.GoodBuckets = nil
		a.ReauthFailures = 0 // the sessions that failed re-authentications are gone: the count starts again (5.7)
		return a.RenewSessions()
	})
	return err
}

// Unlock clears the account's locks and failure counters at once and lifts restricted and passkey_only.
func (s *Store) Unlock(by Actor, username string, now time.Time) error {
	return s.changeOne(by, "account_unlocked", "", username, nil, func(a *Account) error {
		clearCounters(a)
		if a.State == StateRestricted || a.State == StatePasskeyOnly {
			a.State = StateActive
		}
		a.Notices = append(a.Notices, Notice{Time: now.UTC(), Kind: "unlocked", By: by.By()})
		return nil
	})
}
