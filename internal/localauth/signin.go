package localauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/login"
	"github.com/kazuhahub/rackbook/internal/roles"
)

// The one-step sign-in (docs/design-local-accounts.md, 5.6 and 8): the password and the second factor are checked in
// the same request and a failure never says which was wrong.

// attempt starts a passkey ceremony: a sealed token that carries the challenge. With the CAPTCHA (piece 5) it
// also says whether a CAPTCHA is needed now; it never is yet.
func (s *Service) attempt(w http.ResponseWriter, r *http.Request) {
	bucket, _ := s.where(r)
	if s.tables.Flood(bucket) {
		s.sleep(refusalDelay)
		fail(w, http.StatusTooManyRequests, "too_many_attempts", msgTooMany)
		return
	}
	opts, token, err := s.pk.BeginLogin(withBucket(r.Context(), bucket))
	if err != nil {
		s.log.Error("could not start a passkey ceremony", "err", err)
		fail(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	needed := s.o.Captcha != nil && s.o.Captcha.Required(bucket, "")
	reply(w, http.StatusOK, map[string]any{"attempt": token, "captcha": needed, "passkey": opts})
}

type signInRequest struct {
	Username string          `json:"username"`
	Password string          `json:"password"`
	Code     string          `json:"code"`
	Passkey  json.RawMessage `json:"passkey"`
	Attempt  string          `json:"attempt"`
	Captcha  string          `json:"captcha"`
	Return   string          `json:"return"`
}

func lockOf(set config.SignInSettings) lockSetting {
	return lockSetting{Enabled: set.LockEnabled, Duration: set.LockDuration, Scope: set.LockScope}
}

func hasAccountLock(a *accounts.Account, now time.Time) bool {
	for _, l := range a.Locks {
		if l.Scope == config.LockScopeAccount && l.Until.After(now) {
			return true
		}
	}
	return false
}

func totpLocked(a *accounts.Account, set config.SignInSettings, now time.Time) bool {
	return a.TOTPFailures >= set.TOTPPerDay && !a.TOTPWindowStart.IsZero() && now.Before(a.TOTPWindowStart.Add(24*time.Hour))
}

func passkeyPathLimited(a *accounts.Account, set config.SignInSettings, now time.Time) bool {
	return a.PasskeyPathFailures >= set.PasskeyPathPerHour && !a.PasskeyWindowStart.IsZero() && now.Before(a.PasskeyWindowStart.Add(time.Hour))
}

// facts is what is known of a failed attempt when its counters are written.
type facts struct {
	name, bucket, addr string
	acct               *accounts.Account // nil: not an account
	reason             string
	passwordWrong      bool // a real password check ran and failed
	codeWrong          bool // the password was right and the code was not
	viaPasskey         bool // a verified passkey went past the throttle (passkey_path_failures)
	reauth             bool // a failed re-authentication (5.7): reauth_failures count, three end every session
}

func (s *Service) signIn(w http.ResponseWriter, r *http.Request) {
	var in signInRequest
	if !decode(w, r, &in) {
		return
	}
	set := s.settings()
	bucket, addr := s.where(r)
	if !s.auditOK() {
		fail(w, http.StatusServiceUnavailable, "audit_unavailable", msgAuditDown)
		return
	}
	name := normalise(in.Username)
	now := s.now()
	ctx := withBucket(r.Context(), bucket)
	f := facts{name: name, bucket: bucket, addr: addr}

	// 1. before the name is looked up, without hashing: the flood ceiling
	if s.tables.Flood(bucket) {
		s.refuseEarly(w, f, "flood")
		return
	}
	// the CAPTCHA, when one is configured and needed (piece 5): an unsolved one is the same answer for every name
	if c := s.o.Captcha; c != nil && c.Required(bucket, name) {
		if err := c.Verify(ctx, in.Attempt, in.Captcha, addr); err != nil {
			f.reason = "captcha"
			s.record(f)
			fail(w, http.StatusUnauthorized, "captcha_required", "Please confirm you are a person.")
			return
		}
	}
	// a passkey assertion is verified before any hash: nobody can guess with it, so a verified one goes past the
	// throttle and the locks (8.2, 8.3)
	var pkOwner string
	if len(in.Passkey) > 0 && in.Attempt != "" {
		pkOwner, _ = s.pk.VerifyAssertion(ctx, in.Attempt, in.Passkey)
	}
	acct := s.store.Lookup(name)
	f.acct = acct
	passkeyOK := pkOwner != "" && pkOwner == name && acct != nil && acct.Live() && !passkeyPathLimited(acct, set, now)
	if !passkeyOK {
		// the throttle and the locks of scope ip and ip_account answer alike for every name
		c := s.tables.Pre(bucket, name, set.ThrottleMax, set.ThrottleWindow)
		switch {
		case c.Throttled:
			s.refuseEarly(w, f, "throttled")
			return
		case c.Locked:
			s.refuseEarly(w, f, "locked")
			return
		}
		// 2. the name is looked up: a lock of scope account, from the store for an account and from the name table
		// for any other name, with the same answer and delay
		if acct != nil && hasAccountLock(acct, now) || acct == nil && s.tables.NameLocked(name) {
			s.refuseEarly(w, f, "locked")
			return
		}
	}
	ssoOnly := s.ssoOnly(set)

	// 3. an account that cannot sign in this attempt gets a dummy argon2id (or, past the budget, an equal wait) and the
	// same answer as a wrong password
	f.reason = s.cannotSignIn(acct, in, passkeyOK, bucket, set, now)
	if f.reason != "" {
		if err := s.deadEnd(ctx, bucket, s.classFor(acct, bucket)); err != nil {
			s.busy(w, f, err)
			return
		}
		s.answerFailed(w, ssoOnly)
		s.afterFailure(f, set)
		return
	}

	// 4. the password, in a slot, and then the second factor
	ok, rehash, took, err := s.hasher.VerifyTimed(ctx, s.classFor(acct, bucket), in.Password, acct.Password)
	if err != nil {
		s.busy(w, f, err)
		return
	}
	s.sample.Add(took, bucket, name)
	factor := ""
	switch {
	case !ok:
		f.passwordWrong, f.viaPasskey = true, passkeyOK
		f.reason = "bad_credentials"
	case passkeyOK:
		factor = "passkey"
	case in.Code != "" && acct.TOTP != nil && s.store.UseTOTP(name, in.Code, now, nil) == nil:
		factor = "totp"
	default:
		f.codeWrong = in.Code != ""
		f.reason = "bad_credentials"
	}
	if factor == "" {
		s.answerFailed(w, ssoOnly)
		s.afterFailure(f, set)
		return
	}

	// 5. sso_only, only now that the password and the second factor verified: until here every outcome was the same
	if ssoOnly && !s.isAdmin(name) {
		f.reason = "sso_required"
		reply(w, http.StatusForbidden, map[string]string{"error": "sso_required", "message": msgSSORequired})
		s.afterFailure(f, set) // it counts as a guess like any other, in the memory tables
		return
	}
	// 6. success: the audit line is written before the session exists (fail closed)
	role := s.o.Login.LocalRole(name)
	if role == roles.None {
		s.log.Warn("local sign-in refused: the account has no role", "identity", "local:"+name)
		s.o.Audit.Record(audit.Event{Event: "login_refused", Identity: "local:" + name, Method: "local", Reason: "no_role", Addr: addr})
		fail(w, http.StatusForbidden, "no_role", "you are not allowed to use this ledger")
		return
	}
	ev := audit.Event{Event: "login", Identity: "local:" + name, Name: acct.Name, Method: "local", Role: role.String(), Addr: addr, Detail: []string{"factor:" + factor}}
	if err := s.store.Counter(&ev, func(st *accounts.State) error {
		a := st.Accounts[name]
		if a == nil || !a.Live() {
			return errNotLive
		}
		a.ConsecutiveFailures, a.TOTPFailures, a.PasskeyPathFailures = 0, 0, 0
		a.TOTPWindowStart, a.PasskeyWindowStart = time.Time{}, time.Time{}
		a.Locks = nil
		if a.State == accounts.StateRestricted || a.State == accounts.StatePasskeyOnly {
			a.State = accounts.StateActive
		}
		a.LastLogin = &accounts.Seen{Time: now.UTC(), Addr: addr}
		withGoodBucket(a, bucket, now)
		return nil
	}); err != nil {
		s.counterError(w, f, err)
		return
	}
	s.tables.Succeed(bucket, name)
	if _, err := s.o.Login.IssueLocal(w, r, login.LocalGrant{Username: name, Name: acct.Name, Factor: factor}); err != nil {
		s.log.Error("could not issue a local session", "err", err)
		fail(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	reply(w, http.StatusOK, map[string]any{"ok": true, "return": login.SafeReturn(in.Return)})
	if rehash {
		s.rehash(ctx, name, in.Password, acct.Password)
	}
}

var errNotLive = errors.New("the account cannot sign in")

func (s *Service) isAdmin(name string) bool { return s.o.IsAdmin != nil && s.o.IsAdmin(name) }

// cannotSignIn says why this attempt cannot reach the password check, or "" when it can. The reasons are for the audit
// log; the answer is the same for all of them.
func (s *Service) cannotSignIn(a *accounts.Account, in signInRequest, passkeyOK bool, bucket string, set config.SignInSettings, now time.Time) string {
	if a == nil {
		return "unknown_account"
	}
	switch a.State {
	case accounts.StateInvited:
		return "not_set_up"
	case accounts.StateResetPending:
		return "reset_pending"
	case accounts.StateDisabled:
		return "disabled"
	case accounts.StateRemoved:
		return "unknown_account"
	case accounts.StateRestricted:
		if !passkeyOK && !inGoodBuckets(a, bucket, now) {
			return "restricted"
		}
	case accounts.StatePasskeyOnly:
		if !passkeyOK {
			return "restricted"
		}
	}
	if a.Password == "" {
		return "not_set_up"
	}
	if !passkeyOK && in.Code != "" && totpLocked(a, set, now) {
		return "totp_locked"
	}
	return ""
}

// deadEnd runs the dummy argon2id of 5.6, or, past the budget of 8.6, waits as a real check would: it joins the slot queue
// and gives the slot back, then sleeps a duration drawn from the hash-only sample. Before the sample is ready it
// always hashes.
func (s *Service) deadEnd(ctx context.Context, bucket string, class accounts.Class) error {
	if !s.sample.Ready() || s.budget.Take(bucket) {
		d, err := s.hasher.DummyTimed(ctx, class, "rackbook dummy password")
		if err != nil {
			return err
		}
		s.sample.Add(d, bucket, "")
		return nil
	}
	if err := s.hasher.Wait(ctx, class); err != nil {
		return err
	}
	s.sleep(s.sample.Draw())
	return nil
}

// answerFailed is the one answer of a failed sign-in; under sso_only it is the sso_required answer instead.
func (s *Service) answerFailed(w http.ResponseWriter, ssoOnly bool) {
	if ssoOnly {
		reply(w, http.StatusForbidden, map[string]string{"error": "sso_required", "message": msgSSORequired})
		return
	}
	reply(w, http.StatusUnauthorized, map[string]string{"error": "sign_in_failed", "message": msgFailed})
}

// refuseEarly answers a refusal that does not depend on the name: a fixed delay, no hash, the same answer for every
// name. The refusal is counted for the summary like any other.
func (s *Service) refuseEarly(w http.ResponseWriter, f facts, reason string) {
	s.sleep(refusalDelay)
	f.reason = reason
	s.record(f)
	fail(w, http.StatusTooManyRequests, "too_many_attempts", msgTooMany)
}

// busy answers 503 when no hashing slot became free in time (or the request went away).
func (s *Service) busy(w http.ResponseWriter, f facts, err error) {
	if errors.Is(err, accounts.ErrBusy) {
		f.reason = "busy"
		s.record(f)
		w.Header().Set("Retry-After", "2")
		fail(w, http.StatusServiceUnavailable, "busy", msgBusy)
		return
	}
	fail(w, http.StatusServiceUnavailable, "busy", msgBusy)
}

// counterError answers a success whose audit line could not be written: no session, 503.
func (s *Service) counterError(w http.ResponseWriter, f facts, err error) {
	if errors.Is(err, accounts.ErrAuditUnavailable) || errors.Is(err, accounts.ErrStoreFailed) {
		s.log.Error("local sign-in refused: the audit log cannot be written", "err", err)
		fail(w, http.StatusServiceUnavailable, "audit_unavailable", msgAuditDown)
		return
	}
	if errors.Is(err, errNotLive) {
		reply(w, http.StatusUnauthorized, map[string]string{"error": "sign_in_failed", "message": msgFailed})
		return
	}
	s.log.Error("local sign-in failed", "err", err)
	fail(w, http.StatusInternalServerError, "internal", "internal error")
}

// record counts a refusal and writes it in full when it is the first of its account in the bucket this minute.
func (s *Service) record(f facts) {
	ident := ""
	if f.acct != nil {
		ident = "local:" + f.name
	}
	if s.refused.Note(s.now(), f.bucket, f.addr, ident, f.reason) {
		s.o.Audit.Record(s.refusalEvent(f))
	}
}

func (s *Service) refusalEvent(f facts) audit.Event {
	e := audit.Event{Event: "login_refused", Method: "local", Reason: f.reason, Addr: f.addr}
	if f.acct != nil {
		e.Identity = "local:" + f.name
	}
	return e
}

// afterFailure is everything a failed attempt costs once its answer has been sent (8.6): the memory counters, then the
// counters of an existing account in the store, with the attempt's audit line appended by RecordSync in the same write.
// If that write fails the answer already sent stands, and the next attempt is the one refused with 503.
func (s *Service) afterFailure(f facts, set config.SignInSettings) {
	now := s.now()
	tf := s.tables.Fail(f.bucket, f.name, f.acct != nil, set.ThrottleMax, set.ThrottleWindow, lockOf(set))
	ident := ""
	if f.acct != nil {
		ident = "local:" + f.name
	}
	full := s.refused.Note(now, f.bucket, f.addr, ident, f.reason)
	cur := (*accounts.Account)(nil)
	if f.acct != nil {
		cur = s.store.Lookup(f.name)
	}
	touches := cur != nil && cur.Live() && (f.passwordWrong || f.codeWrong || tf.AccountLock || f.reauth)
	if !touches {
		if full {
			s.o.Audit.Record(s.refusalEvent(f))
		}
		return
	}
	// the event this write carries: a transition outranks the plain refusal
	var ev *audit.Event
	plain := s.refusalEvent(f)
	if f.reauth {
		plain.Code = "reauth"
	}
	switch {
	case f.passwordWrong && stateForCount(cur.State, cur.ConsecutiveFailures+1, set.NISTCap) != cur.State:
		st := stateForCount(cur.State, cur.ConsecutiveFailures+1, set.NISTCap)
		ev = &audit.Event{Event: "account_restricted", Identity: ident, Method: "local", Code: st, Addr: f.addr, Detail: []string{"failures:" + itoa(cur.ConsecutiveFailures+1)}}
	case f.codeWrong && totpAfter(cur, set, now) >= set.TOTPPerDay && cur.TOTPFailures < set.TOTPPerDay:
		ev = &audit.Event{Event: "account_locked", Identity: ident, Method: "local", Code: "totp", Addr: f.addr, Detail: []string{"failures:" + itoa(totpAfter(cur, set, now))}}
	case tf.AccountLock:
		ev = &audit.Event{Event: "account_locked", Identity: ident, Method: "local", Code: "account", Addr: f.addr, Detail: []string{"until:" + now.Add(set.LockDuration).UTC().Format(time.RFC3339)}}
	case full:
		ev = &plain
	}
	if ev != nil && full && ev != &plain {
		s.o.Audit.Record(plain)
	}
	err := s.store.Counter(ev, func(st *accounts.State) error {
		a := st.Accounts[f.name]
		if a == nil || !a.Live() {
			return nil
		}
		if f.passwordWrong {
			a.ConsecutiveFailures++
			a.State = stateForCount(a.State, a.ConsecutiveFailures, set.NISTCap)
			if f.viaPasskey {
				incWindow(&a.PasskeyPathFailures, &a.PasskeyWindowStart, now, time.Hour)
			}
		}
		if f.codeWrong {
			incWindow(&a.TOTPFailures, &a.TOTPWindowStart, now, 24*time.Hour)
			a.LastSecondFactorFailure = &accounts.Seen{Time: now.UTC(), Addr: f.addr}
		}
		if f.reauth {
			a.ReauthFailures++
		}
		if tf.AccountLock {
			a.Locks = append(liveLocks(a.Locks, now), accounts.Lock{Scope: config.LockScopeAccount, Until: now.Add(set.LockDuration).UTC()})
		}
		return nil
	})
	if err != nil {
		s.counterFailed.Store(true)
		s.log.Error("the counters of a failed sign-in could not be written; the next attempt is refused", "err", err)
		return
	}
	if f.reauth && cur.ReauthFailures+1 >= MaxReauthFailures {
		if err := s.store.EndSessions(accounts.Self(f.name, cur.Name, f.addr), f.name, "reauth_failed", now); err != nil {
			s.counterFailed.Store(true)
			s.log.Error("the sessions of an account could not be ended after failed re-authentications", "err", err)
		}
	}
}

func liveLocks(in []accounts.Lock, now time.Time) []accounts.Lock {
	var out []accounts.Lock
	for _, l := range in {
		if l.Until.After(now) {
			out = append(out, l)
		}
	}
	return out
}

// incWindow raises a counter that counts within a window that starts at its first failure.
func incWindow(n *int, start *time.Time, now time.Time, length time.Duration) {
	if start.IsZero() || !now.Before(start.Add(length)) {
		*n, *start = 0, now.UTC()
	}
	*n++
}

func totpAfter(a *accounts.Account, set config.SignInSettings, now time.Time) int {
	if a.TOTPWindowStart.IsZero() || !now.Before(a.TOTPWindowStart.Add(24*time.Hour)) {
		return 1
	}
	return a.TOTPFailures + 1
}

// stateForCount is the state an account is in after count consecutive failed password checks (8.4): restricted at cap-1,
// passkey_only at cap. The state only moves forward.
func stateForCount(state string, count, cap int) string {
	switch {
	case state == accounts.StatePasskeyOnly:
		return state
	case count >= cap:
		return accounts.StatePasskeyOnly
	case count >= cap-1:
		return accounts.StateRestricted
	}
	return state
}

func itoa(n int) string { return strconv.Itoa(n) }

// rehash stores a new hash of a password whose stored hash is under older parameters (4.2), as an audited change.
func (s *Service) rehash(ctx context.Context, name, password, old string) {
	nh, err := s.hasher.Hash(ctx, accounts.ClassPriority, password)
	if err != nil {
		return
	}
	ev := audit.Event{Event: "password_changed", Identity: "local:" + name, Method: "local", Code: "rehash"}
	if _, err := s.store.Change(ev, func(st *accounts.State) error {
		if a := st.Accounts[name]; a != nil && a.Password == old {
			a.Password = nh
		}
		return nil
	}); err != nil {
		s.log.Warn("could not store the rehashed password", "err", err)
	}
}
