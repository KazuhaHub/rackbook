package localauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/login"
	"github.com/kazuhahub/rackbook/internal/roles"
)

// Opening an invite or a reset link, and the setup it leads to (docs/design-local-accounts.md, 5.2 to 5.5, 5.8). The
// link is in the URL fragment, so the page reads it and removes it before anything is sent; nothing happens until
// the person presses Continue. The page keeps the token in memory and sends it with every call.

// HoldCookie is the cookie that binds a held link to the browser that opened it.
const HoldCookie = "__Host-rackbook_setup"

const (
	purposeTOTP    = "rackbook totp enrol v1"
	totpEnrolTTL   = 15 * time.Minute
	maxSetupFails  = 10
	maxFailedLinks = 1000
)

type linkRequest struct {
	Token string `json:"token"`
}

type setupFailures struct {
	mu sync.Mutex
	n  map[string]int // by token hash: failed proofs of an existing password or factor
}

func (f *setupFailures) add(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.n == nil {
		f.n = map[string]int{}
	}
	if _, ok := f.n[key]; !ok && len(f.n) >= maxFailedLinks {
		clear(f.n) // memory only, bounded: dropping it forgives, which the throttle still bounds
	}
	f.n[key]++
	return f.n[key]
}

func (f *setupFailures) get(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n[key]
}

var setupFails setupFailures

func holdOf(r *http.Request) (secret, hash string) {
	c, err := r.Cookie(HoldCookie)
	if err != nil || c.Value == "" || len(c.Value) > 128 {
		return "", ""
	}
	return c.Value, accounts.HoldHash(c.Value)
}

func setHold(w http.ResponseWriter, secret string) {
	http.SetCookie(w, &http.Cookie{Name: HoldCookie, Value: secret, Path: "/", MaxAge: int(accounts.HoldTime.Seconds()), Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func clearHold(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: HoldCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// linkError maps a link failure to its answer and the reason of the audit event.
func linkError(err error) (status int, code, msg, reason string) {
	switch {
	case errors.Is(err, accounts.ErrLinkExpired):
		return http.StatusGone, "invite_expired", "This link has expired. Ask an administrator for a new one.", "invite_expired"
	case errors.Is(err, accounts.ErrLinkClaimed):
		return http.StatusConflict, "invite_claimed", "This link is already open in another browser.", "invite_claimed"
	case errors.Is(err, accounts.ErrRevocations):
		return http.StatusConflict, "revocations_pending", "An administrator must finish revoking this account's API tokens first. Try again later.", "invite_invalid"
	}
	return http.StatusNotFound, "invite_invalid", "This link is not valid. Ask an administrator for a new one.", "invite_invalid"
}

func (s *Service) linkFail(w http.ResponseWriter, f facts, err error) {
	status, code, msg, reason := linkError(err)
	f.reason = reason
	s.record(f)
	fail(w, status, code, msg)
}

// linkAccount finds the account whose pending link has this token and checks the link as the hold holder sees it. The
// returned account is a copy.
func (s *Service) linkAccount(token, holder string, now time.Time) (*accounts.Account, error) {
	var out *accounts.Account
	s.store.Peek(func(st *accounts.State) {
		if a := accounts.FindByLink(st, token); a != nil {
			out = st.Account(a.Username)
		}
	})
	if out == nil {
		return nil, accounts.ErrLinkInvalid
	}
	if err := out.CheckLink(out.Pending.Kind, holder, now); err != nil {
		return out, err
	}
	if setupFails.get(string(accounts.HashToken(token))) >= maxSetupFails {
		return out, accounts.ErrLinkInvalid
	}
	return out, nil
}

// linkGate is the start of every setup endpoint: the audit log can be written, the bucket is not flooded or throttled.
// It answers and returns false when not.
func (s *Service) linkGate(w http.ResponseWriter, r *http.Request, set config.SignInSettings) (facts, bool) {
	bucket, addr := s.where(r)
	f := facts{bucket: bucket, addr: addr}
	if !s.available() {
		fail(w, http.StatusServiceUnavailable, "audit_unavailable", msgAuditDown)
		return f, false
	}
	if s.tables.Flood(bucket) {
		s.refuseEarly(w, f, "flood")
		return f, false
	}
	return f, true
}

// setupOpen holds the link for this browser and says what it is for.
func (s *Service) setupOpen(w http.ResponseWriter, r *http.Request) {
	set := s.settings()
	f, ok := s.linkGate(w, r, set) // the flood ceiling comes before the body is read
	if !ok {
		return
	}
	var in linkRequest
	if !decode(w, r, &in) {
		return
	}
	if c := s.tables.Pre(f.bucket, "", set.ThrottleMax, set.ThrottleWindow); c.Throttled {
		s.refuseEarly(w, f, "throttled")
		return
	}
	now := s.now()
	secret, hash := holdOf(r)
	if secret == "" {
		var err error
		if secret, hash, err = accounts.NewHold(); err != nil {
			fail(w, http.StatusInternalServerError, "internal", "internal error")
			return
		}
	}
	username, kind, err := s.store.OpenLink(in.Token, hash, f.addr, now)
	if err != nil {
		if errors.Is(err, accounts.ErrLinkInvalid) {
			s.tables.Fail(f.bucket, "", set.ThrottleMax, set.ThrottleWindow, lockSetting{})
		}
		if username != "" {
			f.acct = &accounts.Account{Username: username}
			f.name = username
		}
		if errors.Is(err, accounts.ErrAuditUnavailable) {
			fail(w, http.StatusServiceUnavailable, "audit_unavailable", msgAuditDown)
			return
		}
		s.linkFail(w, f, err)
		return
	}
	a := s.store.Lookup(username)
	setHold(w, secret)
	scope := a.Pending.Scope
	if kind == accounts.LinkInvite || scope == "" {
		scope = accounts.ScopeAll
	}
	out := map[string]any{
		"kind": kind, "scope": scope, "username": username, "name": a.Name, "minLength": set.PasswordMinLength,
		"expires": a.Pending.LinkExpiry().UTC().Format(time.RFC3339),
		// what the person must give: a new password (invite, all, password), the current one (second_factor), a new
		// factor (invite, all, second_factor), or an existing factor (password)
		"newPassword":     scope != accounts.ScopeSecondFactor,
		"currentPassword": scope == accounts.ScopeSecondFactor,
		"newFactor":       scope != accounts.ScopePassword,
		"proveFactor":     scope == accounts.ScopePassword,
		"proveWith":       factorKinds(a),
	}
	reply(w, http.StatusOK, out)
}

func factorKinds(a *accounts.Account) []string {
	out := []string{}
	if a.TOTP != nil {
		out = append(out, "totp")
	}
	if len(a.Passkeys) > 0 {
		out = append(out, "passkey")
	}
	return out
}

// heldAccount is the account of a link held by this browser, or an answer.
func (s *Service) heldAccount(w http.ResponseWriter, r *http.Request, token string, f facts) (*accounts.Account, string, bool) {
	_, hash := holdOf(r)
	if hash == "" {
		s.linkFail(w, f, accounts.ErrLinkInvalid)
		return nil, "", false
	}
	a, err := s.linkAccount(token, hash, s.now())
	if err != nil {
		if a != nil {
			f.name, f.acct = a.Username, a
		}
		s.linkFail(w, f, err)
		return nil, "", false
	}
	if a.Pending.HeldBy == "" {
		s.linkFail(w, f, accounts.ErrLinkInvalid) // not opened yet: Continue comes first
		return nil, "", false
	}
	return a, hash, true
}

type totpEnrol struct {
	Secret  string `json:"s"`
	Hold    string `json:"h"`
	Expires int64  `json:"e"`
}

// setupTOTP makes the secret of a new authenticator: sealed into a token the page sends back with the code.
func (s *Service) setupTOTP(w http.ResponseWriter, r *http.Request) {
	f, ok := s.linkGate(w, r, s.settings())
	if !ok {
		return
	}
	var in linkRequest
	if !decode(w, r, &in) {
		return
	}
	a, hash, ok := s.heldAccount(w, r, in.Token, f)
	if !ok {
		return
	}
	secret, err := accounts.NewTOTPSecret()
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	tok, err := s.sealer.seal(purposeTOTP, totpEnrol{Secret: base64.RawURLEncoding.EncodeToString(secret), Hold: hash, Expires: s.now().Add(totpEnrolTTL).Unix()})
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	reply(w, http.StatusOK, map[string]string{
		"enrol": tok, "secret": accounts.TOTPBase32(secret), "uri": accounts.TOTPURI(s.productName(), a.Username, secret),
	})
}

func (s *Service) productName() string {
	if n := s.o.Config().Branding.Name; n != "" {
		return n
	}
	return "Rackbook"
}

// setupPasskey starts the registration of a passkey.
func (s *Service) setupPasskey(w http.ResponseWriter, r *http.Request) {
	f, ok := s.linkGate(w, r, s.settings())
	if !ok {
		return
	}
	var in linkRequest
	if !decode(w, r, &in) {
		return
	}
	a, hash, ok := s.heldAccount(w, r, in.Token, f)
	if !ok {
		return
	}
	creation, token, err := s.pk.BeginEnrol(withBucket(r.Context(), f.bucket), a.Username, displayOf(a), hash)
	if err != nil {
		s.log.Error("could not start a passkey registration", "err", err)
		fail(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	reply(w, http.StatusOK, map[string]any{"ceremony": token, "options": creation})
}

func displayOf(a *accounts.Account) string {
	if a.Name != "" {
		return a.Name
	}
	return a.Username
}

type setupFinishRequest struct {
	Token           string `json:"token"`
	Password        string `json:"password"`
	CurrentPassword string `json:"current_password"`
	TOTP            *struct {
		Enrol string `json:"enrol"`
		Code  string `json:"code"`
	} `json:"totp"`
	Passkey *struct {
		Ceremony   string          `json:"ceremony"`
		Credential json.RawMessage `json:"credential"`
		Name       string          `json:"name"`
	} `json:"passkey"`
	// Proof is an existing factor, for a reset of the password: a code, or an attempt token with an assertion.
	Proof *struct {
		Code    string          `json:"code"`
		Attempt string          `json:"attempt"`
		Passkey json.RawMessage `json:"passkey"`
	} `json:"proof"`
	Return string `json:"return"`
}

func (s *Service) passwordError(w http.ResponseWriter, err error) {
	var pe *accounts.PasswordError
	if errors.As(err, &pe) {
		reply(w, http.StatusUnprocessableEntity, map[string]any{"error": "password_rules", "message": pe.Error(), "rule": pe.Code, "min": pe.Min})
		return
	}
	fail(w, http.StatusUnprocessableEntity, "password_rules", err.Error())
}

// setupFinish writes the setup: the password, the second factor, and, in one change, an active account. The
// person is signed in.
func (s *Service) setupFinish(w http.ResponseWriter, r *http.Request) {
	set := s.settings()
	f, ok := s.linkGate(w, r, set)
	if !ok {
		return
	}
	var in setupFinishRequest
	if !decode(w, r, &in) {
		return
	}
	a, hold, ok := s.heldAccount(w, r, in.Token, f)
	if !ok {
		return
	}
	f.name, f.acct = a.Username, a
	now := s.now()
	ctx := withBucket(r.Context(), f.bucket)
	kind, scope := a.Pending.Kind, a.Pending.Scope
	if kind == accounts.LinkInvite || scope == "" {
		scope = accounts.ScopeAll
	}
	tokenKey := string(accounts.HashToken(in.Token))
	// this attempt is counted in the throttle before any proof is checked, and given back when the setup goes through
	tk, c := s.tables.Begin(f.bucket, a.Username, set.ThrottleMax, set.ThrottleWindow, lockOf(set), true)
	var res *resv
	finished := false
	defer func() {
		if !finished {
			s.tables.Refund(tk)
			res.release()
		}
	}()
	if c.Throttled || c.Locked {
		s.refuseEarly(w, f, "throttled")
		return
	}
	proofFailed := func(codeTried bool) {
		f.reason, f.proof, f.codeWrong = "bad_credentials", true, codeTried
		finished = true
		s.afterFailure(f, set, tk, res)
		setupFails.add(tokenKey)
		reply(w, http.StatusUnauthorized, map[string]string{"error": "sign_in_failed", "message": msgFailed})
	}
	cls := accounts.ClassPriority // a person who holds a link must not be queued behind a flood

	su := accounts.Setup{Token: in.Token, Holder: hold, Addr: f.addr}

	// what the person must prove
	switch scope {
	case accounts.ScopeSecondFactor: // the current password, then a new factor
		// the place in the account's persistent counter is reserved before the password is checked, as for a sign-in
		var held bool
		if res, held = s.reserveProofPassword(a.Username, set); !held {
			if err := s.deadEnd(ctx, f.bucket, cls); err != nil {
				s.busy(w, f, err)
				return
			}
			proofFailed(false)
			return
		}
		ok, _, took, err := s.hasher.VerifyTimed(ctx, cls, in.CurrentPassword, a.Password)
		if err != nil {
			s.busy(w, f, err)
			return
		}
		s.sample.Add(took, f.bucket, a.Username)
		if !ok || a.Password == "" {
			f.passwordWrong = true // it counts in the account's counter, with the place reserved above
			proofFailed(false)
			return
		}
		res.releasePassword()
	case accounts.ScopePassword: // an existing factor, then a new password
		passed, tried := false, false
		if p := in.Proof; p != nil {
			switch {
			case p.Code != "" && a.TOTP != nil:
				// a wrong code counts against the account's own limit, reserved before the code is checked
				var held bool
				if res, held = s.reserveTOTP(a.Username, res, set); !held {
					s.store.ProbeTOTP(a.Username, p.Code, now)
				} else if passed = s.store.UseTOTP(a.Username, p.Code, now, nil) == nil; !passed {
					tried = true
				}
			case len(p.Passkey) > 0:
				// the account is reset_pending: its passkey proves the person for this purpose only
				owner, _ := s.pk.VerifyAssertion(ctx, p.Attempt, p.Passkey, true)
				passed = owner == a.Username
			}
		}
		if !passed {
			proofFailed(tried)
			return
		}
		res.release()
	}

	// the new password
	if scope != accounts.ScopeSecondFactor {
		if err := accounts.CheckPassword(in.Password, accounts.PasswordRules{MinLen: set.PasswordMinLength, Username: a.Username, Host: s.o.Login.Host(), List: s.o.CommonList}); err != nil {
			s.passwordError(w, err)
			return
		}
		h, err := s.hasher.Hash(ctx, cls, in.Password)
		if err != nil {
			s.busy(w, f, err)
			return
		}
		su.Password = h
	}
	// the new second factor, which is never optional (2.2)
	factor := ""
	if scope != accounts.ScopePassword {
		switch {
		case in.TOTP != nil:
			var t totpEnrol
			if s.sealer.open(purposeTOTP, in.TOTP.Enrol, &t) != nil || t.Hold != hold || !now.Before(time.Unix(t.Expires, 0)) {
				fail(w, http.StatusUnprocessableEntity, "bad_code", "The code is not right. Check the clock of your phone and try again.")
				return
			}
			sec, _ := base64.RawURLEncoding.DecodeString(t.Secret)
			tf, err := accounts.NewTOTPFactor(sec, in.TOTP.Code, now)
			if err != nil {
				fail(w, http.StatusUnprocessableEntity, "bad_code", "The code is not right. Check the clock of your phone and try again.")
				return
			}
			su.TOTP, factor = tf, "totp"
		case in.Passkey != nil:
			pk, err := s.pk.FinishEnrol(ctx, a.Username, hold, in.Passkey.Ceremony, in.Passkey.Credential, cleanKeyName(in.Passkey.Name), now)
			if err != nil {
				fail(w, http.StatusUnprocessableEntity, "passkey_failed", "The passkey could not be added. Try again or use an authenticator app.")
				return
			}
			su.Passkey, factor = pk, "passkey"
		default:
			fail(w, http.StatusUnprocessableEntity, "factor_required", "A second factor is required: an authenticator app or a passkey.")
			return
		}
	} else {
		factor = existingFactor(in.Proof)
	}
	su.Factor = factor

	username, err := s.store.CompleteSetup(su, now)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrAuditUnavailable), errors.Is(err, accounts.ErrStoreFailed):
			fail(w, http.StatusServiceUnavailable, "audit_unavailable", msgAuditDown)
		case errors.Is(err, accounts.ErrNeedsFactor):
			fail(w, http.StatusUnprocessableEntity, "factor_required", "A second factor is required: an authenticator app or a passkey.")
		default:
			s.linkFail(w, f, err)
		}
		return
	}
	clearHold(w)
	s.tables.Refund(tk)
	res.release()
	finished = true
	s.signedInAfterSetup(w, r, f, username, factor, in.Return)
}

func existingFactor(p *struct {
	Code    string          `json:"code"`
	Attempt string          `json:"attempt"`
	Passkey json.RawMessage `json:"passkey"`
}) string {
	if p != nil && len(p.Passkey) > 0 {
		return "passkey"
	}
	return "totp"
}

func cleanKeyName(n string) string {
	r := []rune(n)
	if len(r) > 60 {
		r = r[:60]
	}
	out := make([]rune, 0, len(r))
	for _, c := range r {
		if c >= 0x20 && c != 0x7f {
			out = append(out, c)
		}
	}
	return string(out)
}

// signedInAfterSetup writes the login event of the new account and issues its session. An account with no role is set
// up but gets no session.
func (s *Service) signedInAfterSetup(w http.ResponseWriter, r *http.Request, f facts, username, factor, ret string) {
	now := s.now()
	a := s.store.Lookup(username)
	role := s.o.Login.LocalRole(username)
	if a == nil || !a.Live() || role == roles.None {
		reply(w, http.StatusOK, map[string]any{"ok": true, "signedIn": false, "reason": "no_role"})
		return
	}
	ev := audit.Event{Event: "login", Identity: "local:" + username, Name: a.Name, Method: "local", Role: role.String(), Addr: f.addr, Detail: []string{"factor:" + factor, "setup"}}
	if err := s.store.Counter(&ev, func(st *accounts.State) error {
		x := st.Accounts[username]
		if x == nil || !x.Live() {
			return errNotLive
		}
		x.LastLogin = &accounts.Seen{Time: now.UTC(), Addr: f.addr}
		withGoodBucket(x, f.bucket, now)
		return nil
	}); err != nil {
		// the setup is done and audited; only the sign-in could not be written: ask the person to sign in
		s.log.Error("the login after setup could not be written", "err", err)
		reply(w, http.StatusOK, map[string]any{"ok": true, "signedIn": false, "reason": "sign_in"})
		return
	}
	if _, err := s.o.Login.IssueLocal(w, r, login.LocalGrant{Username: username, Name: a.Name, Factor: factor}); err != nil {
		reply(w, http.StatusOK, map[string]any{"ok": true, "signedIn": false, "reason": "sign_in"})
		return
	}
	reply(w, http.StatusOK, map[string]any{"ok": true, "signedIn": true, "return": login.SafeReturn(ret)})
}
