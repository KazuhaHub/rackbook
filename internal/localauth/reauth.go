package localauth

import (
	"encoding/json"
	"net/http"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/login"
)

// Re-authentication (docs/design-local-accounts.md, 5.7): the same one-step form, in the reserved hashing slot, with
// one answer. reauth_failures is per account, in the store; a success resets it, and three failures end every session
// of the account. A failure also counts toward consecutive_failures. Like a sign-in, an attempt reserves its place in the
// account's counters before it hashes anything.

// MaxReauthFailures ends every session of the account.
const MaxReauthFailures = 3

type reauthRequest struct {
	Password string          `json:"password"`
	Code     string          `json:"code"`
	Passkey  json.RawMessage `json:"passkey"`
	Attempt  string          `json:"attempt"`
	Return   string          `json:"return"`
}

func (s *Service) reauth(w http.ResponseWriter, r *http.Request) {
	set := s.settings()
	bucket, addr := s.where(r)
	f := facts{bucket: bucket, addr: addr}
	if !s.available() {
		fail(w, http.StatusServiceUnavailable, "audit_unavailable", msgAuditDown)
		return
	}
	// before the body is read: the flood ceiling
	if s.tables.Flood(bucket) {
		s.refuseEarly(w, f, "flood")
		return
	}
	var in reauthRequest
	if !decode(w, r, &in) {
		return
	}
	info, ok := s.o.Login.LocalSession(r)
	if !ok {
		reply(w, http.StatusUnauthorized, map[string]string{"error": "login_required", "message": "log in to continue"})
		return
	}
	name := info.Username
	f.name = name
	now := s.now()
	ctx := withBucket(r.Context(), bucket)
	var pkOwner string
	if len(in.Passkey) > 0 && in.Attempt != "" {
		pkOwner, _ = s.pk.VerifyAssertion(ctx, in.Attempt, in.Passkey, false)
	}
	passkeyOK := pkOwner == name

	tk, _ := s.tables.Begin(bucket, name, set.ThrottleMax, set.ThrottleWindow, lockOf(set), false)
	finished := false
	var res *resv
	defer func() {
		if !finished {
			s.tables.Refund(tk)
			res.release()
		}
	}()
	acct, res, reason := s.reservePassword(name, bucket, passkeyOK, in.Code != "", true, set)
	f.acct = acct
	if acct == nil || !acct.Live() {
		reply(w, http.StatusUnauthorized, map[string]string{"error": "login_required", "message": "log in to continue"})
		return
	}
	if reason == "passkey_path_limit" {
		passkeyOK = false
	}
	endNow := acct.ReauthFailures+1 >= MaxReauthFailures
	denied := func() {
		f.reason, f.reauth = "bad_credentials", true
		if endNow {
			s.o.Login.ClearSession(w) // the third failure ends every session of the account, this one included
		}
		reply(w, http.StatusUnauthorized, map[string]string{"error": "sign_in_failed", "message": msgFailed})
		finished = true
		s.afterFailure(f, set, tk, res)
	}
	if reason != "" {
		// a re-authentication that cannot be tried (a restricted account, a spent limit) is a failure like any other, after a hash
		if err := s.deadEnd(ctx, bucket, accounts.ClassPriority); err != nil {
			s.busy(w, f, err)
			return
		}
		f.reason = reason
		denied()
		return
	}

	// the reserved slot: a person who is signed in must not be queued behind a flood of guesses
	ok, _, took, err := s.hasher.VerifyTimed(ctx, accounts.ClassPriority, in.Password, acct.Password)
	if err != nil {
		s.busy(w, f, err)
		return
	}
	s.sample.Add(took, bucket, name)
	factor := ""
	switch {
	case !ok:
		f.passwordWrong = true
		if in.Code != "" {
			s.store.ProbeTOTP(name, in.Code, now)
		}
	case passkeyOK:
		res.releasePassword()
		factor = "passkey"
	case in.Code != "" && acct.TOTP != nil:
		res.releasePassword()
		var held bool
		if res, held = s.reserveTOTP(name, res, set); !held {
			s.store.ProbeTOTP(name, in.Code, now)
		} else if s.store.UseTOTP(name, in.Code, now, nil) == nil {
			factor = "totp"
		} else {
			f.codeWrong = true
		}
	default:
		res.releasePassword()
	}
	if factor == "" {
		denied()
		return
	}
	ev := audit.Event{Event: "reauth", Identity: "local:" + name, Name: acct.Name, Method: "local", Addr: addr, Detail: []string{"factor:" + factor}}
	if err := s.store.Counter(&ev, func(st *accounts.State) error {
		a := st.Accounts[name]
		if a == nil || !a.Live() || !s.mayCommit(a, factor == "passkey", bucket, set, now, factor) {
			return errNotLive
		}
		a.ReauthFailures = 0
		return nil
	}); err != nil {
		s.counterError(w, f, err)
		return
	}
	s.tables.Refund(tk)
	res.release()
	finished = true
	if _, err := s.o.Login.IssueLocal(w, r, login.LocalGrant{Username: name, Name: acct.Name, Factor: factor}); err != nil {
		fail(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	reply(w, http.StatusOK, map[string]any{"ok": true, "return": login.SafeReturn(in.Return)})
}
