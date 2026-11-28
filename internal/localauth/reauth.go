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
// of the account. A failure also counts toward consecutive_failures.

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
	var in reauthRequest
	if !decode(w, r, &in) {
		return
	}
	info, ok := s.o.Login.LocalSession(r)
	if !ok {
		reply(w, http.StatusUnauthorized, map[string]string{"error": "login_required", "message": "log in to continue"})
		return
	}
	set := s.settings()
	bucket, addr := s.where(r)
	f := facts{name: info.Username, bucket: bucket, addr: addr}
	if !s.auditOK() {
		fail(w, http.StatusServiceUnavailable, "audit_unavailable", msgAuditDown)
		return
	}
	if s.tables.Flood(bucket) {
		s.refuseEarly(w, f, "flood")
		return
	}
	acct := s.store.Lookup(info.Username)
	if acct == nil || !acct.Live() {
		reply(w, http.StatusUnauthorized, map[string]string{"error": "login_required", "message": "log in to continue"})
		return
	}
	f.acct = acct
	now := s.now()
	ctx := withBucket(r.Context(), bucket)
	var pkOwner string
	if len(in.Passkey) > 0 && in.Attempt != "" {
		pkOwner, _ = s.pk.VerifyAssertion(ctx, in.Attempt, in.Passkey)
	}
	passkeyOK := pkOwner == info.Username

	// the reserved slot: a person who is signed in must not be queued behind a flood of guesses
	ok, _, took, err := s.hasher.VerifyTimed(ctx, accounts.ClassPriority, in.Password, acct.Password)
	if err != nil {
		s.busy(w, f, err)
		return
	}
	s.sample.Add(took, bucket, info.Username)
	factor := ""
	switch {
	case !ok:
		f.passwordWrong = true
	case passkeyOK:
		factor = "passkey"
	case in.Code != "" && acct.TOTP != nil && s.store.UseTOTP(info.Username, in.Code, now, nil) == nil:
		factor = "totp"
	default:
		f.codeWrong = in.Code != ""
	}
	if factor == "" {
		f.reason, f.reauth = "bad_credentials", true
		end := acct.ReauthFailures+1 >= MaxReauthFailures
		if end {
			s.o.Login.ClearSession(w) // the third failure ends every session of the account, this one included
		}
		reply(w, http.StatusUnauthorized, map[string]string{"error": "sign_in_failed", "message": msgFailed})
		s.afterFailure(f, set)
		return
	}
	ev := audit.Event{Event: "reauth", Identity: "local:" + info.Username, Name: acct.Name, Method: "local", Addr: addr, Detail: []string{"factor:" + factor}}
	if err := s.store.Counter(&ev, func(st *accounts.State) error {
		a := st.Accounts[info.Username]
		if a == nil || !a.Live() {
			return errNotLive
		}
		a.ReauthFailures = 0
		return nil
	}); err != nil {
		s.counterError(w, f, err)
		return
	}
	if _, err := s.o.Login.IssueLocal(w, r, login.LocalGrant{Username: info.Username, Name: acct.Name, Factor: factor}); err != nil {
		fail(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	reply(w, http.StatusOK, map[string]any{"ok": true, "return": login.SafeReturn(in.Return)})
}
