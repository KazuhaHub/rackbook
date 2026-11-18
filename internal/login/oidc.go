package login

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	authoidc "github.com/KazuhaHub/authcore/oidc"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/roles"
)

// loginFail sends the browser to the login page with an error the console
// knows how to explain. return is kept so a retry lands where the user was.
func (s *Service) loginFail(w http.ResponseWriter, r *http.Request, code, ret string) {
	http.Redirect(w, r, loginURL(ret, url.Values{"error": {code}}), http.StatusSeeOther)
}

// oidcStart begins the authorization-code flow: it stores the protocol state
// in memory, binds it to this browser with a cookie, and redirects to the IdP.
func (s *Service) oidcStart(w http.ResponseWriter, r *http.Request) {
	ret := SafeReturn(r.URL.Query().Get("return"))
	if !s.limit.allow(clientIP(r)) {
		s.log.Warn("login start rate limited", "remote", clientIP(r))
		http.Error(w, "too many login attempts, wait a minute", http.StatusTooManyRequests)
		return
	}
	p, err := s.provider()
	if err != nil {
		s.log.Error("OIDC provider unavailable", "err", err)
		s.loginFail(w, r, "idp_unavailable", ret)
		return
	}
	az, err := p.Begin()
	if err != nil {
		s.log.Error("OIDC begin failed", "err", err)
		s.loginFail(w, r, "idp_unavailable", ret)
		return
	}
	id, err := s.pending.put(az.State, ret)
	if err != nil {
		s.log.Error("could not store the login state", "err", err)
		s.loginFail(w, r, "idp_unavailable", ret)
		return
	}
	setCookie(w, LoginCookie, id, int(pendingTTL.Seconds()))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, az.URL, http.StatusFound)
}

// oneParam returns the single value of a query parameter; ok is false when
// the parameter is repeated (an ambiguous callback is refused outright).
func oneParam(q url.Values, k string) (string, bool) {
	v := q[k]
	if len(v) > 1 {
		return "", false
	}
	if len(v) == 0 {
		return "", true
	}
	return v[0], true
}

// oidcCallback completes the flow, exactly as docs/design-v0.2.md 2.2:
//  1. duplicate or missing state/code, and an IdP error, get a friendly page;
//  2. the browser-binding cookie must name a pending login whose state is the
//     callback's, and that login is taken atomically (a replay finds nothing);
//  3. Complete verifies the ID token; claims are decoded with an explicit schema;
//  4. tid is checked against allowed_tenants;
//  5. the identity claim is folded to lowercase ASCII;
//  6. a role is required (else 403, logged);
//  7. the session is issued and the browser goes to the stored return path.
func (s *Service) oidcCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var bindID string
	if c, err := r.Cookie(LoginCookie); err == nil {
		bindID = c.Value
	}

	q := r.URL.Query()
	state, ok1 := oneParam(q, "state")
	code, ok2 := oneParam(q, "code")
	idpErr, ok3 := oneParam(q, "error")
	if !ok1 || !ok2 || !ok3 {
		s.log.Warn("login refused: duplicate callback parameters", "remote", r.RemoteAddr)
		s.loginFail(w, r, "bad_callback", "")
		return
	}
	if idpErr != "" {
		// The IdP echoes state: only the matching browser's pending login is
		// dropped, so a forged link cannot cancel someone else's login.
		if bindID != "" && state != "" {
			if _, res := s.pending.take(bindID, state); res != takeBinding {
				clearCookie(w, LoginCookie)
			}
		}
		s.log.Warn("login failed at the IdP", "error", sanitizeLog(idpErr), "remote", r.RemoteAddr)
		s.loginFail(w, r, "idp_error", "")
		return
	}
	if state == "" || code == "" {
		s.log.Warn("login refused: callback without state or code", "remote", r.RemoteAddr)
		s.loginFail(w, r, "bad_callback", "")
		return
	}
	if bindID == "" {
		s.log.Warn("login refused: no browser-binding cookie", "remote", r.RemoteAddr)
		s.loginFail(w, r, "expired", "")
		return
	}
	entry, res := s.pending.take(bindID, state)
	switch res {
	case takeUnknown:
		clearCookie(w, LoginCookie)
		s.log.Warn("login refused: unknown, expired or replayed state", "remote", r.RemoteAddr)
		s.loginFail(w, r, "expired", "")
		return
	case takeBinding:
		// the pending login (and its cookie) stay: a forged callback must not cancel it
		s.log.Warn("login refused: state does not match the browser", "remote", r.RemoteAddr)
		s.loginFail(w, r, "bad_callback", "")
		return
	}
	clearCookie(w, LoginCookie) // single use
	p, err := s.provider()
	if err != nil {
		s.log.Error("OIDC provider unavailable", "err", err)
		s.loginFail(w, r, "idp_unavailable", entry.ret)
		return
	}
	assertion, err := p.Complete(r.Context(), state, code, entry.state)
	if err != nil {
		s.log.Warn("login failed: ID token or code exchange rejected", "reason", completeReason(err), "remote", r.RemoteAddr)
		s.loginFail(w, r, "idp_error", entry.ret)
		return
	}
	id, tid, err := s.identityFromClaims(assertion)
	if err != nil {
		s.log.Warn("login failed: claims", "reason", err.Error(), "subject", sanitizeLog(assertion.Subject))
		s.loginFail(w, r, "claims", entry.ret)
		return
	}
	if allowed := s.o.Login.OIDC.AllowedTenants; len(allowed) > 0 && !tenantAllowed(allowed, tid) {
		s.log.Warn("login refused: tenant not allowed", "identity", id.ID, "tid", sanitizeLog(tid))
		s.loginFail(w, r, "tenant", entry.ret)
		return
	}
	if s.roleOf(id) == roles.None {
		s.log.Warn("login refused: identity has no role", "identity", id.ID, "method", auth.MethodOIDC)
		s.loginFail(w, r, "no_role", "")
		return
	}
	s.issue(w, id, auth.MethodOIDC, "")
	s.log.Info("login", "identity", id.ID, "method", auth.MethodOIDC, "remote", r.RemoteAddr)
	http.Redirect(w, r, SafeReturn(entry.ret), http.StatusSeeOther)
}

// identityFromClaims decodes the verified ID token's claims with an explicit
// schema: the identity and name claims must be JSON strings.
func (s *Service) identityFromClaims(a *authoidc.Assertion) (*auth.Identity, string, error) {
	var claims map[string]json.RawMessage
	if err := a.Claims(&claims); err != nil {
		return nil, "", errors.New("claims are not a JSON object")
	}
	idClaim, nameClaim := s.o.Login.OIDC.ClaimsOrDefault()
	str := func(k string, required bool) (string, error) {
		raw, ok := claims[k]
		if !ok {
			if required {
				return "", errors.New("claim " + k + " is missing")
			}
			return "", nil
		}
		var v string
		if json.Unmarshal(raw, &v) != nil {
			return "", errors.New("claim " + k + " is not a string")
		}
		return v, nil
	}
	ident, err := str(idClaim, true)
	if err != nil {
		return nil, "", err
	}
	ident = strings.TrimSpace(ident)
	if ident == "" || len(ident) > 320 || !utf8.ValidString(ident) || strings.ContainsFunc(ident, func(r rune) bool {
		return r <= 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 || r == '<' || r == '>'
	}) {
		return nil, "", errors.New("claim " + idClaim + " is empty or not usable as an identity")
	}
	if idClaim == "email" {
		// An e-mail address is only an identity if the IdP vouches for it
		// (Entra does not: its "email" claim is user-editable).
		var verified bool
		if raw, ok := claims["email_verified"]; !ok || json.Unmarshal(raw, &verified) != nil || !verified {
			return nil, "", errors.New("claim email is used as the identity but email_verified is not true")
		}
	}
	name, err := str(nameClaim, false)
	if err != nil {
		return nil, "", err
	}
	name = cleanName(name)
	tid, err := str("tid", false)
	if err != nil {
		return nil, "", err
	}
	id := &auth.Identity{ID: roles.FoldASCII(ident), Name: name, Method: auth.MethodOIDC}
	if strings.Contains(ident, "@") {
		id.Email = id.ID
	}
	return id, tid, nil
}

func tenantAllowed(allowed []string, tid string) bool {
	if tid == "" {
		return false
	}
	for _, a := range allowed {
		if roles.FoldASCII(strings.TrimSpace(a)) == roles.FoldASCII(tid) {
			return true
		}
	}
	return false
}

// cleanName makes a display name safe for logs, commit authors and the
// session cookie: control characters become spaces, the length is bounded.
func cleanName(n string) string {
	n = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 || r == '<' || r == '>' {
			return ' '
		}
		return r
	}, n)
	n = strings.TrimSpace(n)
	if len(n) > 200 {
		n = strings.ToValidUTF8(n[:200], "")
	}
	return n
}

func sanitizeLog(s string) string {
	if len(s) > 100 {
		s = s[:100]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

func completeReason(err error) string {
	switch {
	case errors.Is(err, authoidc.ErrExchange):
		return "code exchange"
	case errors.Is(err, authoidc.ErrInvalidToken):
		return "id token"
	case errors.Is(err, authoidc.ErrNonceMismatch):
		return "nonce"
	case errors.Is(err, authoidc.ErrInvalidState):
		return "state"
	}
	return "other"
}
