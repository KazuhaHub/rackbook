package oauthserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/kazuhahub/rackbook/internal/locale"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/roles"
)

var (
	errUnknownClient    = errors.New("unknown client_id")
	errClientNotAllowed = errors.New("this client is not on the allowed_clients list")
)

const maxTokenBody = 16 << 10

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// refresh tokens are "<grant id>.<secret>": the id finds the grant, the secret
// is checked against its stored hash.
func splitRefresh(t string) (gid, secret string, ok bool) {
	gid, secret, ok = strings.Cut(t, ".")
	return gid, secret, ok && gid != "" && secret != ""
}

// token is POST /oauth/token.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "use POST")
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/x-www-form-urlencoded" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "Content-Type must be application/x-www-form-urlencoded")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenBody)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the body is not a valid form")
		return
	}
	// Parameters travel in the body only: ParseForm also reads the URL query,
	// which proxies log.
	form := r.PostForm
	if form.Get("client_secret") != "" || form.Get("client_assertion") != "" {
		oauthError(w, http.StatusBadRequest, "invalid_client", "only public clients are supported: send client_id and no secret")
		return
	}
	switch form.Get("grant_type") {
	case "authorization_code":
		s.exchangeCode(w, r)
	case "refresh_token":
		s.refresh(w, r)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
	}
}

// role is the role auth.roles gives the grant's subject right now.
func (s *Server) role(sub Subject) roles.Role {
	id := &auth.Identity{ID: sub.ID, Email: sub.Email, Method: auth.MethodOAuth}
	s.o.Auth.EvaluateSubject(id, roles.Subject{ID: roles.FoldASCII(sub.ID), Email: sub.Email, Method: sub.Method, Groups: sub.Groups, AppRoles: sub.AppRoles})
	return id.Role
}

// reasonClaimsExpired is why a grant ended when the groups or app roles it was approved
// with stopped counting and the person has no role by identity.
const reasonClaimsExpired = "claims_expired"

var claimsExpiredTexts = map[string]string{
	"en-US": "the grant has ended: its role came from groups or app roles, which count only for a limited time after approval, and you have no role by name; authorize again",
	"zh-CN": "授权已结束：它的角色来自用户组或应用角色，这些只在批准后的一段时间内有效，而你按名称没有角色；请重新授权",
	"zh-TW": "授權已結束：它的角色來自群組或應用程式角色，這些只在核准後的一段時間內有效，而你依名稱沒有角色；請重新授權",
}

func claimsExpiredText(acceptLanguage string) string {
	if t, ok := claimsExpiredTexts[locale.Match(acceptLanguage, locale.Default)]; ok {
		return t
	}
	return claimsExpiredTexts["en-US"]
}

// effective is the grant's subject as it counts now. The groups and app roles in
// it are a snapshot of the sign-in that approved the grant: they count for
// auth.session.claims_absolute after the approval and not a moment longer, then the
// grant is evaluated by identity entries alone, like an API token. So a role
// removed at the identity provider cannot outlive that bound by refreshing. The
// bound starts at the earlier of the approving session's sign-in and the grant's
// creation, because the claims are as old as the sign-in: a session that signed in
// 23h59m ago and approves a grant gives its claims about a minute. A grant with no
// sign-in or creation time (made before they were recorded) has no claims left.
func (s *Server) effective(g *Grant) Subject {
	sub := g.Subject
	limit := s.o.Config().Auth.Session.ClaimsAbsoluteOrDefault()
	start := g.Subject.SignedIn
	if g.Created.Before(start) {
		start = g.Created
	}
	if start.IsZero() || !s.now().Before(start.Add(limit)) {
		sub.Groups, sub.AppRoles = nil, nil
	}
	return sub
}

func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	now := s.now()
	key := codeKey(f.Get("code"))
	s.mu.Lock()
	s.prune(now)
	c := s.codes[key]
	delete(s.codes, key) // single use, whatever happens next
	replay, wasUsed := s.used[key]
	s.mu.Unlock()
	if wasUsed {
		// A code presented twice: someone else may hold it. End the grant it made.
		s.log.Warn("oauth authorization code replayed; revoking the grant", "grant", replay.gid)
		if _, err := s.revoke(replay.gid, "code replay"); err != nil {
			s.fail(w, "revoking after a code replay", err)
			return
		}
	}
	if c == nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the authorization code is invalid, expired or already used")
		return
	}
	switch {
	case f.Get("client_id") != c.client.ID:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the code was issued to another client")
		return
	case f.Get("redirect_uri") != c.redirectURI:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	case !pkceOK(f.Get("code_verifier"), c.challenge):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code_verifier does not match the code_challenge")
		return
	}
	if res := f.Get("resource"); res != "" && res != c.resource {
		oauthError(w, http.StatusBadRequest, "invalid_target", "resource does not match the authorization request")
		return
	}
	if s.role(c.subject) == roles.None {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the user is no longer allowed to use this ledger")
		return
	}
	gid, err := randomToken(12)
	if err != nil {
		s.fail(w, "grant id", err)
		return
	}
	secret, err := randomToken(32)
	if err != nil {
		s.fail(w, "refresh token", err)
		return
	}
	refresh := gid + "." + secret
	g := &Grant{ID: gid, Subject: c.subject, ClientID: c.client.ID, ClientName: c.client.Name, Scopes: c.scopes, Resource: c.resource,
		Created: now, LastUsed: now, RefreshHash: hashToken(secret), Approved: c.expires.Add(-codeTTL)}
	// a code approved before the account's credentials were revoked is refused at the exchange: no grant is made
	if s.store.isBlocked(g) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the authorization code is not valid")
		return
	}
	// The grant and the hash of its refresh token reach the disk before the
	// token reaches the client.
	if err := s.store.mutate(func(d *fileData) error {
		d.Grants[gid] = g
		if cl := d.Clients[c.client.ID]; cl != nil {
			cl.LastUsed = now
		}
		return nil
	}); err != nil {
		s.fail(w, "saving the grant", err)
		return
	}
	s.mu.Lock()
	s.used[key] = usedCode{gid: gid, expires: now.Add(codeTTL)}
	s.mu.Unlock()
	s.log.Info("oauth grant created", "grant", gid, "user", c.subject.ID, "client", c.client.ID)
	s.respondTokens(w, g, g.Scopes, refresh)
}

// maxRetiredTokens is how many replaced refresh tokens a grant remembers.
const maxRetiredTokens = 8

// replayEntry is the answer given to a refresh, kept in memory for the grace
// window so that the same request, repeated, gets the same answer.
type replayEntry struct {
	gid     string
	body    []byte
	expires time.Time
}

// refresh answers a refresh token. A grant has exactly one live refresh token.
//   - The live token is replaced: a new access and refresh token are made, the
//     state is saved, and the answer is remembered (in memory only) for the
//     grace window under the token it replaced.
//   - That replaced token, inside the grace window, gets exactly the
//     remembered answer: a lost response and two simultaneous requests are the
//     same thing. Nothing changes on disk. After a restart there is no
//     remembered answer: refused, the grant stays.
//   - A replaced token after the grace window ends the whole grant.
//   - An unknown token is refused and changes nothing.
//
// Everything that can refuse the request is checked before anything is saved.
func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	gid, secret, ok := splitRefresh(f.Get("refresh_token"))
	if !ok {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token is not valid")
		return
	}
	h := hashToken(secret)
	s.refreshMu.Lock() // one refresh at a time: a second request with the same token sees the first one's answer
	defer s.refreshMu.Unlock()
	now := s.now()
	grace := s.cfg().RefreshReuseGraceOrDefault()
	s.pruneReplay(now)

	g := s.store.grant(gid)
	if g == nil || f.Get("client_id") != g.ClientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token is not valid")
		return
	}
	live := equalStrings(g.RefreshHash, h)
	ri := -1
	for i, rt := range g.Retired {
		if equalStrings(rt.Hash, h) {
			ri = i
		}
	}
	if !live && ri < 0 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token is not valid") // a guess must not end anyone's grant
		return
	}
	end := func(reason string) {
		if _, err := s.revoke(gid, reason); err != nil {
			s.fail(w, "ending a grant", err)
			return
		}
		if reason == reasonClaimsExpired {
			// a distinct answer, so the person can be told why in their language (reason says it to a program)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "reason": reasonClaimsExpired,
				"error_description": claimsExpiredText(r.Header.Get("Accept-Language"))})
			return
		}
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the grant has ended; authorize again")
	}
	switch {
	case !live && now.Sub(g.Retired[ri].At) > grace:
		s.log.Warn("oauth refresh token reused after the grace window; grant revoked", "grant", gid)
		end("refresh token reused")
		return
	case now.Sub(g.LastUsed) > s.cfg().IdleExpiryOrDefault():
		end("idle")
		return
	case s.role(s.effective(g)) == roles.None:
		if s.role(g.Subject) != roles.None {
			end(reasonClaimsExpired) // the role was only the claims', which no longer count
			return
		}
		end("role removed")
		return
	case len(s.cfg().AllowedClients) > 0 && !contains(s.cfg().AllowedClients, g.ClientID):
		s.log.Warn("oauth grant ended: the client is no longer in allowed_clients", "grant", gid, "client", g.ClientID)
		end("client not allowed")
		return
	}
	// Refusals that leave the grant as it is.
	if res := f.Get("resource"); res != "" && res != g.Resource {
		oauthError(w, http.StatusBadRequest, "invalid_target", "resource does not match the grant")
		return
	}
	scopes := g.Scopes
	if req := strings.Fields(f.Get("scope")); len(req) > 0 {
		for _, sc := range req {
			if !contains(g.Scopes, sc) {
				oauthError(w, http.StatusBadRequest, "invalid_scope", "scope is wider than the grant")
				return
			}
		}
		scopes = req
	}

	if !live { // inside the grace window
		if body := s.replayFor(h, gid, now); body != nil {
			writeBytes(w, body)
			return
		}
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token was already used; authorize again if this keeps happening")
		return
	}

	secretNew, err := randomToken(32)
	if err != nil {
		s.fail(w, "refresh token", err)
		return
	}
	newRef := gid + "." + secretNew
	body, err := s.tokenBody(g, scopes, newRef)
	if err != nil {
		s.fail(w, "signing", err)
		return
	}
	// The new hash is on disk before the answer leaves.
	if err := s.store.mutate(func(d *fileData) error {
		cur := d.Grants[gid]
		if cur == nil || s.store.isBlocked(cur) || !equalStrings(cur.RefreshHash, h) {
			return errNoChange
		}
		cur.Retired = append(cur.Retired, Retired{Hash: h, At: now})
		if n := len(cur.Retired); n > maxRetiredTokens {
			cur.Retired = append([]Retired(nil), cur.Retired[n-maxRetiredTokens:]...)
		}
		cur.RefreshHash = hashToken(secretNew)
		cur.LastUsed = now
		return nil
	}); err != nil {
		if errors.Is(err, errNoChange) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token is not valid")
			return
		}
		s.fail(w, "refreshing", err)
		return
	}
	s.rememberReplay(h, gid, body, now.Add(grace))
	writeBytes(w, body)
}

const maxReplay = 1000

// rememberReplay keeps an answer for the grace window. It holds tokens, so it
// is only in memory, never logged, small, and dropped with its grant.
func (s *Server) rememberReplay(h, gid string, body []byte, until time.Time) {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	if len(s.replay) < maxReplay {
		s.replay[h] = replayEntry{gid: gid, body: body, expires: until}
	}
}

func (s *Server) replayFor(h, gid string, now time.Time) []byte {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	if e, ok := s.replay[h]; ok && e.gid == gid && now.Before(e.expires) {
		return e.body
	}
	return nil
}

func (s *Server) pruneReplay(now time.Time) {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	for k, e := range s.replay {
		if !now.Before(e.expires) {
			delete(s.replay, k)
		}
	}
}

func (s *Server) dropReplay(gid string) {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	for k, e := range s.replay {
		if e.gid == gid {
			delete(s.replay, k)
		}
	}
}

func writeBytes(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) respondTokens(w http.ResponseWriter, g *Grant, scopes []string, refresh string) {
	body, err := s.tokenBody(g, scopes, refresh)
	if err != nil {
		s.fail(w, "signing", err)
		return
	}
	writeBytes(w, body)
}

// tokenBody makes the token response: a new access token and the refresh token.
func (s *Server) tokenBody(g *Grant, scopes []string, refresh string) ([]byte, error) {
	jti, err := randomToken(12)
	if err != nil {
		return nil, err
	}
	now := s.now()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: s.key.priv},
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", s.key.kid))
	if err != nil {
		return nil, err
	}
	claims := accessClaims{
		Claims: jwt.Claims{Issuer: s.o.Issuer, Subject: g.Subject.ID, Audience: jwt.Audience{g.Resource}, ID: jti,
			IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(accessTTL))},
		ClientID: g.ClientID, Scope: strings.Join(scopes, " "), GrantID: g.ID,
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"access_token": raw, "token_type": "Bearer", "expires_in": int(accessTTL / time.Second),
		"refresh_token": refresh, "scope": strings.Join(scopes, " "),
	})
}

type accessClaims struct {
	jwt.Claims
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	GrantID  string `json:"gid"`
}

// Claims is what the resource side learns from a verified access token.
type Claims struct {
	Subject    Subject
	ClientID   string
	ClientName string
	Scopes     []string
	GrantID    string
}

// ErrInvalidToken is every reason an access token is refused.
var ErrInvalidToken = errors.New("invalid access token")

// IsOwn reports whether raw is a JWT that claims this server as its issuer. The
// claim is not trusted here; it only picks the verifier, which then checks
// everything (a forged token is refused there, never handed to another issuer).
func (s *Server) IsOwn(raw string) bool {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return false
	}
	var peek struct {
		Iss string `json:"iss"`
	}
	if err := decodeSegment(parts[1], &peek); err != nil {
		return false
	}
	return peek.Iss == s.o.Issuer
}

// VerifyAccess checks an access token this server issued, in-process: ES256
// only, typ at+jwt, our key, our issuer, the /mcp audience, expiry with 60 s of
// skew, and a grant that still exists (so revoking a grant ends its tokens at
// once). It does not evaluate the role; the caller does, from Claims.Subject.
func (s *Server) VerifyAccess(raw string) (*Claims, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(tok.Headers) != 1 {
		return nil, ErrInvalidToken
	}
	h := tok.Headers[0]
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); !strings.EqualFold(typ, "at+jwt") && !strings.EqualFold(typ, "application/at+jwt") {
		return nil, ErrInvalidToken
	}
	if h.KeyID != s.key.kid {
		return nil, ErrInvalidToken
	}
	var c accessClaims
	if err := tok.Claims(&s.key.priv.PublicKey, &c); err != nil {
		return nil, ErrInvalidToken
	}
	const skew = 60 * time.Second
	now := s.now()
	if c.Issuer != s.o.Issuer || !c.Audience.Contains(s.o.Resource) || c.Subject == "" || c.GrantID == "" || c.Expiry == nil ||
		now.After(c.Expiry.Time().Add(skew)) || (c.NotBefore != nil && now.Add(skew).Before(c.NotBefore.Time())) ||
		(c.IssuedAt != nil && now.Add(skew).Before(c.IssuedAt.Time())) {
		return nil, ErrInvalidToken
	}
	g := s.store.grant(c.GrantID)
	if g == nil || g.ClientID != c.ClientID || g.Subject.ID != c.Subject || g.Resource != s.o.Resource ||
		now.Sub(g.LastUsed) > s.cfg().IdleExpiryOrDefault() {
		return nil, ErrInvalidToken
	}
	return &Claims{Subject: s.effective(g), ClientID: g.ClientID, ClientName: g.ClientName, Scopes: strings.Fields(c.Scope), GrantID: g.ID}, nil
}

// revoke ends a grant. It reports whether one existed, and an error when the
// change could not be saved (then the grant is still in force).
func (s *Server) revoke(gid, why string) (bool, error) {
	found := false
	err := s.store.mutate(func(d *fileData) error {
		if _, found = d.Grants[gid]; !found {
			return errNoChange
		}
		delete(d.Grants, gid)
		return nil
	})
	if errors.Is(err, errNoChange) {
		return false, nil
	}
	if err != nil {
		s.log.Error("could not save a revoked grant", "grant", gid, "err", err)
		return false, err
	}
	s.dropReplay(gid)
	s.log.Info("oauth grant revoked", "grant", gid, "why", why)
	return true, nil
}
