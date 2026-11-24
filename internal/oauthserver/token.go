package oauthserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
		Created: now, LastUsed: now, RefreshHash: hashToken(secret)}
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
	case s.role(g.Subject) == roles.None:
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
		if cur == nil || !equalStrings(cur.RefreshHash, h) {
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
	return &Claims{Subject: g.Subject, ClientID: g.ClientID, ClientName: g.ClientName, Scopes: strings.Fields(c.Scope), GrantID: g.ID}, nil
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
