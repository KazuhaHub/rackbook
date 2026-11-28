package oauthserver

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/roles"
)

// pendingAuth is an authorization request that passed every check and waits
// for the person to approve it on the consent page. It is bound to the person
// who made it.
type pendingAuth struct {
	id          string
	client      clientInfo
	redirectURI string
	state       string
	challenge   string
	scopes      []string
	resource    string
	subject     Subject
	expires     time.Time
}

// authCode is an issued authorization code (memory only, single use).
type authCode struct {
	client      clientInfo
	redirectURI string
	challenge   string
	scopes      []string
	resource    string
	subject     Subject
	expires     time.Time
}

type usedCode struct {
	gid     string
	expires time.Time
}

var (
	challengeRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	verifierRe  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

// humanSubject returns who is signed in to the console, or false for a caller
// that is not a person (an API token, an access token) or has no identity.
func humanSubject(r *http.Request) (Subject, bool) {
	id := auth.FromContext(r.Context())
	if id == nil || id.ID == "" {
		return Subject{}, false
	}
	switch id.Method {
	case auth.MethodToken, auth.MethodOAuth, auth.MethodMCPHub:
		return Subject{}, false
	}
	sub := Subject{ID: roles.FoldASCII(id.ID), Email: id.Email, Name: id.Name, Method: id.Method, Groups: boundGroups(id.Groups), AppRoles: boundAppRoles(id.AppRoles), SignedIn: id.OIDCAt}
	return sub, true
}

// boundGroups keeps the groups a grant stores small, with the same rule as the session cookie.
func boundGroups(in []string) []string { out, _ := roles.BoundClaim(in, true); return out }

// boundAppRoles is the same for the roles claim, whose values are kept exactly as sent.
func boundAppRoles(in []string) []string { out, _ := roles.BoundClaim(in, false); return out }

// redirectBack sends the browser back to the client with an error (RFC 6749
// section 4.1.2.1). It is used only after client_id and redirect_uri were
// accepted, so the target is trusted.
func (s *Server) redirectBack(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	http.Redirect(w, r, s.callback(redirectURI, state, url.Values{"error": {code}, "error_description": {desc}}), http.StatusFound)
}

// callback builds the redirect to the client, with state and the RFC 9207 iss.
func (s *Server) callback(redirectURI, state string, params url.Values) string {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", s.o.Issuer)
	u.RawQuery = q.Encode()
	return u.String()
}

// lookupClient finds the client behind a client_id: a metadata document for an
// https URL, else a registered client.
func (s *Server) lookupClient(r *http.Request, clientID string) (*clientInfo, error) {
	// With allowed_clients, only those metadata-document clients may authorize
	// (registered clients are not served then, see dcrOn).
	if allowed := s.cfg().AllowedClients; len(allowed) > 0 && !contains(allowed, clientID) {
		return nil, errClientNotAllowed
	}
	if isCIMDClient(clientID) {
		return s.cimd.get(r.Context(), clientID)
	}
	c := s.store.client(clientID)
	if c == nil {
		return nil, errUnknownClient
	}
	return &clientInfo{ID: c.ID, Name: c.Name, RedirectURIs: c.RedirectURIs}, nil
}

func isCIMDClient(id string) bool { return isCIMDClientID(id) }

// authorize is GET /oauth/authorize. The person is already signed in (the
// console's own login ran before this handler, and sent them back here).
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	subject, ok := humanSubject(r)
	if !ok {
		s.errorPage(w, r, http.StatusForbidden, reasonNotPerson, nil)
		return
	}
	q := r.URL.Query()
	clientID := q.Get("client_id")
	if clientID == "" {
		s.errorPage(w, r, http.StatusBadRequest, reasonNoClientID, nil)
		return
	}
	client, err := s.lookupClient(r, clientID)
	if err != nil {
		s.log.Info("oauth authorize: client refused", "client", clientID, "err", err.Error())
		s.errorPage(w, r, http.StatusBadRequest, reasonClient, err)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" || !redirectAllowed(client.RedirectURIs, redirectURI) {
		s.log.Info("oauth authorize: redirect_uri not registered", "client", clientID, "redirect_uri", redirectURI)
		s.errorPage(w, r, http.StatusBadRequest, reasonRedirect, nil)
		return
	}
	// From here on the redirect target is known to be the client's own.
	state := q.Get("state")
	if q.Get("response_type") != "code" {
		s.redirectBack(w, r, redirectURI, state, "unsupported_response_type", "response_type must be code")
		return
	}
	challenge := q.Get("code_challenge")
	if method := q.Get("code_challenge_method"); challenge == "" || method != "S256" {
		s.redirectBack(w, r, redirectURI, state, "invalid_request", "PKCE with code_challenge_method S256 is required")
		return
	}
	if !challengeRe.MatchString(challenge) {
		s.redirectBack(w, r, redirectURI, state, "invalid_request", "code_challenge is not a base64url SHA-256 value")
		return
	}
	resource := q.Get("resource")
	if resource == "" {
		s.redirectBack(w, r, redirectURI, state, "invalid_target", "the resource parameter (RFC 8707) is required")
		return
	}
	if resource != s.o.Resource {
		s.redirectBack(w, r, redirectURI, state, "invalid_target", "unknown resource")
		return
	}
	scopes, ok := s.grantScopes(q.Get("scope"))
	if !ok {
		s.redirectBack(w, r, redirectURI, state, "invalid_scope", "scope must be one of: "+strings.Join(s.scopesSupported(), " "))
		return
	}

	id, err := randomToken(24)
	if err != nil {
		s.redirectBack(w, r, redirectURI, state, "server_error", "could not start the request")
		return
	}
	now := s.now()
	s.mu.Lock()
	s.prune(now)
	if len(s.pending) >= maxPending {
		s.mu.Unlock()
		s.redirectBack(w, r, redirectURI, state, "temporarily_unavailable", "too many pending requests")
		return
	}
	s.pending[id] = &pendingAuth{id: id, client: *client, redirectURI: redirectURI, state: state, challenge: challenge,
		scopes: scopes, resource: resource, subject: subject, expires: now.Add(pendingTTL)}
	s.mu.Unlock()
	http.Redirect(w, r, PathConsent+"?req="+url.QueryEscape(id), http.StatusFound)
}

// grantScopes checks the requested scopes against the supported ones (an
// unknown one is invalid_scope, RFC 6749 section 4.1.2.1). No request
// means everything supported; the role still decides what is allowed.
func (s *Server) grantScopes(requested string) ([]string, bool) {
	supported := s.scopesSupported()
	if strings.TrimSpace(requested) == "" {
		return supported, true
	}
	out := []string{}
	for _, sc := range strings.Fields(requested) {
		if !contains(supported, sc) {
			return nil, false
		}
		if !contains(out, sc) {
			out = append(out, sc)
		}
	}
	return out, true
}

// prune drops expired pending requests, codes and replay markers. s.mu is held.
func (s *Server) prune(now time.Time) {
	for k, p := range s.pending {
		if now.After(p.expires) {
			delete(s.pending, k)
		}
	}
	for k, c := range s.codes {
		if now.After(c.expires) {
			delete(s.codes, k)
		}
	}
	for k, u := range s.used {
		if now.After(u.expires) {
			delete(s.used, k)
		}
	}
}

// takePending finds the caller's own pending request and removes it: a request
// is decided once.
func (s *Server) takePending(id string, who Subject, keep bool) *pendingAuth {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pending[id]
	if p == nil || s.now().After(p.expires) || p.subject.ID != who.ID || p.subject.Method != who.Method {
		return nil
	}
	if !keep {
		delete(s.pending, id)
	}
	return p
}

// consentInfo is GET /api/oauth/consent?req=...: what the consent page shows.
func (s *Server) consentInfo(w http.ResponseWriter, r *http.Request) {
	who, ok := humanSubject(r)
	if !ok {
		apiError(w, http.StatusForbidden, "forbidden", "only signed-in people can authorize a client")
		return
	}
	p := s.takePending(r.URL.Query().Get("req"), who, true)
	if p == nil {
		apiError(w, http.StatusNotFound, "not_found", "this authorization request has expired or is not yours; start again from the client")
		return
	}
	clientHost := ""
	if u, err := url.Parse(p.client.ID); err == nil && isCIMDClient(p.client.ID) {
		clientHost = u.Hostname()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"clientName": p.client.Name, "clientId": p.client.ID,
		"redirectUri": p.redirectURI, "redirectHost": redirectHost(p.redirectURI),
		// What the grant could do: the role of the person, limited by the scopes.
		"scopes": p.scopes, "canWrite": s.canWrite(who, p.scopes),
		// A host label starting xn-- may display as look-alike letters.
		"punycode": hasPunycode(redirectHostname(p.redirectURI)) || hasPunycode(clientHost),
		"user":     map[string]string{"id": who.ID, "name": who.Name},
	})
}

// consentDecision is POST /api/oauth/consent. The server's same-origin check
// (Sec-Fetch-Site, Origin) and the JSON content type guard it against another
// site approving on the person's behalf; the request id is secret and bound
// to the person.
func (s *Server) consentDecision(w http.ResponseWriter, r *http.Request) {
	who, ok := humanSubject(r)
	if !ok {
		apiError(w, http.StatusForbidden, "forbidden", "only signed-in people can authorize a client")
		return
	}
	var body struct {
		Req     string `json:"req"`
		Approve bool   `json:"approve"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body); err != nil {
		apiError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	// approving a client hands out a credential: a local account re-authenticates first (6), before the request is used up, so
	// that the consent page can be opened again after the re-authentication
	if body.Approve && s.o.Auth.RequireRecentAuth(w, r) {
		return
	}
	p := s.takePending(body.Req, who, false)
	if p == nil {
		apiError(w, http.StatusNotFound, "not_found", "this authorization request has expired or is not yours; start again from the client")
		return
	}
	if !body.Approve {
		s.log.Info("oauth authorization denied", "user", who.ID, "client", p.client.ID)
		writeJSON(w, http.StatusOK, map[string]string{"redirect": s.callback(p.redirectURI, p.state, url.Values{"error": {"access_denied"}, "error_description": {"the user denied the request"}})})
		return
	}
	raw, err := randomToken(32)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "internal", "could not issue a code")
		return
	}
	now := s.now()
	s.mu.Lock()
	s.codes[codeKey(raw)] = &authCode{client: p.client, redirectURI: p.redirectURI, challenge: p.challenge, scopes: p.scopes,
		resource: p.resource, subject: p.subject, expires: now.Add(codeTTL)}
	s.mu.Unlock()
	s.log.Info("oauth authorization approved", "user", who.ID, "client", p.client.ID, "scopes", p.scopes)
	writeJSON(w, http.StatusOK, map[string]string{"redirect": s.callback(p.redirectURI, p.state, url.Values{"code": {raw}})})
}

func codeKey(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// pkceOK checks code_verifier against the stored S256 challenge.
func pkceOK(verifier, challenge string) bool {
	if !verifierRe.MatchString(verifier) {
		return false
	}
	h := sha256.Sum256([]byte(verifier))
	return equalStrings(base64.RawURLEncoding.EncodeToString(h[:]), challenge)
}

// redirectHostname is the host name of a redirect URI, without the port.
func redirectHostname(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// canWrite says a grant with these scopes could write for subject: the role
// must allow writing and the scopes must include the write scope.
func (s *Server) canWrite(sub Subject, scopes []string) bool {
	ws := s.o.Config().Auth.MCP.Scopes.WriteScope()
	return (ws == "" || contains(scopes, ws)) && s.role(sub).Allows(roles.Write)
}

// redirectAllowed reports whether redirectURI is one of the client's
// registered redirect URIs. The match is exact, with one exception from
// RFC 8252 section 7.3: for an http loopback redirect (localhost, 127.0.0.1
// or [::1]) the port may differ, because a native app such as Claude Code
// listens on a port the system picks at sign-in time. This holds whether or
// not the registered URI names a port. Scheme, host, path and query must
// still match exactly, and the requested URI must itself pass the same checks
// as a registered one, with a port of 1 to 65535 when it names one.
func redirectAllowed(registered []string, redirectURI string) bool {
	if contains(registered, redirectURI) {
		return true
	}
	if validateRedirect(redirectURI) != nil {
		return false
	}
	got, err := url.Parse(redirectURI)
	if err != nil || got.Scheme != "http" || !isLoopbackHost(got.Hostname()) || !validPort(got) {
		return false
	}
	for _, r := range registered {
		want, err := url.Parse(r)
		if err != nil || want.Scheme != "http" || !isLoopbackHost(want.Hostname()) {
			continue
		}
		if want.Hostname() == got.Hostname() && want.RawPath == got.RawPath && want.Path == got.Path &&
			want.RawQuery == got.RawQuery {
			return true
		}
	}
	return false
}

// validPort accepts no port at all, or a decimal port from 1 to 65535 written
// without leading zeros.
func validPort(u *url.URL) bool {
	p := u.Port()
	if p == "" {
		return !strings.HasSuffix(u.Host, ":")
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == p
}

// isLoopbackHost is the one list of hosts an http redirect may use, shared by
// registration and authorization.
func isLoopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}
