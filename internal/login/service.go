// Package login is the built-in login of Rackbook (docs/design-v0.2.md,
// section 2): OIDC (authorization code with PKCE through authcore/oidc),
// optional passkeys, and HMAC-signed session cookies. It keeps no database:
// sessions are signed cookies, pending logins live in memory, and passkey
// credentials are committed to .rackbook/passkeys.yml in the data repository.
package login

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	authoidc "github.com/KazuhaHub/authcore/oidc"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/locale"
	"github.com/kazuhahub/rackbook/internal/prefs"
	"github.com/kazuhahub/rackbook/internal/roles"
)

// StateFiles is where passkey credentials are read and committed. The Git
// store implements it.
type StateFiles interface {
	StateFile(rel string) (content []byte, exists bool, err error)
	// StateSettled says no pull, replay or write is in progress and the clone is at a loaded commit.
	StateSettled() bool
	MutateStateFile(ctx context.Context, rel, subject string, who *auth.Identity, mutate func(old []byte, exists bool) ([]byte, error), opts ...gitstore.StateOption) (*gitstore.StateResult, error)
}

// Options configures the Service.
type Options struct {
	Login config.Login
	// Config returns the current rackbook.yml, which changes when the data
	// repository is pulled. It supplies the sign-in label and branding; nil
	// = use Login and no branding.
	Config         func() *config.Config
	BaseURL        string // public https URL of the console (required)
	Key            []byte // session signing key, 32 or more bytes
	ClientSecret   string // RACKBOOK_OIDC_CLIENT_SECRET
	CAFile         string // extra root CAs for the IdP (private CA); optional
	HTTPClient     *http.Client
	Prefs          *prefs.Store   // per-person preferences (the language); nil = in memory only
	Files          StateFiles     // nil = no passkeys
	ReadOnly       bool           // refuse passkey changes
	TrustedProxies []netip.Prefix // --trusted-proxy CIDRs
	Logger         *slog.Logger
	Now            func() time.Time
	Context        context.Context // lifetime of the OIDC provider; default Background
}

// Service implements auth.SessionAuth and serves /auth/*.
type Service struct {
	o        Options
	log      *slog.Logger
	now      func() time.Time
	codec    codec
	idle     time.Duration
	absolute time.Duration
	pending  *pendingStore
	users    *userRegistry
	base     *url.URL
	redirect string
	client   *http.Client
	authn    *auth.Authenticator

	pmu     sync.Mutex
	prov    *authoidc.Provider
	provErr error
	provTry time.Time

	pk      *passkeys
	limit   *limiter       // unauthenticated begin endpoints
	trusted []netip.Prefix // --trusted-proxy: whose CF-Connecting-IP is believed
}

// New validates the options. It does not contact the IdP: discovery happens
// on first use (and is retried), so an IdP that is down at boot does not keep
// the server from starting.
func New(o Options) (*Service, error) {
	if len(o.Key) < 32 {
		return nil, errors.New("login: the session key must be at least 32 bytes")
	}
	if err := o.Login.OIDC.Check(); err != nil {
		return nil, err
	}
	base, err := url.Parse(o.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || (base.Path != "" && base.Path != "/") || base.RawQuery != "" || base.Fragment != "" {
		return nil, fmt.Errorf("--base-url must be the https origin of the console (e.g. https://ledger.example.com) for --auth oidc, got %q", o.BaseURL)
	}
	s := &Service{o: o, log: o.Logger, now: o.Now, base: &url.URL{Scheme: "https", Host: base.Host}}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.o.Context == nil {
		s.o.Context = context.Background()
	}
	if w := o.Login.OIDC.IdentityClaimWarning(); w != "" {
		s.log.Warn(w)
	}
	s.codec = codec{key: o.Key}
	s.idle, s.absolute = o.Login.Session.IdleOrDefault(), o.Login.Session.AbsoluteOrDefault()
	s.pending = newPendingStore(s.now)
	s.users = newUserRegistry()
	if s.o.Prefs == nil {
		s.o.Prefs = &prefs.Store{}
	}
	s.limit = newLimiter(30, 10, s.now)
	s.trusted = o.TrustedProxies
	s.redirect = s.base.String() + "/auth/oidc/callback"
	s.client = o.HTTPClient
	if s.client == nil && o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("--oidc-ca-file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("--oidc-ca-file: no certificate found")
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		s.client = &http.Client{Transport: tr}
	}
	if o.Login.Passkeys.Enabled {
		if o.Files == nil {
			return nil, errors.New("login: passkeys need a data repository to store credentials")
		}
		if s.pk, err = newPasskeys(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Bind connects the role evaluation of the authenticator. Call it once after
// auth.New (which needs this Service first).
func (s *Service) Bind(a *auth.Authenticator) { s.authn = a }

// Warm tries OIDC discovery now and logs the result, so a wrong issuer shows
// up at startup. It never fails the server.
func (s *Service) Warm() {
	if _, err := s.provider(); err != nil {
		s.log.Warn("OIDC discovery failed; will retry on the next login", "issuer", s.o.Login.OIDC.Issuer, "err", err)
		return
	}
	s.log.Info("OIDC discovery ok", "issuer", s.o.Login.OIDC.Issuer)
}

func (s *Service) provider() (*authoidc.Provider, error) {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	if s.prov != nil {
		return s.prov, nil
	}
	if s.provErr != nil && s.now().Sub(s.provTry) < 5*time.Second {
		return nil, s.provErr
	}
	c := s.o.Login.OIDC
	p, err := authoidc.New(s.o.Context, authoidc.Config{
		IssuerURL: c.Issuer, ClientID: c.ClientID, ClientSecret: s.o.ClientSecret,
		RedirectURL: s.redirect, Scopes: c.Scopes, HTTPClient: s.client,
	})
	s.provTry = s.now()
	if err != nil {
		s.provErr = err
		return nil, err
	}
	s.prov, s.provErr = p, nil
	return p, nil
}

// Mount registers the /auth endpoints and the account and user APIs. static
// serves the console's index.html (the login page is part of the console).
func (s *Service) Mount(mux *http.ServeMux, static http.Handler) {
	mux.HandleFunc("GET /auth/login", func(w http.ResponseWriter, r *http.Request) { s.loginPage(w, r, static) })
	mux.HandleFunc("GET /auth/config", s.publicConfig)
	mux.HandleFunc("GET /auth/oidc/start", s.oidcStart)
	mux.HandleFunc("GET /auth/oidc/callback", s.oidcCallback)
	mux.HandleFunc("POST /auth/logout", s.logout)
	if s.pk != nil {
		mux.HandleFunc("POST /auth/passkey/begin", s.pk.loginBegin)
		mux.HandleFunc("POST /auth/passkey/finish", s.pk.loginFinish)
	}
	mux.HandleFunc("GET /api/account", humansOnly(s.account))
	mux.HandleFunc("GET /api/admin/users", humansOnly(s.adminUsers))
	if s.pk != nil {
		mux.HandleFunc("POST /api/account/passkeys/begin", humansOnly(s.pk.enrolBegin))
		mux.HandleFunc("POST /api/account/passkeys/finish", humansOnly(s.pk.enrolFinish))
		mux.HandleFunc("DELETE /api/account/passkeys/{id}", humansOnly(s.pk.removeOwn))
		mux.HandleFunc("DELETE /api/admin/passkeys/{id}", humansOnly(s.pk.removeAny))
	}
}

// humansOnly refuses credentials that are not a person's browser login: API
// tokens and OAuth access tokens never manage accounts, passkeys or users.
func humansOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if id := auth.FromContext(r.Context()); id != nil {
			switch id.Method {
			case auth.MethodToken, auth.MethodOAuth, auth.MethodMCPHub:
				writeErr(w, http.StatusForbidden, "forbidden", "this endpoint is for signed-in people, not API tokens")
				return
			}
		}
		next(w, r)
	}
}

// auth.SessionAuth -----------------------------------------------------------

// Public reports requests that need no session: the login endpoints and the
// console's static files (which hold no data).
func (s *Service) Public(r *http.Request) bool {
	p, ok := auth.CanonicalPath(r)
	if !ok {
		return false
	}
	return p == "/auth" || strings.HasPrefix(p, "/auth/") || strings.HasPrefix(p, "/assets/") || p == "/favicon.svg" || p == "/favicon.ico"
}

func unauth(err error) error { return fmt.Errorf("%w: %w", auth.ErrUnauthenticated, err) }

// readSession returns the verified session of r.
func (s *Service) readSession(r *http.Request) (session, error) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return session{}, errNoSession
	}
	sess, err := s.codec.open(c.Value)
	if err != nil {
		return session{}, err
	}
	if err := sess.check(s.now(), s.idle, s.absolute); err != nil {
		return session{}, err
	}
	if sess.Method == auth.MethodOIDC && sess.Iss != s.o.Login.OIDC.Issuer {
		// The issuer changed (or the cookie predates the check): log in again.
		return session{}, errExpired
	}
	if sess.Method == auth.MethodPasskey {
		// A passkey session ends when its credential is deleted (revocation), and
		// only then: a file that cannot be read right now answers 503 for this
		// request and leaves the cookie alone.
		if s.pk == nil || sess.Cred == "" {
			return session{}, errRevoked
		}
		present, err := s.pk.credentialState(sess.Cred)
		if err != nil {
			return session{}, err
		}
		if !present {
			return session{}, errRevoked
		}
	}
	return sess, nil
}

// Identify implements auth.SessionAuth.
func (s *Service) Identify(w http.ResponseWriter, r *http.Request) (*auth.Identity, error) {
	sess, err := s.readSession(r)
	if errors.Is(err, errUnavailable) {
		return nil, err // not ErrUnauthenticated: the session may well be fine
	}
	if err != nil {
		return nil, unauth(err)
	}
	now := s.now()
	if w != nil && now.Sub(time.Unix(sess.Seen, 0)) >= refreshEvery {
		sess.Seen = now.Unix()
		s.setSession(w, sess)
	}
	s.users.touch(sess.ID, sess.Name, sess.Method, now)
	return identityOf(sess), nil
}

func identityOf(sess session) *auth.Identity {
	id := &auth.Identity{ID: sess.ID, Name: sess.Name, Method: sess.Method, Groups: sess.Groups}
	if strings.Contains(sess.ID, "@") {
		id.Email = sess.ID
	}
	if sess.Method == auth.MethodOIDC {
		id.OIDCIssuer, id.OIDCClient = sess.Iss, sess.Cli
		if sess.OIDCAt > 0 {
			id.OIDCAt = time.Unix(sess.OIDCAt, 0)
		}
	}
	return id
}

func (s *Service) setSession(w http.ResponseWriter, sess session) {
	v, err := s.codec.seal(sess)
	if err != nil {
		s.log.Error("could not sign a session", "err", err)
		return
	}
	left := time.Unix(sess.Issued, 0).Add(s.absolute).Sub(s.now())
	setCookie(w, SessionCookie, v, max(1, int(left.Seconds())))
}

// issue starts a session for id.
func (s *Service) issue(w http.ResponseWriter, id *auth.Identity, method, cred string) {
	now := s.now().Unix()
	sess := session{ID: id.ID, Name: id.Name, Method: method, Issued: now, Seen: now, Cred: cred}
	if method == auth.MethodOIDC {
		sess.OIDCAt = now
		sess.Iss = s.o.Login.OIDC.Issuer
		sess.Cli = s.o.Login.OIDC.ClientID
		var cut bool
		if sess.Groups, cut = boundGroups(id.Groups); cut {
			s.log.Warn("the ID token has more groups than fit the session cookie; the rest are ignored", "identity", id.ID)
		}
	}
	s.setSession(w, sess)
	s.users.touch(id.ID, id.Name, method, s.now())
}

// isAPI tells API-style requests (answered with JSON) from console pages
// (answered with a redirect).
func isAPI(r *http.Request) bool {
	p := r.URL.Path
	return strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/export.") || strings.HasPrefix(p, "/llms") || p == "/mcp" || strings.HasPrefix(p, "/mcp/") ||
		(r.Method != http.MethodGet && r.Method != http.MethodHead)
}

func loginURL(ret string, extra url.Values) string {
	v := url.Values{}
	if ret = SafeReturn(ret); ret != "/" {
		v.Set("return", ret)
	}
	for k, vals := range extra {
		v[k] = vals
	}
	if len(v) == 0 {
		return "/auth/login"
	}
	return "/auth/login?" + v.Encode()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

// returnOf is the page a rejected request should come back to: the request
// itself for a console page, the Referer's path for an API call.
func returnOf(r *http.Request) string {
	if !isAPI(r) {
		return SafeReturn(r.URL.RequestURI())
	}
	if ref := r.Referer(); ref != "" {
		if u, err := url.Parse(ref); err == nil && strings.EqualFold(u.Host, r.Host) {
			return SafeReturn(u.RequestURI())
		}
	}
	return "/"
}

// Reject implements auth.SessionAuth.
func (s *Service) Reject(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errUnavailable) {
		// Transient (the passkey file is being updated): keep the cookie.
		w.Header().Set("Retry-After", "2")
		writeErr(w, http.StatusServiceUnavailable, "passkey_unavailable", "passkeys are briefly unavailable, try again")
		return
	}
	expired := errors.Is(err, errExpired)
	if !errors.Is(err, errNoSession) {
		clearCookie(w, SessionCookie)
	}
	extra := url.Values{}
	if expired {
		extra.Set("error", "expired")
	}
	to := loginURL(returnOf(r), extra)
	if isAPI(r) {
		body := map[string]string{"error": "login_required", "message": "log in to continue", "login": to}
		if expired {
			body["reason"] = "expired"
		}
		writeJSON(w, http.StatusUnauthorized, body)
		return
	}
	// The redirect depends on the session cookie, so no cache may keep it.
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, to, http.StatusFound)
}

// NoRole implements auth.SessionAuth.
func (s *Service) NoRole(w http.ResponseWriter, r *http.Request, id *auth.Identity) {
	s.log.Warn("request refused: identity has no role", "identity", id.ID, "method", id.Method, "path", r.URL.Path)
	if isAPI(r) {
		writeErr(w, http.StatusForbidden, "no_role", "you are not allowed to use this ledger")
		return
	}
	http.Redirect(w, r, loginURL("", url.Values{"error": {"no_role"}}), http.StatusSeeOther)
}

// Login page and small endpoints ---------------------------------------------

// statusWriter lets the console's index.html be served with another status
// (403 for the no-role page).
type statusWriter struct {
	http.ResponseWriter
	status int
	done   bool
}

func (w *statusWriter) WriteHeader(int) {
	if !w.done {
		w.done = true
		w.ResponseWriter.WriteHeader(w.status)
	}
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.WriteHeader(0)
	return w.ResponseWriter.Write(b)
}

// loginErrors are the error codes the console knows how to show.
var loginErrors = map[string]int{
	"no_role": http.StatusForbidden, "tenant": http.StatusForbidden,
	"idp_error": http.StatusOK, "idp_unavailable": http.StatusOK, "expired": http.StatusOK,
	"bad_callback": http.StatusOK, "claims": http.StatusOK, "logged_out": http.StatusOK, "passkey": http.StatusOK,
}

func (s *Service) loginPage(w http.ResponseWriter, r *http.Request, static http.Handler) {
	code := r.URL.Query().Get("error")
	status, known := loginErrors[code]
	if code == "" {
		// An already logged-in user goes straight on.
		if sess, err := s.readSession(r); err == nil && s.authn != nil {
			if s.authn.Evaluate(identityOf(sess)).EffectiveRole() != roles.None {
				http.Redirect(w, r, SafeReturn(r.URL.Query().Get("return")), http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, loginURL("", url.Values{"error": {"no_role"}}), http.StatusSeeOther)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	if known && status != http.StatusOK {
		w = &statusWriter{ResponseWriter: w, status: status}
	}
	static.ServeHTTP(w, r)
}

func (s *Service) publicConfig(w http.ResponseWriter, r *http.Request) {
	label, name, logo, def := s.o.Login.OIDC.Label, "", false, locale.Default
	if s.o.Config != nil {
		cfg := s.o.Config()
		label, name, logo, def = cfg.Auth.OIDC.Label, cfg.Branding.Name, cfg.BrandLogo() != nil, cfg.DefaultLocale()
	}
	// The answer depends on the browser's language, so no cache may reuse it.
	w.Header().Add("Vary", "Accept-Language")
	// "provider" stays for older consoles; it no longer names the IdP.
	writeJSON(w, http.StatusOK, map[string]any{
		"oidc": true, "provider": "oidc", "passkeys": s.pk != nil,
		"label": label, "name": name, "logo": logo,
		"locale": locale.Match(r.Header.Get("Accept-Language"), def), "defaultLocale": def,
	})
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	if sess, err := s.readSession(r); err == nil {
		s.log.Info("logout", "identity", sess.ID, "method", sess.Method)
	}
	clearCookie(w, SessionCookie)
	to := loginURL("", url.Values{"error": {"logged_out"}})
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeJSON(w, http.StatusOK, map[string]string{"login": to})
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// roleOf evaluates the role of an identity from the current config.
func (s *Service) roleOf(id *auth.Identity) roles.Role {
	if s.authn == nil {
		return roles.None
	}
	return s.authn.Evaluate(id).EffectiveRole()
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	return dec.Decode(v)
}
