// Package login is the built-in login of Rackbook (docs/design-v0.2.md,
// section 2): OIDC (authorization code with PKCE through authcore/oidc),
// optional passkeys, and HMAC-signed session cookies. It keeps no database:
// sessions are signed cookies, pending logins live in memory, and passkey
// credentials are committed to .rackbook/passkeys.yml in the data repository.
package login

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	authoidc "github.com/KazuhaHub/authcore/oidc"

	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/clientip"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/locale"
	"github.com/kazuhahub/rackbook/internal/prefs"
	"github.com/kazuhahub/rackbook/internal/roles"
	"github.com/kazuhahub/rackbook/internal/routes"
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
	Audit          *audit.Log // sign-ins, sign-outs and refusals; nil = none
	// Infra is the --infra-admins and --infra-auditors lists (nil = no /infra). The login
	// only asks them how a person is an infra administrator, for the login event and the
	// account page; it never decides /infra access.
	Infra *auth.InfraAccess
	// Local is the store of local accounts, nil when there are none (no state key). Sessions of
	// method local verify against it and against nothing else; no route of this package creates one
	// (the sign-in pages and endpoints are a later piece).
	Local   LocalSessions
	Now     func() time.Time
	Context context.Context // lifetime of the OIDC provider; default Background

	// ssoPasskeys is a test seam. This Service is the OIDC login, and people who
	// sign in through OIDC get no passkey sign-in (docs/design-audit.md, section 4),
	// so auth.passkeys is ignored here. The passkey code stays for local accounts;
	// the tests of it set this to build it anyway.
	ssoPasskeys bool
}

// Service implements auth.SessionAuth and serves /auth/*.
type Service struct {
	o        Options
	log      *slog.Logger
	now      func() time.Time
	codec    codec
	idle     time.Duration
	absolute time.Duration
	// claimsAbsolute is the absolute lifetime of a session whose role came from
	// groups or app roles (auth.session.claims_absolute), already below absolute.
	claimsAbsolute time.Duration
	pending        *pendingStore
	users          *userRegistry
	base           *url.URL
	redirect       string
	client         *http.Client
	authn          *auth.Authenticator
	// sso says single sign-on is configured (auth.oidc has an issuer). Without it the service is
	// local accounts alone: no OIDC provider, and /auth/oidc/* answers 404.
	sso bool

	pmu     sync.Mutex
	prov    *authoidc.Provider
	provErr error
	provTry time.Time

	limitMu    sync.Mutex
	limitCache map[string]limitEntry // claimsLimited, per session, claims and config generation

	checkedMu sync.Mutex
	checked   map[string]any // session key -> the role policy generation it was last looked at under

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
	sso := o.Login.OIDC.Issuer != "" || o.Login.OIDC.ClientID != ""
	if sso {
		if err := o.Login.OIDC.Check(); err != nil {
			return nil, err
		}
	} else if o.Local == nil {
		return nil, errors.New("login: neither single sign-on (auth.oidc) nor local accounts (a state key) is available")
	}
	base, err := url.Parse(o.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || (base.Path != "" && base.Path != "/") || base.RawQuery != "" || base.Fragment != "" {
		return nil, fmt.Errorf("--base-url must be the https origin of the console (e.g. https://ledger.example.com) for --auth oidc, got %q", o.BaseURL)
	}
	s := &Service{o: o, log: o.Logger, now: o.Now, base: &url.URL{Scheme: "https", Host: base.Host}, sso: sso}
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
	s.codec = codec{key: o.Key, local: o.Local}
	s.idle, s.absolute = o.Login.Session.IdleOrDefault(), o.Login.Session.AbsoluteOrDefault()
	s.claimsAbsolute = o.Login.Session.ClaimsAbsoluteOrDefault()
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
		if !o.ssoPasskeys {
			// Not an error: a rackbook.yml written for an older Rackbook keeps loading. The
			// routes stay and refuse (passkeysRefused), the console hides the passkey pages.
			s.log.Warn("auth.passkeys is ignored: people who sign in through single sign-on are not offered passkeys, the identity provider is their second factor")
		} else {
			if o.Files == nil {
				return nil, errors.New("login: passkeys need a data repository to store credentials")
			}
			if s.pk, err = newPasskeys(s); err != nil {
				return nil, err
			}
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
	if !s.sso {
		return
	}
	if _, err := s.provider(); err != nil {
		s.log.Warn("OIDC discovery failed; will retry on the next login", "issuer", s.o.Login.OIDC.Issuer, "err", err)
		return
	}
	s.log.Info("OIDC discovery ok", "issuer", s.o.Login.OIDC.Issuer)
}

func (s *Service) provider() (*authoidc.Provider, error) {
	if !s.sso {
		return nil, errNoSSO
	}
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
func (s *Service) Mount(mux routes.Mux, static http.Handler) {
	mux.HandleFunc("GET /auth/login", func(w http.ResponseWriter, r *http.Request) { s.loginPage(w, r, static) })
	mux.HandleFunc("GET /auth/config", s.publicConfig)
	mux.HandleFunc("GET /auth/oidc/start", s.oidcStart)
	mux.HandleFunc("GET /auth/oidc/callback", s.oidcCallback)
	mux.HandleFunc("POST /auth/logout", s.logout)
	if s.pk != nil {
		mux.HandleFunc("POST /auth/passkey/begin", s.pk.loginBegin)
		mux.HandleFunc("POST /auth/passkey/finish", s.pk.loginFinish)
	} else if s.o.Login.Passkeys.Enabled {
		mux.HandleFunc("POST /auth/passkey/begin", s.passkeysRefused)
		mux.HandleFunc("POST /auth/passkey/finish", s.passkeysRefused)
	}
	mux.HandleFunc("GET /api/account", humansOnly(s.account))
	mux.HandleFunc("GET /api/admin/users", humansOnly(s.adminUsers))
	if s.pk != nil {
		mux.HandleFunc("POST /api/account/passkeys/begin", humansOnly(s.pk.enrolBegin))
		mux.HandleFunc("POST /api/account/passkeys/finish", humansOnly(s.pk.enrolFinish))
		mux.HandleFunc("DELETE /api/account/passkeys/{id}", humansOnly(s.pk.removeOwn))
		mux.HandleFunc("DELETE /api/admin/passkeys/{id}", humansOnly(s.pk.removeAny))
	} else if s.o.Login.Passkeys.Enabled {
		refuse := humansOnly(s.passkeysRefused)
		mux.HandleFunc("POST /api/account/passkeys/begin", refuse)
		mux.HandleFunc("POST /api/account/passkeys/finish", refuse)
		mux.HandleFunc("DELETE /api/account/passkeys/{id}", refuse)
		mux.HandleFunc("DELETE /api/admin/passkeys/{id}", refuse)
	}
}

// passkeysRefused answers every passkey route while auth.passkeys is ignored: an
// SSO identity can neither register nor use a passkey.
func (s *Service) passkeysRefused(w http.ResponseWriter, r *http.Request) {
	writeErr(w, http.StatusForbidden, "passkey_sso", "passkeys are not available to people who sign in through single sign-on: the identity provider is the second factor")
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
	if err := sess.check(s.now(), s.idle, s.limitOf(sess)); err != nil {
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
		// the one Set-Cookie of this response; what was sent (claims trimmed to fit) is what counts
		if sent, _, _, err := s.setSession(w, sess); err == nil {
			sess = sent
		}
	}
	s.users.touch(sess.ID, sess.Name, sess.Method, sess.Groups, sess.Roles, now)
	s.observeConfig(sess)
	return identityOf(sess), nil
}

func identityOf(sess session) *auth.Identity {
	id := &auth.Identity{ID: sess.ID, Name: sess.Name, Method: sess.Method, Groups: sess.Groups, AppRoles: sess.Roles}
	if strings.Contains(sess.ID, "@") {
		id.Email = sess.ID
	}
	if sess.Method == auth.MethodOIDC {
		id.OIDCIssuer, id.OIDCClient, id.OIDCClaim, id.OIDCTenant = sess.Iss, sess.Cli, sess.Clm, sess.Tid
		if sess.OIDCAt > 0 {
			id.OIDCAt = time.Unix(sess.OIDCAt, 0)
		}
	}
	return id
}

// fit seals sess and checks that the whole Set-Cookie header fits maxSetCookieBytes. If
// it does not, claim values are dropped, last first, from the longer list (groups when
// they are equal), and it is sealed again, until it fits. cutGroups and cutRoles say a
// list lost values. With both lists empty and still too long it is errCookieTooLarge.
func (s *Service) fit(sess session) (out session, value string, maxAge int, cutGroups, cutRoles bool, err error) {
	for {
		left := time.Unix(sess.Issued, 0).Add(s.limitOf(sess)).Sub(s.now())
		maxAge = max(1, int(left.Seconds()))
		if value, err = s.codec.seal(sess); err != nil {
			return sess, "", 0, cutGroups, cutRoles, err
		}
		c := http.Cookie{Name: SessionCookie, Value: value, Path: "/", MaxAge: maxAge, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
		if len(c.String()) <= maxSetCookieBytes {
			return sess, value, maxAge, cutGroups, cutRoles, nil
		}
		switch {
		case len(sess.Groups) == 0 && len(sess.Roles) == 0:
			return sess, "", 0, cutGroups, cutRoles, errCookieTooLarge
		case len(strings.Join(sess.Roles, ",")) > len(strings.Join(sess.Groups, ",")):
			sess.Roles, cutRoles = sess.Roles[:len(sess.Roles)-1], true
		default:
			sess.Groups, cutGroups = sess.Groups[:len(sess.Groups)-1], true
		}
	}
}

// setSession sends sess as the session cookie, with fewer claim values if it has to (see
// fit). It returns what was sent; on an error nothing is sent.
func (s *Service) setSession(w http.ResponseWriter, sess session) (session, bool, bool, error) {
	sess, v, maxAge, cg, cr, err := s.fit(sess)
	if err != nil {
		s.log.Error("could not issue a session cookie", "err", err)
		return sess, cg, cr, err
	}
	setCookie(w, SessionCookie, v, maxAge)
	return sess, cg, cr, nil
}

// issue starts a session for id and returns it.
func (s *Service) issue(w http.ResponseWriter, id *auth.Identity, method, cred string) (session, overage, error) {
	if method == auth.MethodLocal {
		// A local session needs the account's session id and a verified sign-in; this path has neither, and
		// no route may create one (the sign-in of local accounts is a later piece).
		return session{}, overage{}, errors.New("a local session cannot be issued here")
	}
	now := s.now().Unix()
	sess := session{ID: id.ID, Name: id.Name, Method: method, Issued: now, Seen: now, Cred: cred}
	if method == auth.MethodOIDC {
		sess.OIDCAt = now
		sess.Iss = s.o.Login.OIDC.Issuer
		sess.Cli = s.o.Login.OIDC.ClientID
		sess.Clm, sess.Tid = id.OIDCClaim, id.OIDCTenant
		// already bounded at sign-in; bounding again keeps the cookie small whatever the caller passes
		sess.Groups, _ = boundGroups(id.Groups)
		sess.Roles, _ = boundAppRoles(id.AppRoles)
	}
	sess, cg, cr, err := s.setSession(w, sess)
	if err != nil {
		return sess, overage{}, err
	}
	s.users.touch(id.ID, id.Name, method, sess.Groups, sess.Roles, s.now())
	return sess, overage{groups: cg, appRoles: cr}, nil
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
	"bad_callback": http.StatusOK, "claims": http.StatusOK, "session_too_large": http.StatusOK, "logged_out": http.StatusOK, "passkey": http.StatusOK,
}

// signIn is the sign-in settings of the current rackbook.yml (the defaults when there is no config function).
func (s *Service) signIn() config.SignInSettings {
	if s.o.Config != nil {
		return s.o.Config().Auth.SignInSettings()
	}
	return config.SignInDefaults()
}

func (s *Service) loginPage(w http.ResponseWriter, r *http.Request, static http.Handler) {
	code := r.URL.Query().Get("error")
	// sso_redirect goes straight to the provider; ?local=1 shows the form (the way in for administrators when the
	// provider breaks), and so does any error, so that a failed redirect cannot loop.
	if code == "" && r.URL.Query().Get("local") != "1" && s.sso && s.signIn().PageMode(s.sso) == config.LoginSSORedirect {
		if _, err := s.readSession(r); err != nil {
			to := "/auth/oidc/start"
			if ret := SafeReturn(r.URL.Query().Get("return")); ret != "/" {
				to += "?return=" + url.QueryEscape(ret)
			}
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, to, http.StatusSeeOther)
			return
		}
	}
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
	mode := s.signIn().PageMode(s.sso)
	if s.o.Config != nil {
		cfg := s.o.Config()
		label, name, logo, def = cfg.Auth.OIDC.Label, cfg.Branding.Name, cfg.BrandLogo() != nil, cfg.DefaultLocale()
	}
	// The answer depends on the browser's language, so no cache may reuse it.
	w.Header().Add("Vary", "Accept-Language")
	// "provider" stays for older consoles; it no longer names the IdP.
	writeJSON(w, http.StatusOK, map[string]any{
		"oidc": s.sso, "provider": "oidc", "passkeys": s.pk != nil,
		// the sign-in page is shaped by the mode (sso_only is the endpoint's business, not the page's);
		// local says the local sign-in is offered at all (a state key and a state directory)
		"mode": mode, "local": s.o.Local != nil,
		"label": label, "name": name, "logo": logo,
		"locale": locale.Match(r.Header.Get("Accept-Language"), def), "defaultLocale": def,
	})
}

// record writes an event of this request to the audit log; addr is the client
// address by the trusted-proxy rules.
func (s *Service) record(r *http.Request, e audit.Event) {
	e.Addr = clientip.Of(r, s.trusted)
	s.o.Audit.Record(e)
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	if sess, err := s.readSession(r); err == nil {
		s.log.Info("logout", "identity", sess.ID, "method", sess.Method)
		s.record(r, audit.Event{Event: "logout", Identity: sess.ID, Name: sess.Name, Method: sess.Method, Role: s.roleOf(identityOf(sess)).String()})
	}
	clearCookie(w, SessionCookie)
	to := loginURL("", url.Values{"error": {"logged_out"}})
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeJSON(w, http.StatusOK, map[string]string{"login": to})
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// evaluate sets the role, the auditor capability and the claims flag of id from
// the current config and returns it.
func (s *Service) evaluate(id *auth.Identity) *auth.Identity {
	if s.authn == nil {
		return id
	}
	return s.authn.Evaluate(id)
}

// overageNote is the value of the login event's groups and app_roles fields.
func overageNote(cut bool) string {
	if cut {
		return "overage"
	}
	return ""
}

// maxCheckedSessions bounds the memory of which sessions were looked at under
// which config; when it is full the memory is dropped, which costs one more
// (cheap) look for each session still in use.
const maxCheckedSessions = 20_000

// sessionKey names a session without a server-side row: the person and when it
// was issued.
func sessionKey(id string, issued int64) string { return id + "|" + strconv.FormatInt(issued, 10) }

// observeRole compares the role id has now with the one stored in
// audit/identities.json and records role_changed when they differ (docs: roles
// from the provider's claims). signedIn is false for a sign-in that was refused.
// While the latest rackbook.yml does not load, roles are capped at viewer and
// say nothing about the person, so nothing is looked at.
func (s *Service) observeRole(r *http.Request, id *auth.Identity, cause string, signedIn bool) {
	if s.authn == nil || s.o.Audit == nil || s.authn.Degraded() {
		return
	}
	s.o.Audit.ObserveRole(audit.RoleObservation{
		Identity: id.ID, Name: id.Name, Method: id.Method, Role: id.EffectiveRole().String(), Auditor: id.IsAuditor(),
		Addr: clientip.Of(r, s.trusted), Cause: cause, SignedIn: signedIn, Refused: !signedIn,
	})
}

// alreadyChecked reports that sess was looked at under the config generation gen.
func (s *Service) alreadyChecked(sess session, gen any) bool {
	s.checkedMu.Lock()
	defer s.checkedMu.Unlock()
	return s.checked[sessionKey(sess.ID, sess.Issued)] == gen
}

// markChecked remembers that sess was looked at under the config generation gen.
// It reports false when it already was, so the caller can skip the look.
func (s *Service) markChecked(sess session, gen any) bool {
	key := sessionKey(sess.ID, sess.Issued)
	s.checkedMu.Lock()
	defer s.checkedMu.Unlock()
	if s.checked[key] == gen {
		return false
	}
	if s.checked == nil || len(s.checked) >= maxCheckedSessions {
		s.checked = map[string]any{}
	}
	s.checked[key] = gen
	return true
}

// observeConfig is the lazy half of role_changed: when rackbook.yml has changed
// since this session was last looked at, the role it has now is compared with the
// stored one, once. A person who never comes back is not recomputed (their claims
// are not kept). The cost on every other request is one map lookup. The session is
// marked as looked at only after the comparison, and its event if any, are done, so
// a failure in between is looked at again, never lost.
func (s *Service) observeConfig(sess session) {
	if s.authn == nil || s.authn.Degraded() {
		return
	}
	gen := s.authn.Generation()
	if s.alreadyChecked(sess, gen) {
		return
	}
	id := s.evaluate(identityOf(sess))
	if s.o.Audit != nil {
		s.o.Audit.ObserveRole(audit.RoleObservation{
			Identity: id.ID, Name: id.Name, Method: id.Method, Role: id.EffectiveRole().String(), Auditor: id.IsAuditor(),
			Cause: audit.CauseConfig, Session: time.Unix(sess.Issued, 0),
		})
	}
	s.markChecked(sess, gen)
}

// markObserved marks a session the sign-in has just compared with identities.json.
func (s *Service) markObserved(sess session) {
	if s.authn != nil && !s.authn.Degraded() {
		s.markChecked(sess, s.authn.Generation())
	}
}

// claimsLimited says claims contribute to the role or the auditor capability of the
// session, so that it lives claims_absolute and not absolute. It is decided from what
// the signed cookie carries (the identity, its groups and app roles) against the
// CURRENT config, on every request, with the sign-in's rule: an identity entry that
// grants the same role wins. Nothing in the cookie says how it was decided, so an old
// cookie that is replayed, or requests that race, get the same answer.
//
// A session that carries no groups and no app roles is never claims-limited. While the
// config does not load (roles are then capped at viewer, which would hide what claims
// give) a session that carries any is limited: it fails safe. The answer is cached per
// session, claims and config generation, for cost only: a new config is a new
// generation, a degraded config is never cached, and an entry never outlives its
// generation, so the cache cannot make a limit looser than the evaluation would.
func (s *Service) claimsLimited(sess session) bool {
	if sess.Method != auth.MethodOIDC || (len(sess.Groups) == 0 && len(sess.Roles) == 0) {
		return false
	}
	if s.authn == nil || s.authn.Degraded() {
		return true
	}
	gen := s.authn.Generation()
	h := sha256.Sum256([]byte(strings.Join(sess.Groups, "\x00") + "\x01" + strings.Join(sess.Roles, "\x00")))
	key := sessionKey(sess.ID, sess.Issued) + "|" + hex.EncodeToString(h[:8])
	s.limitMu.Lock()
	e, ok := s.limitCache[key]
	s.limitMu.Unlock()
	if ok && e.gen == gen {
		return e.limited
	}
	limited := s.evaluate(identityOf(sess)).FromClaims
	s.limitMu.Lock()
	if s.limitCache == nil || len(s.limitCache) >= maxCheckedSessions {
		s.limitCache = map[string]limitEntry{}
	}
	s.limitCache[key] = limitEntry{gen: gen, limited: limited}
	s.limitMu.Unlock()
	return limited
}

type limitEntry struct {
	gen     any
	limited bool
}

// limitOf is the absolute lifetime of sess under the current config.
func (s *Service) limitOf(sess session) time.Duration {
	return absoluteLimit(s.absolute, s.claimsAbsolute, s.claimsLimited(sess))
}

// roleOf evaluates the role of an identity from the current config.
func (s *Service) roleOf(id *auth.Identity) roles.Role {
	if s.authn == nil {
		return roles.None
	}
	return s.authn.Evaluate(id).EffectiveRole()
}

// auditorOf says whether the identity is on auth.auditors in the current config.
func (s *Service) auditorOf(id *auth.Identity) bool {
	return s.authn != nil && s.authn.Evaluate(id).IsAuditor()
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	return dec.Decode(v)
}
