// Package oauthserver is Rackbook's built-in OAuth 2.1 authorization server for
// MCP clients (docs/oauth-server.md, docs/design-v0.2.md decisions 7-12).
//
// It serves what the MCP authorization specification asks of a server: RFC 8414
// metadata, an authorization endpoint with a consent page, PKCE (S256 only),
// RFC 8707 resource binding, client identification by Client ID Metadata
// Document or RFC 7591 registration, the RFC 9207 iss parameter, a token
// endpoint with rotating refresh tokens, and a JWKS. Clients are public (no
// secret); the only grants are authorization_code and refresh_token.
//
// Access tokens are short ES256 JWTs that only this process checks (the
// resource side calls VerifyAccess in-process). Grants and the SHA-256 hashes of
// refresh tokens live in <state-dir>/oauth-grants.json; authorization codes,
// consent requests and fetched client documents live in memory only.
package oauthserver

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
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

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/prefs"
	"github.com/kazuhahub/rackbook/internal/routes"
	"github.com/kazuhahub/rackbook/internal/tokens"
)

// Endpoint paths.
const (
	PathMetadata  = "/.well-known/oauth-authorization-server"
	PathAuthorize = "/oauth/authorize"
	PathToken     = "/oauth/token"
	PathRegister  = "/oauth/register"
	PathJWKS      = "/oauth/jwks"
	// PathConsent is the console page that asks the user to approve.
	PathConsent = "/oauth/consent"
)

const (
	accessTTL  = 10 * time.Minute
	codeTTL    = 60 * time.Second
	pendingTTL = 10 * time.Minute
	maxPending = 1000
)

// Options configures the server.
type Options struct {
	// Issuer is the public origin of Rackbook (--base-url), e.g.
	// https://ledger.example.com. It is the "iss" of every token.
	Issuer string
	// Resource is the URL of /mcp (auth.mcp.resource): tokens are bound to it.
	Resource string
	// StateDir holds oauth-grants.json and, unless configured otherwise, the
	// generated signing key.
	StateDir string
	// Config returns the current rackbook.yml (builtin_issuer settings and
	// scopes are read from it on every use).
	Config func() *config.Config
	// Auth evaluates the role of a grant's subject.
	Auth *auth.Authenticator
	Log  *slog.Logger
	// Now is the clock; nil = time.Now.
	Now func() time.Time
	// Getenv reads RACKBOOK_OAUTH_SIGNING_KEY and CREDENTIALS_DIRECTORY; nil = os.Getenv.
	Getenv func(string) string
	// CIMDClient fetches client metadata documents; nil = a client that refuses
	// private addresses. Tests replace it.
	CIMDClient *http.Client
	// TrustedProxies are the --trusted-proxy prefixes: CF-Connecting-IP is
	// believed only from them (the registration limit is per client address).
	TrustedProxies []netip.Prefix
	// Prefs holds each person's console language, for the pages this server
	// shows; nil = the browser's language only.
	Prefs *prefs.Store
	// Blocked, when set, says a grant (its id, the identity that approved it and when) is revoked for a local account
	// (design-local-accounts.md, 5.11): it is on the account store's revocation list, or the account's credentials_valid_after is
	// later than the approval. The grant is refused at once, whether or not its state file entry could be removed.
	Blocked func(id, subject string, approved time.Time) bool
}

// Server is the authorization server.
type Server struct {
	o     Options
	log   *slog.Logger
	store *store
	key   *signingKey
	cimd  *cimdFetcher
	now   func() time.Time

	mu       sync.Mutex
	pending  map[string]*pendingAuth // consent requests by id
	codes    map[string]*authCode    // by SHA-256 of the code
	used     map[string]usedCode     // codes already exchanged, to revoke on replay
	regLimit *tokens.Limiter         // new registrations per client address

	refreshMu sync.Mutex // serialises refresh requests
	replayMu  sync.Mutex
	replay    map[string]replayEntry // answers to recent refreshes, by hash of the replaced token; memory only
}

// New opens the state, loads or generates the signing key and returns the server.
func New(o Options) (*Server, error) {
	if o.Issuer == "" || o.Resource == "" || o.StateDir == "" {
		return nil, errors.New("the built-in authorization server needs --base-url, --state-dir and auth.mcp.resource")
	}
	o.Issuer = strings.TrimRight(o.Issuer, "/")
	if err := config.ValidURL(o.Issuer, false); err != nil {
		return nil, fmt.Errorf("--base-url: %w", err)
	}
	if u, _ := url.Parse(o.Issuer); u.Path != "" {
		return nil, fmt.Errorf("--base-url %q must be an origin without a path for the built-in authorization server", o.Issuer)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	s := &Server{o: o, log: o.Log, now: o.Now, replay: map[string]replayEntry{}, pending: map[string]*pendingAuth{}, codes: map[string]*authCode{}, used: map[string]usedCode{}}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	keyFile := ""
	if o.Config != nil {
		keyFile = o.Config().Auth.MCP.BuiltinIssuer.SigningKeyFile
	}
	key, source, err := loadKey(keyFile, o.StateDir, o.Getenv)
	if err != nil {
		return nil, fmt.Errorf("oauth signing key: %w", err)
	}
	s.key = key
	if s.store, err = openStore(o.StateDir); err != nil {
		return nil, err
	}
	s.store.blocked = o.Blocked
	s.pruneExpired()
	s.cimd = newCIMDFetcher(o.CIMDClient, s.now, s.log)
	s.regLimit = &tokens.Limiter{Max: registerPerWindow, Window: registerWindow, Now: s.now}
	if c := s.cfg(); c.Registration() && len(c.AllowedClients) > 0 {
		s.log.Info("dynamic client registration is off because auth.mcp.builtin_issuer.allowed_clients is set")
	}
	s.log.Info("built-in authorization server ready", "issuer", o.Issuer, "signing_key", source, "grants", len(s.store.data.Grants))
	return s, nil
}

// Issuer is the issuer identifier ("iss") of the server's tokens.
func (s *Server) Issuer() string { return s.o.Issuer }

func (s *Server) cfg() config.BuiltinIssuer { return s.o.Config().Auth.MCP.BuiltinIssuer }

// dcrOn says registration is served: on by default, off with
// dynamic_registration: false, and off whenever allowed_clients names the only
// clients that may authorize.
func (s *Server) dcrOn() bool {
	c := s.cfg()
	return c.Registration() && len(c.AllowedClients) == 0
}

// scopesSupported are the scopes of auth.mcp.scopes that are not empty.
func (s *Server) scopesSupported() []string {
	sc := s.o.Config().Auth.MCP.Scopes
	var out []string
	for _, v := range []string{sc.ReadScope(), sc.WriteScope()} {
		if v != "" && !contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Public are the endpoints that need no sign-in: the metadata, the token
// endpoint, registration and the JWKS. Only these answer cross-origin requests
// (browser-based MCP clients such as MCP Inspector call them).
func (s *Server) Public() map[string]http.Handler {
	m := map[string]http.Handler{
		PathMetadata: cors(http.HandlerFunc(s.metadata)),
		PathToken:    cors(http.HandlerFunc(s.token)),
		PathRegister: cors(http.HandlerFunc(s.register)),
		PathJWKS:     cors(http.HandlerFunc(s.serveJWKS)),
	}
	return m
}

// Mount registers the endpoints that need a signed-in person.
func (s *Server) Mount(mux routes.Mux) {
	mux.HandleFunc("GET "+PathAuthorize, s.authorize)
	mux.HandleFunc("GET /api/oauth/consent", s.consentInfo)
	mux.HandleFunc("POST /api/oauth/consent", s.consentDecision)
	mux.HandleFunc("GET /api/account/grants", s.accountGrants)
	mux.HandleFunc("DELETE /api/account/grants/{id}", s.revokeOwn)
	mux.HandleFunc("GET /api/admin/grants", s.adminGrants)
	mux.HandleFunc("DELETE /api/admin/grants/{id}", s.revokeAny)
}

// cors opens a public endpoint to every origin. These endpoints take no cookies
// and no ambient credentials, so this adds no attack surface.
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Content-Type")
		h.Set("Access-Control-Max-Age", "600")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// oauthError is the RFC 6749 section 5.2 error body.
func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// apiError is the console API's error body.
func apiError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

func (s *Server) fail(w http.ResponseWriter, what string, err error) {
	s.log.Error("oauth server error", "during", what, "err", err)
	oauthError(w, http.StatusInternalServerError, "server_error", "the server could not complete the request")
}

func (s *Server) metadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "use GET")
		return
	}
	doc := map[string]any{
		"issuer":                                         s.o.Issuer,
		"authorization_endpoint":                         s.o.Issuer + PathAuthorize,
		"token_endpoint":                                 s.o.Issuer + PathToken,
		"jwks_uri":                                       s.o.Issuer + PathJWKS,
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"client_id_metadata_document_supported":          true,
		"authorization_response_iss_parameter_supported": true,
		"scopes_supported":                               s.scopesSupported(),
	}
	if s.dcrOn() {
		doc["registration_endpoint"] = s.o.Issuer + PathRegister
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(doc)
}

func (s *Server) serveJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "use GET")
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(s.key.jwks())
}

// randomToken is n random bytes in base64url.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func equalStrings(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// pruneExpired drops grants that went idle past idle_expiry while the server was
// not looking, and registrations nobody uses, so the file does not collect them.
func (s *Server) pruneExpired() {
	now, idle := s.now(), s.cfg().IdleExpiryOrDefault()
	stale := false
	for _, g := range s.store.data.Grants {
		stale = stale || now.Sub(g.LastUsed) > idle
	}
	if !stale {
		return
	}
	err := s.store.mutate(func(d *fileData) error {
		for id, g := range d.Grants {
			if now.Sub(g.LastUsed) > idle {
				delete(d.Grants, id)
			}
		}
		pruneClients(d, now)
		return nil
	})
	if err != nil {
		s.log.Warn("could not prune expired oauth grants", "err", err)
	}
}
