// Package auth identifies the caller and decides what the caller may do. In
// "none" mode every request is accepted (writes are attributed to a configured
// editor); in "cloudflare-access" mode every request must carry a valid
// Cloudflare Access JWT. Either way the result is an Identity in the request
// context, whose Role comes from auth.roles (package roles) evaluated against
// the current config on every request.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"path"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/roles"
)

// Modes.
const (
	ModeNone             = "none"
	ModeCloudflareAccess = "cloudflare-access"
	ModeOIDC             = "oidc"
)

// SessionAuth supplies identities from login sessions (oidc mode); the
// internal/login package implements it.
type SessionAuth interface {
	// Identify returns the identity of the session cookie of r, without a
	// role. It may set a refreshed cookie on w (w may be nil). A failure wraps
	// ErrUnauthenticated.
	Identify(w http.ResponseWriter, r *http.Request) (*Identity, error)
	// Public reports requests that need no session (login pages, console
	// assets, the login endpoints).
	Public(r *http.Request) bool
	// Reject answers a request without a valid session: 401 login_required
	// for API clients, a redirect to the login page for the console.
	Reject(w http.ResponseWriter, r *http.Request, err error)
	// NoRole answers a request whose identity has no role.
	NoRole(w http.ResponseWriter, r *http.Request, id *Identity)
}

// CanonicalPath returns the decoded request path and whether it is canonical:
// it contains no encoded dots, slashes or backslashes, and path.Clean leaves it
// unchanged (no "..", "." or empty segments). Decisions that exempt a path from
// authentication must use it and treat a non-canonical path as not exempt.
func CanonicalPath(r *http.Request) (string, bool) {
	raw := strings.ToLower(r.URL.EscapedPath())
	if strings.Contains(raw, "%2e") || strings.Contains(raw, "%2f") || strings.Contains(raw, "%5c") {
		return r.URL.Path, false
	}
	p := r.URL.Path
	if strings.Contains(p, `\`) {
		return p, false
	}
	c := path.Clean(p)
	if c != p && c+"/" != p {
		return p, false
	}
	return p, true
}

// Config selects and configures the authentication mode.
type Config struct {
	Mode     string
	Team     string   // cloudflare-access: team name (<team>.cloudflareaccess.com)
	Audience string   // cloudflare-access: Application Audience (AUD) tag
	Editor   string   // none: attribute writes to "Name <email>"
	Editors  []string // extra editor entries (--editors); auth.editors from the config is added

	// Config returns the current config. It is called on every request, so a
	// reload shows up at once. Nil = no auth.roles (v0.1 behaviour), with
	// Editors as the only allow-list.
	Config func() *config.Config

	// Degraded reports that the latest config failed to load. Roles then come
	// from the last good config, but nobody may do more than read: writes and
	// admin actions fail closed until the config loads again.
	Degraded func() bool

	// Sessions is required in oidc mode.
	Sessions SessionAuth

	// JWKSURL and Issuer override the values derived from Team. They exist
	// for tests and self-hosted setups.
	JWKSURL string
	Issuer  string
}

// Authenticator verifies requests and evaluates roles.
type Authenticator struct {
	cfg      Config
	verifier *oidc.IDTokenVerifier
	fixed    *Identity // none mode with an editor
	cached   atomic.Pointer[cachedPolicy]
	bearer   atomic.Pointer[bearerHolder]
}

type bearerHolder struct{ b BearerAuthenticator }

// BearerAuthenticator authenticates "Authorization: Bearer" credentials that
// the built-in modes do not know: Rackbook API tokens and MCPHub access tokens.
// It is consulted before the mode's own authentication, in every mode.
type BearerAuthenticator interface {
	// AuthenticateBearer returns (nil, nil) when the request carries no
	// credential it handles on this path (the mode's own authentication then
	// applies), an identity whose Role it has set with Evaluate or EvaluateSubject, or a
	// *RequestError when a credential was presented and is wrong.
	AuthenticateBearer(r *http.Request) (*Identity, error)
	// Challenge is the WWW-Authenticate value to send with a 401 on this
	// request, or "".
	Challenge(r *http.Request) string
}

// SetBearer installs the bearer authenticator.
func (a *Authenticator) SetBearer(b BearerAuthenticator) { a.bearer.Store(&bearerHolder{b}) }

func (a *Authenticator) bearerAuth() BearerAuthenticator {
	if h := a.bearer.Load(); h != nil {
		return h.b
	}
	return nil
}

// RequestError is an authentication failure with its own HTTP answer.
type RequestError struct {
	Status     int    // 401 when zero
	Code       string // JSON error code; "unauthorized" when empty
	Msg        string
	Challenge  string // WWW-Authenticate value
	RetryAfter int    // seconds, for 429
}

func (e *RequestError) Error() string { return e.Msg }

type cachedPolicy struct {
	cfg    *config.Config
	policy *roles.Policy
}

// New validates cfg and prepares verification. ctx bounds the lifetime of the
// background JWKS refresh.
func New(ctx context.Context, cfg Config) (*Authenticator, error) {
	if cfg.Mode == "" {
		cfg.Mode = ModeNone
	}
	a := &Authenticator{cfg: cfg}
	if _, err := roles.Compile(nil, roles.Options{}, cfg.Editors...); err != nil {
		return nil, err
	}
	switch cfg.Mode {
	case ModeNone:
		if cfg.Editor != "" {
			addr, err := mail.ParseAddress(cfg.Editor)
			if err != nil {
				return nil, fmt.Errorf("--editor %q: want \"Name <email>\": %w", cfg.Editor, err)
			}
			name := addr.Name
			if name == "" {
				name = strings.SplitN(addr.Address, "@", 2)[0]
			}
			a.fixed = &Identity{ID: roles.FoldASCII(addr.Address), Email: addr.Address, Name: name, Method: MethodNone}
		}
	case ModeCloudflareAccess:
		issuer, jwks := cfg.Issuer, cfg.JWKSURL
		if issuer == "" || jwks == "" {
			if cfg.Team == "" {
				return nil, errors.New("--auth cloudflare-access needs --cf-team")
			}
			issuer = "https://" + cfg.Team + ".cloudflareaccess.com"
			jwks = issuer + "/cdn-cgi/access/certs"
		}
		if cfg.Audience == "" {
			return nil, errors.New("--auth cloudflare-access needs --cf-aud")
		}
		keys := oidc.NewRemoteKeySet(ctx, jwks)
		a.verifier = oidc.NewVerifier(issuer, keys, &oidc.Config{ClientID: cfg.Audience, SupportedSigningAlgs: []string{"RS256"}})
	case ModeOIDC:
		if cfg.Sessions == nil {
			return nil, errors.New("--auth oidc needs a session provider")
		}
	default:
		return nil, fmt.Errorf("unknown auth mode %q (want none, cloudflare-access or oidc)", cfg.Mode)
	}
	return a, nil
}

// Policy returns the role policy for the current config. It is recompiled
// only when the config object changes (after a reload).
func (a *Authenticator) Policy() *roles.Policy {
	var cur *config.Config
	if a.cfg.Config != nil {
		cur = a.cfg.Config()
	}
	if c := a.cached.Load(); c != nil && c.cfg == cur {
		return c.policy
	}
	var spec *roles.Spec
	var auditors []string
	editors := append([]string{}, a.cfg.Editors...)
	if cur != nil {
		spec = cur.Auth.Roles
		auditors = cur.Auth.Auditors
		editors = append(editors, cur.Auth.Editors...)
	}
	var opt roles.Options
	if cur != nil {
		opt.MCPMatchEmail = cur.Auth.MCP.MatchEmail
	}
	p, err := roles.CompileAuditors(spec, auditors, opt, editors...)
	if err != nil { // config.Load validates, so this is a defensive fallback: deny
		p, _ = roles.Compile(&roles.Spec{}, roles.Options{})
	}
	a.cached.Store(&cachedPolicy{cfg: cur, policy: p})
	return p
}

// Evaluate sets id.Role from the current auth.roles. An anonymous identity
// (auth none without --editor: there is nobody to authenticate) never ends up
// below viewer, so a local server stays readable.
func (a *Authenticator) Evaluate(id *Identity) *Identity {
	return a.EvaluateSubject(id, id.Subject())
}

// RoleFor is the role auth.roles grants to a plain identity string (an e-mail
// or UPN), as it is now. It is how an API token's creator is evaluated.
func (a *Authenticator) RoleFor(identity string) roles.Role {
	return a.RoleForVia(identity, MethodNone)
}

// RoleForVia is RoleFor for an identity that logged in with method (so a
// subject identity oidc:<sub> finds its role entry). It includes the viewer
// floor of an auditor, as the identity's own evaluation does.
func (a *Authenticator) RoleForVia(identity, method string) roles.Role {
	r, _ := a.CapabilitiesForVia(identity, method)
	return r
}

// CapabilitiesForVia is the role and the auditor capability that an identity
// string has now, evaluated like RoleForVia. It is how a token's creator is
// evaluated, so a token carries the capability only while its creator is on
// auth.auditors.
func (a *Authenticator) CapabilitiesForVia(identity, method string) (roles.Role, bool) {
	id := roles.FoldASCII(identity)
	// No groups and no app roles: a creator is evaluated by identity alone.
	return a.evaluate(roles.Subject{ID: id, Email: emailOf(id), Method: method})
}

func emailOf(id string) string {
	if strings.Contains(id, "@") {
		return id
	}
	return ""
}

// evaluate is the one place that computes the role and the auditor capability
// of a subject. An auditor never ends up below viewer (the viewer floor); one
// who has a role keeps it. A degraded config (the latest one failed to load)
// limits the role to viewer, so nothing here can write.
func (a *Authenticator) evaluate(s roles.Subject) (roles.Role, bool) {
	p := a.Policy()
	r, auditor := p.Evaluate(s), p.IsAuditor(s)
	if auditor && r < roles.Viewer {
		r = roles.Viewer
	}
	if a.cfg.Degraded != nil && a.cfg.Degraded() {
		r = roles.Lower(r, roles.Viewer)
	}
	return r, auditor
}

// fromClaims says the role or the auditor capability of s, as evaluated, depends
// on its groups or app roles: evaluated by identity alone, the role would be lower
// or the capability would be absent. A role an identity entry also grants is not
// from claims, even when a group entry matches too.
func (a *Authenticator) fromClaims(s roles.Subject, role roles.Role, auditor bool) bool {
	if len(s.Groups) == 0 && len(s.AppRoles) == 0 {
		return false
	}
	r, aud := a.evaluate(s.WithoutClaims())
	return role > r || (auditor && !aud)
}

// Sources says which kinds of role entry (roles.SourceIdentity, SourceGroup,
// SourceAppRole) grant id its role and its auditor capability now. The account
// page shows it as "Role from".
func (a *Authenticator) Sources(id *Identity) (role, auditor []string) {
	return a.Policy().Sources(id.Subject())
}

// Generation identifies the role policy now in force. It changes when a config
// reload brings a new auth block (even an equal one), so a caller that has
// already looked at a person for one generation need not do it again.
func (a *Authenticator) Generation() any { return a.Policy() }

// Degraded reports that the latest rackbook.yml failed to load: roles then come
// from the last good config, capped at viewer.
func (a *Authenticator) Degraded() bool { return a.cfg.Degraded != nil && a.cfg.Degraded() }

// EvaluateSubject is Evaluate with the role and the auditor capability looked
// up for s instead of for the identity itself (a token takes its creator's).
func (a *Authenticator) EvaluateSubject(id *Identity, s roles.Subject) *Identity {
	id.Role, id.Auditor = a.evaluate(s)
	id.FromClaims = a.fromClaims(s, id.Role, id.Auditor)
	if id.Anonymous() && id.Method == MethodNone && id.Role == roles.None {
		id.Role = roles.Viewer
	}
	return id
}

// ErrUnauthenticated is returned when no valid credential is present.
var ErrUnauthenticated = errors.New("authentication required")

// Authenticate identifies the caller of r and evaluates its role. In none
// mode it returns the configured editor, or an anonymous identity.
func (a *Authenticator) Authenticate(r *http.Request) (*Identity, error) {
	return a.authenticate(nil, r)
}

func (a *Authenticator) authenticate(w http.ResponseWriter, r *http.Request) (*Identity, error) {
	if b := a.bearerAuth(); b != nil {
		id, err := b.AuthenticateBearer(r)
		if err != nil {
			return nil, err
		}
		if id != nil {
			return id, nil
		}
	}
	if a.cfg.Mode == ModeOIDC {
		id, err := a.cfg.Sessions.Identify(w, r)
		if err != nil {
			return nil, err
		}
		return a.Evaluate(id), nil
	}
	if a.cfg.Mode == ModeNone {
		id := &Identity{Method: MethodNone}
		if a.fixed != nil {
			c := *a.fixed
			id = &c
		}
		return a.Evaluate(id), nil
	}
	raw := r.Header.Get("Cf-Access-Jwt-Assertion")
	if raw == "" {
		if c, err := r.Cookie("CF_Authorization"); err == nil {
			raw = c.Value
		}
	}
	if raw == "" {
		return nil, fmt.Errorf("%w: missing Cloudflare Access token", ErrUnauthenticated)
	}
	tok, err := a.verifier.Verify(r.Context(), raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	var claims struct {
		Email      string `json:"email"`
		CommonName string `json:"common_name"`
		Name       string `json:"name"`
	}
	if err := tok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	identity := claims.Email
	if identity == "" {
		identity = claims.CommonName // Access service token
	}
	if identity == "" {
		return nil, fmt.Errorf("%w: token has neither email nor common_name", ErrUnauthenticated)
	}
	name := claims.Name
	if name == "" {
		name = strings.SplitN(identity, "@", 2)[0]
	}
	id := &Identity{ID: roles.FoldASCII(identity), Name: name, Email: claims.Email, Method: MethodCloudflareAccess}
	return a.Evaluate(id), nil
}

func writeJSONError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": msg})
}

// Middleware rejects unauthenticated requests with 401, identities without a
// role with 403 "no_role", and stores the Identity in the context otherwise.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.Sessions != nil && a.cfg.Sessions.Public(r) {
			next.ServeHTTP(w, r)
			return
		}
		id, err := a.authenticate(w, r)
		if err != nil {
			var re *RequestError
			status, code := http.StatusUnauthorized, "unauthorized"
			challenge := ""
			if b := a.bearerAuth(); b != nil {
				challenge = b.Challenge(r)
			}
			if errors.As(err, &re) {
				if re.Status != 0 {
					status = re.Status
				}
				if re.Code != "" {
					code = re.Code
				}
				if re.Challenge != "" {
					challenge = re.Challenge
				}
				if re.RetryAfter > 0 {
					w.Header().Set("Retry-After", strconv.Itoa(re.RetryAfter))
				}
			} else if a.cfg.Sessions != nil && challenge == "" {
				// A missing or bad session: the login flow answers (a redirect for
				// the console, 401 login_required for API clients). Paths that
				// carry an OAuth challenge (/mcp) are answered with it instead,
				// never with a redirect.
				a.cfg.Sessions.Reject(w, r, err)
				return
			}
			if challenge != "" && status == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", challenge)
			}
			writeJSONError(w, status, code, err.Error())
			return
		}
		if id.EffectiveRole() == roles.None {
			if id.Method == MethodMCPHub || id.Method == MethodOAuth || id.Method == MethodToken {
				// A valid credential that grants nothing here: RFC 6750 insufficient_scope.
				w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
			} else if a.cfg.Sessions != nil {
				a.cfg.Sessions.NoRole(w, r, id)
				return
			}
			writeJSONError(w, http.StatusForbidden, "no_role", "you are not allowed to use this ledger")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
	})
}
