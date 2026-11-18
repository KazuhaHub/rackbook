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
)

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
	default:
		return nil, fmt.Errorf("unknown auth mode %q (want none or cloudflare-access)", cfg.Mode)
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
	editors := append([]string{}, a.cfg.Editors...)
	if cur != nil {
		spec = cur.Auth.Roles
		editors = append(editors, cur.Auth.Editors...)
	}
	var opt roles.Options
	if cur != nil {
		opt.MCPMatchEmail = cur.Auth.MCP.MatchEmail
	}
	p, err := roles.Compile(spec, opt, editors...)
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
	id := roles.FoldASCII(identity)
	r := a.Policy().Evaluate(roles.Subject{ID: id, Email: emailOf(id), Method: MethodNone})
	if a.cfg.Degraded != nil && a.cfg.Degraded() {
		r = roles.Lower(r, roles.Viewer)
	}
	return r
}

func emailOf(id string) string {
	if strings.Contains(id, "@") {
		return id
	}
	return ""
}

// EvaluateSubject is Evaluate with the role looked up for s instead of for the
// identity itself (a token takes its creator's role).
func (a *Authenticator) EvaluateSubject(id *Identity, s roles.Subject) *Identity {
	id.Role = a.Policy().Evaluate(s)
	if a.cfg.Degraded != nil && a.cfg.Degraded() {
		id.Role = roles.Lower(id.Role, roles.Viewer)
	}
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
	if b := a.bearerAuth(); b != nil {
		id, err := b.AuthenticateBearer(r)
		if err != nil {
			return nil, err
		}
		if id != nil {
			return id, nil
		}
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
		id, err := a.Authenticate(r)
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
			}
			writeJSONError(w, http.StatusForbidden, "no_role", "you are not allowed to use this ledger")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
	})
}
