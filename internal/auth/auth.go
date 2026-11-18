// Package auth identifies the caller. In "none" mode every request is
// accepted (writes are attributed to a configured editor); in
// "cloudflare-access" mode every request must carry a valid Cloudflare Access
// JWT.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Modes.
const (
	ModeNone             = "none"
	ModeCloudflareAccess = "cloudflare-access"
)

// Config selects and configures the authentication mode.
type Config struct {
	Mode     string
	Team     string // cloudflare-access: team name (<team>.cloudflareaccess.com)
	Audience string // cloudflare-access: Application Audience (AUD) tag
	Editor   string // none: attribute writes to "Name <email>"
	Editors  []string

	// JWKSURL and Issuer override the values derived from Team. They exist
	// for tests and self-hosted setups.
	JWKSURL string
	Issuer  string
}

// User is an identified caller.
type User struct {
	Email   string `json:"email"`
	Name    string `json:"name"`
	CanEdit bool   `json:"canEdit"`
}

// Authenticator verifies requests.
type Authenticator struct {
	cfg      Config
	verifier *oidc.IDTokenVerifier
	editors  map[string]bool
	fixed    *User // none mode with an editor
}

type ctxKey struct{}

// New validates cfg and prepares verification. ctx bounds the lifetime of the
// background JWKS refresh.
func New(ctx context.Context, cfg Config) (*Authenticator, error) {
	if cfg.Mode == "" {
		cfg.Mode = ModeNone
	}
	a := &Authenticator{cfg: cfg, editors: map[string]bool{}}
	for _, e := range cfg.Editors {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			a.editors[e] = true
		}
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
			a.fixed = &User{Email: addr.Address, Name: name}
			a.fixed.CanEdit = a.canEdit(addr.Address)
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

func (a *Authenticator) canEdit(identity string) bool {
	return len(a.editors) == 0 || a.editors[strings.ToLower(identity)]
}

// CanEdit reports whether u may write. A nil user (auth none, no editor
// configured) may write unless an editors allow-list exists.
func (a *Authenticator) CanEdit(u *User) bool {
	if u == nil {
		return len(a.editors) == 0
	}
	return u.CanEdit
}

// ErrUnauthenticated is returned when no valid credential is present.
var ErrUnauthenticated = errors.New("authentication required")

// Authenticate identifies the caller of r. In none mode it returns the
// configured editor, possibly nil.
func (a *Authenticator) Authenticate(r *http.Request) (*User, error) {
	if a.cfg.Mode == ModeNone {
		return a.fixed, nil
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
	return &User{Email: identity, Name: name, CanEdit: a.canEdit(identity)}, nil
}

// Middleware rejects unauthenticated requests with 401 and stores the user in the context.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := a.Authenticate(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized", "message": err.Error()})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	})
}

// UserFrom returns the authenticated user stored by Middleware, or nil.
func UserFrom(ctx context.Context) *User {
	u, _ := ctx.Value(ctxKey{}).(*User)
	return u
}

// WithUser stores u in ctx (used when no Middleware is installed).
func WithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, ctxKey{}, u)
}
