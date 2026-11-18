package config

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Login modes (auth.mode).
const (
	AuthModeNone             = "none"
	AuthModeCloudflareAccess = "cloudflare-access"
	AuthModeOIDC             = "oidc"
)

// Defaults of auth.session.
const (
	DefaultSessionIdle     = 12 * time.Hour
	DefaultSessionAbsolute = 7 * 24 * time.Hour
)

// Login is the part of the auth block that selects and configures how people
// log in (see docs/design-v0.2.md, section 2). It is inlined into Auth.
type Login struct {
	// Mode is none, cloudflare-access or oidc. Empty = not set in the file:
	// --auth decides, else none.
	Mode     string   `yaml:"mode"`
	OIDC     OIDC     `yaml:"oidc"`
	Passkeys Passkeys `yaml:"passkeys"`
	Session  Session  `yaml:"session"`
}

// OIDC is auth.oidc. The client secret is never read from the file: it comes
// from RACKBOOK_OIDC_CLIENT_SECRET.
type OIDC struct {
	Issuer        string   `yaml:"issuer"`
	ClientID      string   `yaml:"client_id"`
	Scopes        []string `yaml:"scopes"`
	IdentityClaim string   `yaml:"identity_claim"` // default preferred_username
	// Identity is how a login is named: "claim" (default) uses identity_claim,
	// which must be controlled by the IdP, not editable by users; "subject"
	// uses the stable iss|sub pair, written oidc:<sub> in auth.roles.
	Identity       string   `yaml:"identity"`
	NameClaim      string   `yaml:"name_claim"` // default name
	AllowedTenants []string `yaml:"allowed_tenants"`
}

// Passkeys is auth.passkeys: a bool, or {user_verification: preferred|required}.
type Passkeys struct {
	Enabled          bool
	UserVerification string // preferred (default) or required
}

// UnmarshalYAML accepts `passkeys: true` and `passkeys: {user_verification: required}`.
func (p *Passkeys) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		var b bool
		if err := n.Decode(&b); err != nil {
			return fmt.Errorf("auth.passkeys: want true, false or a mapping")
		}
		*p = Passkeys{Enabled: b}
		return nil
	}
	var raw struct {
		Enabled          *bool  `yaml:"enabled"`
		UserVerification string `yaml:"user_verification"`
	}
	if err := n.Decode(&raw); err != nil {
		return err
	}
	*p = Passkeys{Enabled: raw.Enabled == nil || *raw.Enabled, UserVerification: raw.UserVerification}
	return nil
}

// Duration is a time.Duration that also accepts a "d" (24 h) unit: 12h, 7d, 7d12h.
type Duration time.Duration

// ParseDuration parses "12h", "30m", "7d" or "7d12h".
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	var total time.Duration
	if i := strings.Index(s, "d"); i > 0 {
		days, err := strconv.Atoi(s[:i])
		if err != nil || days < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		total = time.Duration(days) * 24 * time.Hour
		s = s[i+1:]
		if s == "" {
			return total, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return total + d, nil
}

// UnmarshalYAML parses the string form.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseDuration(n.Value)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// Session is auth.session.
type Session struct {
	Idle     Duration `yaml:"idle"`
	Absolute Duration `yaml:"absolute"`
}

// IdleOrDefault is the idle timeout (default 12h).
func (s Session) IdleOrDefault() time.Duration {
	if s.Idle > 0 {
		return time.Duration(s.Idle)
	}
	return DefaultSessionIdle
}

// AbsoluteOrDefault is the absolute lifetime (default 7d).
func (s Session) AbsoluteOrDefault() time.Duration {
	if s.Absolute > 0 {
		return time.Duration(s.Absolute)
	}
	return DefaultSessionAbsolute
}

// IdentityMode values of auth.oidc.identity.
const (
	IdentityClaim   = "claim"
	IdentitySubject = "subject"
)

// BySubject reports identity: subject.
func (o OIDC) BySubject() bool { return o.Identity == IdentitySubject }

// IdentityClaimWarning returns why the configured identity claim may be
// user-controlled (so anyone who can edit it could take over another identity),
// or "" when it is fine: identity: subject, email (which must be verified),
// or Entra's upn / preferred_username with allowed_tenants set.
func (o OIDC) IdentityClaimWarning() string {
	if o.BySubject() {
		return ""
	}
	claim, _ := o.ClaimsOrDefault()
	switch {
	case claim == "email":
		return ""
	case (claim == "upn" || claim == "preferred_username") && len(o.AllowedTenants) > 0:
		return ""
	}
	return fmt.Sprintf("auth.oidc.identity_claim %q must be controlled by the identity provider, not editable by users or tenants you do not trust; set auth.oidc.allowed_tenants (Entra), use email (verified), or set auth.oidc.identity: subject", claim)
}

// ClaimsOrDefault returns the identity and name claims.
func (o OIDC) ClaimsOrDefault() (identity, name string) {
	identity, name = o.IdentityClaim, o.NameClaim
	if identity == "" {
		identity = "preferred_username"
	}
	if name == "" {
		name = "name"
	}
	return
}

// check validates the login settings of the file. It only enforces what the
// file alone decides; the effective mode can still be overridden by --auth.
func (l *Login) check() error {
	switch l.Mode {
	case "", AuthModeNone, AuthModeCloudflareAccess, AuthModeOIDC:
	default:
		return fmt.Errorf("auth.mode must be none, cloudflare-access or oidc, got %q", l.Mode)
	}
	if l.Session.Idle < 0 || l.Session.Absolute < 0 {
		return fmt.Errorf("auth.session: durations must be positive")
	}
	if l.Session.IdleOrDefault() > l.Session.AbsoluteOrDefault() {
		return fmt.Errorf("auth.session.idle must not exceed auth.session.absolute")
	}
	switch l.Passkeys.UserVerification {
	case "", "preferred", "required":
	default:
		return fmt.Errorf("auth.passkeys.user_verification must be preferred or required, got %q", l.Passkeys.UserVerification)
	}
	if l.Passkeys.Enabled && l.Mode != "" && l.Mode != AuthModeOIDC {
		return fmt.Errorf("auth.passkeys needs auth.mode: oidc")
	}
	if l.Mode == AuthModeOIDC {
		if err := l.OIDC.Check(); err != nil {
			return err
		}
		if l.OIDC.BySubject() && l.Passkeys.Enabled {
			return fmt.Errorf("auth.passkeys cannot be combined with auth.oidc.identity: subject (passkeys are stored by e-mail identity)")
		}
	}
	return nil
}

// Check validates auth.oidc.
func (o OIDC) Check() error {
	u, err := url.Parse(o.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("auth.oidc.issuer must be an https URL, got %q", o.Issuer)
	}
	if o.ClientID == "" {
		return fmt.Errorf("auth.oidc.client_id is required")
	}
	switch o.Identity {
	case "", IdentityClaim, IdentitySubject:
	default:
		return fmt.Errorf("auth.oidc.identity must be claim or subject, got %q", o.Identity)
	}
	return nil
}
