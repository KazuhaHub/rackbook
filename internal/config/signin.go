package config

import (
	"fmt"
	"time"
)

// The sign-in settings of local accounts and SSO together (docs/design-local-accounts.md, 2 and 9.2). They are
// read from rackbook.yml on every request, so a change by a push takes effect without a restart. The bounds are
// enforced here; a hand edit outside them is refused like any invalid config.

// Login presentation modes (auth.login.mode).
const (
	LoginDual        = "dual"
	LoginSSOFirst    = "sso_first"
	LoginSSORedirect = "sso_redirect"
	LoginLocalOnly   = "local_only"
)

// Lock scopes (auth.lock.scope).
const (
	LockScopeIP        = "ip"
	LockScopeIPAccount = "ip_account"
	LockScopeAccount   = "account"
)

// Hard bounds that stay in code (design 3, 9.2).
const (
	MaxNISTCap = 100
	MinNISTCap = 10
)

// SignIn is auth.login: what the sign-in page shows and what the local endpoint accepts. (The block
// auth.mode, auth.oidc, auth.passkeys and auth.session are the older settings of Login.)
type SignIn struct {
	Mode    string `yaml:"mode"`
	SSOOnly bool   `yaml:"sso_only"`
}

// LocalSettings is auth.local.
type LocalSettings struct {
	// Passwordless is off, synced or device_bound. Only off is built (piece 4).
	Passwordless      string   `yaml:"passwordless"`
	PasswordMinLength int      `yaml:"password_min_length"`
	InviteTTL         Duration `yaml:"invite_ttl"`
	ResetTTL          Duration `yaml:"reset_ttl"`
	ReauthWindow      Duration `yaml:"reauth_window"`
}

// Throttle is auth.throttle: at most Max failed sign-ins per bucket in Window (always on).
type Throttle struct {
	Max    int      `yaml:"max"`
	Window Duration `yaml:"window"`
}

// Lock is auth.lock: when enabled, reaching the throttle's max locks the scope's key for Duration.
type Lock struct {
	Enabled  bool     `yaml:"enabled"`
	Duration Duration `yaml:"duration"`
	Scope    string   `yaml:"scope"`
}

// TwoFALimits is auth.twofa_limits.
type TwoFALimits struct {
	TOTPPerDay         int `yaml:"totp_per_day"`
	PasskeyPathPerHour int `yaml:"passkey_path_per_hour"`
}

// CaptchaSettings is auth.captcha. The CAPTCHA is piece 5: the key is read and reported, never acted on.
type CaptchaSettings struct {
	Enabled bool `yaml:"enabled"`
}

// SignInSettings are the effective values, with defaults filled in and every bound applied.
type SignInSettings struct {
	Mode    string
	SSOOnly bool

	PasswordMinLength int
	InviteTTL         time.Duration
	ResetTTL          time.Duration
	ReauthWindow      time.Duration

	ThrottleMax    int
	ThrottleWindow time.Duration

	LockEnabled  bool
	LockDuration time.Duration
	LockScope    string

	NISTCap            int
	TOTPPerDay         int
	PasskeyPathPerHour int
}

// SignInDefaults are the values of an auth block that sets none of them.
func SignInDefaults() SignInSettings {
	return SignInSettings{
		Mode: LoginDual, PasswordMinLength: 12,
		InviteTTL: 72 * time.Hour, ResetTTL: 24 * time.Hour, ReauthWindow: 10 * time.Minute,
		ThrottleMax: 10, ThrottleWindow: 15 * time.Minute,
		LockDuration: 30 * time.Minute, LockScope: LockScopeIPAccount,
		NISTCap: MaxNISTCap, TOTPPerDay: 10, PasskeyPathPerHour: 10,
	}
}

// SignInSettings returns the effective sign-in settings of the auth block. The block was validated at load, so
// every value is within its bounds.
func (a Auth) SignInSettings() SignInSettings {
	s := SignInDefaults()
	if a.SignIn.Mode != "" {
		s.Mode = a.SignIn.Mode
	}
	s.SSOOnly = a.SignIn.SSOOnly
	if a.Local.PasswordMinLength != 0 {
		s.PasswordMinLength = a.Local.PasswordMinLength
	}
	if a.Local.InviteTTL != 0 {
		s.InviteTTL = time.Duration(a.Local.InviteTTL)
	}
	if a.Local.ResetTTL != 0 {
		s.ResetTTL = time.Duration(a.Local.ResetTTL)
	}
	if a.Local.ReauthWindow != 0 {
		s.ReauthWindow = time.Duration(a.Local.ReauthWindow)
	}
	if a.Throttle.Max != 0 {
		s.ThrottleMax = a.Throttle.Max
	}
	if a.Throttle.Window != 0 {
		s.ThrottleWindow = time.Duration(a.Throttle.Window)
	}
	s.LockEnabled = a.Lock.Enabled
	if a.Lock.Duration != 0 {
		s.LockDuration = time.Duration(a.Lock.Duration)
	}
	if a.Lock.Scope != "" {
		s.LockScope = a.Lock.Scope
	}
	if a.NISTCap != 0 {
		s.NISTCap = a.NISTCap
	}
	if a.TwoFALimits.TOTPPerDay != 0 {
		s.TOTPPerDay = a.TwoFALimits.TOTPPerDay
	}
	if a.TwoFALimits.PasskeyPathPerHour != 0 {
		s.PasskeyPathPerHour = a.TwoFALimits.PasskeyPathPerHour
	}
	return s
}

func inRange(name string, v, lo, hi int) error {
	if v != 0 && (v < lo || v > hi) {
		return fmt.Errorf("%s must be between %d and %d, got %d", name, lo, hi, v)
	}
	return nil
}

func durRange(name string, d Duration, lo, hi time.Duration) error {
	if d != 0 && (time.Duration(d) < lo || time.Duration(d) > hi) {
		return fmt.Errorf("%s must be between %s and %s, got %s", name, lo, hi, time.Duration(d))
	}
	return nil
}

// checkSignIn validates auth.login, auth.local, auth.throttle, auth.lock, auth.nist_cap and
// auth.twofa_limits against the bounds of the design (9.2).
func (a *Auth) checkSignIn() error {
	switch a.SignIn.Mode {
	case "", LoginDual, LoginSSOFirst, LoginSSORedirect, LoginLocalOnly:
	default:
		return fmt.Errorf("auth.login.mode must be dual, sso_first, sso_redirect or local_only, got %q", a.SignIn.Mode)
	}
	switch a.Local.Passwordless {
	case "", "off":
	case "synced", "device_bound":
		return fmt.Errorf("auth.local.passwordless %q is not built yet: only off is available", a.Local.Passwordless)
	default:
		return fmt.Errorf("auth.local.passwordless must be off, synced or device_bound, got %q", a.Local.Passwordless)
	}
	for _, c := range []error{
		inRange("auth.local.password_min_length", a.Local.PasswordMinLength, 12, 64),
		durRange("auth.local.invite_ttl", a.Local.InviteTTL, time.Hour, 14*24*time.Hour),
		durRange("auth.local.reset_ttl", a.Local.ResetTTL, time.Hour, 7*24*time.Hour),
		durRange("auth.local.reauth_window", a.Local.ReauthWindow, time.Minute, time.Hour),
		inRange("auth.throttle.max", a.Throttle.Max, 1, 1000),
		durRange("auth.throttle.window", a.Throttle.Window, time.Minute, 24*time.Hour),
		durRange("auth.lock.duration", a.Lock.Duration, time.Minute, 7*24*time.Hour),
		inRange("auth.nist_cap", a.NISTCap, MinNISTCap, MaxNISTCap),
		inRange("auth.twofa_limits.totp_per_day", a.TwoFALimits.TOTPPerDay, 3, 20),
		inRange("auth.twofa_limits.passkey_path_per_hour", a.TwoFALimits.PasskeyPathPerHour, 3, 20),
	} {
		if c != nil {
			return c
		}
	}
	switch a.Lock.Scope {
	case "", LockScopeIP, LockScopeIPAccount, LockScopeAccount:
	default:
		return fmt.Errorf("auth.lock.scope must be ip, ip_account or account, got %q", a.Lock.Scope)
	}
	return nil
}

// CaptchaIgnoredWarning is the warning for auth.captcha.enabled, which nothing acts on yet.
func (a Auth) CaptchaIgnoredWarning() string {
	if !a.Captcha.Enabled {
		return ""
	}
	return "auth.captcha is not built yet and is ignored: the throttle and the NIST cap apply, and a throttled network is refused until the window ends"
}
