package config

import (
	"strings"
	"testing"
	"time"
)

func TestSignInDefaultsAndValues(t *testing.T) {
	c, err := parse(t, "  mode: none\n")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := c.Auth.SignInSettings(), SignInDefaults(); got != want {
		t.Fatalf("defaults: %+v want %+v", got, want)
	}
	d := SignInDefaults()
	if d.Mode != LoginDual || d.SSOOnly || d.ThrottleMax != 10 || d.ThrottleWindow != 15*time.Minute || d.LockEnabled || d.LockDuration != 30*time.Minute ||
		d.LockScope != LockScopeIPAccount || d.NISTCap != 100 || d.TOTPPerDay != 10 || d.PasskeyPathPerHour != 10 || d.PasswordMinLength != 12 ||
		d.InviteTTL != 72*time.Hour || d.ResetTTL != 24*time.Hour || d.ReauthWindow != 10*time.Minute {
		t.Fatalf("the design's defaults changed: %+v", d)
	}
	c, err = parse(t, `  login: {mode: sso_first, sso_only: true}
  local: {password_min_length: 16, invite_ttl: 48h, reset_ttl: 2h, reauth_window: 5m}
  throttle: {max: 5, window: 30m}
  lock: {enabled: true, duration: 2h, scope: account}
  nist_cap: 20
  twofa_limits: {totp_per_day: 5, passkey_path_per_hour: 4}
`)
	if err != nil {
		t.Fatal(err)
	}
	s := c.Auth.SignInSettings()
	if s.Mode != LoginSSOFirst || !s.SSOOnly || s.PasswordMinLength != 16 || s.InviteTTL != 48*time.Hour || s.ResetTTL != 2*time.Hour || s.ReauthWindow != 5*time.Minute ||
		s.ThrottleMax != 5 || s.ThrottleWindow != 30*time.Minute || !s.LockEnabled || s.LockDuration != 2*time.Hour || s.LockScope != LockScopeAccount ||
		s.NISTCap != 20 || s.TOTPPerDay != 5 || s.PasskeyPathPerHour != 4 {
		t.Fatalf("%+v", s)
	}
}

func TestSignInBoundsAreEnforced(t *testing.T) {
	for name, tc := range map[string]struct{ auth, msg string }{
		"mode":                 {"  login: {mode: both}\n", "auth.login.mode"},
		"passwordless":         {"  local: {passwordless: synced}\n", "not built yet"},
		"min length":           {"  local: {password_min_length: 8}\n", "auth.local.password_min_length"},
		"min length max":       {"  local: {password_min_length: 65}\n", "auth.local.password_min_length"},
		"invite ttl":           {"  local: {invite_ttl: 15d}\n", "auth.local.invite_ttl"},
		"reset ttl":            {"  local: {reset_ttl: 30m}\n", "auth.local.reset_ttl"},
		"reauth window":        {"  local: {reauth_window: 2h}\n", "auth.local.reauth_window"},
		"throttle max":         {"  throttle: {max: 1001}\n", "auth.throttle.max"},
		"throttle window":      {"  throttle: {window: 30s}\n", "auth.throttle.window"},
		"lock duration":        {"  lock: {duration: 8d}\n", "auth.lock.duration"},
		"lock scope":           {"  lock: {scope: everyone}\n", "auth.lock.scope"},
		"nist cap above 100":   {"  nist_cap: 101\n", "auth.nist_cap"},
		"nist cap below 10":    {"  nist_cap: 5\n", "auth.nist_cap"},
		"totp limit":           {"  twofa_limits: {totp_per_day: 2}\n", "auth.twofa_limits.totp_per_day"},
		"passkey path limit":   {"  twofa_limits: {passkey_path_per_hour: 21}\n", "auth.twofa_limits.passkey_path_per_hour"},
		"lock over a week": {"  lock: {duration: 169h}\n", "auth.lock.duration"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parse(t, tc.auth)
			if err == nil || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("err = %v, want %q", err, tc.msg)
			}
		})
	}
	// the bounds themselves are allowed
	if _, err := parse(t, "  nist_cap: 10\n  lock: {duration: 168h}\n  throttle: {max: 1000, window: 24h}\n  local: {invite_ttl: 14d}\n"); err != nil {
		t.Fatal(err)
	}
}

func TestCaptchaSettingIsReportedAsIgnored(t *testing.T) {
	c, err := parse(t, "  captcha: {enabled: true}\n")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range c.Warnings {
		found = found || strings.Contains(w, "auth.captcha")
	}
	if !found {
		t.Fatalf("warnings: %v", c.Warnings)
	}
}
