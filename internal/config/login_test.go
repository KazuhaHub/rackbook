package config

import (
	"strings"
	"testing"
	"time"
)

const base = "collections:\n  a: {file: a.yml, schema: s.json}\n"

func parse(t *testing.T, auth string) (*Config, error) {
	t.Helper()
	return Parse([]byte(base+"auth:\n"+auth), "/r/rackbook.yml")
}

func TestLoginBlock(t *testing.T) {
	c, err := parse(t, `  mode: oidc
  oidc:
    issuer: https://login.microsoftonline.com/t/v2.0
    client_id: abc
    scopes: [openid, profile, email]
    allowed_tenants: [t]
  passkeys: true
  session: {idle: 6h, absolute: 7d}
  roles: {admin: [a@b.c]}
`)
	if err != nil {
		t.Fatal(err)
	}
	a := c.Auth
	idc, nc := a.OIDC.ClaimsOrDefault()
	if a.Mode != "oidc" || a.OIDC.ClientID != "abc" || idc != "preferred_username" || nc != "name" || !a.Passkeys.Enabled || a.Passkeys.UserVerification != "" {
		t.Fatalf("%+v", a)
	}
	if a.Session.IdleOrDefault() != 6*time.Hour || a.Session.AbsoluteOrDefault() != 7*24*time.Hour {
		t.Fatalf("%+v", a.Session)
	}
	if a.Roles == nil || a.Roles.Admin[0] != "a@b.c" {
		t.Fatal("roles lost next to the inlined login block")
	}
	// Defaults.
	c, err = parse(t, "  mode: none\n")
	if err != nil || c.Auth.Session.IdleOrDefault() != 12*time.Hour || c.Auth.Session.AbsoluteOrDefault() != 7*24*time.Hour || c.Auth.Passkeys.Enabled {
		t.Fatalf("defaults: %v %+v", err, c.Auth)
	}
	// Passkeys as a mapping.
	c, err = parse(t, "  mode: oidc\n  oidc: {issuer: 'https://i.example', client_id: x}\n  passkeys: {user_verification: required}\n")
	if err != nil || !c.Auth.Passkeys.Enabled || c.Auth.Passkeys.UserVerification != "required" {
		t.Fatalf("%v %+v", err, c.Auth.Passkeys)
	}
	// v0.1 files without a mode keep working.
	if c, err = parse(t, "  editors: [a@b.c]\n"); err != nil || c.Auth.Mode != "" || len(c.Auth.Editors) != 1 {
		t.Fatalf("v0.1: %v %+v", err, c.Auth)
	}
}

func TestLoginBlockErrors(t *testing.T) {
	oidc := "  mode: oidc\n  oidc: {issuer: 'https://i.example', client_id: x}\n"
	for name, tc := range map[string]struct{ auth, msg string }{
		"unknown mode":     {"  mode: saml\n", "auth.mode"},
		"no issuer":        {"  mode: oidc\n  oidc: {client_id: x}\n", "issuer"},
		"http issuer":      {"  mode: oidc\n  oidc: {issuer: 'http://i.example', client_id: x}\n", "https"},
		"no client id":     {"  mode: oidc\n  oidc: {issuer: 'https://i.example'}\n", "client_id"},
		"bad duration":     {oidc + "  session: {idle: soon}\n", "duration"},
		"idle > absolute":  {oidc + "  session: {idle: 8d, absolute: 7d}\n", "idle"},
		"passkeys no oidc": {"  mode: cloudflare-access\n  passkeys: true\n", "passkeys"},
		"bad uv":           {oidc + "  passkeys: {user_verification: sometimes}\n", "user_verification"},
		"bad passkeys":     {oidc + "  passkeys: maybe\n", "passkeys"},
	} {
		if _, err := parse(t, tc.auth); err == nil || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s: %v (want %q)", name, err, tc.msg)
		}
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"12h": 12 * time.Hour, "7d": 168 * time.Hour, "7d12h": 180 * time.Hour, "30m": 30 * time.Minute, "1d": 24 * time.Hour} {
		if got, err := ParseDuration(in); err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "d", "-1d", "xd", "7 days", "1.5d"} {
		if _, err := ParseDuration(in); err == nil {
			t.Errorf("%q must fail", in)
		}
	}
}

func TestStateDirIsNotLedgerData(t *testing.T) {
	for _, p := range []string{".rackbook/passkeys.yml", ".rackbook/x/y.json", "./.rackbook/a.yml", ".Rackbook/a.yml"} {
		src := "collections:\n  a: {file: '" + p + "', schema: s.json}\n"
		if _, err := Parse([]byte(src), "/r/rackbook.yml"); err == nil || !strings.Contains(err.Error(), ".rackbook") {
			t.Errorf("collection file %q must be refused: %v", p, err)
		}
		src = "collections:\n  a: {file: a.yml, schema: '" + p + "'}\n"
		if _, err := Parse([]byte(src), "/r/rackbook.yml"); err == nil {
			t.Errorf("schema %q must be refused", p)
		}
	}
	if _, err := Parse([]byte("collections:\n  a: {file: x/.rackbook/a.yml, schema: s.json}\n"), "/r/rackbook.yml"); err != nil {
		t.Errorf("only the top-level .rackbook is reserved: %v", err)
	}
}

func TestClaimsAbsolute(t *testing.T) {
	oidc := "  mode: oidc\n  oidc: {issuer: 'https://i.example', client_id: x}\n"
	// default: 24h, below the default absolute of 7 days
	c, err := parse(t, oidc)
	if err != nil || c.Auth.Session.ClaimsAbsoluteOrDefault() != 24*time.Hour {
		t.Fatalf("%v %v", err, c.Auth.Session.ClaimsAbsoluteOrDefault())
	}
	// explicit
	c, err = parse(t, oidc+"  session: {claims_absolute: 6h}\n")
	if err != nil || c.Auth.Session.ClaimsAbsoluteOrDefault() != 6*time.Hour {
		t.Fatalf("%v", err)
	}
	// the default yields to a shorter absolute instead of failing the file
	c, err = parse(t, oidc+"  session: {idle: 2h, absolute: 8h}\n")
	if err != nil || c.Auth.Session.ClaimsAbsoluteOrDefault() != 8*time.Hour {
		t.Fatalf("%v %v", err, c.Auth.Session.ClaimsAbsoluteOrDefault())
	}
	// equal to absolute is fine
	if _, err = parse(t, oidc+"  session: {absolute: 48h, claims_absolute: 48h}\n"); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ auth, msg string }{
		"above absolute":         {oidc + "  session: {claims_absolute: 8d}\n", "claims_absolute must not exceed"},
		"above a short absolute": {oidc + "  session: {idle: 1h, absolute: 12h, claims_absolute: 13h}\n", "claims_absolute must not exceed"},
		"negative":               {oidc + "  session: {claims_absolute: -1h}\n", "positive"},
		"not a duration":         {oidc + "  session: {claims_absolute: soon}\n", "duration"},
	} {
		if _, err := parse(t, tc.auth); err == nil || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s: %v (want %q)", name, err, tc.msg)
		}
	}
}

// auth.passkeys beside an OIDC provider loads and is reported as ignored; without
// one it is still refused as before. A removed key is reported, not an error.
func TestPasskeysWarningsAndRemovedKeys(t *testing.T) {
	oidc := "  mode: oidc\n  oidc: {issuer: 'https://i.example', client_id: x}\n"
	c, err := parse(t, oidc+"  passkeys: true\n")
	if err != nil || len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "auth.passkeys is ignored") {
		t.Fatalf("%v %v", err, c.Warnings)
	}
	// with identity: subject it used to be an error; it is ignored like any other
	if c, err = parse(t, oidc[:len(oidc)-len("}\n")]+", identity: subject}\n  passkeys: true\n"); err != nil || len(c.Warnings) != 1 {
		t.Fatalf("%v %v", err, c.Warnings)
	}
	if c, err = parse(t, oidc+"  passkeys: false\n"); err != nil || len(c.Warnings) != 0 {
		t.Fatalf("%v %v", err, c.Warnings)
	}
	if _, err = parse(t, "  mode: cloudflare-access\n  passkeys: true\n"); err == nil || !strings.Contains(err.Error(), "auth.passkeys needs auth.mode: oidc") {
		t.Fatalf("without OIDC passkeys are refused as before: %v", err)
	}
	c, err = parse(t, oidc+"  passkeys_oidc_max_age: 12h\n")
	if err != nil || len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "auth.passkeys_oidc_max_age is no longer used") {
		t.Fatalf("%v %v", err, c.Warnings)
	}
	// also without a mode: the key is reported wherever it is
	if c, err = parse(t, "  passkeys_oidc_max_age: 12h\n"); err != nil || len(c.Warnings) != 1 {
		t.Fatalf("%v %v", err, c.Warnings)
	}
}
