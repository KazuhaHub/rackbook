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
