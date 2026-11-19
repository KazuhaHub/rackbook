package config

import (
	"strings"
	"testing"
	"time"
)

func TestBuiltinIssuerConfig(t *testing.T) {
	base := "title: t\ncollections:\n  a: {file: a.yml, schema: a.json}\nauth:\n  mcp:\n"
	for name, c := range map[string]struct{ yaml, want string }{
		"needs resource":      {"    builtin_issuer: {enabled: true}\n", "resource is required"},
		"grace too long":      {"    resource: https://r.example.com/mcp\n    builtin_issuer: {enabled: true, refresh_reuse_grace: 1h}\n", "refresh_reuse_grace"},
		"allowed client http": {"    resource: https://r.example.com/mcp\n    builtin_issuer: {enabled: true, allowed_clients: [\"http://c.example/c.json\"]}\n", "allowed_clients"},
		"allowed client root": {"    resource: https://r.example.com/mcp\n    builtin_issuer: {enabled: true, allowed_clients: [\"https://c.example/\"]}\n", "allowed_clients"},
		"reserved alias":      {"    resource: https://r.example.com/mcp\n    builtin_issuer: {enabled: true}\n    trusted_issuers: [{issuer: \"https://i.example.com\", alias: rackbook}]\n", "reserved"},
	} {
		if _, err := Parse([]byte(base+c.yaml), "/x/rackbook.yml"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	cfg, err := Parse([]byte(base+"    resource: https://r.example.com/mcp\n    builtin_issuer: {enabled: true}\n"), "/x/rackbook.yml")
	if err != nil {
		t.Fatal(err)
	}
	b := cfg.Auth.MCP.BuiltinIssuer
	if !cfg.Auth.MCP.Enabled() || b.IdleExpiryOrDefault() != 90*24*time.Hour || b.RefreshReuseGraceOrDefault() != time.Minute || !b.Registration() || len(b.AllowedClients) != 0 {
		t.Fatalf("defaults: %+v", b)
	}
	cfg, err = Parse([]byte(base+"    resource: https://r.example.com/mcp\n    builtin_issuer: {enabled: true, idle_expiry: 30d, refresh_reuse_grace: 10s, dynamic_registration: false, allowed_clients: [\"https://c.example/c.json\"], signing_key_file: /k.pem}\n"), "/x/rackbook.yml")
	if err != nil {
		t.Fatal(err)
	}
	b = cfg.Auth.MCP.BuiltinIssuer
	if b.IdleExpiryOrDefault() != 30*24*time.Hour || b.RefreshReuseGraceOrDefault() != 10*time.Second || b.Registration() || b.SigningKeyFile != "/k.pem" {
		t.Fatalf("set: %+v", b)
	}
}
