package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/testutil"
)

func oidcConfig(t *testing.T) string {
	t.Helper()
	dir := testutil.CopyExample(t)
	p := filepath.Join(dir, "rackbook.yml")
	b, _ := os.ReadFile(p)
	b = append(b, "\nauth:\n  mode: oidc\n  oidc: {issuer: 'https://login.example/v2.0', client_id: abc}\n  roles: {admin: [a@b.c]}\n"...)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// A misconfigured oidc server stops at startup with a message that says what
// is missing, before it listens.
func TestServeOIDCStartupChecks(t *testing.T) {
	cfg := oidcConfig(t)
	key := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	args := []string{"serve", "--config", cfg, "--no-git", "--listen", "127.0.0.1:0"}
	for name, tc := range map[string]struct {
		env  map[string]string
		args []string
		want string
	}{
		"no session key": {nil, nil, "RACKBOOK_SESSION_KEY"},
		"short key":      {map[string]string{"RACKBOOK_SESSION_KEY": "c2hvcnQ="}, nil, "at least 32"},
		"no secret":      {map[string]string{"RACKBOOK_SESSION_KEY": key}, nil, "RACKBOOK_OIDC_CLIENT_SECRET"},
		"no base url":    {map[string]string{"RACKBOOK_SESSION_KEY": key, "RACKBOOK_OIDC_CLIENT_SECRET": "s"}, nil, "--base-url"},
		"http base url":  {map[string]string{"RACKBOOK_SESSION_KEY": key, "RACKBOOK_OIDC_CLIENT_SECRET": "s"}, []string{"--base-url", "http://ledger.example.com"}, "https"},
		"key file":       {map[string]string{"RACKBOOK_SESSION_KEY": key}, []string{"--session-key-file", "/nonexistent"}, "only one"},
	} {
		for _, k := range []string{"RACKBOOK_SESSION_KEY", "RACKBOOK_OIDC_CLIENT_SECRET", "RACKBOOK_AUTH"} {
			t.Setenv(k, "")
		}
		for k, v := range tc.env {
			t.Setenv(k, v)
		}
		_, err := run(t, append(append([]string{}, args...), tc.args...)...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v (want %q)", name, err, tc.want)
		}
	}
}

func TestServeTLSFlagsGoTogether(t *testing.T) {
	cfg := filepath.Join(testutil.CopyExample(t), "rackbook.yml")
	_, err := run(t, "serve", "--config", cfg, "--no-git", "--listen", "127.0.0.1:0", "--tls-cert", "x.pem")
	if err == nil || !strings.Contains(err.Error(), "--tls-key") {
		t.Fatalf("%v", err)
	}
}
