package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/secretscan"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

// Assembled at run time: this file holds no string a scanner would flag.
var cliSecret = "gh" + "p_" + strings.Repeat("a1B2", 9)

func TestCLIAddAndSetRefuseSecretsAndCheckReportsThem(t *testing.T) {
	dir := testutil.CopyExample(t)
	cfg := filepath.Join(dir, "rackbook.yml")
	read := func() string { b, _ := os.ReadFile(filepath.Join(dir, "docs/ledger/services.yml")); return string(b) }
	orig := read()

	for _, args := range [][]string{
		{"add", "services", "device=web-hostco-ashburn-va-us-dc", "service=nginx", "port=TCP 80", "notes=login with " + cliSecret},
		{"set", "services", "web-hostco-ashburn-va-us-dc/SSH", "notes=password: hunter2hunter2"},
	} {
		out, err := run(t, append(args, "--config", cfg)...)
		var se *secretscan.Error
		if !errors.As(err, &se) {
			t.Fatalf("%v: want a secret error, got %v\n%s", args, err, out)
		}
		msg := err.Error()
		if !strings.Contains(msg, "services/") || !strings.Contains(msg, "/notes") || !strings.Contains(msg, "secret_scan.allow") || strings.Contains(msg, cliSecret[:8]) || strings.Contains(msg, "hunter") {
			t.Fatalf("%s", msg)
		}
		if read() != orig {
			t.Fatal("a refused command wrote")
		}
	}

	// A secret that is already in the repo makes `check` fail, redacted.
	testutil.Replace(t, dir, "docs/ledger/todo.yml", "scope: gw, status: 待决定", "scope: \"gw "+cliSecret+"\", status: 待决定")
	out, err := run(t, "check", "--config", cfg)
	var ee exitError
	if !errors.As(err, &ee) || ee.code != 1 || !strings.Contains(out, "[secret]") || !strings.Contains(out, "github-token") || strings.Contains(out, cliSecret[:8]) {
		t.Fatalf("%v\n%s", err, out)
	}
	out, err = run(t, "check", "--config", cfg, "--format", "json")
	if !errors.As(err, &ee) || !strings.Contains(out, `"rule": "secret"`) || strings.Contains(out, cliSecret[:8]) {
		t.Fatalf("%v\n%s", err, out)
	}
	// ... unless that value is allowed precisely.
	f, _ := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("\nsecret_scan:\n  allow:\n    - {rule: github-token, collection: todo, field: /scope, value_sha256: " + secretscan.Hash(cliSecret) + "}\n")
	f.Close()
	if out, err := run(t, "check", "--config", cfg); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestInvalidSecretScanConfigIsAConfigError(t *testing.T) {
	dir := testutil.CopyExample(t)
	cfg := filepath.Join(dir, "rackbook.yml")
	f, _ := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("\nsecret_scan:\n  extra_patterns:\n    - {id: bad, pattern: '('}\n")
	f.Close()
	out, err := run(t, "check", "--config", cfg)
	var ee exitError
	if !errors.As(err, &ee) || !strings.Contains(out, "secret_scan.extra_patterns[0]") {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestExamplesPassTheSecretScanClean(t *testing.T) {
	for _, ex := range []string{"homelab", "homelab-login"} {
		out, err := run(t, "check", "--config", filepath.Join(testutil.RepoRoot(t), "examples", ex, "rackbook.yml"))
		if err != nil || !strings.HasPrefix(out, "ok: ") {
			t.Fatalf("%s: %v\n%s", ex, err, out)
		}
	}
}
