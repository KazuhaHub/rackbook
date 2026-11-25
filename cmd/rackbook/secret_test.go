package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/secretscan"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

// Assembled at run time: this file holds no string a scanner would flag.
var cliSecret = "gh" + "p_" + strings.Repeat("a1B2", 9)

func TestCLIAddAndSetRefuseSecretsAndCheckReportsThem(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	for _, ex := range []string{"homelab", "homelab-login"} {
		out, err := run(t, "check", "--config", filepath.Join(testutil.RepoRoot(t), "examples", ex, "rackbook.yml"))
		if err != nil || !strings.HasPrefix(out, "ok: ") {
			t.Fatalf("%s: %v\n%s", ex, err, out)
		}
	}
}

func TestCheckScansStateFileLabelsButNotKeysOrHashes(t *testing.T) {
	t.Parallel()
	dir := testutil.CopyExample(t)
	cfg := filepath.Join(dir, "rackbook.yml")
	os.MkdirAll(filepath.Join(dir, ".rackbook"), 0o755)
	tokens := "tokens:\n  - name: ci\n    prefix: rbk_abcd\n    sha256: " + strings.Repeat("e", 64) + "\n"
	os.WriteFile(filepath.Join(dir, ".rackbook/tokens.yml"), []byte(tokens), 0o644)
	if out, err := run(t, "check", "--config", cfg); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	os.WriteFile(filepath.Join(dir, ".rackbook/tokens.yml"), []byte(strings.Replace(tokens, "name: ci", "name: \""+cliSecret+"\"", 1)), 0o644)
	out, err := run(t, "check", "--config", cfg)
	var ee exitError
	if !errors.As(err, &ee) || !strings.Contains(out, ".rackbook/tokens.yml") || !strings.Contains(out, "github-token") || strings.Contains(out, cliSecret[:8]) {
		t.Fatalf("%v\n%s", err, out)
	}
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestConfirmTierIsAWarningInCheckAndConfirmationIsRecorded(t *testing.T) {
	t.Parallel()
	dir := testutil.CopyExample(t)
	cfg := filepath.Join(dir, "rackbook.yml")
	gitIn(t, dir, "init", "-q", "-b", "main")
	gitIn(t, dir, "config", "user.name", "Ann")
	gitIn(t, dir, "config", "user.email", "ann@example.com")
	testutil.Replace(t, dir, "docs/ledger/todo.yml", "scope: gw, status: 待决定", "scope: \"gw 密码：Hunter2Hunter2\", status: 待决定")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "seed")

	// a heuristic hit already in the data is a warning: exit 0
	out, err := run(t, "check", "--config", cfg)
	if err != nil || !strings.Contains(out, "warning: ") || !strings.Contains(out, "secret-assignment") || strings.Contains(out, "Hunter") {
		t.Fatalf("%v\n%s", err, out)
	}
	out, err = run(t, "check", "--config", cfg, "--format", "json")
	if err != nil || !strings.Contains(out, `"ok": true`) || !strings.Contains(out, `"warnings"`) || !strings.Contains(out, `"severity": "warning"`) {
		t.Fatalf("%v\n%s", err, out)
	}

	// a write is held until it is confirmed
	add := []string{"add", "todo", "item=x", "status=待办", "scope=root密码：Hunter2Hunter2", "--config", cfg, "--commit"}
	_, err = run(t, add...)
	if err == nil || !strings.Contains(err.Error(), "--confirm-not-secret") {
		t.Fatalf("%v", err)
	}
	if _, err = run(t, append(add, "--confirm-not-secret")...); err != nil {
		t.Fatal(err)
	}
	if msg := gitIn(t, dir, "log", "-1", "--format=%B"); !strings.Contains(msg, "Secret-scan: confirmed-not-secret by ann@example.com (secret-assignment)") {
		t.Fatal(msg)
	}
	// block tier cannot be confirmed
	if _, err = run(t, "add", "todo", "item=y", "status=待办", "scope="+cliSecret, "--config", cfg, "--confirm-not-secret"); err == nil || strings.Contains(err.Error(), "repeat the command") {
		t.Fatalf("%v", err)
	}

	// the confirmed record no longer warns; the hand-committed one still does
	out, _ = run(t, "check", "--config", cfg)
	if strings.Count(out, "warning: ") != 1 || strings.Contains(out, "todo/x ") {
		t.Fatalf("%s", out)
	}
	// once a later, unconfirmed commit changes the record, it warns again
	if _, err = run(t, "set", "todo", "x", "status=完成", "--config", cfg, "--commit"); err != nil {
		t.Fatal(err)
	}
	out, _ = run(t, "check", "--config", cfg)
	if strings.Count(out, "warning: ") != 2 {
		t.Fatalf("%s", out)
	}
}
