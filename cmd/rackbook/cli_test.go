package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/testutil"
)

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	root := newRoot()
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(args)
	err := root.Execute()
	return out.String() + errb.String(), err
}

func TestCheckExitCodes(t *testing.T) {
	dir := testutil.CopyExample(t)
	cfg := filepath.Join(dir, "rackbook.yml")
	out, err := run(t, "check", "--config", cfg)
	if err != nil || !strings.HasPrefix(out, "ok: 9 collections") {
		t.Fatalf("%v %s", err, out)
	}
	testutil.Replace(t, dir, "docs/ledger/addresses.yml", "{device: laptop-me-pc, network", "{device: ghost, network")
	out, err = run(t, "check", "--config", cfg)
	var ee exitError
	if !errors.As(err, &ee) || ee.code != 1 || !strings.Contains(out, `addresses/ghost/Tailscale: /device: unknown devices.name "ghost" [ref]`) {
		t.Fatalf("%v %s", err, out)
	}
	out, err = run(t, "check", "--config", cfg, "--format", "json")
	if !errors.As(err, &ee) || !strings.Contains(out, `"ok": false`) || !strings.Contains(out, `"rule": "ref"`) {
		t.Fatalf("%v %s", err, out)
	}
	if _, err = run(t, "check", "--config", filepath.Join(dir, "missing.yml")); err == nil {
		t.Fatal("missing config must fail")
	}
}

func TestListGetSchemaExport(t *testing.T) {
	cfg := filepath.Join(testutil.CopyExample(t), "rackbook.yml")
	out, err := run(t, "list", "services", "--config", cfg, "--where", "device=web-hostco-ashburn-va-us-dc")
	if err != nil || strings.Count(out, "\n") != 4 || !strings.HasPrefix(out, "device") {
		t.Fatalf("%v\n%s", err, out)
	}
	out, _ = run(t, "list", "devices", "--config", cfg, "--where", "managed=true", "--format", "json")
	if strings.Count(out, `"id"`) != 2 {
		t.Fatal(out)
	}
	out, _ = run(t, "list", "ports", "--config", cfg, "--format", "yaml")
	if !strings.HasPrefix(out, "- service: 管理面板\n  port: TCP 10510\n") {
		t.Fatal(out)
	}
	out, err = run(t, "get", "devices", "laptop-me-pc", "--config", cfg)
	if err != nil || out != "name: laptop-me-pc\ncategory: 我的终端\nsite: 随身\nos: macOS 26\nmanaged: false\n" {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err = run(t, "get", "devices", "nope", "--config", cfg); err == nil {
		t.Fatal("expected not found")
	}
	if _, err = run(t, "list", "nope", "--config", cfg); err == nil || !strings.Contains(err.Error(), "available:") {
		t.Fatalf("%v", err)
	}
	out, err = run(t, "schema", "device", "--config", cfg)
	if err == nil {
		t.Fatalf("unknown collection: %s", out)
	}
	out, err = run(t, "schema", "devices", "--config", cfg)
	if err != nil || !strings.Contains(out, `"设备名"`) {
		t.Fatalf("%v\n%s", err, out)
	}
	out, err = run(t, "export", "--format", "llms", "--config", cfg)
	if err != nil || !strings.HasPrefix(out, "# 示例网络台账") {
		t.Fatalf("%v\n%s", err, out)
	}
	target := filepath.Join(t.TempDir(), "out.md")
	if _, err = run(t, "export", "--format", "markdown", "-o", target, "--config", cfg); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); !strings.Contains(string(b), "| 设备名 |") {
		t.Fatal(string(b))
	}
}

func TestAddSetRm(t *testing.T) {
	dir := testutil.CopyExample(t)
	cfg := filepath.Join(dir, "rackbook.yml")
	read := func() string { b, _ := os.ReadFile(filepath.Join(dir, "docs/ledger/services.yml")); return string(b) }
	orig := read()

	if _, err := run(t, "add", "services", "device=web-hostco-ashburn-va-us-dc", "service=nginx", "port=TCP 80", "managed=true", "--config", cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(), "{device: web-hostco-ashburn-va-us-dc, service: nginx, port: TCP 80, managed: true}\n- {device: web-hostco-ashburn-va-us-dc, service: STUN") && !strings.Contains(read(), "service: nginx, port: TCP 80, managed: true}") {
		t.Fatal(read())
	}
	if _, err := run(t, "set", "services", "web-hostco-ashburn-va-us-dc/nginx", "port=TCP 8080", "managed=", "--config", cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(), "service: nginx, port: TCP 8080}") {
		t.Fatal(read())
	}
	out, err := run(t, "set", "services", "web-hostco-ashburn-va-us-dc/nginx", "port=TCP 8080", "--config", cfg)
	if err != nil || !strings.HasPrefix(out, "unchanged") {
		t.Fatalf("%v %s", err, out)
	}
	if _, err := run(t, "rm", "services", "web-hostco-ashburn-va-us-dc/nginx", "--config", cfg); err != nil {
		t.Fatal(err)
	}
	if read() != orig {
		t.Fatal("add + rm must restore the file byte for byte")
	}
	// Invalid input leaves the file alone.
	for _, args := range [][]string{
		{"add", "services", "device=ghost", "service=x", "port=TCP 1"},
		{"set", "devices", "laptop-me-pc", "managed=maybe"},
		{"add", "services", "nonsense"},
		{"rm", "devices", "laptop-me-pc"}, // still referenced by addresses
	} {
		if _, err := run(t, append(args, "--config", cfg)...); err == nil {
			t.Errorf("%v must fail", args)
		}
	}
	if read() != orig {
		t.Fatal("failed commands must not write")
	}
}

func TestEnvFlags(t *testing.T) {
	cfg := filepath.Join(testutil.CopyExample(t), "rackbook.yml")
	t.Setenv("RACKBOOK_CONFIG", cfg)
	out, err := run(t, "check")
	if err != nil || !strings.HasPrefix(out, "ok:") {
		t.Fatalf("%v %s", err, out)
	}
	t.Setenv("RACKBOOK_FORMAT", "json")
	out, _ = run(t, "check")
	if !strings.Contains(out, `"ok": true`) {
		t.Fatal(out)
	}
	cmd := newServe()
	t.Setenv("RACKBOOK_CF_TEAM", "acme")
	t.Setenv("RACKBOOK_EDITORS", "a@x.com,b@x.com")
	t.Setenv("RACKBOOK_PULL_INTERVAL", "5s")
	if err := applyEnv(cmd.Flags()); err != nil {
		t.Fatal(err)
	}
	if v, _ := cmd.Flags().GetString("cf-team"); v != "acme" {
		t.Fatal(v)
	}
	if v, _ := cmd.Flags().GetStringSlice("editors"); len(v) != 2 {
		t.Fatal(v)
	}
	if v, _ := cmd.Flags().GetDuration("pull-interval"); v.Seconds() != 5 {
		t.Fatal(v)
	}
	t.Setenv("RACKBOOK_PULL_INTERVAL", "soon")
	if err := applyEnv(newServe().Flags()); err == nil {
		t.Fatal("bad env value must fail")
	}
}

func TestCoerce(t *testing.T) {
	dir := testutil.CopyExample(t)
	testutil.Replace(t, dir, "schemas/port.json", `"scope": {"type": "string"`, `"count": {"type": "integer"}, "ratio": {"type": "number"}, "tags": {"type": "array"}, "scope": {"type": "string"`)
	out, err := run(t, "add", "ports", "service=x", "port=TCP 1", "count=3", "ratio=1.5", "tags=a, b", "--config", filepath.Join(dir, "rackbook.yml"))
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "docs/ledger/ports.yml"))
	if !strings.Contains(string(b), "{service: x, port: TCP 1, count: 3, ratio: 1.5, tags: [a, b]}") {
		t.Fatal(string(b))
	}
}

func TestServeRefusesNonLoopbackWithoutAuth(t *testing.T) {
	cfg := filepath.Join(testutil.CopyExample(t), "rackbook.yml")
	for _, listen := range []string{"0.0.0.0:0", ":0"} {
		_, err := run(t, "serve", "--listen", listen, "--config", cfg, "--no-git")
		if err == nil || !strings.Contains(err.Error(), "--insecure-no-auth") {
			t.Fatalf("%s: %v", listen, err)
		}
	}
	if isLoopback("0.0.0.0:80") || !isLoopback("127.0.0.1:80") || !isLoopback("[::1]:80") {
		t.Fatal("isLoopback")
	}
}

func TestCommitRefusedWhenRemoteHistoryWasRewritten(t *testing.T) {
	root := t.TempDir()
	g := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@e.com", "GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@e.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	bare, mine, other := filepath.Join(root, "o.git"), filepath.Join(root, "mine"), filepath.Join(root, "other")
	g(root, "init", "--bare", "-b", "main", bare)
	seed := testutil.CopyExample(t)
	g(seed, "init", "-b", "main")
	g(seed, "add", ".")
	g(seed, "commit", "-m", "seed")
	g(seed, "remote", "add", "origin", bare)
	g(seed, "push", "origin", "main")
	g(root, "clone", bare, mine)
	g(root, "clone", bare, other)
	g(mine, "config", "user.name", "Me")
	g(mine, "config", "user.email", "me@example.com")
	cfg := filepath.Join(mine, "rackbook.yml")

	// Normal case: commits carry the Record trailer.
	if out, err := run(t, "set", "todo", "统一代理入站端口", "status=完成", "--config", cfg, "--commit"); err != nil || !strings.Contains(out, "committed") {
		t.Fatalf("%v %s", err, out)
	}
	if msg, _ := exec.Command("git", "-C", mine, "log", "-1", "--format=%B").Output(); !strings.Contains(string(msg), "Edited-via: rackbook (cli)\nRecord: todo/统一代理入站端口") {
		t.Fatalf("%s", msg)
	}
	// Somebody rewrites the remote's history.
	g(other, "commit", "--amend", "-qm", "rewritten seed", "--allow-empty")
	g(other, "push", "--quiet", "--force", "origin", "main")
	todo := filepath.Join(mine, "docs/ledger/todo.yml")
	before, _ := os.ReadFile(todo)
	out, err := run(t, "set", "todo", "统一代理入站端口", "status=推迟", "--config", cfg, "--commit")
	if err == nil || !strings.Contains(err.Error(), "history was rewritten") || !strings.Contains(err.Error(), "rackbook accept-remote") {
		t.Fatalf("%v %s", err, out)
	}
	if after, _ := os.ReadFile(todo); string(after) != string(before) {
		t.Fatal("no file may be edited when the commit would be refused")
	}
	// rackbook accept-remote records the new base; it never resets the user's clone.
	tip, _ := exec.Command("git", "-C", other, "rev-parse", "HEAD").Output()
	remote := strings.TrimSpace(string(tip))
	headBefore, _ := exec.Command("git", "-C", mine, "rev-parse", "HEAD").Output()
	if out, err := run(t, "accept-remote", "0123456", "--config", cfg); err == nil || !strings.Contains(err.Error(), "not the current tip") {
		t.Fatalf("%v %s", err, out)
	}
	if out, err := run(t, "accept-remote", remote, "--config", cfg); err != nil || !strings.Contains(out, "accepted "+remote) {
		t.Fatalf("%v %s", err, out)
	}
	if headAfter, _ := exec.Command("git", "-C", mine, "rev-parse", "HEAD").Output(); string(headAfter) != string(headBefore) {
		t.Fatal("accept-remote must not move the user's branch")
	}
	if out, err := run(t, "accept-remote", remote, "--config", cfg); err == nil || !strings.Contains(err.Error(), "no_alert") {
		t.Fatalf("%v %s", err, out)
	}
	// serve --accept-remote refuses anything but the current remote tip (and exits instead of serving).
	if out, err := run(t, "serve", "--repo", mine, "--listen", "127.0.0.1:0", "--accept-remote", "0123456789abcdef"); err == nil || !strings.Contains(err.Error(), "--accept-remote") {
		t.Fatalf("%v %s", err, out)
	}
}

func TestServeAcceptRemoteCannotBeReadOnly(t *testing.T) {
	cfg := filepath.Join(testutil.CopyExample(t), "rackbook.yml")
	if out, err := run(t, "serve", "--config", cfg, "--listen", "127.0.0.1:0", "--read-only", "--accept-remote", "0123456"); err == nil || !strings.Contains(err.Error(), "--read-only") {
		t.Fatalf("%v %s", err, out)
	}
}

func TestServeRefusesStateDirInsideRepo(t *testing.T) {
	dir := testutil.CopyExample(t)
	_, err := run(t, "serve", "--listen", "127.0.0.1:0", "--config", filepath.Join(dir, "rackbook.yml"), "--no-git", "--state-dir", filepath.Join(dir, "state"))
	if err == nil || !strings.Contains(err.Error(), "inside the data repository") {
		t.Fatalf("%v", err)
	}
}

func TestServeInfraFlagsAreChecked(t *testing.T) {
	dir := testutil.CopyExample(t)
	cfg := filepath.Join(dir, "rackbook.yml")
	other := t.TempDir()
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"admins without a repo":     {[]string{"--infra-admins", "a@x.org"}, "--infra-admins needs --infra-repo"},
		"status file without repo":  {[]string{"--hub-status-file", "/run/hub/status.json"}, "--hub-status-file needs --infra-repo"},
		"repo without oidc":         {[]string{"--infra-repo", other, "--infra-admins", "a@x.org"}, "needs --auth oidc"},
		"oidc without admins":       {[]string{"--auth", "oidc", "--infra-repo", other}, "names nobody"},
		"wildcard admin":            {[]string{"--auth", "oidc", "--infra-repo", other, "--infra-admins", "*"}, "no wildcards"},
		"repo inside the ledger":    {[]string{"--auth", "oidc", "--infra-repo", filepath.Join(dir, "infra"), "--infra-admins", "a@x.org"}, "separate directories"},
		"repo is the ledger itself": {[]string{"--auth", "oidc", "--infra-repo", dir, "--infra-admins", "a@x.org"}, "separate directories"},
	} {
		args := append([]string{"serve", "--listen", "127.0.0.1:0", "--config", cfg, "--no-git"}, c.args...)
		if _, err := run(t, args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", name, err, c.want)
		}
	}
}
