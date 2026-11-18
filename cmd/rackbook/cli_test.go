package main

import (
	"bytes"
	"errors"
	"os"
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
