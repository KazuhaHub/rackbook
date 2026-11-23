package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const sample = `
title: T
collections:
  b:
    file: b.yml
    schema: schemas/b.json
    key: [name]
    facets:
      - name
      - {field: x, contains: [a, b]}
      - {field: y, match: prefix, values: [p]}
  a:
    file: a.yml
    schema: schemas/a.json
rules:
  - ref: {from: a.dev, to: b.name, allow: [all]}
`

func TestParseOrderAndFacets(t *testing.T) {
	c, err := Parse([]byte(sample), "/r/rackbook.yml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Collections[0].Name != "b" || c.Collections[1].Name != "a" {
		t.Fatalf("order lost: %v", c.Collections)
	}
	f := c.Collections[0].Facets
	if f[0].Match != "exact" || f[1].Match != "contains" || f[1].Values[1] != "b" || f[2].Match != "prefix" {
		t.Fatalf("facets: %+v", f)
	}
	if c.Write.Mode != "push" {
		t.Fatal("default mode")
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"escape":   "collections:\n  a: {file: ../x.yml, schema: s.json}\n",
		"absolute": "collections:\n  a: {file: /etc/x.yml, schema: s.json}\n",
		"badref":   "collections:\n  a: {file: a.yml, schema: s.json}\nrules:\n  - ref: {from: a.x, to: zz.y}\n",
		"norule":   "collections:\n  a: {file: a.yml, schema: s.json}\nrules:\n  - {}\n",
		"mode":     "collections:\n  a: {file: a.yml, schema: s.json}\nwrite: {mode: nope}\n",
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src), "/r/rackbook.yml"); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestFindUpwards(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Find(sub)
	if err != nil || !strings.HasSuffix(got, FileName) {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := Find(t.TempDir()); err == nil {
		t.Skip("a parent of the temp dir has a config")
	}
}

func TestResolveRefusesSymlinksOutOfTheRoot(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.yml"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// (internal/testutil imports this package, so it cannot be used here.)
	for _, l := range [][2]string{{outside, "link"}, {filepath.Join(outside, "secret.yml"), "file.yml"}} {
		if err := os.Symlink(l[0], filepath.Join(root, l[1])); err != nil {
			t.Skipf("SKIPPED: cannot create symbolic links here (%s): %v", runtime.GOOS, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "ok"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := &Config{Dir: root}
	for _, p := range []string{"link/secret.yml", "link/new.yml", "file.yml"} {
		if _, err := c.Resolve(p); err == nil {
			t.Errorf("%s must be refused", p)
		}
	}
	for _, p := range []string{"ok/a.yml", "missing/a.yml"} {
		if _, err := c.Resolve(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}

func TestParseRoles(t *testing.T) {
	c, err := Parse([]byte(sample+"auth:\n  editors: [old@x.org]\n  roles:\n    admin: [A@x.org]\n    editor: ['*@x.org', 'mcphub:alice', 'group:ops']\n    viewer: ['*']\n"), "/r/rackbook.yml")
	if err != nil {
		t.Fatal(err)
	}
	r := c.Auth.Roles
	if r == nil || r.Admin[0] != "A@x.org" || len(r.Editor) != 3 || r.Viewer[0] != "*" || c.Auth.Editors[0] != "old@x.org" {
		t.Fatalf("%+v", c.Auth)
	}
	c, err = Parse([]byte(sample), "/r/rackbook.yml")
	if err != nil || c.Auth.Roles != nil {
		t.Fatalf("no roles block must stay nil: %v %+v", err, c.Auth)
	}
	for _, bad := range []string{"{admin: ['*@']}", "{editor: ['']}", "{viewer: ['a*b']}", "{editor: ['group:']}"} {
		if _, err := Parse([]byte(sample+"auth:\n  roles: "+bad+"\n"), "/r/rackbook.yml"); err == nil || !strings.Contains(err.Error(), "auth.roles") {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

func TestParseMCPMatchEmail(t *testing.T) {
	c, err := Parse([]byte(sample), "/r/rackbook.yml")
	if err != nil || c.Auth.MCP.MatchEmail {
		t.Fatalf("default must be off: %v %+v", err, c.Auth)
	}
	c, err = Parse([]byte(sample+"auth:\n  mcp:\n    match_email: true\n"), "/r/rackbook.yml")
	if err != nil || !c.Auth.MCP.MatchEmail {
		t.Fatalf("%v %+v", err, c.Auth)
	}
}

func TestAuthMCPValidation(t *testing.T) {
	base := "title: t\ncollections:\n  a: {file: a.yml, schema: a.json}\nauth:\n  mcp:\n"
	for name, c := range map[string]struct{ yaml, want string }{
		"issuer without resource": {"    trusted_issuers: [{issuer: \"https://i.example.com\", alias: x}]\n", "resource is required"},
		"no alias":                {"    resource: https://r.example.com/mcp\n    trusted_issuers: [{issuer: \"https://i.example.com\"}]\n", "alias is required"},
		"same alias twice":        {"    resource: https://r.example.com/mcp\n    trusted_issuers: [{issuer: \"https://i.example.com\", alias: x}, {issuer: \"https://j.example.com\", alias: x}]\n", "used twice"},
		"bad kind":                {"    resource: https://r.example.com/mcp\n    trusted_issuers: [{issuer: \"https://i.example.com\", alias: x, kind: saml}]\n", "kind"},
		"introspection no secret": {"    resource: https://r.example.com/mcp\n    trusted_issuers: [{issuer: \"https://i.example.com\", alias: x, introspection: {client_id: c}}]\n", "client_secret_env"},
		"direct push no scope":    {"    direct_push: [{users: [a]}]\n", "collections"},
		"direct push viewer":      {"    direct_push: [{roles: [viewer], collections: [a]}]\n", "admin or editor"},
	} {
		if _, err := Parse([]byte(base+c.yaml), "/x/rackbook.yml"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	ok := base + "    resource: https://r.example.com/mcp\n    trusted_issuers: [{issuer: \"https://i.example.com\", kind: mcphub}]\n    scopes: {read: \"\"}\n"
	cfg, err := Parse([]byte(ok), "/x/rackbook.yml")
	if err != nil {
		t.Fatal(err)
	}
	m := cfg.Auth.MCP
	if m.TrustedIssuers[0].Name() != "mcphub" || m.Audience(m.TrustedIssuers[0]) != "https://r.example.com/mcp" || m.Scopes.WriteScope() != "rackbook:write" || m.Scopes.ReadScope() != "" || !m.TrustedIssuers[0].NeedTypATJWT() {
		t.Fatalf("%+v", m)
	}
	if _, err := Parse([]byte("title: t\ncollections:\n  a: {file: .rackbook/a.yml, schema: a.json}\n"), "/x/rackbook.yml"); err == nil || !strings.Contains(err.Error(), ".rackbook") {
		t.Fatalf("collections must not live in .rackbook: %v", err)
	}
}

func TestDirectPushUsersAreMethodGated(t *testing.T) {
	for _, u := range []string{"alice", "alice@example.com", "oauth:entra", "mcphub:"} {
		m := AuthMCP{DirectPush: []DirectPush{{Users: []string{u}, Collections: []string{"*"}}}}
		if err := m.validate(); err == nil {
			t.Errorf("user %q must be refused (no match_email)", u)
		}
	}
	for _, u := range []string{"mcphub:alice", "oauth:entra:bob@example.com"} {
		m := AuthMCP{DirectPush: []DirectPush{{Users: []string{u}, Collections: []string{"*"}}}}
		if err := m.validate(); err != nil {
			t.Errorf("%q: %v", u, err)
		}
	}
	m := AuthMCP{MatchEmail: true, DirectPush: []DirectPush{{Users: []string{"a@b.c"}, Collections: []string{"*"}}}}
	if err := m.validate(); err != nil {
		t.Error(err)
	}
}

func TestLoadRefusesCollectionsOnTheConfigFileOrGit(t *testing.T) {
	for _, file := range []string{"rackbook.yml", "./rackbook.yml", ".git/data.yml", ".GIT/data.yml"} {
		dir := t.TempDir()
		src := "collections:\n  x: {file: " + file + ", schema: s.json}\n"
		if err := os.WriteFile(filepath.Join(dir, "rackbook.yml"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(filepath.Join(dir, "rackbook.yml")); err == nil {
			t.Errorf("a collection file %q must be refused", file)
		}
	}
}

func TestWindowsNonRelative(t *testing.T) {
	for _, p := range []string{`C:\x.yml`, `C:x.yml`, `c:/x.yml`, `\\host\share\x.yml`, `\\?\C:\x.yml`, `\x.yml`, `/x.yml`, `a.yml:stream`} {
		if !windowsNonRelative(p) {
			t.Errorf("%q must be refused on Windows", p)
		}
	}
	for _, p := range []string{`data/x.yml`, `data\x.yml`, `..\x.yml`, `a b/c.yml`} {
		if windowsNonRelative(p) {
			t.Errorf("%q is a plain relative path", p)
		}
	}
}

func TestResolveRefusesRootedAndDrivePaths(t *testing.T) {
	c := &Config{Dir: t.TempDir()}
	bad := []string{"/etc/passwd", "../x.yml", "a/../../x.yml"}
	if runtime.GOOS == "windows" {
		bad = append(bad, `C:\Windows\win.ini`, `C:win.ini`, `\\host\share\x.yml`, `\Windows\win.ini`, `..\x.yml`, `a.yml:stream`)
	}
	for _, p := range bad {
		if _, err := c.Resolve(p); err == nil {
			t.Errorf("%q must be refused", p)
		}
	}
}

func TestModules(t *testing.T) {
	const cols = "collections:\n  creds: {file: c.yml, schema: s.json}\n"
	c, err := Parse([]byte(cols+"modules:\n  entra: {token: entra-sync, collection: creds, fields: [expires, kid], direct_push: true}\n  m2.x: {token: other, collection: creds, fields: [a]}\n"), "/r/rackbook.yml")
	if err != nil {
		t.Fatal(err)
	}
	name, m := c.ModuleForToken("entra-sync")
	if name != "entra" || m == nil || m.Collection != "creds" || !m.DirectPush || len(m.Fields) != 2 {
		t.Fatalf("module: %q %+v", name, m)
	}
	if name, m := c.ModuleForToken("other"); name != "m2.x" || m.DirectPush {
		t.Fatalf("module: %q %+v", name, m)
	}
	if name, m := c.ModuleForToken("nobody"); name != "" || m != nil {
		t.Fatal("unknown token matched a module")
	}
	if _, m := c.ModuleForToken(""); m != nil {
		t.Fatal("empty token matched a module")
	}
	plain, err := Parse([]byte(cols), "/r/rackbook.yml")
	if err != nil || plain.Modules != nil {
		t.Fatalf("v0.2 config: %v %v", err, plain.Modules)
	}
	bad := map[string]string{
		"manual":      "  manual: {token: t, collection: creds, fields: [a]}\n",
		"uppercase":   "  Entra: {token: t, collection: creds, fields: [a]}\n",
		"toolong":     "  " + strings.Repeat("a", 33) + ": {token: t, collection: creds, fields: [a]}\n",
		"no token":    "  m: {collection: creds, fields: [a]}\n",
		"dup token":   "  m: {token: t, collection: creds, fields: [a]}\n  n: {token: t, collection: creds, fields: [a]}\n",
		"unknown col": "  m: {token: t, collection: nope, fields: [a]}\n",
		"no col":      "  m: {token: t, fields: [a]}\n",
		"no fields":   "  m: {token: t, collection: creds}\n",
		"source":      "  m: {token: t, collection: creds, fields: [a, source]}\n",
		"null":        "  m:\n",
	}
	for name, block := range bad {
		if _, err := Parse([]byte(cols+"modules:\n"+block), "/r/rackbook.yml"); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestParseAuditors(t *testing.T) {
	c, err := Parse([]byte(sample+"auth:\n  roles:\n    admin: [a@x.org]\n  auditors: ['group:audit', '*@audit.x.org', 'oauth:acme:aud', 'aud@x.org']\n"), "/r/rackbook.yml")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Auth.Auditors; len(got) != 4 || got[0] != "group:audit" || got[3] != "aud@x.org" {
		t.Fatalf("%v", got)
	}
	if c.Auth.Roles == nil || len(c.Auth.Roles.Admin) != 1 {
		t.Fatalf("roles are untouched: %+v", c.Auth)
	}
	// auditors need no roles block, and absent means none
	if c, err = Parse([]byte(sample+"auth:\n  auditors: ['aud@x.org']\n"), "/r/rackbook.yml"); err != nil || c.Auth.Roles != nil || len(c.Auth.Auditors) != 1 {
		t.Fatalf("%v %+v", err, c.Auth)
	}
	if c, err = Parse([]byte(sample), "/r/rackbook.yml"); err != nil || c.Auth.Auditors != nil {
		t.Fatalf("%v %+v", err, c.Auth)
	}
	// the same validation as a role list, with the key in the message
	for _, bad := range []string{"['*@']", "['']", "['a*b']", "['group:']", "['oauth:x']"} {
		if _, err := Parse([]byte(sample+"auth:\n  auditors: "+bad+"\n"), "/r/rackbook.yml"); err == nil || !strings.Contains(err.Error(), "auth.auditors") {
			t.Errorf("%s: %v", bad, err)
		}
	}
	// an unknown key stays ignored, as before
	if _, err := Parse([]byte(sample+"auth:\n  auditorz: ['x']\n"), "/r/rackbook.yml"); err != nil {
		t.Fatal(err)
	}
}
