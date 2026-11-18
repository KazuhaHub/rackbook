package config

import (
	"os"
	"path/filepath"
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
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if err := os.Symlink(filepath.Join(outside, "secret.yml"), filepath.Join(root, "file.yml")); err != nil {
		t.Fatal(err)
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
