package api_test

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

const rolesBlock = `
auth:
  roles:
    admin: [boss@example.com]
    editor: ["*@team.example.com"]
    viewer: [guest@example.com]
`

func withRoles(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "rackbook.yml")
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(p, append(b, rolesBlock...), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRolesDecideWhatTheAPIAllows(t *testing.T) {
	dir := withRoles(t, testutil.CopyExample(t))
	cases := []struct {
		who                  string
		role                 string
		canEdit, canAdmin    bool
		wantPost, wantDelete int
		wantPostErr          string
	}{
		{"Boss <boss@example.com>", "admin", true, true, 201, 200, ""},
		{"Tom <Tom@team.example.com>", "editor", true, false, 201, 200, ""},
		{"Guest <guest@example.com>", "viewer", false, false, 403, 403, "forbidden"},
	}
	for _, c := range cases {
		f := newFixtureWithConfigSource(t, c.who, dir)
		_, m, _ := f.do(t, "GET", "/api/meta", nil, nil)
		u := m["user"].(map[string]any)
		if u["role"] != c.role || u["authMethod"] != "none" || u["canEdit"] != c.canEdit || u["canAdmin"] != c.canAdmin || u["id"] != strings.ToLower(u["email"].(string)) {
			t.Fatalf("%s: %v", c.who, u)
		}
		code, r, _ := f.do(t, "POST", "/api/c/todo", map[string]any{"data": map[string]any{"item": "by " + c.role, "status": "待办"}}, nil)
		if code != c.wantPost || r["error"] != nilIfEmpty(c.wantPostErr) {
			t.Fatalf("%s POST: %d %v", c.role, code, r)
		}
		// Reads are open to every role.
		if code, _, _ := f.do(t, "GET", "/api/c/todo", nil, nil); code != 200 {
			t.Fatalf("%s GET: %d", c.role, code)
		}
		if code, _, _ := f.do(t, "DELETE", "/api/c/todo/"+url.PathEscape("by "+c.role)+"?hash=x", nil, nil); (code == 403) != (c.wantDelete == 403) {
			t.Fatalf("%s DELETE: %d", c.role, code)
		}
	}
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// newFixtureWithConfigSource wires roles from the store's own config.
func newFixtureWithConfigSource(t *testing.T, who, dir string) *fixture {
	t.Helper()
	return newFixture(t, func(o *api.Options) {
		a, err := auth.New(context.Background(), auth.Config{Mode: auth.ModeNone, Editor: who, Config: o.Store.Config, Degraded: func() bool { return o.Store.ConfigProblem() != "" }})
		if err != nil {
			t.Fatal(err)
		}
		o.Auth = a
	}, dir)
}

func TestIdentityWithoutARoleIsRefusedAndRolesFollowTheFile(t *testing.T) {
	dir := withRoles(t, testutil.CopyExample(t))
	f := newFixtureWithConfigSource(t, "Eve <eve@elsewhere.org>", dir)
	for _, p := range []string{"/api/meta", "/api/c/todo", "/export.json", "/"} {
		if code, r, _ := f.do(t, "GET", p, nil, nil); code != 403 || r["error"] != "no_role" {
			t.Fatalf("%s: %d %v", p, code, r)
		}
	}
	if code, _, _ := f.do(t, "GET", "/healthz", nil, nil); code != 200 {
		t.Fatal("healthz must stay open")
	}
	// Without Git the files are re-read on every request: editing roles in the file takes effect at once.
	testutil.Replace(t, dir, "rackbook.yml", "viewer: [guest@example.com]", "viewer: [guest@example.com, eve@elsewhere.org]")
	_, m, _ := f.do(t, "GET", "/api/meta", nil, nil)
	if m["user"].(map[string]any)["role"] != "viewer" {
		t.Fatalf("%v", m["user"])
	}
	testutil.Replace(t, dir, "rackbook.yml", "editor: [\"*@team.example.com\"]", "editor: [\"*@team.example.com\", eve@elsewhere.org]")
	if code, _, _ := f.do(t, "POST", "/api/c/todo", map[string]any{"data": map[string]any{"item": "eve", "status": "待办"}}, nil); code != 201 {
		t.Fatalf("promoted user must be able to write: %d", code)
	}
}

func TestDefaultAuthStillAppliesRoles(t *testing.T) {
	// No Auth option at all (library use): auth none, but roles and editors apply; anonymous reads.
	f := newFixture(t, nil, withRoles(t, testutil.CopyExample(t)))
	_, m, _ := f.do(t, "GET", "/api/meta", nil, nil)
	u := m["user"].(map[string]any)
	if u["role"] != "viewer" || u["canEdit"] != false || u["canAdmin"] != false || u["authMethod"] != "none" {
		t.Fatalf("%v", u)
	}
	if _, has := u["email"]; has {
		t.Fatalf("anonymous has no e-mail: %v", u)
	}
	f = newFixture(t, nil, "")
	_, m, _ = f.do(t, "GET", "/api/meta", nil, nil)
	if u := m["user"].(map[string]any); u["role"] != "editor" || u["canEdit"] != true {
		t.Fatalf("no roles block: everyone edits: %v", u)
	}
}
