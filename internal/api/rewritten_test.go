package api_test

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

// gitEnv seeds a bare origin with the example (plus roles), clones it as the
// server and as a laptop, and serves the server clone as the given user.
func gitEnv(t *testing.T, who string) (f *fixture, bare, laptop, server string, store **gitstore.Store) {
	t.Helper()
	root := t.TempDir()
	bare = filepath.Join(root, "origin.git")
	sh(t, root, "init", "--bare", "-b", "main", bare)
	seed := withRoles(t, testutil.CopyExample(t))
	sh(t, seed, "init", "-b", "main")
	sh(t, seed, "add", ".")
	sh(t, seed, "commit", "-m", "seed")
	sh(t, seed, "remote", "add", "origin", bare)
	sh(t, seed, "push", "origin", "main")
	server, laptop = filepath.Join(root, "server"), filepath.Join(root, "laptop")
	sh(t, root, "clone", bare, server)
	sh(t, root, "clone", bare, laptop)
	var st *gitstore.Store
	f = newFixture(t, func(o *api.Options) {
		a, err := auth.New(context.Background(), auth.Config{Mode: auth.ModeNone, Editor: who, Config: o.Store.Config})
		if err != nil {
			t.Fatal(err)
		}
		o.Auth, st = a, o.Store
	}, server)
	return f, bare, laptop, server, &st
}

func TestRewrittenHistoryOverHTTP(t *testing.T) {
	t.Parallel()
	f, bare, laptop, _, store := gitEnv(t, "Boss <boss@example.com>")
	ctx := context.Background()
	good := sh(t, bare, "rev-parse", "main")

	_, m, _ := f.do(t, "GET", "/api/meta", nil, nil)
	if _, has := m["alert"]; has {
		t.Fatalf("no alert expected: %v", m["alert"])
	}

	// The remote's history is rewritten (the test setup force-pushes; Rackbook never does).
	p := filepath.Join(laptop, "docs/ledger/todo.yml")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append(b, "- {item: rewritten, status: 待办}\n"...), 0o644)
	sh(t, laptop, "commit", "-q", "--amend", "-am", "rewritten seed")
	sh(t, laptop, "push", "--quiet", "--force", "origin", "main")
	bad := sh(t, bare, "rev-parse", "main")
	if err := (*store).Pull(ctx); err == nil {
		t.Fatal("pull must report the rewrite")
	}

	// Meta shows the alert; reads keep working from the last good commit.
	_, m, _ = f.do(t, "GET", "/api/meta", nil, nil)
	al, _ := m["alert"].(map[string]any)
	if al["kind"] != "history_rewritten" || al["lastGood"] != good || al["remote"] != bad {
		t.Fatalf("alert: %v", m["alert"])
	}
	code, list, _ := f.do(t, "GET", "/api/c/todo", nil, nil)
	if code != 200 || len(arr(t, list["records"])) != 4 {
		t.Fatalf("read-only serving: %d %v", code, list)
	}
	// Every write endpoint answers 503 with the ids.
	body := map[string]any{"data": map[string]any{"item": "x", "status": "待办"}}
	for _, c := range []struct{ method, path string }{{"POST", "/api/c/todo"}, {"PUT", "/api/c/todo/" + url.PathEscape("某项")}, {"DELETE", "/api/c/todo/x?hash=abc"}} {
		var bd any = body
		if c.method == "DELETE" {
			bd = nil
		}
		if c.method == "PUT" {
			bd = map[string]any{"data": body["data"], "hash": "abc"}
		}
		code, r, _ := f.do(t, c.method, c.path, bd, nil)
		if code != 503 || r["error"] != "history_rewritten" || r["lastGood"] != good || r["remote"] != bad {
			t.Fatalf("%s: %d %v", c.method, code, r)
		}
	}

	// Accepting: wrong commit 409, then the tip.
	if code, r, _ := f.do(t, "POST", "/api/admin/accept-remote", map[string]any{"commit": good}, nil); code != 409 || r["error"] != "not_remote_tip" {
		t.Fatalf("%d %v", code, r)
	}
	if code, _, _ := f.do(t, "POST", "/api/admin/accept-remote", map[string]any{}, nil); code != 400 {
		t.Fatalf("missing commit: %d", code)
	}
	code, r, _ := f.do(t, "POST", "/api/admin/accept-remote", map[string]any{"commit": bad}, nil)
	if code != 200 || r["ok"] != true || r["lastGood"] != bad {
		t.Fatalf("%d %v", code, r)
	}
	_, m, _ = f.do(t, "GET", "/api/meta", nil, nil)
	if _, has := m["alert"]; has {
		t.Fatalf("alert must be gone: %v", m["alert"])
	}
	if code, r, _ := f.do(t, "POST", "/api/c/todo", body, nil); code != 201 {
		t.Fatalf("writes must work again: %d %v", code, r)
	}
}

func TestAcceptRemoteIsAdminOnly(t *testing.T) {
	t.Parallel()
	for who, want := range map[string]int{"Tom <tom@team.example.com>": 403, "Guest <guest@example.com>": 403, "Boss <boss@example.com>": 409} {
		f, bare, _, _, _ := gitEnv(t, who)
		tip := sh(t, bare, "rev-parse", "main")
		code, r, _ := f.do(t, "POST", "/api/admin/accept-remote", map[string]any{"commit": tip}, nil)
		if code != want {
			t.Errorf("%s: %d %v", who, code, r)
		}
		if want == 403 && r["error"] != "forbidden" {
			t.Errorf("%s: %v", who, r)
		}
		if want == 409 && r["error"] != "no_alert" {
			t.Errorf("an admin with nothing to accept gets no_alert: %v", r)
		}
	}
}

func TestPerRecordHistoryAndTrailersOverHTTP(t *testing.T) {
	t.Parallel()
	f, bare, _, _, _ := gitEnv(t, "Tom <tom@team.example.com>")
	for _, item := range []string{"alpha", "beta"} {
		if code, r, _ := f.do(t, "POST", "/api/c/todo", map[string]any{"data": map[string]any{"item": item, "status": "待办"}}, nil); code != 201 {
			t.Fatalf("%d %v", code, r)
		}
	}
	msg := sh(t, bare, "log", "-1", "--format=%B", "main")
	want := "ledger(todo): add beta\n\nEdited-by: tom@team.example.com\nEdited-via: rackbook (none)\nRecord: todo/beta"
	if msg != want {
		t.Fatalf("%q\nwant %q", msg, want)
	}
	_, h, _ := f.do(t, "GET", "/api/history?collection=todo&id=alpha", nil, nil)
	c := arr(t, h["commits"])
	if len(c) != 1 || c[0].(map[string]any)["subject"] != "ledger(todo): add alpha" {
		t.Fatalf("%v", h)
	}
	_, h, _ = f.do(t, "GET", "/api/history?collection=todo&id=untouched", nil, nil)
	if len(arr(t, h["commits"])) != 3 {
		t.Fatalf("fallback to the file history: %v", h)
	}
	if code, _, _ := f.do(t, "GET", "/api/history?id=alpha", nil, nil); code != 400 {
		t.Fatalf("id without collection: %d", code)
	}
}

func TestAcceptRemoteRefusedInReadOnlyMode(t *testing.T) {
	t.Parallel()
	f, bare, laptop, _, store := gitEnv(t, "Boss <boss@example.com>")
	// Rewrite the remote and let the server notice.
	p := filepath.Join(laptop, "docs/ledger/todo.yml")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append(b, "- {item: rewritten, status: 待办}\n"...), 0o644)
	sh(t, laptop, "commit", "-q", "--amend", "-am", "rewritten seed")
	sh(t, laptop, "push", "--quiet", "--force", "origin", "main")
	bad := sh(t, bare, "rev-parse", "main")
	if err := (*store).Pull(context.Background()); err == nil {
		t.Fatal("expected the rewrite")
	}
	ro := newFixture(t, func(o *api.Options) {
		o.ReadOnly = true
		a, _ := auth.New(context.Background(), auth.Config{Mode: auth.ModeNone, Editor: "Boss <boss@example.com>", Config: o.Store.Config})
		o.Auth = a
	}, filepath.Join(filepath.Dir(bare), "server"))
	code, r, _ := ro.do(t, "POST", "/api/admin/accept-remote", map[string]any{"commit": bad}, nil)
	if code != 403 || r["error"] != "read_only" {
		t.Fatalf("%d %v", code, r)
	}
	_ = f
}

func TestBrokenConfigFailsClosedForWritesAndAdminButKeepsReading(t *testing.T) {
	t.Parallel()
	dir := withRoles(t, testutil.CopyExample(t))
	f := newFixtureWithConfigSource(t, "Boss <boss@example.com>", dir)
	_, m, _ := f.do(t, "GET", "/api/meta", nil, nil)
	if u := m["user"].(map[string]any); u["role"] != "admin" || m["alert"] != nil {
		t.Fatalf("%v", m)
	}
	good, _ := os.ReadFile(filepath.Join(dir, "rackbook.yml"))
	os.WriteFile(filepath.Join(dir, "rackbook.yml"), []byte("title: [unclosed\n"), 0o644)

	_, m, _ = f.do(t, "GET", "/api/meta", nil, nil)
	al, _ := m["alert"].(map[string]any)
	u := m["user"].(map[string]any)
	if al["kind"] != "config_error" || al["message"] == "" || u["canEdit"] != false || u["canAdmin"] != false || u["role"] != "viewer" {
		t.Fatalf("alert %v user %v", al, u)
	}
	// Reads keep working from the last good config.
	if code, r, _ := f.do(t, "GET", "/api/c/todo", nil, nil); code != 200 || len(arr(t, r["records"])) != 4 {
		t.Fatalf("%d %v", code, r)
	}
	if code, r, _ := f.do(t, "POST", "/api/c/todo", map[string]any{"data": map[string]any{"item": "x", "status": "待办"}}, nil); code != 403 {
		t.Fatalf("write: %d %v", code, r)
	}
	if code, _, _ := f.do(t, "POST", "/api/admin/accept-remote", map[string]any{"commit": "abcdef0"}, nil); code != 403 {
		t.Fatalf("admin: %d", code)
	}
	// Fixed: back to normal without a restart.
	os.WriteFile(filepath.Join(dir, "rackbook.yml"), good, 0o644)
	_, m, _ = f.do(t, "GET", "/api/meta", nil, nil)
	if m["alert"] != nil || m["user"].(map[string]any)["role"] != "admin" {
		t.Fatalf("%v", m)
	}
	if code, _, _ := f.do(t, "POST", "/api/c/todo", map[string]any{"data": map[string]any{"item": "x", "status": "待办"}}, nil); code != 201 {
		t.Fatalf("write after the fix: %d", code)
	}
}
