package gitstore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/roles"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

func TestStateFileCommitsPushesAndRefusesOtherPaths(t *testing.T) {
	e := newEnv(t)
	s := open(t, e.server, nil)
	ctx := context.Background()
	res, err := s.MutateStateFile(ctx, ".rackbook/tokens.yml", "rackbook(auth): create token x", editor, func(old []byte, exists bool) ([]byte, error) {
		if exists {
			t.Fatal("new file")
		}
		return []byte("tokens: []\n"), nil
	})
	if err != nil || res.Commit == "" || res.PullRequest {
		t.Fatalf("%v %+v", err, res)
	}
	if got := sh(t, e.bare, "show", "main:.rackbook/tokens.yml"); got != "tokens: []" {
		t.Fatal(got)
	}
	if got := sh(t, e.bare, "log", "-1", "--format=%an|%B", "main"); !strings.HasPrefix(got, "Ann Editor|rackbook(auth): create token x") || strings.Contains(got, "Record:") {
		t.Fatal(got)
	}
	// Unchanged content commits nothing.
	if res, err := s.MutateStateFile(ctx, ".rackbook/tokens.yml", "noop", editor, func(old []byte, _ bool) ([]byte, error) { return old, nil }); err != nil || res.Commit != "" {
		t.Fatalf("%v %+v", err, res)
	}
	for _, bad := range []string{"rackbook.yml", "docs/ledger/todo.yml", ".rackbook", "../x", ".rackbookx/a"} {
		if _, err := s.MutateStateFile(ctx, bad, "x", editor, func([]byte, bool) ([]byte, error) { return []byte("x"), nil }); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestStateFileInPRModeLeavesACleanClone(t *testing.T) {
	e := newEnv(t)
	sh(t, e.server, "pull", "--quiet")
	testutil.Replace(t, e.server, "rackbook.yml", "mode: push", "mode: pr")
	sh(t, e.server, "commit", "-qam", "pr mode")
	sh(t, e.server, "push", "--quiet", "origin", "main")
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p map[string]string
		json.NewDecoder(r.Body).Decode(&p)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"html_url":"https://github.com/acme/ledger/pull/9"}`))
	}))
	defer gh.Close()
	s := open(t, e.server, func(o *Options) { o.GitHubToken, o.GitHubRepo, o.GitHubAPI = "tok", "acme/ledger", gh.URL })
	res, err := s.MutateStateFile(context.Background(), ".rackbook/tokens.yml", "rackbook(auth): create token y", editor, func([]byte, bool) ([]byte, error) {
		return []byte("tokens: []\n"), nil
	})
	if err != nil || !res.PullRequest || !strings.HasSuffix(res.Commit, "/pull/9") {
		t.Fatalf("%v %+v", err, res)
	}
	if _, err := os.Stat(filepath.Join(e.server, ".rackbook", "tokens.yml")); err == nil {
		t.Fatal("the dropped commit's new file must be removed")
	}
	if sh(t, e.server, "status", "--porcelain", "--untracked-files=all") != "" {
		t.Fatal("clone must stay clean")
	}
	// Writes still work afterwards.
	if _, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), editor); err != nil {
		t.Fatal(err)
	}
}

func TestWriteOptionsFor(t *testing.T) {
	cfg := &config.Config{Auth: config.Auth{MCP: config.AuthMCP{DirectPush: []config.DirectPush{
		{Users: []string{"MCPHub:Alice"}, Collections: []string{"todo"}},
		{Roles: []string{"admin"}, Collections: []string{"*"}},
	}}}}
	hub := func(id string, role string) *auth.Identity {
		return &auth.Identity{ID: id, Method: auth.MethodMCPHub, Role: roleOf(role)}
	}
	cases := []struct {
		who        *auth.Identity
		kind       edit.Kind
		coll       string
		forcePR    bool
		branchHead string
	}{
		{nil, edit.Add, "todo", false, ""},
		{editor, edit.Add, "todo", false, ""}, // console users follow write.mode
		{hub("alice", "editor"), edit.Add, "todo", false, "rackbook/mcp/alice"},
		{hub("alice", "editor"), edit.Edit, "todo", false, "rackbook/mcp/alice"},
		{hub("alice", "editor"), edit.Delete, "todo", true, "rackbook/mcp/alice"},
		{hub("alice", "editor"), edit.Add, "sites", true, "rackbook/mcp/alice"},
		{hub("bob", "editor"), edit.Add, "todo", true, "rackbook/mcp/bob"},
		{hub("root", "admin"), edit.Add, "sites", false, "rackbook/mcp/root"}, // role entry
		{hub("root", "admin"), edit.Delete, "sites", true, "rackbook/mcp/root"},
		{&auth.Identity{ID: "x@y.z", Method: auth.MethodToken, Token: "ci", Role: roleOf("editor")}, edit.Add, "todo", true, "rackbook/token/ci"},
		{&auth.Identity{ID: "x@y.z", Method: auth.MethodToken, Token: "ci", DirectPush: true}, edit.Edit, "todo", false, "rackbook/token/ci"},
		{&auth.Identity{ID: "x@y.z", Method: auth.MethodToken, Token: "ci", DirectPush: true}, edit.Delete, "todo", true, "rackbook/token/ci"},
	}
	for i, c := range cases {
		o := WriteOptionsFor(c.who, cfg, c.kind, c.coll)
		if o.ForcePR != c.forcePR || o.BranchPrefix != c.branchHead {
			t.Errorf("case %d: %+v", i, o)
		}
	}
}

func roleOf(s string) roles.Role {
	switch s {
	case "admin":
		return roles.Admin
	case "editor":
		return roles.Editor
	}
	return roles.Viewer
}
