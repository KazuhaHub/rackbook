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
		{Users: []string{"oauth:entra:carol"}, Collections: []string{"docs"}},
		{Users: []string{"dave@y.z"}, Collections: []string{"mail"}},
		{Roles: []string{"admin"}, Collections: []string{"*"}},
	}, MatchEmail: true}}}
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
		// Entries are method-gated: an OAuth user named alice does not match mcphub:alice.
		{&auth.Identity{ID: "alice", Method: auth.MethodOAuth, Issuer: "entra", Role: roleOf("editor")}, edit.Add, "todo", true, "rackbook/mcp/alice"},
		{&auth.Identity{ID: "carol", Method: auth.MethodOAuth, Issuer: "entra", Role: roleOf("editor")}, edit.Add, "docs", false, "rackbook/mcp/carol"},
		{&auth.Identity{ID: "carol", Method: auth.MethodOAuth, Issuer: "other", Role: roleOf("editor")}, edit.Add, "docs", true, "rackbook/mcp/carol"},
		{&auth.Identity{ID: "dave@y.z", Email: "dave@y.z", Method: auth.MethodOAuth, Issuer: "entra", Role: roleOf("editor")}, edit.Add, "mail", false, "rackbook/mcp/dave-y-z"},
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

func TestStateFileHistoryWalksTheCommitsOfOneFileOldestFirst(t *testing.T) {
	e := newEnv(t)
	s := open(t, e.server, nil)
	ctx := context.Background()
	const rel = ".rackbook/audit-anchors"
	var commits []string
	for _, line := range []string{"a", "b", "c"} {
		if _, err := s.MutateStateFile(ctx, rel, "anchor "+line, nil, appendLine(line)); err != nil {
			t.Fatal(err)
		}
		commits = append(commits, sh(t, e.server, "rev-parse", "HEAD"))
		// a commit that does not touch the file is not a version
		if _, err := s.MutateStateFile(ctx, ".rackbook/other.yml", "other "+line, nil, appendLine("x: "+line)); err != nil {
			t.Fatal(err)
		}
	}
	h, err := s.StateFileHistory(ctx, rel, "")
	if err != nil || h.Restarted || len(h.Versions) != 3 || h.Base != nil || h.Tip != sh(t, e.server, "rev-parse", "HEAD") {
		t.Fatalf("%+v %v", h, err)
	}
	for i, v := range h.Versions {
		if v.Commit != commits[i] || string(v.Content) != strings.Join([]string{"a", "b", "c"}[:i+1], "\n")+"\n" {
			t.Fatalf("version %d: %+v", i, v)
		}
	}
	// from a commit already checked: only what came after, with the file as it was at that commit
	h2, err := s.StateFileHistory(ctx, rel, commits[0])
	if err != nil || len(h2.Versions) != 2 || string(h2.Base) != "a\n" || h2.Versions[0].Commit != commits[1] {
		t.Fatalf("%+v %v", h2, err)
	}
	// nothing new
	if h3, err := s.StateFileHistory(ctx, rel, h.Tip); err != nil || len(h3.Versions) != 0 || h3.Restarted {
		t.Fatalf("%+v %v", h3, err)
	}
	// a commit that is not an ancestor of the tip (the history was rewritten): from the start again
	sh(t, e.laptop, "pull", "--quiet")
	sh(t, e.laptop, "checkout", "-q", "--orphan", "other")
	sh(t, e.laptop, "commit", "-q", "--allow-empty", "-m", "elsewhere")
	foreign := sh(t, e.laptop, "rev-parse", "HEAD")
	sh(t, e.server, "fetch", "--quiet", e.laptop, "other")
	h4, err := s.StateFileHistory(ctx, rel, foreign)
	if err != nil || !h4.Restarted || len(h4.Versions) != 3 {
		t.Fatalf("%+v %v", h4, err)
	}
	// an unusable commit, or a file outside .rackbook/, is refused or restarted, never run as an option
	if h5, err := s.StateFileHistory(ctx, rel, "--output=/tmp/x"); err != nil || len(h5.Versions) != 3 {
		t.Fatalf("%+v %v", h5, err)
	}
	for _, bad := range []string{"rackbook.yml", ".rackbook", "../x", ".rackbook/../rackbook.yml"} {
		if _, err := s.StateFileHistory(ctx, bad, ""); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}
