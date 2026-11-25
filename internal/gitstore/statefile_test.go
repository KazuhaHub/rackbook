package gitstore

import (
	"context"
	"encoding/json"
	"errors"
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

const anchorsRel = ".rackbook/audit-anchors"

func appendState(t *testing.T, s *Store, line string) string {
	t.Helper()
	if _, err := s.MutateStateFile(context.Background(), anchorsRel, "anchor "+line, nil, appendLine(line)); err != nil {
		t.Fatal(err)
	}
	return sh(t, s.repo.Dir, "rev-parse", "HEAD")
}

func TestStateFileHistoryAcceptsAppendsAndFindsOtherChanges(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := open(t, e.server, nil)
	ctx := context.Background()
	var commits []string
	for _, line := range []string{"a", "b", "c"} {
		commits = append(commits, appendState(t, s, line))
		// a commit that does not touch the file is no concern of it
		if _, err := s.MutateStateFile(ctx, ".rackbook/other.yml", "other "+line, nil, appendLine("x: "+line)); err != nil {
			t.Fatal(err)
		}
	}
	tip := sh(t, e.server, "rev-parse", "HEAD")
	c, err := s.CheckStateFileHistory(ctx, anchorsRel, "")
	if err != nil || c.Restarted || len(c.Violations) != 0 || c.Commits != 3 || c.Tip != tip {
		t.Fatalf("%+v %v", c, err)
	}
	// nothing new since the tip; and from an earlier commit only what came after is looked at
	if c, err = s.CheckStateFileHistory(ctx, anchorsRel, tip); err != nil || c.Commits != 0 || c.Restarted {
		t.Fatalf("%+v %v", c, err)
	}
	if c, err = s.CheckStateFileHistory(ctx, anchorsRel, commits[0]); err != nil || c.Commits != 2 || len(c.Violations) != 0 {
		t.Fatalf("%+v %v", c, err)
	}
	// a rewrite of the first line by a forward commit
	sh(t, e.laptop, "pull", "--quiet")
	if err := os.WriteFile(filepath.Join(e.laptop, anchorsRel), []byte("A\nb\nc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sh(t, e.laptop, "commit", "-qam", "tidy")
	sh(t, e.laptop, "push", "--quiet", "origin", "main")
	bad := sh(t, e.laptop, "rev-parse", "HEAD")
	if err := s.Pull(ctx); err != nil {
		t.Fatal(err)
	}
	for _, after := range []string{"", tip} {
		c, err = s.CheckStateFileHistory(ctx, anchorsRel, after)
		if err != nil || len(c.Violations) != 1 || c.Violations[0].Commit != bad || c.Violations[0].Parent != tip || string(c.Violations[0].Base) != "a\nb\nc\n" {
			t.Fatalf("after %q: %+v %v", after, c, err)
		}
	}
	// a commit that is not an ancestor of the tip (the history was rewritten): everything again
	sh(t, e.laptop, "checkout", "-q", "--orphan", "other")
	sh(t, e.laptop, "commit", "-q", "--allow-empty", "-m", "elsewhere")
	foreign := sh(t, e.laptop, "rev-parse", "HEAD")
	sh(t, e.server, "fetch", "--quiet", e.laptop, "other")
	if c, err = s.CheckStateFileHistory(ctx, anchorsRel, foreign); err != nil || !c.Restarted || c.Commits != 4 || len(c.Violations) != 1 {
		t.Fatalf("%+v %v", c, err)
	}
	if c, err = s.CheckStateFileHistory(ctx, anchorsRel, "--output=/tmp/x"); err != nil || c.Commits != 4 {
		t.Fatalf("%+v %v", c, err)
	}
	for _, p := range []string{"rackbook.yml", ".rackbook", "../x", ".rackbook/../rackbook.yml"} {
		if _, err := s.CheckStateFileHistory(ctx, p, ""); err == nil {
			t.Errorf("%q must be refused", p)
		}
	}
	// and a clone that no server owns can be checked the same way
	cc, err := CheckStateFileInClone(ctx, e.laptop, anchorsRel)
	if err != nil || len(cc.Violations) != 0 && cc.Commits == 0 {
		t.Fatalf("%+v %v", cc, err)
	}
	if _, err := CheckStateFileInClone(ctx, t.TempDir(), anchorsRel); err == nil {
		t.Fatal("not a repository")
	}
}

// mergeEnv makes a branch that was cut before the anchor file existed (so its file can only be
// the forged one) and gives the server's main two real anchors.
func mergeEnv(t *testing.T) (e env, s *Store, forged string) {
	t.Helper()
	e = newEnv(t)
	sh(t, e.laptop, "checkout", "-q", "-b", "forged")
	if err := os.MkdirAll(filepath.Join(e.laptop, ".rackbook"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.laptop, anchorsRel), []byte("FORGED\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sh(t, e.laptop, "add", ".")
	sh(t, e.laptop, "commit", "-qm", "a branch with its own anchors")
	forged = sh(t, e.laptop, "rev-parse", "HEAD")
	s = open(t, e.server, nil)
	appendState(t, s, "real1")
	appendState(t, s, "real2")
	sh(t, e.laptop, "fetch", "--quiet", "origin", "main")
	return e, s, forged
}

func TestAMergeThatTakesAForgedAnchorFileIsFoundOnEitherSide(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("forged side is the second parent", func(t *testing.T) {
		e, s, _ := mergeEnv(t)
		sh(t, e.laptop, "checkout", "-q", "main")
		sh(t, e.laptop, "merge", "--quiet", "origin/main")
		sh(t, e.laptop, "merge", "--quiet", "-X", "theirs", "forged", "-m", "merge the branch")
		if got := sh(t, e.laptop, "show", "HEAD:"+anchorsRel); got != "FORGED" {
			t.Fatalf("the merge did not take the forged file: %q", got)
		}
		merge := sh(t, e.laptop, "rev-parse", "HEAD")
		sh(t, e.laptop, "push", "--quiet", "origin", "main")
		if err := s.Pull(ctx); err != nil {
			t.Fatal(err)
		}
		c, err := s.CheckStateFileHistory(ctx, anchorsRel, "")
		if err != nil || !hasViolation(c, merge) {
			t.Fatalf("%+v %v", c, err)
		}
	})
	t.Run("forged side is the first parent", func(t *testing.T) {
		e, s, forged := mergeEnv(t)
		sh(t, e.laptop, "checkout", "-q", "forged")
		sh(t, e.laptop, "merge", "--quiet", "-X", "ours", "origin/main", "-m", "merge main into the branch")
		if got := sh(t, e.laptop, "show", "HEAD:"+anchorsRel); got != "FORGED" {
			t.Fatalf("the merge did not keep the forged file: %q", got)
		}
		if p := sh(t, e.laptop, "rev-parse", "HEAD^1"); p != forged {
			t.Fatalf("first parent %s", p)
		}
		merge := sh(t, e.laptop, "rev-parse", "HEAD")
		sh(t, e.laptop, "push", "--quiet", "origin", "HEAD:main")
		if err := s.Pull(ctx); err != nil {
			t.Fatal(err)
		}
		c, err := s.CheckStateFileHistory(ctx, anchorsRel, "")
		if err != nil || !hasViolation(c, merge) {
			t.Fatalf("%+v %v", c, err)
		}
		// the incremental check from the tip before the merge sees it as well
		c, err = s.CheckStateFileHistory(ctx, anchorsRel, sh(t, e.server, "rev-parse", "HEAD^2"))
		if err != nil || !hasViolation(c, merge) {
			t.Fatalf("incremental: %+v %v", c, err)
		}
	})
	t.Run("a harmless merge passes", func(t *testing.T) {
		e := newEnv(t)
		sh(t, e.laptop, "checkout", "-q", "-b", "side")
		if err := os.WriteFile(filepath.Join(e.laptop, "notes.txt"), []byte("hi\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		sh(t, e.laptop, "add", ".")
		sh(t, e.laptop, "commit", "-qm", "notes")
		s := open(t, e.server, nil)
		appendState(t, s, "real1")
		appendState(t, s, "real2")
		sh(t, e.laptop, "fetch", "--quiet", "origin", "main")
		sh(t, e.laptop, "checkout", "-q", "main")
		sh(t, e.laptop, "merge", "--quiet", "origin/main")
		sh(t, e.laptop, "merge", "--quiet", "--no-ff", "side", "-m", "merge notes")
		sh(t, e.laptop, "push", "--quiet", "origin", "main")
		if err := s.Pull(ctx); err != nil {
			t.Fatal(err)
		}
		c, err := s.CheckStateFileHistory(ctx, anchorsRel, "")
		if err != nil || len(c.Violations) != 0 || c.Commits < 2 {
			t.Fatalf("%+v %v", c, err)
		}
	})
}

func hasViolation(c *StateCheck, commit string) bool {
	for _, v := range c.Violations {
		if v.Commit == commit {
			return true
		}
	}
	return false
}

// pushFromLaptop commits what is in the laptop's work tree and pushes it, and has the server take it in.
// With staged the index was prepared by hand (a submodule entry): the work tree is not added.
func pushFromLaptop(t *testing.T, e env, s *Store, msg string, staged ...bool) string {
	t.Helper()
	if len(staged) == 0 || !staged[0] {
		sh(t, e.laptop, "add", "-A", ".")
	}
	sh(t, e.laptop, "commit", "-qm", msg)
	sh(t, e.laptop, "push", "--quiet", "origin", "main")
	if err := s.Pull(context.Background()); err != nil {
		t.Fatal(err)
	}
	return sh(t, e.laptop, "rev-parse", "HEAD")
}

func TestStateFileHistoryRefusesWhatIsNoRegularFileAndNeverDesyncs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	abs := func(e env) string { return filepath.Join(e.laptop, anchorsRel) }
	clear := func(t *testing.T, e env) {
		t.Helper()
		if err := os.RemoveAll(abs(e)); err != nil {
			t.Fatal(err)
		}
	}
	setFile := func(t *testing.T, e env, body string) {
		t.Helper()
		clear(t, e)
		if err := os.MkdirAll(filepath.Dir(abs(e)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs(e), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name   string
		middle func(t *testing.T, e env)
		staged bool // the middle step prepares the index itself
	}{
		{"a directory", func(t *testing.T, e env) {
			clear(t, e)
			// inside it, a name with a newline and what looks like the header of the next object
			fake := "x\n0123456789abcdef0123456789abcdef01234567 blob 3\nabc"
			if err := os.MkdirAll(abs(e), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(abs(e), fake), []byte("zz\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"a symbolic link", func(t *testing.T, e env) {
			clear(t, e)
			if err := os.Symlink("somewhere-else", abs(e)); err != nil {
				t.Skip("no symbolic links here")
			}
		}, false},
		{"a submodule", func(t *testing.T, e env) {
			clear(t, e)
			sh(t, e.laptop, "rm", "-q", "--cached", "-r", "--ignore-unmatch", anchorsRel)
			sh(t, e.laptop, "update-index", "--add", "--cacheinfo", "160000,"+sh(t, e.laptop, "rev-parse", "HEAD")+","+anchorsRel)
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			s := open(t, e.server, nil)
			setFile(t, e, "a\n")
			first := pushFromLaptop(t, e, s, "a")
			c.middle(t, e)
			bad := pushFromLaptop(t, e, s, "odd", c.staged)
			setFile(t, e, "a\nb\n")
			last := pushFromLaptop(t, e, s, "b again")
			setFile(t, e, "a\nb\nc\n")
			pushFromLaptop(t, e, s, "c")
			for _, after := range []string{"", first} {
				ck, err := s.CheckStateFileHistory(ctx, anchorsRel, after)
				if err != nil {
					t.Fatalf("after %q: %v", after, err)
				}
				// only the odd commit is refused: the honest ones around it were read correctly
				if len(ck.Violations) != 1 || ck.Violations[0].Commit != bad || ck.Violations[0].Reason != ReasonNotRegular {
					t.Fatalf("after %q: %+v", after, ck.Violations)
				}
				_ = last
			}
		})
	}
}

func TestStateFileHistoryRefusesAVersionAboveTheLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := open(t, e.server, nil)
	if err := os.MkdirAll(filepath.Join(e.laptop, ".rackbook"), 0o755); err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("0123456789abcdef\n", (MaxStateFileBytes/17)+10)
	if err := os.WriteFile(filepath.Join(e.laptop, anchorsRel), []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	bigCommit := pushFromLaptop(t, e, s, "big")
	if err := os.WriteFile(filepath.Join(e.laptop, anchorsRel), []byte(big+"more\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pushFromLaptop(t, e, s, "bigger")
	ck, err := s.CheckStateFileHistory(context.Background(), anchorsRel, "")
	if err != nil || len(ck.Violations) != 2 || ck.Violations[0].Reason != ReasonTooLarge || ck.Violations[1].Reason != ReasonTooLarge || ck.Violations[1].Commit != bigCommit && ck.Violations[0].Commit != bigCommit {
		t.Fatalf("%+v %v", ck, err)
	}
	if ck.Violations[0].Content != nil {
		t.Fatal("a version above the limit must not be kept")
	}
}

func TestStateFileHistoryDoesNotAcceptAnAnswerThatIsNotWhatWasAsked(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := open(t, e.server, nil)
	appendState(t, s, "a")
	appendState(t, s, "b")
	s.repo.Runner = answerWrong{inner: RealRunner()}
	ck, err := s.CheckStateFileHistory(context.Background(), anchorsRel, "")
	if !errors.Is(err, ErrStateDesync) || ck == nil || ck.Tip == "" {
		t.Fatalf("%+v %v", ck, err)
	}
}

// answerWrong lets everything through, but answers cat-file --batch with the right header for
// another object.
type answerWrong struct{ inner Runner }

func (a answerWrong) Run(ctx context.Context, c Cmd) (string, string, error) {
	out, errOut, err := a.inner.Run(ctx, c)
	if len(c.Args) >= 2 && c.Args[0] == "cat-file" && c.Args[1] == "--batch" && len(out) > 3 {
		out = "0000000000000000000000000000000000000000" + out[40:]
	}
	return out, errOut, err
}
