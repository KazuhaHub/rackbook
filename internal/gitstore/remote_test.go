package gitstore

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

// pushLaptop makes a commit on the laptop clone and pushes it normally.
func pushLaptop(t *testing.T, e env, item string) {
	t.Helper()
	sh(t, e.laptop, "pull", "--quiet", "--ff-only")
	p := filepath.Join(e.laptop, "docs/ledger/todo.yml")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append(b, ("- {item: "+item+", status: 待办}\n")...), 0o644)
	sh(t, e.laptop, "commit", "-qam", item)
	sh(t, e.laptop, "push", "--quiet", "origin", "main")
}

// rewriteRemote replaces the remote's last commit with a different one. The
// test setup has to force-push; Rackbook itself never does.
func rewriteRemote(t *testing.T, e env, item string) string {
	t.Helper()
	sh(t, e.laptop, "fetch", "--quiet")
	sh(t, e.laptop, "reset", "--quiet", "--hard", "origin/main~1")
	p := filepath.Join(e.laptop, "docs/ledger/todo.yml")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append(b, ("- {item: "+item+", status: 待办}\n")...), 0o644)
	sh(t, e.laptop, "commit", "-qam", "rewritten "+item)
	sh(t, e.laptop, "push", "--quiet", "--force", "origin", "main")
	return sh(t, e.bare, "rev-parse", "main")
}

func lastGoodOnDisk(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ".git", "rackbook-last-good", "main"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestFastForwardsAdvanceLastGood(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := open(t, e.server, nil)
	seed := sh(t, e.bare, "rev-parse", "main")
	if lastGoodOnDisk(t, e.server) != seed || s.Alert() != nil {
		t.Fatal("startup must record the accepted remote commit")
	}
	pushLaptop(t, e, "one")
	pushLaptop(t, e, "two")
	if err := s.Pull(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, tip := lastGoodOnDisk(t, e.server), sh(t, e.bare, "rev-parse", "main"); got != tip || s.lastGood != tip {
		t.Fatalf("last good %s, memory %s, tip %s", got, s.lastGood, tip)
	}
	// Our own write is a fast-forward too.
	if _, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), editor); err != nil {
		t.Fatal(err)
	}
	if err := s.Pull(context.Background()); err != nil || s.Alert() != nil {
		t.Fatalf("%v %+v", err, s.Alert())
	}
}

func TestRewrittenHistoryPausesWritesAndKeepsServing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	pushLaptop(t, e, "kept-until-rewrite")
	s := open(t, e.server, nil)
	good := sh(t, e.bare, "rev-parse", "main")
	headBefore := sh(t, e.server, "rev-parse", "HEAD")
	if headBefore != good || s.Ledger().Collection("todo").Get("kept-until-rewrite") == nil {
		t.Fatal("setup")
	}
	cmdsBefore := len(rec.all())

	bad := rewriteRemote(t, e, "after-rewrite")
	err := s.Pull(ctx)
	var he *HistoryRewrittenError
	if !errors.As(err, &he) || !errors.Is(err, ErrHistoryRewritten) || he.LastGood != good || he.Remote != bad {
		t.Fatalf("pull: %v", err)
	}
	if a := s.Alert(); a == nil || a.Kind != "history_rewritten" || a.LastGood != good || a.Remote != bad {
		t.Fatalf("alert: %+v", a)
	}
	// Read-only: still serving the last good commit, clone untouched.
	if sh(t, e.server, "rev-parse", "HEAD") != headBefore || sh(t, e.server, "status", "--porcelain") != "" {
		t.Fatal("the clone must not move")
	}
	l := s.Ledger()
	if l.Collection("todo").Get("kept-until-rewrite") == nil || l.Collection("todo").Get("after-rewrite") != nil {
		t.Fatal("must keep serving the last good ledger")
	}
	// Every write is refused with the typed error, on both write modes' path.
	_, err = s.Write(ctx, sshEdit(t, s, "TCP 22"), editor)
	if !errors.As(err, &he) || he.Remote != bad || he.LastGood != good {
		t.Fatalf("write: %v", err)
	}
	if lastGoodOnDisk(t, e.server) != good {
		t.Fatal("last good must not move to the rewritten tip")
	}
	// CLI commit/push in the same clone are refused too.
	if _, err := CommitFiles(ctx, e.server, []string{"docs/ledger/todo.yml"}, "x", nil, "todo/x"); !errors.Is(err, ErrHistoryRewritten) {
		t.Fatalf("CommitFiles: %v", err)
	}
	if err := PushCurrent(ctx, e.server); !errors.Is(err, ErrHistoryRewritten) {
		t.Fatalf("PushCurrent: %v", err)
	}
	// The bare remote was not touched by us.
	if sh(t, e.bare, "rev-parse", "main") != bad {
		t.Fatal("remote moved")
	}
	// No reset, no push and no other history-changing command ran while paused.
	for _, c := range rec.all()[cmdsBefore:] {
		if sub, _ := subcommand(c.Args); c.Dir == e.server && (sub == "reset" || sub == "merge" || sub == "push" || sub == "commit") {
			t.Errorf("git %s ran in the clone while history was rewritten", strings.Join(c.Args, " "))
		}
	}
	// Another poll keeps the state without noise.
	if err := s.Pull(ctx); !errors.Is(err, ErrHistoryRewritten) {
		t.Fatal(err)
	}

	// Recovery: refuse a wrong commit, a short one and a non-tip; accept the tip.
	for _, c := range []string{good, "abc", "", bad[:6], "zzzzzzzz"} {
		if _, err := s.AcceptRemote(ctx, c); !errors.Is(err, ErrNotRemoteTip) {
			t.Errorf("accept %q: %v", c, err)
		}
	}
	if s.Alert() == nil {
		t.Fatal("a refused accept must not clear the alert")
	}
	got, err := s.AcceptRemote(ctx, bad[:10])
	if err != nil || got != bad {
		t.Fatalf("accept: %q %v", got, err)
	}
	if s.Alert() != nil || lastGoodOnDisk(t, e.server) != bad || sh(t, e.server, "rev-parse", "HEAD") != bad {
		t.Fatal("accepting must record the tip, move the clone and clear the alert")
	}
	if s.Ledger().Collection("todo").Get("after-rewrite") == nil || s.Ledger().Collection("todo").Get("kept-until-rewrite") != nil {
		t.Fatal("ledger must follow the accepted history")
	}
	if _, err := s.Write(ctx, sshEdit(t, s, "TCP 22"), editor); err != nil {
		t.Fatalf("writes must work again: %v", err)
	}
}

func TestRewriteDetectedAtStartupAndSurvivesRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	pushLaptop(t, e, "one")
	s := open(t, e.server, nil)
	good := sh(t, e.bare, "rev-parse", "main")
	_ = s
	// The remote is rewritten while the server is down.
	bad := rewriteRemote(t, e, "two")
	s2 := open(t, e.server, nil)
	if a := s2.Alert(); a == nil || a.LastGood != good || a.Remote != bad {
		t.Fatalf("startup must detect it: %+v", a)
	}
	if s2.Ledger().Collection("todo").Get("one") == nil {
		t.Fatal("must serve the last good commit")
	}
	if _, err := s2.Write(ctx, sshEdit(t, s2, "TCP 22"), editor); !errors.Is(err, ErrHistoryRewritten) {
		t.Fatalf("%v", err)
	}
	// A restart does not accept it either.
	if s3 := open(t, e.server, nil); s3.Alert() == nil {
		t.Fatal("alert must survive a restart")
	}
	if _, err := s2.AcceptRemote(ctx, bad); err != nil {
		t.Fatal(err)
	}
	if s4 := open(t, e.server, nil); s4.Alert() != nil {
		t.Fatal("accepted history must stay accepted after a restart")
	}
}

func TestRewriteDuringPushRaceIsNotReplayedOntoNewHistory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	pushLaptop(t, e, "one")
	s := open(t, e.server, nil)
	good := sh(t, e.bare, "rev-parse", "main")
	s.beforePush = func() { rewriteRemote(t, e, "sneaky") }
	_, err := s.Write(ctx, sshEdit(t, s, "TCP 22"), editor)
	var he *HistoryRewrittenError
	if !errors.As(err, &he) || he.LastGood != good {
		t.Fatalf("%v", err)
	}
	if sh(t, e.server, "status", "--porcelain") != "" {
		t.Fatal("our unpushed commit must be dropped and the tree left clean")
	}
	if sh(t, e.server, "rev-parse", "HEAD") != good {
		t.Fatal("clone must stay on the last good commit")
	}
}

func TestUnrelatedNewRootIsRewrittenTooAndNoRemoteIsFine(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	s := open(t, e.server, nil)
	// Branch deleted and recreated from scratch with an unrelated history.
	sh(t, e.laptop, "checkout", "--quiet", "--orphan", "fresh")
	sh(t, e.laptop, "commit", "-qm", "fresh start")
	sh(t, e.laptop, "push", "--quiet", "--force", "origin", "fresh:main")
	if err := s.Pull(ctx); !errors.Is(err, ErrHistoryRewritten) {
		t.Fatalf("%v", err)
	}
	// Without a remote there is nothing to rewrite.
	local := open(t, localRepo(t), nil)
	if local.Alert() != nil || acceptErr(local) == nil {
		t.Fatal("no remote: no alert, nothing to accept")
	}
	if _, err := local.Write(ctx, edit.Op{Kind: edit.Add, Collection: "todo", Data: map[string]any{"item": "y", "status": "待办"}}, editor); err != nil {
		t.Fatal(err)
	}
}

func acceptErr(s *Store) error {
	_, err := s.AcceptRemote(context.Background(), "abcdef0")
	return err
}

func TestOwnPushAdvancesLastGoodSoALaterRewriteIsNotMistakenForDivergence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	s := open(t, e.server, nil)
	g := sh(t, e.bare, "rev-parse", "main")
	if _, err := s.Write(ctx, sshEdit(t, s, "TCP 22"), editor); err != nil {
		t.Fatal(err)
	}
	c := sh(t, e.bare, "rev-parse", "main")
	if s.lastGood != c || lastGoodOnDisk(t, e.server) != c {
		t.Fatalf("last good must follow our own push: mem %s disk %s want %s", s.lastGood, lastGoodOnDisk(t, e.server), c)
	}
	// Somebody force-pushes G+X: it descends from G but not from C.
	sh(t, e.laptop, "fetch", "--quiet")
	sh(t, e.laptop, "reset", "--quiet", "--hard", g)
	p := filepath.Join(e.laptop, "docs/ledger/todo.yml")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append(b, "- {item: x, status: 待办}\n"...), 0o644)
	sh(t, e.laptop, "commit", "-qam", "G+X")
	sh(t, e.laptop, "push", "--quiet", "--force", "origin", "main")
	x := sh(t, e.bare, "rev-parse", "main")

	var he *HistoryRewrittenError
	if err := s.Pull(ctx); !errors.As(err, &he) || he.LastGood != c || he.Remote != x {
		t.Fatalf("pull: %v", err)
	}
	_, err := s.Write(ctx, sshEdit(t, s, "TCP 2222"), editor)
	if !errors.Is(err, ErrHistoryRewritten) || errors.Is(err, ErrRepoDiverged) {
		t.Fatalf("must be history_rewritten, not repo_diverged: %v", err)
	}
	if a := s.Alert(); a == nil || a.Kind != AlertHistoryRewritten {
		t.Fatalf("%+v", a)
	}
}

func TestAcceptRemoteRefusalsChangeNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	pushLaptop(t, e, "one")
	s := open(t, e.server, nil)
	tip := sh(t, e.bare, "rev-parse", "main")
	// No alert: refused, even for the right tip.
	if _, err := s.AcceptRemote(ctx, tip); !errors.Is(err, ErrNoAlert) {
		t.Fatalf("no alert: %v", err)
	}
	if s.Alert() != nil || sh(t, e.server, "rev-parse", "HEAD") != tip {
		t.Fatal("nothing may change")
	}

	good := tip
	bad := rewriteRemote(t, e, "after")
	if err := s.Pull(ctx); !errors.Is(err, ErrHistoryRewritten) {
		t.Fatal(err)
	}
	// A dirty tree.
	f := filepath.Join(e.server, "docs/ledger/todo.yml")
	orig, _ := os.ReadFile(f)
	os.WriteFile(f, append(append([]byte{}, orig...), "# hand edit\n"...), 0o644)
	if _, err := s.AcceptRemote(ctx, bad); !errors.Is(err, ErrRepoDirty) {
		t.Fatalf("dirty: %v", err)
	}
	if got, _ := os.ReadFile(f); string(got) == string(orig) {
		t.Fatal("the hand edit must survive")
	}
	os.WriteFile(f, orig, 0o644)
	// A local commit that exists nowhere else.
	os.WriteFile(f, append(append([]byte{}, orig...), "- {item: local-only, status: 待办}\n"...), 0o644)
	sh(t, e.server, "commit", "-qam", "local only")
	local := sh(t, e.server, "rev-parse", "HEAD")
	if _, err := s.AcceptRemote(ctx, bad); !errors.Is(err, ErrLocalCommits) {
		t.Fatalf("local commits: %v", err)
	}
	if sh(t, e.server, "rev-parse", "HEAD") != local || s.Alert() == nil || lastGoodOnDisk(t, e.server) != good {
		t.Fatal("a refused accept must not move the clone, the alert or the base")
	}
	// Dropping our own stray commit (an operator's decision) lets it through.
	sh(t, e.server, "reset", "--quiet", "--hard", good)
	if got, err := s.AcceptRemote(ctx, bad); err != nil || got != bad {
		t.Fatalf("%q %v", got, err)
	}
	// And a second accept has nothing to accept.
	if _, err := s.AcceptRemote(ctx, bad); !errors.Is(err, ErrNoAlert) {
		t.Fatalf("%v", err)
	}
}

func TestAcceptRemoteInCloneFollowsTheSameRules(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	pushLaptop(t, e, "one")
	sh(t, e.server, "pull", "--quiet")
	good := sh(t, e.bare, "rev-parse", "main")
	if _, err := AcceptRemoteInClone(ctx, filepath.Join(e.server, "rackbook.yml"), good); !errors.Is(err, ErrNoAlert) {
		t.Fatalf("%v", err)
	}
	if _, err := CheckRemoteHistory(ctx, e.server, true); err != nil { // records the base
		t.Fatal(err)
	}
	bad := rewriteRemote(t, e, "after")
	var he *HistoryRewrittenError
	if _, err := CheckRemoteHistory(ctx, e.server, true); !errors.As(err, &he) {
		t.Fatalf("%v", err)
	}
	if _, err := AcceptRemoteInClone(ctx, filepath.Join(e.server, "rackbook.yml"), good); !errors.Is(err, ErrNotRemoteTip) {
		t.Fatalf("%v", err)
	}
	headBefore := sh(t, e.server, "rev-parse", "HEAD")
	got, err := AcceptRemoteInClone(ctx, filepath.Join(e.server, "rackbook.yml"), bad)
	if err != nil || got != bad || lastGoodOnDisk(t, e.server) != bad {
		t.Fatalf("%q %v", got, err)
	}
	if sh(t, e.server, "rev-parse", "HEAD") != headBefore {
		t.Fatal("the CLI accept must never reset or move the user's branch")
	}
	if _, err := CheckRemoteHistory(ctx, e.server, true); err != nil {
		t.Fatalf("accepted history must pass: %v", err)
	}
}

func TestCLIPushAdvancesLastGoodSoRemovingOnlyOurCommitIsARewrite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	sh(t, e.server, "config", "user.name", "Me")
	sh(t, e.server, "config", "user.email", "me@example.com")
	g := sh(t, e.bare, "rev-parse", "main")
	testutil.Replace(t, e.server, "docs/ledger/todo.yml", "status: 推迟}", "status: 完成}")
	if _, err := CommitFiles(ctx, e.server, []string{"docs/ledger/todo.yml"}, "ledger(todo): edit x", nil, "todo/x"); err != nil {
		t.Fatal(err)
	}
	if err := PushCurrent(ctx, e.server); err != nil {
		t.Fatal(err)
	}
	c := sh(t, e.bare, "rev-parse", "main")
	if lastGoodOnDisk(t, e.server) != c {
		t.Fatalf("PushCurrent must record the pushed commit: %s want %s", lastGoodOnDisk(t, e.server), c)
	}
	// Somebody force-pushes G+X, dropping only our commit.
	sh(t, e.laptop, "fetch", "--quiet")
	sh(t, e.laptop, "reset", "--quiet", "--hard", g)
	p := filepath.Join(e.laptop, "docs/ledger/todo.yml")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append(b, "- {item: x, status: 待办}\n"...), 0o644)
	sh(t, e.laptop, "commit", "-qam", "G+X")
	sh(t, e.laptop, "push", "--quiet", "--force", "origin", "main")
	// The commit is still in our clone; pushing again must not re-add it.
	if err := PushCurrent(ctx, e.server); !errors.Is(err, ErrHistoryRewritten) {
		t.Fatalf("PushCurrent: %v", err)
	}
	if _, err := CommitFiles(ctx, e.server, []string{"docs/ledger/todo.yml"}, "ledger(todo): edit y", nil, "todo/y"); !errors.Is(err, ErrHistoryRewritten) {
		t.Fatalf("CommitFiles: %v", err)
	}
}

func TestServerCloneMustContainOnlyTrackedFiles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	pushLaptop(t, e, "one")
	sh(t, e.server, "pull", "--quiet")
	s := open(t, e.server, nil)
	bad := rewriteRemote(t, e, "after")
	if err := s.Pull(ctx); !errors.Is(err, ErrHistoryRewritten) {
		t.Fatal(err)
	}
	// Any untracked or ignored file refuses accept, nothing is changed.
	stray := filepath.Join(e.server, "notes.txt")
	os.WriteFile(stray, []byte("mine"), 0o644)
	if _, err := s.AcceptRemote(ctx, bad); !errors.Is(err, ErrRepoDirty) {
		t.Fatalf("untracked: %v", err)
	}
	os.Remove(stray)
	os.WriteFile(filepath.Join(e.server, ".git", "info", "exclude"), []byte("secret.env\n"), 0o644)
	os.WriteFile(filepath.Join(e.server, "secret.env"), []byte("x"), 0o644)
	if _, err := s.AcceptRemote(ctx, bad); !errors.Is(err, ErrRepoDirty) {
		t.Fatalf("ignored: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(e.server, "secret.env")); string(b) != "x" || s.Alert() == nil {
		t.Fatal("nothing may change")
	}
	os.Remove(filepath.Join(e.server, "secret.env"))
	if _, err := s.AcceptRemote(ctx, bad); err != nil {
		t.Fatal(err)
	}

	// Writes and pulls refuse too, for an unrelated file, a file that collides with an
	// incoming one, and a directory where an incoming file goes.
	for name, path := range map[string]string{"unrelated": "unrelated.txt", "collides": "docs/ledger/new.txt", "case": "docs/ledger/NEW.TXT", "dir-vs-file": "docs/ledger/new.txt/inner"} {
		sh(t, e.laptop, "pull", "--quiet", "--ff-only")
		if _, err := os.Stat(filepath.Join(e.laptop, "docs/ledger/new.txt")); err != nil {
			os.WriteFile(filepath.Join(e.laptop, "docs/ledger/new.txt"), []byte("theirs"), 0o644)
			sh(t, e.laptop, "add", ".")
			sh(t, e.laptop, "commit", "-qm", "adds new.txt")
			sh(t, e.laptop, "push", "--quiet", "origin", "main")
		}
		mine := filepath.Join(e.server, path)
		os.MkdirAll(filepath.Dir(mine), 0o755)
		if err := os.WriteFile(mine, []byte("mine"), 0o644); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := s.Write(ctx, sshEdit(t, s, "TCP 22"), editor); !errors.Is(err, ErrRepoDirty) {
			t.Fatalf("%s: write: %v", name, err)
		}
		if err := s.Pull(ctx); !errors.Is(err, ErrRepoDirty) {
			t.Fatalf("%s: pull: %v", name, err)
		}
		if b, _ := os.ReadFile(mine); string(b) != "mine" {
			t.Fatalf("%s: the file was touched", name)
		}
		os.RemoveAll(mine)
		os.Remove(filepath.Dir(mine) + "/") // only if it became empty
	}
	if _, err := s.Write(ctx, sshEdit(t, s, "TCP 22"), editor); err != nil {
		t.Fatalf("a clean clone writes again: %v", err)
	}
}

func TestAcceptRemoteRefusesATipWhoseConfigDoesNotLoad(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	pushLaptop(t, e, "one")
	s := open(t, e.server, nil)
	good := sh(t, e.bare, "rev-parse", "main")
	sh(t, e.laptop, "fetch", "--quiet")
	sh(t, e.laptop, "reset", "--quiet", "--hard", "origin/main~1")
	os.WriteFile(filepath.Join(e.laptop, "rackbook.yml"), []byte("title: [unclosed\n"), 0o644)
	sh(t, e.laptop, "commit", "-qam", "break the config")
	sh(t, e.laptop, "push", "--quiet", "--force", "origin", "main")
	bad := sh(t, e.bare, "rev-parse", "main")
	if err := s.Pull(ctx); !errors.Is(err, ErrHistoryRewritten) {
		t.Fatal(err)
	}
	if _, err := s.AcceptRemote(ctx, bad); !errors.Is(err, ErrConfig) {
		t.Fatalf("%v", err)
	}
	if sh(t, e.server, "rev-parse", "HEAD") != good || lastGoodOnDisk(t, e.server) != good || s.Alert() == nil || s.Alert().Kind != AlertHistoryRewritten {
		t.Fatal("a refused accept must change nothing")
	}
	if _, err := AcceptRemoteInClone(ctx, filepath.Join(e.server, "rackbook.yml"), bad); !errors.Is(err, ErrConfig) {
		t.Fatalf("clone: %v", err)
	}
}

func TestLastGoodIsStoredPerBranchAndTheOldFileIsMigrated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	good := sh(t, e.bare, "rev-parse", "main")
	// A single-file state from before: migrated for the configured branch.
	gitDir := filepath.Join(e.server, ".git")
	os.WriteFile(filepath.Join(gitDir, "rackbook-last-good"), []byte(good+"\n"), 0o644)
	s := open(t, e.server, nil)
	if fi, err := os.Stat(filepath.Join(gitDir, "rackbook-last-good")); err != nil || !fi.IsDir() {
		t.Fatalf("the old file must become a directory: %v", err)
	}
	if s.lastGood != good || lastGoodOnDisk(t, e.server) != good {
		t.Fatalf("migration: %q %q", s.lastGood, lastGoodOnDisk(t, e.server))
	}
	// Another branch has its own file, with the branch name escaped.
	r := &Repo{Dir: e.server}
	other := sh(t, e.bare, "rev-parse", "main")
	if err := r.writeLastGood(ctx, "feature/x y", other); err != nil {
		t.Fatal(err)
	}
	if got := r.readLastGood(ctx, "feature/x y"); got != other || r.readLastGood(ctx, "feature/z") != "" {
		t.Fatalf("%q", got)
	}
	if _, err := os.Stat(filepath.Join(gitDir, "rackbook-last-good", "feature%2Fx%20y")); err != nil {
		t.Fatal("the branch name must be escaped into one safe file name")
	}
	if got := r.readLastGood(ctx, "main"); got != good {
		t.Fatalf("main must be unaffected: %q", got)
	}
	// Switching branches in a clone does not mix the bases up.
	if err := r.writeLastGood(ctx, "main", good); err != nil {
		t.Fatal(err)
	}
}

func TestAcceptedTipWithAnEscapingSymlinkIsRolledBack(t *testing.T) {
	t.Parallel()
	testutil.SkipOnWindows(t, "committing a symbolic link needs core.symlinks, which Git for Windows does not enable by default; the escaping-symlink check itself is covered by TestResolveRefusesSymlinksOutOfTheRoot")
	ctx := context.Background()
	e := newEnv(t)
	pushLaptop(t, e, "one")
	sh(t, e.server, "pull", "--quiet")
	s := open(t, e.server, nil)
	good := sh(t, e.bare, "rev-parse", "main")
	// The rewritten tip turns a schema file into a symlink that leaves the repository.
	sh(t, e.laptop, "fetch", "--quiet")
	sh(t, e.laptop, "reset", "--quiet", "--hard", "origin/main~1")
	schema := filepath.Join(e.laptop, "schemas/todo.json")
	os.Remove(schema)
	if err := os.Symlink("/etc/hosts", schema); err != nil {
		t.Fatal(err)
	}
	sh(t, e.laptop, "add", ".")
	sh(t, e.laptop, "commit", "-qm", "evil symlink")
	sh(t, e.laptop, "push", "--quiet", "--force", "origin", "main")
	bad := sh(t, e.bare, "rev-parse", "main")
	if err := s.Pull(ctx); !errors.Is(err, ErrHistoryRewritten) {
		t.Fatal(err)
	}
	if _, err := s.AcceptRemote(ctx, bad); !errors.Is(err, ErrConfig) {
		t.Fatalf("%v", err)
	}
	if sh(t, e.server, "rev-parse", "HEAD") != good || lastGoodOnDisk(t, e.server) != good {
		t.Fatal("the clone and the base must be restored")
	}
	if a := s.Alert(); a == nil || a.Kind != AlertHistoryRewritten || a.Remote != bad {
		t.Fatalf("the rewritten alert must remain: %+v", a)
	}
	if s.ConfigProblem() != "" || s.Ledger().Collection("todo").Get("one") == nil {
		t.Fatalf("the old config must be serving again: %q", s.ConfigProblem())
	}
	if fi, err := os.Lstat(filepath.Join(e.server, "schemas/todo.json")); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("the symlink must be gone after the rollback")
	}
}

func TestOfflineCheckOnlyForCommitNeverForPush(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	sh(t, e.server, "config", "user.name", "Me")
	sh(t, e.server, "config", "user.email", "me@example.com")
	sh(t, e.server, "remote", "set-url", "origin", filepath.Join(e.server, "no-such-remote.git"))
	if offline, err := CheckRemoteHistory(ctx, e.server, false); err != nil || !offline {
		t.Fatalf("--commit may go on offline: %v %v", offline, err)
	}
	if _, err := CheckRemoteHistory(ctx, e.server, true); err == nil || !strings.Contains(err.Error(), "before pushing") {
		t.Fatalf("--push must fail when the remote cannot be checked: %v", err)
	}
	testutil.Replace(t, e.server, "docs/ledger/todo.yml", "status: 推迟}", "status: 完成}")
	if _, err := CommitFiles(ctx, e.server, []string{"docs/ledger/todo.yml"}, "ledger(todo): edit x", nil, "todo/x"); err != nil {
		t.Fatalf("committing offline works: %v", err)
	}
	if err := PushCurrent(ctx, e.server); err == nil {
		t.Fatal("PushCurrent must not push (or skip the check) when the remote cannot be fetched")
	}
}

func TestMigrationOnlyForTheCheckedOutBranchAndNeverLosesTheOldFile(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	good := sh(t, e.bare, "rev-parse", "main")
	gitDir := filepath.Join(e.server, ".git")
	old := filepath.Join(gitDir, "rackbook-last-good")
	os.WriteFile(old, []byte(good+"\n"), 0o644)
	r := &Repo{Dir: e.server}
	// Another branch: no guessing, the old file stays.
	if got := r.readLastGood(ctx, "feature"); got != "" {
		t.Fatalf("%q", got)
	}
	if err := r.writeLastGood(ctx, "feature", good); err == nil {
		t.Fatal("must not write a base for another branch while the old file is unmigrated")
	}
	if fi, err := os.Stat(old); err != nil || fi.IsDir() {
		t.Fatal("the old file must still be there")
	}
	// A failing migration leaves the old file alone.
	if runtime.GOOS == "windows" {
		t.Log("SKIPPED on Windows: the failed-migration case (a read-only .git via chmod 0555) does not apply; Windows ignores directory permission bits")
	} else if os.Getuid() != 0 {
		os.Chmod(gitDir, 0o555)
		got := r.readLastGood(ctx, "main")
		os.Chmod(gitDir, 0o755)
		if got != "" {
			t.Fatalf("%q", got)
		}
		if fi, err := os.Stat(old); err != nil || fi.IsDir() {
			t.Fatal("a failed migration must keep the old file")
		}
	}
	// The checked-out branch migrates; no temporary files are left.
	if got := r.readLastGood(ctx, "main"); got != good {
		t.Fatalf("%q", got)
	}
	if err := r.writeLastGood(ctx, "feature", good); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(old)
	names := map[string]bool{}
	for _, en := range entries {
		names[en.Name()] = true
	}
	if len(names) != 2 || !names["main"] || !names["feature"] {
		t.Fatalf("only the two branch files may exist: %v", names)
	}
	if left, _ := filepath.Glob(filepath.Join(gitDir, ".tmp-*")); len(left) != 0 {
		t.Fatalf("temporary leftovers: %v", left)
	}
	// Temp names cannot collide with a branch file: they start with a dot.
	if strings.HasPrefix(url.PathEscape("main"), ".") {
		t.Fatal("unreachable")
	}
}

func TestRunCallsAfterPullAfterAPull(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	pulled := make(chan struct{}, 8)
	s := open(t, e.server, func(o *Options) {
		o.PullInterval = 5 * time.Millisecond
		o.AfterPull = func() { pulled <- struct{}{} }
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	select {
	case <-pulled:
	case <-time.After(30 * time.Second):
		t.Fatal("AfterPull was not called after a successful pull")
	}
}
