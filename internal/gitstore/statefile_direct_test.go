package gitstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

const stateRel = ".rackbook/passkeys.yml"

func appendLine(line string) func([]byte, bool) ([]byte, error) {
	return func(old []byte, _ bool) ([]byte, error) { return append(old, []byte(line+"\n")...), nil }
}

// updateState is MutateStateFile in direct mode, as the passkey store uses it.
func (s *Store) updateState(ctx context.Context, rel string, who *auth.Identity, subject string, fn func([]byte, bool) ([]byte, error)) error {
	_, err := s.MutateStateFile(ctx, rel, subject, who, fn, Direct())
	return err
}

func (s *Store) readState(rel string) ([]byte, error) {
	b, _, err := s.StateFile(rel)
	return b, err
}

func TestStateFileCommitsAsTheUserAndPushes(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := open(t, e.server, nil)
	if b, err := s.readState(stateRel); err != nil || b != nil {
		t.Fatalf("absent file: %q, %v", b, err)
	}
	if err := s.updateState(context.Background(), stateRel, editor, "rackbook(auth): add passkey for ann@example.com", appendLine("a: 1")); err != nil {
		t.Fatal(err)
	}
	got := sh(t, e.bare, "log", "-1", "--format=%an <%ae>|%cn|%B")
	want := "Ann Editor <ann@example.com>|Rackbook|rackbook(auth): add passkey for ann@example.com\n\nEdited-by: ann@example.com\nEdited-via: rackbook (cloudflare-access)"
	if got != want {
		t.Fatalf("commit:\n%s\nwant:\n%s", got, want)
	}
	if b, _ := s.readState(stateRel); string(b) != "a: 1\n" {
		t.Fatalf("content %q", b)
	}
	if st := sh(t, e.server, "status", "--porcelain"); st != "" {
		t.Fatalf("dirty clone: %s", st)
	}
	// No change, no commit.
	head := sh(t, e.server, "rev-parse", "HEAD")
	if err := s.updateState(context.Background(), stateRel, editor, "x", func(old []byte, _ bool) ([]byte, error) { return old, nil }); err != nil {
		t.Fatal(err)
	}
	if sh(t, e.server, "rev-parse", "HEAD") != head {
		t.Fatal("an unchanged file must not be committed")
	}
}

func TestStateFileReplaysOnAMovedRemote(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := open(t, e.server, nil)
	moved := false
	s.beforePush = func() {
		if moved {
			return
		}
		moved = true
		sh(t, e.laptop, "pull", "--quiet")
		_ = os.MkdirAll(filepath.Join(e.laptop, ".rackbook"), 0o755)
		_ = os.WriteFile(filepath.Join(e.laptop, stateRel), []byte("b: 2\n"), 0o644)
		sh(t, e.laptop, "add", ".")
		sh(t, e.laptop, "commit", "-m", "someone else")
		sh(t, e.laptop, "push", "--quiet", "origin", "main")
	}
	if err := s.updateState(context.Background(), stateRel, editor, "rackbook(auth): add passkey", appendLine("a: 1")); err != nil {
		t.Fatal(err)
	}
	// fn ran again on the new tip, so both lines are there.
	if got := sh(t, e.bare, "show", "main:"+stateRel); got != "b: 2\na: 1" {
		t.Fatalf("remote file %q", got)
	}
}

func TestStateFileFailedPushLeavesNoDebris(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := open(t, e.server, nil)
	s.pushFn = func(context.Context, string) error { return errors.New("network down") }
	err := s.updateState(context.Background(), stateRel, editor, "rackbook(auth): add passkey", appendLine("a: 1"))
	if err == nil || !strings.Contains(err.Error(), "push failed") {
		t.Fatalf("err = %v", err)
	}
	if st := sh(t, e.server, "status", "--porcelain", "--untracked-files=all"); st != "" {
		t.Fatalf("debris after a failed push: %s", st)
	}
	if _, err := os.Stat(filepath.Join(e.server, stateRel)); !os.IsNotExist(err) {
		t.Fatalf("file should be gone: %v", err)
	}
}

func TestStateFileWithoutGitWritesInPlace(t *testing.T) {
	t.Parallel()
	dir := testutil.CopyExample(t)
	s := open(t, dir, func(o *Options) { o.NoGit = true })
	if err := s.updateState(context.Background(), stateRel, &auth.Identity{ID: "a@b.c"}, "x", appendLine("a: 1")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, stateRel)); string(b) != "a: 1\n" {
		t.Fatalf("content %q", b)
	}
}

func TestStateFileRefusesPathsOutsideStateDir(t *testing.T) {
	t.Parallel()
	dir := testutil.CopyExample(t)
	s := open(t, dir, func(o *Options) { o.NoGit = true })
	for _, p := range []string{"rackbook.yml", "../x", ".rackbook", "docs/x.yml", "/etc/passwd", ".rackbook/../rackbook.yml"} {
		if err := s.updateState(context.Background(), p, nil, "x", appendLine("a")); err == nil {
			t.Errorf("%q must be refused", p)
		}
		if _, err := s.readState(p); err == nil {
			t.Errorf("reading %q must be refused", p)
		}
	}
}

func TestStateFileCommitsAreNotLedgerHistory(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := open(t, e.server, nil)
	if err := s.updateState(context.Background(), stateRel, editor, "rackbook(auth): add passkey for ann@example.com", appendLine("a: 1")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ collection, id string }{{"", ""}, {"services", ""}} {
		commits, err := s.History(context.Background(), 20, c.collection, c.id)
		if err != nil {
			t.Fatal(err)
		}
		for _, cm := range commits {
			if strings.Contains(cm.Subject, "passkey") {
				t.Errorf("history (%q) lists a state commit: %+v", c.collection, cm)
			}
		}
		if len(commits) == 0 {
			t.Errorf("history (%q) is empty", c.collection)
		}
	}
}

func TestStateFileRefusesSymlinks(t *testing.T) {
	t.Parallel()
	dir := testutil.CopyExample(t)
	outside := t.TempDir()
	testutil.Symlink(t, outside, filepath.Join(dir, ".rackbook"))
	s := open(t, dir, func(o *Options) { o.NoGit = true })
	if err := s.updateState(context.Background(), stateRel, nil, "x", appendLine("a")); err == nil {
		t.Fatal("a symlinked .rackbook must be refused")
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatalf("something was written outside the repo: %v", ents)
	}
}

func TestStateSettledIsFalseWhileAnUpdateRuns(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := open(t, e.server, nil)
	if !s.StateSettled() {
		t.Fatal("an idle clone at a loaded commit is settled")
	}
	s.mu.Lock()
	settled := s.StateSettled()
	s.mu.Unlock()
	if settled {
		t.Fatal("not settled while a write, pull or replay holds the store")
	}
}
