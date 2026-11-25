package gitstore

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=T", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-c", "protocol.file.allow=always"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// mirrorFixture makes a bare origin with one commit on main and a clone of it.
func mirrorFixture(t *testing.T) (bare, work, seed string) {
	t.Helper()
	root := t.TempDir()
	bare = filepath.Join(root, "origin.git")
	seed = filepath.Join(root, "seed")
	work = filepath.Join(root, "work")
	gitIn(t, root, "init", "--bare", "--initial-branch=main", bare)
	gitIn(t, root, "clone", bare, seed)
	if err := os.WriteFile(filepath.Join(seed, "a.txt"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, seed, "add", "a.txt")
	gitIn(t, seed, "commit", "-m", "first")
	gitIn(t, seed, "push", "origin", "HEAD:refs/heads/main")
	gitIn(t, root, "clone", "--branch", "main", bare, work)
	return bare, work, seed
}

func TestMirrorFollowsOriginAndDiscardsLocalChanges(t *testing.T) {
	t.Parallel()
	_, work, seed := mirrorFixture(t)
	m := &Mirror{Dir: work, Branch: "main"}
	ctx := context.Background()
	h1, err := m.Sync(ctx)
	if err != nil || h1 != gitIn(t, seed, "rev-parse", "HEAD") {
		t.Fatalf("first sync: %v %s", err, h1)
	}
	// a new commit on origin, and a local edit that must not survive
	if err := os.WriteFile(filepath.Join(seed, "a.txt"), []byte("two\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, seed, "commit", "-am", "second")
	gitIn(t, seed, "push", "origin", "HEAD:refs/heads/main")
	if err := os.WriteFile(filepath.Join(work, "a.txt"), []byte("local\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h2, err := m.Sync(ctx)
	if err != nil || h2 != gitIn(t, seed, "rev-parse", "HEAD") || h2 == h1 {
		t.Fatalf("second sync: %v %s", err, h2)
	}
	if b, _ := os.ReadFile(filepath.Join(work, "a.txt")); string(b) != "two\n" {
		t.Fatalf("work tree not reset: %q", b)
	}
	log, err := m.Log(ctx, 50)
	if err != nil || len(log) != 2 || log[0].Subject != "second" || log[0].Hash != h2 || log[0].Time.IsZero() {
		t.Fatalf("log: %v %+v", err, log)
	}
}

func TestMirrorNeverWritesToTheRemote(t *testing.T) {
	t.Parallel()
	bare, work, _ := mirrorFixture(t)
	before := gitIn(t, bare, "for-each-ref")
	m := &Mirror{Dir: work, Branch: "main"}
	if _, err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if after := gitIn(t, bare, "for-each-ref"); after != before {
		t.Fatalf("remote refs changed:\n%s\n%s", before, after)
	}
	for _, c := range rec.all() {
		if len(c.Args) > 0 && strings.Contains(strings.Join(c.Args, " "), "push") && strings.Contains(c.Dir, work) {
			t.Fatalf("mirror ran %v", c.Args)
		}
	}
}

func TestMirrorRefusesWhatIsNotAClone(t *testing.T) {
	t.Parallel()
	m := &Mirror{Dir: t.TempDir(), Branch: "main"}
	if _, err := m.Sync(context.Background()); err == nil {
		t.Fatal("want an error for a directory that is not a work tree")
	}
	if _, err := (&Mirror{Dir: t.TempDir(), Branch: "--evil"}).Sync(context.Background()); err == nil {
		t.Fatal("want an error for an unusable branch")
	}
}

func TestMirrorSSHCommandIsInTheEnvironmentOnly(t *testing.T) {
	t.Parallel()
	m := &Mirror{Dir: "/x", Branch: "main", SSHKey: "/data/ssh/it's key", KnownHosts: "/data/ssh/known_hosts"}
	env := m.env()
	if len(env) != 1 || !strings.HasPrefix(env[0], "GIT_SSH_COMMAND=ssh -i '/data/ssh/it'\\''s key' ") ||
		!strings.Contains(env[0], "IdentitiesOnly=yes") || !strings.Contains(env[0], "StrictHostKeyChecking=yes") ||
		!strings.Contains(env[0], "UserKnownHostsFile='/data/ssh/known_hosts'") {
		t.Fatalf("env: %v", env)
	}
	// without a key the inherited GIT_SSH_COMMAND (the ledger's key in the container) must not be used either
	if env := (&Mirror{}).env(); len(env) != 1 || !strings.HasPrefix(env[0], "GIT_SSH_COMMAND=ssh -o BatchMode=yes") || strings.Contains(env[0], "-i ") {
		t.Fatalf("no key: %v", env)
	}
}
