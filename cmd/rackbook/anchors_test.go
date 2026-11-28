package main

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

func anchorGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Seed", "GIT_AUTHOR_EMAIL=seed@example.com", "GIT_COMMITTER_NAME=Seed", "GIT_COMMITTER_EMAIL=seed@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestServeWiringChecksAnchorsAfterAPull runs the code serve runs: anchorWiring.AfterPull is the
// store's AfterPull hook, Start is called once the store is open, and the store's own pull loop
// calls the hook. A bad anchor that arrives by pull ends up recorded in the audit log.
func TestServeWiringChecksAnchorsAfterAPull(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	bare, server, laptop := filepath.Join(root, "origin.git"), filepath.Join(root, "server"), filepath.Join(root, "laptop")
	anchorGit(t, root, "init", "--bare", "-b", "main", bare)
	seed := testutil.CopyExample(t)
	anchorGit(t, seed, "init", "-b", "main")
	anchorGit(t, seed, "add", ".")
	anchorGit(t, seed, "commit", "-m", "seed")
	anchorGit(t, seed, "remote", "add", "origin", bare)
	anchorGit(t, seed, "push", "origin", "main")
	anchorGit(t, root, "clone", bare, server)
	anchorGit(t, root, "clone", bare, laptop)

	l, err := audit.Open(filepath.Join(root, "state", "audit"), audit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < 5; i++ {
		l.Record(audit.Event{Event: "login", Identity: "ann@example.com"})
	}
	var logs strings.Builder
	w := &anchorWiring{log: l, logger: slog.New(slog.NewTextHandler(&logs, nil))}
	pulled := make(chan struct{}, 64)
	store, err := gitstore.Open(context.Background(), gitstore.Options{ConfigPath: filepath.Join(server, "rackbook.yml"),
		PullInterval: 5 * time.Millisecond,
		AfterPull: func() {
			w.AfterPull()
			select {
			case pulled <- struct{}{}:
			default:
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx, store, true) // read-only: no writer loop, only checking
	go store.Run(ctx)
	if !l.Status().OK {
		t.Fatalf("%+v", l.Status())
	}

	// a commit pushed by somebody else: an anchor that does not match the line at its seq
	bad := audit.Anchor{Day: "2026-11-01", Seq: 3, Hash: "sha256:" + strings.Repeat("d", 64), At: "2026-11-01T03:00:00Z"}
	if err := os.MkdirAll(filepath.Join(laptop, ".rackbook"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(laptop, ".rackbook", "audit-anchors"), bad.Line(), 0o644); err != nil {
		t.Fatal(err)
	}
	anchorGit(t, laptop, "add", ".")
	anchorGit(t, laptop, "commit", "-m", "anchor")
	anchorGit(t, laptop, "push", "origin", "main")

	deadline := time.After(60 * time.Second)
	for l.Status().OK {
		select {
		case <-pulled:
		case <-deadline:
			t.Fatal("the anchor that came with a pull was not checked")
		}
	}
	st := l.Status()
	if len(st.Problems) != 1 || st.Problems[0].Kind != audit.KindAnchorMismatch || st.Problems[0].Seq != 3 {
		t.Fatalf("%+v", st)
	}
}
