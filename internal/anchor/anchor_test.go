package anchor

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

func sh(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Seed", "GIT_AUTHOR_EMAIL=seed@example.com",
		"GIT_COMMITTER_NAME=Seed", "GIT_COMMITTER_EMAIL=seed@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

type clock struct{ t time.Time }

func (c *clock) Now() time.Time { return c.t }

type env struct {
	bare, server string
	clk          *clock
	log          *audit.Log
	logDir       string
	store        *gitstore.Store
	a            *Anchorer
	logs         *strings.Builder
}

// newEnv is a data repository with audit.anchor set as given, a bare origin that
// can be made to refuse pushes, a real audit log with the store's commit hook
// writing to it (as serve wires it) and a fake clock.
func newEnv(t *testing.T, anchorYAML string) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{bare: filepath.Join(root, "origin.git"), server: filepath.Join(root, "server"),
		clk: &clock{time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)}, logs: &strings.Builder{}}
	sh(t, root, "init", "--bare", "-b", "main", e.bare)
	hook := "#!/bin/sh\nif [ -e \"$GIT_DIR/reject\" ]; then echo refused >&2; exit 1; fi\n"
	if err := os.WriteFile(filepath.Join(e.bare, "hooks", "pre-receive"), []byte(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	seed := testutil.CopyExample(t)
	if anchorYAML != "" {
		f, err := os.OpenFile(filepath.Join(seed, "rackbook.yml"), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString("\n" + anchorYAML); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	sh(t, seed, "init", "-b", "main")
	sh(t, seed, "add", ".")
	sh(t, seed, "commit", "-m", "seed")
	sh(t, seed, "remote", "add", "origin", e.bare)
	sh(t, seed, "push", "origin", "main")
	sh(t, root, "clone", e.bare, e.server)

	e.logDir = filepath.Join(root, "state", "audit")
	var err error
	if e.log, err = audit.Open(e.logDir, audit.Options{Now: e.clk.Now}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.log.Close)
	e.store, err = gitstore.Open(context.Background(), gitstore.Options{ConfigPath: filepath.Join(e.server, "rackbook.yml"),
		Committer: gitstore.Identity{Name: "Rackbook", Email: "rackbook@example.org"},
		OnCommit: func(hash string, who *auth.Identity, record string) {
			ev := audit.Event{Event: "commit", Area: "ledger", Repo: "ledger", Hash: hash, Record: record}
			ev.By(who)
			e.log.Record(ev)
		}})
	if err != nil {
		t.Fatal(err)
	}
	e.a = &Anchorer{Log: e.log, Store: e.store, Now: e.clk.Now}
	return e
}

func (e *env) activity(n int) {
	for i := 0; i < n; i++ {
		e.log.Record(audit.Event{Event: "login", Identity: "ann@example.com"})
	}
}

// anchors is the anchor file on origin.
func (e *env) anchors(t *testing.T) audit.Anchors {
	t.Helper()
	cmd := exec.Command("git", "-C", e.bare, "show", "main:"+audit.AnchorsPath)
	out, err := cmd.Output()
	if err != nil {
		return audit.Anchors{}
	}
	return audit.ParseAnchors(out)
}

func (e *env) anchorCommits(t *testing.T) []string {
	t.Helper()
	out := sh(t, e.bare, "log", "--format=%s", "--grep=^audit: anchor")
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

func (e *env) tick(t *testing.T) {
	t.Helper()
	if err := e.a.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOneAnchorPerDayAndOnlyWhenTheLogMovedOn(t *testing.T) {
	e := newEnv(t, "audit:\n  anchor: daily\n")
	e.activity(3)
	seq1, hash1 := e.log.Head()

	e.tick(t)
	as := e.anchors(t)
	if len(as.List) != 1 {
		t.Fatalf("%+v", as)
	}
	a := as.List[0]
	if a.Day != "2026-11-20" || a.Seq != seq1 || a.Hash != hash1 || a.At != "2026-11-20T10:00:00Z" {
		t.Fatalf("%+v, head was %d %s", a, seq1, hash1)
	}
	if got := e.anchorCommits(t); len(got) != 1 || got[0] != "audit: anchor seq "+itoa(seq1) {
		t.Fatalf("%q", got)
	}
	// a Rackbook commit like any other: its commit event is in the log, after the anchored seq
	hash := sh(t, e.bare, "log", "-1", "--format=%H")
	found := false
	page, err := e.log.Read(audit.Query{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range page.Events {
		if ev.Event == "commit" && ev.Hash == hash {
			found = true
			if ev.Seq <= seq1 || ev.Identity != Identity.ID {
				t.Fatalf("%+v", ev)
			}
		}
	}
	if !found {
		t.Fatal("the anchor commit has no commit event in the audit log")
	}
	if tr := sh(t, e.bare, "log", "-1", "--format=%B"); !strings.Contains(tr, "Edited-by: "+Identity.ID) {
		t.Fatalf("commit message %q", tr)
	}

	// the same day, more activity: still one
	e.activity(2)
	e.clk.t = e.clk.t.Add(10 * time.Hour) // 20:00 the same UTC day
	e.tick(t)
	if len(e.anchors(t).List) != 1 {
		t.Fatal("a second anchor on the same UTC day")
	}

	// the next day with nothing new but the anchor's own commit event ... there was activity (2 logins)
	e.clk.t = time.Date(2026, 11, 21, 0, 0, 1, 0, time.UTC)
	e.tick(t)
	if got := e.anchors(t).List; len(got) != 2 || got[1].Day != "2026-11-21" {
		t.Fatalf("%+v", got)
	}
	seq2 := e.anchors(t).List[1].Seq
	if seq2 <= seq1 {
		t.Fatalf("seq did not advance: %d then %d", seq1, seq2)
	}

	// the day after, the log only holds the anchor's own commit event: no anchor
	e.clk.t = time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)
	e.tick(t)
	e.tick(t)
	if len(e.anchors(t).List) != 2 {
		t.Fatalf("an idle log must not get a daily anchor: %+v", e.anchors(t).List)
	}
	// real activity makes the next tick write one
	e.activity(1)
	e.tick(t)
	if got := e.anchors(t).List; len(got) != 3 || got[2].Day != "2026-11-22" {
		t.Fatalf("%+v", got)
	}
	// and the file only ever grew by lines
	if b := sh(t, e.bare, "show", "main:"+audit.AnchorsPath); strings.Count(b, "\n") != 2 {
		t.Fatalf("%q", b)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestNothingIsWrittenWhenTheSettingIsOffOrThereIsNoLog(t *testing.T) {
	for _, yml := range []string{"", "audit:\n  anchor: off\n"} {
		e := newEnv(t, yml)
		e.activity(2)
		e.tick(t)
		if len(e.anchorCommits(t)) != 0 {
			t.Fatalf("%q: an anchor was written with the setting off", yml)
		}
	}
	// daily, but no audit log (no --state-dir): a warning, once, and nothing else
	e := newEnv(t, "audit:\n  anchor: daily\n")
	var logs strings.Builder
	e.a = &Anchorer{Store: e.store, Now: e.clk.Now, Logger: slog.New(slog.NewTextHandler(&logs, nil))}
	e.tick(t)
	e.tick(t)
	if strings.Count(logs.String(), "without --state-dir") != 1 || len(e.anchorCommits(t)) != 0 {
		t.Fatalf("logs %q, anchors %v", logs.String(), e.anchorCommits(t))
	}
	e.a.Verify() // and verifying without a log is a no-op
}

func TestAFailedPushLeavesNothingAndTheNextTickRetries(t *testing.T) {
	e := newEnv(t, "audit:\n  anchor: daily\n")
	var logs strings.Builder
	e.a.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	e.activity(2)
	if err := os.WriteFile(filepath.Join(e.bare, "reject"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	err := e.a.Tick(context.Background())
	if err == nil || !strings.Contains(err.Error(), "audit anchor for seq") {
		t.Fatalf("err = %v", err)
	}
	if st := sh(t, e.server, "status", "--porcelain", "--untracked-files=all"); st != "" {
		t.Fatalf("debris after a failed push: %s", st)
	}
	if len(e.anchors(t).List) != 0 {
		t.Fatal("nothing reached origin")
	}
	if p := filepath.Join(e.server, filepath.FromSlash(audit.AnchorsPath)); fileExists(p) {
		t.Fatal("the failed anchor is still in the clone")
	}
	// the remote takes pushes again: the next tick writes it, for the head as it is now
	if err := os.Remove(filepath.Join(e.bare, "reject")); err != nil {
		t.Fatal(err)
	}
	e.clk.t = e.clk.t.Add(time.Hour)
	e.tick(t)
	seq, _ := e.log.Head()
	as := e.anchors(t).List
	if len(as) != 1 || as[0].Seq >= seq || as[0].Day != "2026-11-20" {
		t.Fatalf("%+v (head %d)", as, seq)
	}
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestUnknownLinesAreKeptAndOnlyAppendedTo(t *testing.T) {
	e := newEnv(t, "audit:\n  anchor: daily\n")
	// somebody put a malformed line, and an unknown one without a final newline, in the file
	laptop := filepath.Join(filepath.Dir(e.server), "laptop")
	sh(t, filepath.Dir(e.server), "clone", e.bare, laptop)
	junk := "garbage\n{\"day\":\"2026-11-01\",\"future\":true}"
	if err := os.MkdirAll(filepath.Join(laptop, ".rackbook"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(laptop, filepath.FromSlash(audit.AnchorsPath)), []byte(junk), 0o644); err != nil {
		t.Fatal(err)
	}
	sh(t, laptop, "add", ".")
	sh(t, laptop, "commit", "-m", "junk")
	sh(t, laptop, "push", "origin", "main")
	e.activity(2)
	e.tick(t)
	got := sh(t, e.bare, "show", "main:"+audit.AnchorsPath)
	if !strings.HasPrefix(got, junk+"\n{\"day\":\"2026-11-20\"") || strings.Count(got, "\n") != 2 {
		t.Fatalf("%q", got)
	}
	a := audit.ParseAnchors([]byte(got))
	if len(a.List) != 1 || len(a.Malformed) != 2 {
		t.Fatalf("%+v", a)
	}
	// verification reports them
	var logs strings.Builder
	e.a.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	e.a.Verify()
	e.a.Verify()
	if strings.Count(logs.String(), "are not anchors") != 1 {
		t.Fatalf("%q", logs.String())
	}
}

func TestVerifyAfterPullsRecordsATamperedAnchorOnceAndAcknowledgementClearsIt(t *testing.T) {
	e := newEnv(t, "audit:\n  anchor: daily\n")
	e.activity(3)
	e.tick(t)
	e.a.Verify()
	if st := e.log.Status(); !st.OK {
		t.Fatalf("%+v", st)
	}
	// somebody with the host rewrites the audit log consistently: the anchored line changes
	rebuilt, err := rebuild(t, e)
	if err != nil {
		t.Fatal(err)
	}
	e.log.Close()
	e.log = rebuilt
	e.a.Log = rebuilt
	var recorded func() int = func() int { return countEvents(t, e.logDir, audit.ChainProblemEvent) }
	for i := 0; i < 4; i++ { // four pulls
		e.a.Verify()
	}
	st := rebuilt.Status()
	if st.OK || len(st.Problems) != 1 || st.Problems[0].Kind != audit.KindAnchorMismatch || recorded() != 1 {
		t.Fatalf("%+v, %d recorded", st, recorded())
	}
	// the anchor is not written over a log that does not verify
	e.clk.t = e.clk.t.Add(24 * time.Hour)
	e.activity(1)
	e.tick(t)
	if len(e.anchors(t).List) != 1 {
		t.Fatal("an anchor was written while the log has an unacknowledged problem")
	}
	seq, _ := rebuilt.Head()
	if err := rebuilt.Ack(nil, seq); err != nil {
		t.Fatal(err)
	}
	e.a.Verify()
	if st := rebuilt.Status(); !st.OK || recorded() != 1 {
		t.Fatalf("%+v, %d recorded", st, recorded())
	}
}

// rebuild writes the audit log again, with the same number of lines and one of
// them different, and a head.json that matches: a rewrite the chain alone cannot see.
func rebuild(t *testing.T, e *env) (*audit.Log, error) {
	t.Helper()
	dir := filepath.Join(filepath.Dir(e.logDir), "rebuilt")
	l, err := audit.Open(dir, audit.Options{Now: e.clk.Now})
	if err != nil {
		return nil, err
	}
	old, _ := e.log.Read(audit.Query{Limit: 500})
	for i := len(old.Events) - 1; i >= 0; i-- {
		ev := old.Events[i]
		if ev.Seq == 2 {
			ev.Identity = "mallory@example.com"
		}
		ev.Seq, ev.Prev = 0, ""
		l.Record(ev)
	}
	t.Cleanup(l.Close)
	e.logDir = dir
	return l, nil
}

func countEvents(t *testing.T, dir, event string) int {
	t.Helper()
	n := 0
	files, _ := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		n += strings.Count(string(b), `"event":"`+event+`"`)
	}
	return n
}
