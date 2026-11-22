package gitstore

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// commitAt makes a commit on the laptop clone with a fixed committer date and
// pushes it.
func commitAt(t *testing.T, e env, when, msg string, files map[string]string) {
	t.Helper()
	sh(t, e.laptop, "pull", "--quiet")
	for rel, body := range files {
		p := filepath.Join(e.laptop, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sh(t, e.laptop, "add", "-A")
	cmd := exec.Command("git", "-C", e.laptop, "commit", "-q", "-m", msg)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Lap Top", "GIT_AUTHOR_EMAIL=lap@example.com", "GIT_COMMITTER_NAME=Lap Top", "GIT_COMMITTER_EMAIL=lap@example.com",
		"GIT_AUTHOR_DATE="+when, "GIT_COMMITTER_DATE="+when)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	sh(t, e.laptop, "push", "--quiet", "origin", "main")
}

func subjects(cs []ActivityCommit) string {
	var s []string
	for _, c := range cs {
		s = append(s, c.Subject)
	}
	return strings.Join(s, "|")
}

func TestActivityListsCommitsWithTheirTrailers(t *testing.T) {
	e := newEnv(t)
	s := open(t, e.server, nil)
	ctx := context.Background()
	res, err := s.Write(ctx, sshEdit(t, s, "TCP 22"), editor)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := s.Activity(ctx, ActivityQuery{})
	if err != nil || len(cs) != 2 {
		t.Fatalf("%v %+v", err, cs)
	}
	c := cs[0]
	if len(c.Hash) != 40 || !strings.HasPrefix(c.Hash, res.Commit) || c.Short != res.Commit || c.Author != "Ann Editor" || c.Email != "ann@example.com" ||
		c.Subject != "ledger(services): edit web-hostco-ashburn-va-us-dc/SSH" || c.EditedBy != "ann@example.com" || c.EditedVia != "rackbook (cloudflare-access)" ||
		len(c.Records) != 1 || c.Records[0] != "services/web-hostco-ashburn-va-us-dc/SSH" || c.State != StateNone || c.Time.Location() != time.UTC {
		t.Fatalf("%+v", c)
	}
	if cs[1].Subject != "seed" || cs[1].EditedBy != "" || len(cs[1].Records) != 0 {
		t.Fatalf("%+v", cs[1])
	}
	if cs, _ := s.Activity(ctx, ActivityQuery{Limit: 1}); len(cs) != 1 {
		t.Fatal(len(cs))
	}
}

func TestActivityFilters(t *testing.T) {
	e := newEnv(t)
	commitAt(t, e, "2026-03-01T10:00:00Z", "edit todo", map[string]string{"docs/ledger/todo.yml": "- {item: x, status: 完成}\n"})
	commitAt(t, e, "2026-03-01T10:00:00Z", "same second", map[string]string{"notes.txt": "a\n"})
	commitAt(t, e, "2026-03-05T10:00:00Z", "state only", map[string]string{".rackbook/x.yml": "a: 1\n"})
	commitAt(t, e, "2026-03-09T10:00:00Z", "both", map[string]string{".rackbook/x.yml": "a: 2\n", "notes.txt": "b\n"})
	s := open(t, e.server, nil)
	ctx := context.Background()

	cs, _ := s.Activity(ctx, ActivityQuery{})
	if subjects(cs) != "both|same second|edit todo|seed" {
		t.Fatalf("a commit that touches only .rackbook/ is not listed without includeState: %s", subjects(cs))
	}
	cs, _ = s.Activity(ctx, ActivityQuery{IncludeState: true})
	if len(cs) != 5 || cs[0].Subject != "both" || cs[0].State != StateSome || cs[1].Subject != "state only" || cs[1].State != StateOnly || cs[4].State != StateNone {
		t.Fatalf("%+v", cs)
	}
	for _, c := range cs {
		if c.Subject == "edit todo" && c.State != StateNone {
			t.Fatalf("%+v", c)
		}
	}
	d := func(s string) time.Time { x, _ := time.Parse(time.RFC3339, s); return x }
	// both ends are inclusive to the second
	cs, _ = s.Activity(ctx, ActivityQuery{IncludeState: true, Since: d("2026-03-01T10:00:00Z"), Until: d("2026-03-05T10:00:00Z")})
	if len(cs) != 3 || cs[0].Subject != "state only" {
		t.Fatalf("%s", subjects(cs))
	}
	cs, _ = s.Activity(ctx, ActivityQuery{Until: d("2026-03-01T09:59:59Z")})
	if len(cs) != 0 { // the seed commit is dated today
		t.Fatalf("%s", subjects(cs))
	}
	cs, _ = s.Activity(ctx, ActivityQuery{Until: d("2026-03-01T10:00:00Z")})
	if subjects(cs) != "same second|edit todo" {
		t.Fatalf("%s", subjects(cs))
	}
	// a collection: the commits that touched its file
	cs, err := s.Activity(ctx, ActivityQuery{Collection: "todo"})
	if err != nil || subjects(cs) != "edit todo|seed" { // the seed added the file
		t.Fatalf("%v %s", err, subjects(cs))
	}
	if _, err := s.Activity(ctx, ActivityQuery{Collection: "nope"}); err == nil {
		t.Fatal("unknown collection")
	}
	if _, err := s.Activity(ctx, ActivityQuery{ID: "x"}); err == nil {
		t.Fatal("id needs a collection")
	}
}

func TestActivityByRecordIsAnExactTrailerMatchWithoutFallback(t *testing.T) {
	e := newEnv(t)
	s := open(t, e.server, nil)
	ctx := context.Background()
	if _, err := s.Write(ctx, sshEdit(t, s, "TCP 22"), editor); err != nil {
		t.Fatal(err)
	}
	cs, err := s.Activity(ctx, ActivityQuery{Collection: "services", ID: "web-hostco-ashburn-va-us-dc/SSH"})
	if err != nil || len(cs) != 1 || cs[0].EditedBy != "ann@example.com" {
		t.Fatalf("%v %+v", err, cs)
	}
	// the prefix of an id is another record; the file history is not used instead
	cs, err = s.Activity(ctx, ActivityQuery{Collection: "services", ID: "web-hostco-ashburn-va-us-dc/SS"})
	if err != nil || len(cs) != 0 {
		t.Fatalf("%v %+v", err, cs)
	}
	cs, _ = s.Activity(ctx, ActivityQuery{Collection: "todo", ID: "whatever"})
	if len(cs) != 0 {
		t.Fatalf("%+v", cs)
	}
}

func TestMirrorActivity(t *testing.T) {
	e := newEnv(t)
	commitAt(t, e, "2026-03-01T10:00:00Z", "infra a", map[string]string{"a.yml": "a: 1\n", ".rackbook/x.yml": "a: 1\n"})
	m := &Mirror{Dir: e.server, Branch: "main"}
	if _, err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	cs, err := m.Activity(context.Background(), ActivityQuery{IncludeState: false})
	if err != nil || subjects(cs) != "infra a|seed" || cs[0].State != StateNone {
		t.Fatalf("the mirror has no state directory: %v %+v", err, cs)
	}
}

func TestCommitDiff(t *testing.T) {
	e := newEnv(t)
	big := strings.Repeat("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n", 6000) // 390 KB
	commitAt(t, e, "2026-03-01T10:00:00Z", "mixed", map[string]string{".rackbook/x.yml": "a: 1\n", "notes.txt": "hello\n"})
	commitAt(t, e, "2026-03-02T10:00:00Z", "state only", map[string]string{".rackbook/x.yml": "a: 2\n"})
	commitAt(t, e, "2026-03-03T10:00:00Z", "big", map[string]string{"big.txt": big, "small.txt": "s\n"})
	s := open(t, e.server, nil)
	ctx := context.Background()
	hashOf := func(subject string) string {
		cs, _ := s.Activity(ctx, ActivityQuery{IncludeState: true, Limit: 20})
		for _, c := range cs {
			if c.Subject == subject {
				return c.Hash
			}
		}
		t.Fatalf("no commit %q", subject)
		return ""
	}
	paths := func(d *CommitDiff) string {
		var p []string
		for _, f := range d.Files {
			p = append(p, f.Status+" "+f.Path)
		}
		return strings.Join(p, ",")
	}

	mixed := hashOf("mixed")
	d, err := s.CommitDiff(ctx, mixed, true)
	if err != nil || d.Hash != mixed || paths(d) != "A .rackbook/x.yml,A notes.txt" || !strings.Contains(d.Files[1].Patch, "+hello") || !strings.Contains(d.Files[1].Patch, "@@") {
		t.Fatalf("%v %+v", err, d)
	}
	// a short hash works, and is the same commit
	if d, err := s.CommitDiff(ctx, mixed[:9], false); err != nil || d.Hash != mixed || paths(d) != "A notes.txt" {
		t.Fatalf("the state file is dropped for everyone else: %v %+v", err, d)
	}
	only := hashOf("state only")
	if d, err := s.CommitDiff(ctx, only, true); err != nil || paths(d) != "M .rackbook/x.yml" {
		t.Fatalf("%v %+v", err, d)
	}
	if _, err := s.CommitDiff(ctx, only, false); !errors.Is(err, ErrNoCommit) {
		t.Fatalf("a commit of state files only does not exist for them: %v", err)
	}
	for _, bad := range []string{"", "abc", "ABCDEF1234", "main", "HEAD~1", "--output=x", mixed + "0", strings.Repeat("0", 40), "deadbeef"} {
		if _, err := s.CommitDiff(ctx, bad, true); !errors.Is(err, ErrNoCommit) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// the patches together stop at the limit; the file that crossed it says so
	d, err = s.CommitDiff(ctx, hashOf("big"), false)
	if err != nil || paths(d) != "A big.txt,A small.txt" {
		t.Fatalf("%v %+v", err, d)
	}
	if !d.Files[0].Truncated || len(d.Files[0].Patch) != MaxDiffBytes || !d.Files[1].Truncated || d.Files[1].Patch != "" {
		t.Fatalf("%v %d %v %q", d.Files[0].Truncated, len(d.Files[0].Patch), d.Files[1].Truncated, d.Files[1].Patch)
	}
}

func TestCommitDiffOnlyForCommitsOfTheTrackedBranch(t *testing.T) {
	e := newEnv(t)
	s := open(t, e.server, nil)
	ctx := context.Background()
	// a commit that is in the clone but not on the tracked branch (a branch of its own)
	sh(t, e.laptop, "checkout", "-q", "-b", "side")
	commitAtBranch := filepath.Join(e.laptop, "side.txt")
	_ = os.WriteFile(commitAtBranch, []byte("x\n"), 0o644)
	sh(t, e.laptop, "add", "-A")
	sh(t, e.laptop, "commit", "-qm", "side")
	sh(t, e.laptop, "push", "--quiet", "origin", "side")
	sh(t, e.server, "fetch", "--quiet", "origin")
	side := sh(t, e.server, "rev-parse", "origin/side")
	if _, err := s.CommitDiff(ctx, side, true); !errors.Is(err, ErrNoCommit) {
		t.Fatalf("%v", err)
	}
}

func TestMirrorCommitDiffAppliesTheOptions(t *testing.T) {
	e := newEnv(t)
	commitAt(t, e, "2026-03-01T10:00:00Z", "infra", map[string]string{"secrets/a.sops.yaml": "ENC[x]\n", "inventory/hosts.yml": "all: {}\n"})
	m := &Mirror{Dir: e.server, Branch: "main"}
	if _, err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	head, _ := m.Head(context.Background())
	d, err := m.CommitDiff(context.Background(), head, DiffOptions{
		HidePatch: func(p string) bool { return strings.HasPrefix(p, "secrets/") },
		Redact:    func(s string) string { return strings.ReplaceAll(s, "all", "ALL") },
	})
	if err != nil || len(d.Files) != 2 {
		t.Fatalf("%v %+v", err, d)
	}
	if f := d.Files[0]; f.Path != "inventory/hosts.yml" || !strings.Contains(f.Patch, "ALL") || f.Hidden {
		t.Fatalf("%+v", f)
	}
	if f := d.Files[1]; f.Path != "secrets/a.sops.yaml" || f.Patch != "" || !f.Hidden || f.Status != "A" {
		t.Fatalf("%+v", f)
	}
}
