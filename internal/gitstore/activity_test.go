package gitstore

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

func act(t *testing.T, s *Store, q ActivityQuery) []ActivityCommit {
	t.Helper()
	pg, err := s.Activity(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	return pg.Commits
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
	cs := act(t, s, ActivityQuery{})
	if len(cs) != 2 {
		t.Fatalf("%+v", cs)
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
	if cs := act(t, s, ActivityQuery{Limit: 1}); len(cs) != 1 {
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

	cs := act(t, s, ActivityQuery{})
	if subjects(cs) != "both|same second|edit todo|seed" {
		t.Fatalf("a commit that touches only .rackbook/ is not listed without includeState: %s", subjects(cs))
	}
	if cs[0].State != StateNone {
		t.Fatalf("an ordinary caller is not told which commits touch state files: %+v", cs[0])
	}
	cs = act(t, s, ActivityQuery{IncludeState: true})
	if len(cs) != 5 || cs[0].Subject != "both" || cs[0].State != StateSome || cs[1].Subject != "state only" || cs[1].State != StateOnly || cs[4].State != StateNone {
		t.Fatalf("%+v", cs)
	}
	// a collection: the commits that touched its file
	cs = act(t, s, ActivityQuery{Collection: "todo"})
	if subjects(cs) != "edit todo|seed" { // the seed added the file
		t.Fatalf("%s", subjects(cs))
	}
	for _, q := range []ActivityQuery{{Collection: "nope"}, {ID: "x"}, {Tip: "nothex"}, {Tip: strings.Repeat("0", 40)}} {
		if _, err := s.Activity(context.Background(), q); err == nil {
			t.Fatalf("%+v accepted", q)
		}
	}
}

// Paging is by position in git's walk from a pinned tip, so a history whose
// committer dates are out of order loses nothing, and commits that land between
// two pages change nothing.
func TestActivityPagesByWalkPositionUnderClockSkew(t *testing.T) {
	e := newEnv(t)
	for i, d := range []string{"09:00", "12:00", "10:00", "10:30"} {
		commitAt(t, e, "2026-03-01T"+d+":00Z", "at "+d, map[string]string{"f" + string(rune('a'+i)) + ".txt": d + "\n"})
	}
	s := open(t, e.server, nil)
	ctx := context.Background()
	if all := subjects(act(t, s, ActivityQuery{Limit: 50})); all != "at 10:30|at 10:00|at 12:00|at 09:00|seed" {
		t.Fatalf("the walk is children first: %s", all)
	}
	for _, n := range []int{1, 2, 3} {
		all := subjects(act(t, s, ActivityQuery{Limit: 50})) // what the first page sees now
		var got []string
		q := ActivityQuery{Limit: n}
		for i := 0; ; i++ {
			if i > 10 {
				t.Fatal("does not end")
			}
			pg, err := s.Activity(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			if len(pg.Commits) == 0 {
				break
			}
			got = append(got, subjects(pg.Commits))
			if i == 0 {
				// a commit lands after the first page: the pinned walk does not see it
				commitAt(t, e, "2026-03-02T10:00:00Z", "landed "+string(rune('0'+n)), map[string]string{"late" + string(rune('0'+n)) + ".txt": "x\n"})
				if err := s.Pull(ctx); err != nil {
					t.Fatal(err)
				}
				if first := act(t, s, ActivityQuery{Limit: 1}); !strings.HasPrefix(first[0].Subject, "landed") {
					t.Fatalf("a first page starts at the current tip: %+v", first)
				}
			}
			q = ActivityQuery{Limit: n, Tip: pg.Tip, Skip: q.Skip + len(pg.Commits)}
		}
		if strings.Join(got, "|") != all {
			t.Fatalf("n=%d: %v, want %s", n, got, all)
		}
	}
}

func TestActivityByRecordIsAnExactTrailerMatchWithoutFallback(t *testing.T) {
	e := newEnv(t)
	s := open(t, e.server, nil)
	ctx := context.Background()
	if _, err := s.Write(ctx, sshEdit(t, s, "TCP 22"), editor); err != nil {
		t.Fatal(err)
	}
	cs := act(t, s, ActivityQuery{Collection: "services", ID: "web-hostco-ashburn-va-us-dc/SSH"})
	if len(cs) != 1 || cs[0].EditedBy != "ann@example.com" {
		t.Fatalf("%+v", cs)
	}
	// the prefix of an id is another record; the file history is not used instead
	// the prefix of an id is another record: git's text search finds the commit, the exact check excludes it
	cs = act(t, s, ActivityQuery{Collection: "services", ID: "web-hostco-ashburn-va-us-dc/SS"})
	for _, c := range cs {
		if !c.Excluded {
			t.Fatalf("%+v", c)
		}
	}
	for _, c := range act(t, s, ActivityQuery{Collection: "todo", ID: "whatever"}) {
		if !c.Excluded {
			t.Fatalf("%+v", c)
		}
	}
}

func TestMirrorActivity(t *testing.T) {
	e := newEnv(t)
	commitAt(t, e, "2026-03-01T10:00:00Z", "infra a", map[string]string{"a.yml": "a: 1\n", ".rackbook/x.yml": "a: 1\n"})
	m := &Mirror{Dir: e.server, Branch: "main"}
	if _, err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	pg, err := m.Activity(context.Background(), ActivityQuery{IncludeState: false})
	cs := pg.Commits
	if err != nil || subjects(cs) != "infra a|seed" || len(pg.Tip) != 40 {
		t.Fatalf("%v %+v", err, pg)
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
		cs := act(t, s, ActivityQuery{IncludeState: true, Limit: 20})
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

// git appends the nearest top-level line above a hunk to its header; for a
// YAML file that can be a secret.
func TestCommitDiffDropsTheFunctionContextOfHunkHeaders(t *testing.T) {
	e := newEnv(t)
	var body strings.Builder
	body.WriteString("ansible_become_password: hunter2hunter2\n")
	for i := 1; i <= 12; i++ {
		body.WriteString("  filler" + string(rune('a'+i)) + ": 1\n")
	}
	commitAt(t, e, "2026-03-01T10:00:00Z", "add", map[string]string{"conf.yml": body.String()})
	commitAt(t, e, "2026-03-02T10:00:00Z", "edit", map[string]string{"conf.yml": strings.Replace(body.String(), "fillerj: 1", "fillerj: 2", 1)})
	s := open(t, e.server, nil)
	ctx := context.Background()
	cs := act(t, s, ActivityQuery{})
	d, err := s.CommitDiff(ctx, cs[0].Hash, false)
	if err != nil || len(d.Files) != 1 {
		t.Fatalf("%v %+v", err, d)
	}
	p := d.Files[0].Patch
	if strings.Contains(p, "hunter2") {
		t.Fatalf("the hunk header leaks the line above it:\n%s", p)
	}
	if !strings.Contains(p, "+  fillerj: 2") || !strings.Contains(p, "@@ -") {
		t.Fatalf("%s", p)
	}
	for _, l := range strings.Split(p, "\n") {
		if strings.HasPrefix(l, "@@") && !strings.HasSuffix(l, " @@") {
			t.Fatalf("hunk header with context: %q", l)
		}
	}
}

// recordRunner counts the git commands a store runs.
type recordRunner struct {
	next Runner
	cmds [][]string
	max  []int
}

func (r *recordRunner) Run(ctx context.Context, c Cmd) (string, string, error) {
	r.cmds = append(r.cmds, c.Args)
	r.max = append(r.max, c.MaxStdout)
	return r.next.Run(ctx, c)
}

// One process reads the patches, through a limit, however many files changed.
func TestCommitDiffRunsOneLimitedGitProcess(t *testing.T) {
	e := newEnv(t)
	files := map[string]string{}
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		files[n+".txt"] = n + "\n"
	}
	commitAt(t, e, "2026-03-01T10:00:00Z", "many", files)
	rr := &recordRunner{next: RealRunner()}
	s := open(t, e.server, func(o *Options) { o.Runner = rr })
	ctx := context.Background()
	cs := act(t, s, ActivityQuery{})
	rr.cmds, rr.max = nil, nil
	d, err := s.CommitDiff(ctx, cs[0].Hash, false)
	if err != nil || len(d.Files) != 5 {
		t.Fatalf("%v %+v", err, d)
	}
	patches := 0
	for i, c := range rr.cmds {
		if strings.Contains(strings.Join(c, " "), "--patch") {
			patches++
			if rr.max[i] != MaxDiffBytes {
				t.Errorf("the patch process has no output limit: %d", rr.max[i])
			}
		}
	}
	if patches != 1 {
		t.Fatalf("%d patch processes", patches)
	}
	for _, f := range d.Files {
		if !strings.Contains(f.Patch, "+"+strings.TrimSuffix(f.Path, ".txt")) {
			t.Fatalf("%+v", f)
		}
	}
}

// A type change (a file becomes a symlink) is one name-status entry and two
// "diff --git" sections: the sections belong to files by the path in their own
// header, not by position.
func TestCommitDiffSectionsFollowTheirPathsAcrossATypeChange(t *testing.T) {
	e := newEnv(t)
	commitAt(t, e, "2026-03-01T10:00:00Z", "files", map[string]string{"a.yml": "a: 1\n", "b.yml": "b: 1\n", "c.yml": "c: 1\n"})
	sh(t, e.laptop, "pull", "--quiet")
	if err := os.Remove(filepath.Join(e.laptop, "a.yml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b.yml", filepath.Join(e.laptop, "a.yml")); err != nil {
		t.Fatal(err)
	}
	for f, body := range map[string]string{"b.yml": "b: 2\n", "c.yml": "c: 3\n"} {
		if err := os.WriteFile(filepath.Join(e.laptop, f), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sh(t, e.laptop, "add", "-A")
	sh(t, e.laptop, "commit", "-qm", "type change")
	sh(t, e.laptop, "push", "--quiet", "origin", "main")
	s := open(t, e.server, nil)
	ctx := context.Background()
	if err := s.Pull(ctx); err != nil {
		t.Fatal(err)
	}
	cs := act(t, s, ActivityQuery{})
	d, err := s.CommitDiff(ctx, cs[0].Hash, false)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]FileDiff{}
	for _, f := range d.Files {
		by[f.Path] = f
	}
	if len(d.Files) != 3 || by["a.yml"].Status != "T" {
		t.Fatalf("%+v", d.Files)
	}
	if p := by["b.yml"].Patch; !strings.Contains(p, "+b: 2") || strings.Contains(p, "symbolic") || strings.Contains(p, "-a: 1") {
		t.Fatalf("b.yml shows another file's patch:\n%s", p)
	}
	if p := by["c.yml"].Patch; !strings.Contains(p, "+c: 3") || strings.Contains(p, "+b: 2") {
		t.Fatalf("c.yml:\n%s", p)
	}
	if p := by["a.yml"].Patch; !strings.Contains(p, "-a: 1") || !strings.Contains(p, "120000") {
		t.Fatalf("a.yml holds both its sections:\n%s", p)
	}
}

// The arguments of the patch process do not grow with the number of files.
func TestCommitDiffArgumentsStayBoundedForAHugeCommit(t *testing.T) {
	e := newEnv(t)
	files := map[string]string{}
	for i := 0; i < 1000; i++ {
		files["many/f"+strings.Repeat("0", 4-len(strconv.Itoa(i)))+strconv.Itoa(i)+".txt"] = "x\n"
	}
	commitAt(t, e, "2026-03-01T10:00:00Z", "huge", files)
	rr := &recordRunner{next: RealRunner()}
	s := open(t, e.server, func(o *Options) { o.Runner = rr })
	ctx := context.Background()
	cs := act(t, s, ActivityQuery{})
	rr.cmds, rr.max = nil, nil
	d, err := s.CommitDiff(ctx, cs[0].Hash, false)
	if err != nil || len(d.Files) != MaxDiffFiles || !d.MoreFiles {
		t.Fatalf("%v %d %v", err, len(d.Files), d.MoreFiles)
	}
	for _, c := range rr.cmds {
		if len(c) > MaxDiffFiles+20 {
			t.Fatalf("%d arguments: %v...", len(c), c[:12])
		}
	}
}
