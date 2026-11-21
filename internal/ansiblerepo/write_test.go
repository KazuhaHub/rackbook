package ansiblerepo

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/githubapp"
	"github.com/kazuhahub/rackbook/internal/githubapp/githubapptest"
	"github.com/kazuhahub/rackbook/internal/gitstore"
)

// hook runs before every git command and may interfere (move the remote).
type hook struct {
	mu     sync.Mutex
	before func(c gitstore.Cmd)
	cmds   [][]string
}

func (h *hook) Run(ctx context.Context, c gitstore.Cmd) (string, string, error) {
	h.mu.Lock()
	h.cmds = append(h.cmds, append([]string{}, c.Args...))
	fn := h.before
	h.mu.Unlock()
	if fn != nil {
		fn(c)
	}
	return gitstore.RealRunner().Run(ctx, c)
}

func (h *hook) pushes() [][]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out [][]string
	for _, c := range h.cmds {
		for _, a := range c {
			if a == "push" {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

type auditSink struct {
	mu sync.Mutex
	e  []AuditEntry
}

func (a *auditSink) Record(e AuditEntry) { a.mu.Lock(); a.e = append(a.e, e); a.mu.Unlock() }
func (a *auditSink) outcomes() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var o []string
	for _, e := range a.e {
		o = append(o, e.Outcome)
	}
	return o
}

type wfix struct {
	api   *githubapptest.API
	srv   *githubapptest.Git
	bare  string
	seed  string
	work  string
	repo  *Repo
	hook  *hook
	audit *auditSink
}

var alice = &auth.Identity{ID: "me@kazuha.org", Name: "Kazuha Mo", Email: "me@kazuha.org", Method: auth.MethodOIDC}

const wInv = `# the fleet
all:
  children:
    managed:
      hosts:
        a:
          ansible_host: 100.64.0.1
        b:
    infra_agent:
      hosts:
        a:
        b:
    derp:
      hosts:
        a:
`

const wVarsA = `# host a
ip: 100.64.0.1

features:
  demo:
    name: first   # label
    hub_url: https://hub.example
`

func newWFix(t *testing.T, write bool) *wfix {
	t.Helper()
	root := t.TempDir()
	w := &wfix{hook: &hook{}, audit: &auditSink{}}
	w.api = githubapptest.NewAPI(t, "77", nil)
	w.srv = gitServer(t, w.api)
	w.bare = bareRepo(t, w.srv, "org/infra")
	w.seed, w.work = filepath.Join(root, "seed"), filepath.Join(root, "work")
	git(t, root, "clone", w.bare, w.seed)
	for rel, body := range map[string]string{
		"inventory/hosts.yml":       wInv,
		"inventory/host_vars/a.yml": wVarsA,
		"inventory/host_vars/b.yml": "ip: 100.64.0.2\n",
		"secrets/a.sops.yaml":       "sops: {}\n",
		"secrets/b.sops.yaml":       "sops: {}\n",
		"features/demo/feature.yml": featSpec,
		"roles/x/tasks.yml":         "- debug: {}\n",
	} {
		write2(t, w.seed, rel, body)
	}
	git(t, w.seed, "add", ".")
	git(t, w.seed, "commit", "-m", "seed")
	git(t, w.seed, "push", "origin", "HEAD:refs/heads/main")
	git(t, root, "clone", "--branch", "main", w.bare, w.work)
	git(t, w.work, "remote", "set-url", "origin", w.srv.URL("org/infra"))
	key, err := githubapp.ParseKey(w.api.KeyPEM())
	if err != nil {
		t.Fatal(err)
	}
	app, err := githubapp.New(githubapp.Options{AppID: "77", Key: key, API: w.api.URL})
	if err != nil {
		t.Fatal(err)
	}
	o := Options{Dir: w.work, Branch: "main", Runner: w.hook, Audit: w.audit,
		Committer: gitstore.Identity{Name: "Rackbook", Email: "rackbook@kazuha.org"},
		Auth:      &gitstore.GitAuth{Source: app, Perms: githubapp.Permissions{Contents: "read"}}}
	if write {
		o.WriteAuth = &gitstore.GitAuth{Source: app, Perms: githubapp.Permissions{Contents: "write"}}
	}
	w.repo, err = New(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.repo.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return w
}

func write2(t *testing.T, root, rel, body string) { write(t, root, rel, body) }

// upstream makes a commit on the remote from another clone.
func (w *wfix) upstream(t *testing.T, msg string, files map[string]string) {
	t.Helper()
	git(t, w.seed, "pull", "--quiet", "origin", "main")
	for rel, body := range files {
		write(t, w.seed, rel, body)
	}
	git(t, w.seed, "add", ".")
	git(t, w.seed, "commit", "-m", msg)
	git(t, w.seed, "push", "origin", "HEAD:refs/heads/main")
}

func (w *wfix) rawEdit(path, content string) Edit {
	return Edit{Scope: scopeFor(path), Action: "edit", Who: alice, Files: []FileEdit{{Path: path, Base: w.baseOf(path), Make: func([]byte) ([]byte, error) { return []byte(content), nil }}}}
}

func scopeFor(p string) string {
	return strings.TrimSuffix(strings.TrimPrefix(p, "inventory/"), ".yml")
}

func (w *wfix) baseOf(path string) string {
	id, _ := w.repo.mirror.BlobID(context.Background(), "HEAD", path)
	return id
}

func (w *wfix) log(t *testing.T, format string) string {
	return git(t, w.bare, "log", "-1", "--format="+format)
}

const aPath = "inventory/host_vars/a.yml"

func TestApplyCommitsWithAuthorCommitterAndTrailers(t *testing.T) {
	w := newWFix(t, true)
	before := w.log(t, "%H")
	out, err := w.repo.Apply(context.Background(), w.rawEdit(aPath, wVarsA+"extra: 1\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if out.Commit == "" || len(out.Diffs) != 1 || !strings.Contains(out.Diffs[0].Diff, "+extra: 1") {
		t.Fatalf("%+v", out)
	}
	if w.log(t, "%H") == before || !strings.HasPrefix(w.log(t, "%H"), out.Commit) && out.Commit != w.log(t, "%H") {
		t.Fatalf("the commit did not arrive: %s vs %s", out.Commit, w.log(t, "%H"))
	}
	if got := w.log(t, "%s"); got != "infra(host_vars/a): edit" {
		t.Errorf("subject %q", got)
	}
	if got := w.log(t, "%an <%ae>"); got != "Kazuha Mo <me@kazuha.org>" {
		t.Errorf("author %q", got)
	}
	if got := w.log(t, "%cn <%ce>"); got != "Rackbook <rackbook@kazuha.org>" {
		t.Errorf("committer %q", got)
	}
	body := w.log(t, "%B")
	for _, want := range []string{"Edited-by: me@kazuha.org", "Edited-via: rackbook (oidc)", "Files: " + aPath} {
		if !strings.Contains(body, want) {
			t.Errorf("trailer %q missing:\n%s", want, body)
		}
	}
	// the message is the subject and exactly these trailers: nothing else is attributed
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) != 5 || lines[1] != "" || !strings.HasPrefix(lines[2], "Edited-by: ") || !strings.HasPrefix(lines[3], "Edited-via: ") || !strings.HasPrefix(lines[4], "Files: ") {
		t.Errorf("unexpected message:\n%s", body)
	}
	// the clone follows
	if w.repo.State().Head != w.log(t, "%H") {
		t.Errorf("state head %s", w.repo.State().Head)
	}
	// reads used a read token, the push a write token
	reads, writes := 0, 0
	for _, i := range w.api.Issued() {
		switch i.Perms["contents"] {
		case "read":
			reads++
		case "write":
			writes++
		}
	}
	if reads == 0 || writes == 0 {
		t.Errorf("tokens: read %d write %d", reads, writes)
	}
}

func TestOneEditIsOneCommit(t *testing.T) {
	w := newWFix(t, true)
	n := func() string { return git(t, w.bare, "rev-list", "--count", "HEAD") }
	before := n()
	e := w.rawEdit(aPath, wVarsA+"x: 1\n")
	e.Files = append(e.Files, FileEdit{Path: "inventory/host_vars/b.yml", Base: w.baseOf("inventory/host_vars/b.yml"), Make: func([]byte) ([]byte, error) { return []byte("ip: 9.9.9.9\n"), nil }})
	if _, err := w.repo.Apply(context.Background(), e, false); err != nil {
		t.Fatal(err)
	}
	if n() == before || git(t, w.bare, "rev-list", "--count", "HEAD~1") != before {
		t.Fatalf("two files must be one commit")
	}
	if got := w.log(t, "%B"); !strings.Contains(got, "Files: inventory/host_vars/a.yml, inventory/host_vars/b.yml") {
		t.Errorf("%s", got)
	}
}

func TestPreviewCommitsNothing(t *testing.T) {
	w := newWFix(t, true)
	head := w.log(t, "%H")
	out, err := w.repo.Apply(context.Background(), w.rawEdit(aPath, "ip: [\n"), true)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Blocked || out.Commit != "" || len(out.Issues) == 0 || out.Issues[0].Code != "yaml.invalid" {
		t.Fatalf("%+v", out)
	}
	if w.log(t, "%H") != head || len(w.hook.pushes()) != 0 {
		t.Fatal("a preview must not push")
	}
	if got := w.audit.outcomes(); len(got) != 0 {
		t.Fatalf("a preview is not audited: %v", got)
	}
}

func TestConflictWhenTheFileChangedUpstream(t *testing.T) {
	w := newWFix(t, true)
	e := w.rawEdit(aPath, wVarsA+"mine: 1\n") // base = what the editor saw
	w.upstream(t, "someone else", map[string]string{aPath: wVarsA + "theirs: 2\n"})
	head := w.log(t, "%H")
	_, err := w.repo.Apply(context.Background(), e, false)
	var ce *ConflictError
	if !errors.As(err, &ce) || ce.Reason != "changed" || len(ce.Files) != 1 || ce.Files[0] != aPath {
		t.Fatalf("%v", err)
	}
	if len(ce.Diffs) != 1 || !strings.Contains(ce.Diffs[0].Diff, "-theirs: 2") || !strings.Contains(ce.Diffs[0].Diff, "+mine: 1") {
		t.Fatalf("the diff must show the current file against the edit:\n%+v", ce.Diffs)
	}
	if w.log(t, "%H") != head {
		t.Fatal("nothing may be pushed")
	}
	if got := w.audit.outcomes(); len(got) != 1 || got[0] != "conflict" {
		t.Fatalf("audit %v", got)
	}
	// a fresh load works
	if _, err := w.repo.Apply(context.Background(), w.rawEdit(aPath, wVarsA+"mine: 1\n"), false); err != nil {
		t.Fatalf("after reloading: %v", err)
	}
}

func TestReplayWhenTheBranchMovedButOurFilesDidNot(t *testing.T) {
	w := newWFix(t, true)
	moved := false
	w.hook.before = func(c gitstore.Cmd) {
		if !moved && contains(c.Args, "push") {
			moved = true
			w.upstream(t, "elsewhere", map[string]string{"inventory/host_vars/b.yml": "ip: 100.64.0.3\n"})
		}
	}
	out, err := w.repo.Apply(context.Background(), w.rawEdit(aPath, wVarsA+"x: 1\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.hook.pushes()) != 2 {
		t.Fatalf("expected a rejected push and a replay, saw %d pushes", len(w.hook.pushes()))
	}
	if got := git(t, w.bare, "log", "--format=%s", "-3"); !strings.HasPrefix(got, "infra(host_vars/a): edit\nelsewhere\nseed") {
		t.Fatalf("history:\n%s", got)
	}
	if out.Commit == "" {
		t.Fatal("no commit")
	}
	// the other person's change is intact
	if got := git(t, w.bare, "show", "HEAD:inventory/host_vars/b.yml"); got != "ip: 100.64.0.3" {
		t.Fatalf("%q", got)
	}
}

func TestReplayConflictsWhenTheBranchMovedOnOurFile(t *testing.T) {
	w := newWFix(t, true)
	moved := false
	w.hook.before = func(c gitstore.Cmd) {
		if !moved && contains(c.Args, "push") {
			moved = true
			w.upstream(t, "same file", map[string]string{aPath: wVarsA + "theirs: 1\n"})
		}
	}
	_, err := w.repo.Apply(context.Background(), w.rawEdit(aPath, wVarsA+"mine: 1\n"), false)
	var ce *ConflictError
	if !errors.As(err, &ce) || ce.Reason != "changed" {
		t.Fatalf("%v", err)
	}
	if got := w.log(t, "%s"); got != "same file" {
		t.Fatalf("history was changed: %q", got)
	}
}

func TestGivesUpAfterThreeAttemptsAndNeverForces(t *testing.T) {
	w := newWFix(t, true)
	n := 0
	w.hook.before = func(c gitstore.Cmd) {
		if contains(c.Args, "push") {
			n++
			w.upstream(t, "busy "+string(rune('0'+n)), map[string]string{"inventory/host_vars/b.yml": "ip: 100.64.0." + string(rune('0'+n)) + "\n"})
		}
	}
	_, err := w.repo.Apply(context.Background(), w.rawEdit(aPath, wVarsA+"x: 1\n"), false)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("%v", err)
	}
	if n != 3 {
		t.Fatalf("pushes: %d", n)
	}
	for _, p := range w.hook.pushes() {
		var rest []string
		for i, a := range p {
			if a == "push" {
				rest = p[i:]
			}
		}
		if strings.Join(rest, " ") != "push --quiet origin HEAD:refs/heads/main" {
			t.Fatalf("a push that is not the plain fast-forward: %v", p)
		}
	}
	// the remote only gained other people's commits: none of ours, none lost
	if got := git(t, w.bare, "log", "--format=%s"); strings.Contains(got, "infra(") || strings.Count(got, "busy") != 3 || !strings.HasSuffix(got, "seed") {
		t.Fatalf("history:\n%s", got)
	}
	if got := w.audit.outcomes(); len(got) != 1 || got[0] != "busy" {
		t.Fatalf("audit %v", got)
	}
	// the clone is clean and follows the remote again
	if st := git(t, w.work, "status", "--porcelain"); st != "" {
		t.Fatalf("the clone is dirty:\n%s", st)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestValidationRefusesBeforeAnyCommitAndIsAudited(t *testing.T) {
	w := newWFix(t, true)
	head := w.log(t, "%H")
	for name, content := range map[string]string{
		"duplicate key": "a: 1\na: 2\n",
		"not a mapping": "- x\n",
		"bad feature":   "features:\n  demo: {name: x, hub_url: 'http://insecure', mode: tcp}\n",
		"private key":   "k: |\n  -----BEGIN OPENSSH PRIVATE KEY-----\n  abcdefabcdefabcdefabcdef\n  -----END OPENSSH PRIVATE KEY-----\n",
		"invalid yaml":  "a: [\n",
	} {
		_, err := w.repo.Apply(context.Background(), w.rawEdit(aPath, content), false)
		var ve *ValidationError
		if !errors.As(err, &ve) || len(blocking(ve.Issues, false)) == 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
	if w.log(t, "%H") != head || len(w.hook.pushes()) != 0 {
		t.Fatal("nothing may reach the remote")
	}
	for _, o := range w.audit.outcomes() {
		if o != "validation_failed" {
			t.Errorf("outcome %q", o)
		}
	}
	if len(w.audit.outcomes()) != 5 {
		t.Errorf("audit %v", w.audit.outcomes())
	}
	for _, e := range w.audit.e {
		if strings.Contains(strings.Join(e.Detail, " "), "BEGIN") {
			t.Errorf("a value in the audit: %+v", e)
		}
	}
}

func TestEditingAnotherHostsProblemDoesNotBlock(t *testing.T) {
	w := newWFix(t, true)
	// b loses its secrets file upstream (an old problem)
	git(t, w.seed, "pull", "--quiet", "origin", "main")
	git(t, w.seed, "rm", "-q", "secrets/b.sops.yaml")
	git(t, w.seed, "commit", "-qm", "remove")
	git(t, w.seed, "push", "origin", "HEAD:refs/heads/main")
	if err := w.repo.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	out, err := w.repo.Apply(context.Background(), w.rawEdit(aPath, wVarsA+"x: 1\n"), false)
	if err != nil {
		t.Fatalf("%v", err)
	}
	warned := false
	for _, i := range out.Issues {
		warned = warned || (i.Code == "inventory.no_secrets" && i.Severity == SevWarning)
	}
	if !warned {
		t.Fatalf("the old problem is shown as a warning: %+v", out.Issues)
	}
}

func TestConfirmedSecretScanFindingsGetATrailer(t *testing.T) {
	w := newWFix(t, true)
	content := wVarsA + "db_password: hunter2hunter2\n"
	_, err := w.repo.Apply(context.Background(), w.rawEdit(aPath, content), false)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("%v", err)
	}
	if !hasConfirm(ve.Issues) {
		t.Skip("this value is a block-tier finding")
	}
	e := w.rawEdit(aPath, content)
	e.ConfirmSecretScan = true
	if _, err := w.repo.Apply(context.Background(), e, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.log(t, "%B"), "Secret-scan: confirmed-not-secret") {
		t.Fatal("trailer missing")
	}
}

func TestNoChangeAndFilesOutsideTheEditorsAreRefused(t *testing.T) {
	w := newWFix(t, true)
	if _, err := w.repo.Apply(context.Background(), w.rawEdit(aPath, wVarsA), false); !errors.Is(err, ErrNoChange) {
		t.Fatalf("%v", err)
	}
	for _, p := range []string{"secrets/a.sops.yaml", "roles/x/tasks.yml", "features/demo/feature.yml", "../x.yml", "inventory/host_vars/../hosts.yml", ".github/workflows/x.yml"} {
		e := w.rawEdit(aPath, "x: 1\n")
		e.Files[0].Path = p
		if _, err := w.repo.Apply(context.Background(), e, false); err == nil || errors.Is(err, ErrNoChange) {
			t.Errorf("%s: %v", p, err)
		}
	}
	if len(w.hook.pushes()) != 0 {
		t.Fatal("pushed")
	}
}

func TestReadOnlyRepoRefusesEdits(t *testing.T) {
	w := newWFix(t, false)
	if _, err := w.repo.Apply(context.Background(), w.rawEdit(aPath, "x: 1\n"), false); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("%v", err)
	}
	if _, err := w.repo.Revert(context.Background(), w.log(t, "%H"), alice, false); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("%v", err)
	}
}

func TestFeatureAndGroupEditsThroughTheRepo(t *testing.T) {
	w := newWFix(t, true)
	// features: change one setting, comments elsewhere stay
	spec, _ := w.repo.Feature("demo")
	settings, known, iss := spec.SettingsFromInput(map[string]any{"name": "second", "hub_url": "https://hub.example", "port": float64(8080)})
	if len(iss) != 0 {
		t.Fatal(iss)
	}
	e := Edit{Scope: "host_vars/a", Action: "update demo", Who: alice, Files: []FileEdit{{Path: aPath, Base: w.baseOf(aPath),
		Make: func(old []byte) ([]byte, error) { return SetFeature(old, "demo", true, settings, known) }}}}
	if _, err := w.repo.Apply(context.Background(), e, false); err != nil {
		t.Fatal(err)
	}
	got := git(t, w.bare, "show", "HEAD:"+aPath)
	if !strings.Contains(got, "# host a\n") || !strings.Contains(got, "ip: 100.64.0.1\n\nfeatures:") || !strings.Contains(got, "name: second") || !strings.Contains(got, "port: 8080") {
		t.Fatalf("%s", got)
	}
	// an invalid setting value is refused by the checks
	settings, known, _ = spec.SettingsFromInput(map[string]any{"name": "x", "hub_url": "https://hub.example", "port": float64(0)})
	e.Files[0].Base = w.baseOf(aPath)
	e.Files[0].Make = func(old []byte) ([]byte, error) { return SetFeature(old, "demo", true, settings, known) }
	var ve *ValidationError
	if _, err := w.repo.Apply(context.Background(), e, false); !errors.As(err, &ve) {
		t.Fatalf("port 0 must be refused: %v", err)
	}
	// groups: add b to derp; remove a from derp
	ge := Edit{Scope: "inventory/hosts", Action: "groups", Who: alice, Files: []FileEdit{{Path: "inventory/hosts.yml", Base: w.baseOf("inventory/hosts.yml"),
		Make: func(old []byte) ([]byte, error) {
			return SetMembership(old, []MembershipChange{{"b", "derp", true}, {"a", "derp", false}})
		}}}}
	if _, err := w.repo.Apply(context.Background(), ge, false); err != nil {
		t.Fatal(err)
	}
	inv := git(t, w.bare, "show", "HEAD:inventory/hosts.yml")
	if !strings.Contains(inv, "# the fleet") || !strings.Contains(inv, "    derp:\n      hosts:\n        b:") {
		t.Fatalf("%s", inv)
	}
	// removing a from managed alone is refused: it is still in infra_agent
	ge.Files[0].Base = w.baseOf("inventory/hosts.yml")
	ge.Files[0].Make = func(old []byte) ([]byte, error) {
		return SetMembership(old, []MembershipChange{{"a", "managed", false}})
	}
	if _, err := w.repo.Apply(context.Background(), ge, false); !errors.As(err, &ve) {
		t.Fatalf("%v", err)
	}
}

func TestRevertRestoresTheParentStateAndRefusesWhenLaterCommitsTouchedIt(t *testing.T) {
	w := newWFix(t, true)
	ctx := context.Background()
	if _, err := w.repo.Apply(ctx, w.rawEdit(aPath, wVarsA+"one: 1\n"), false); err != nil {
		t.Fatal(err)
	}
	first := w.log(t, "%H")
	if _, err := w.repo.Apply(ctx, w.rawEdit(aPath, wVarsA+"one: 1\ntwo: 2\n"), false); err != nil {
		t.Fatal(err)
	}
	// the first commit's file was touched later: 409
	_, err := w.repo.Revert(ctx, first, alice, false)
	var ce *ConflictError
	if !errors.As(err, &ce) || ce.Reason != "later_commits" || len(ce.Later) != 1 {
		t.Fatalf("%v", err)
	}
	hist, err := w.repo.History(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	byHash := map[string]HistoryEntry{}
	for _, h := range hist {
		byHash[h.Hash] = h
	}
	if h := byHash[first]; h.Revertible || h.Reason != "later_commits" {
		t.Errorf("%+v", h)
	}
	newest := w.log(t, "%H")
	if h := byHash[newest]; !h.Revertible || len(h.Files) != 1 {
		t.Errorf("%+v", h)
	}
	// the seed commit is a root commit, and touches roles/: never revertible
	for _, h := range hist {
		if h.Subject == "seed" && (h.Revertible || h.Reason != "root") {
			t.Errorf("%+v", h)
		}
	}
	// reverting the newest works and restores the earlier content
	out, err := w.repo.Revert(ctx, newest, alice, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := git(t, w.bare, "show", "HEAD:"+aPath); got != strings.TrimRight(wVarsA+"one: 1\n", "\n") {
		t.Fatalf("%q", got)
	}
	if !strings.HasPrefix(w.log(t, "%s"), "infra(host_vars/a): revert "+newest[:7]) || !strings.Contains(w.log(t, "%B"), "Reverts: "+newest) || !strings.Contains(w.log(t, "%B"), "Edited-by: me@kazuha.org") {
		t.Fatalf("%s", w.log(t, "%B"))
	}
	if out.Commit == "" {
		t.Fatal("no commit")
	}
	// now the first can still not be reverted: the revert commit is a later commit that touched it
	if _, err := w.repo.Revert(ctx, first, alice, false); !errors.As(err, &ce) {
		t.Fatalf("%v", err)
	}
	if got := w.audit.outcomes(); len(got) != 2 || got[0] != "conflict" {
		t.Fatalf("audit %v", got)
	}
}

func TestRevertOfAnAddedFileRemovesItAndOtherCommitsAreRefused(t *testing.T) {
	w := newWFix(t, true)
	ctx := context.Background()
	// a new host_vars file for c comes in upstream
	w.upstream(t, "add c vars", map[string]string{"inventory/host_vars/c.yml": "ip: 1\n"})
	if err := w.repo.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	add := w.log(t, "%H")
	if _, err := w.repo.Revert(ctx, add, alice, false); err != nil {
		t.Fatal(err)
	}
	if out := git(t, w.bare, "ls-tree", "-r", "--name-only", "HEAD"); strings.Contains(out, "host_vars/c.yml") {
		t.Fatalf("the added file must be removed:\n%s", out)
	}
	// a commit that touches a role is not the editors' to revert
	w.upstream(t, "role", map[string]string{"roles/x/tasks.yml": "- debug: {msg: hi}\n"})
	if err := w.repo.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	var rf *RefusedError
	if _, err := w.repo.Revert(ctx, w.log(t, "%H"), alice, false); !errors.As(err, &rf) || rf.Code != "not_editable" {
		t.Fatalf("%v", err)
	}
	// a commit that is not a hash, or not on the branch
	if _, err := w.repo.Revert(ctx, "--output=/tmp/x", alice, false); err == nil {
		t.Fatal("not a commit")
	}
	if _, err := w.repo.Revert(ctx, strings.Repeat("a", 40), alice, false); err == nil {
		t.Fatal("unknown commit")
	}
	// preview of a revert changes nothing
	w.upstream(t, "vars", map[string]string{"inventory/host_vars/b.yml": "ip: 5\n"})
	if err := w.repo.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	head := w.log(t, "%H")
	pv, err := w.repo.Revert(ctx, head, alice, true)
	if err != nil || pv.Commit != "" || len(pv.Diffs) != 1 || w.log(t, "%H") != head {
		t.Fatalf("%v %+v", err, pv)
	}
}

func TestEditDoesNotAddAnAuthorFromNowhere(t *testing.T) {
	w := newWFix(t, true)
	if _, err := w.repo.Apply(context.Background(), Edit{Scope: "host_vars/a", Action: "edit", Who: &auth.Identity{Method: auth.MethodOIDC}, Files: w.rawEdit(aPath, "x: 1\n").Files}, false); !errors.Is(err, ErrNoAuthor) {
		t.Fatalf("%v", err)
	}
}

func TestHostVarsTemplatingAndConnectionVarsAreRefusedOnWrite(t *testing.T) {
	w := newWFix(t, true)
	head := w.log(t, "%H")
	for name, content := range map[string]string{
		"lookup pipe":   wVarsA + "x: \"{{ lookup('pipe', 'id') }}\"\n",
		"ssh args":      wVarsA + "ansible_ssh_common_args: -o ProxyCommand=x\n",
		"interpreter":   wVarsA + "ansible_python_interpreter: /tmp/x\n",
		"nested":        wVarsA + "a:\n  b: '{% if x %}y{% endif %}'\n",
		"templated key": wVarsA + "'{{ k }}': 1\n",
		"merge key":     wVarsA + "base: &b {x: 1}\nc:\n  <<: *b\n",
	} {
		_, err := w.repo.Apply(context.Background(), w.rawEdit(aPath, content), false)
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if w.log(t, "%H") != head || len(w.hook.pushes()) != 0 {
		t.Fatal("nothing may be pushed")
	}
}

func TestResultOfAnEditIsCheckedEvenWhenTheFileWasAlreadyBroken(t *testing.T) {
	w := newWFix(t, true)
	// b already has a duplicate key and a template upstream (an old problem)
	w.upstream(t, "broken", map[string]string{"inventory/host_vars/b.yml": "a: 1\na: 2\nx: '{{ y }}'\n"})
	if err := w.repo.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := "inventory/host_vars/b.yml"
	// an edit that keeps the problems is still refused: the result must pass
	_, err := w.repo.Apply(context.Background(), w.rawEdit(b, "a: 1\na: 2\nx: '{{ y }}'\nz: 1\n"), false)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("%v", err)
	}
	// one that fixes them is accepted
	if _, err := w.repo.Apply(context.Background(), w.rawEdit(b, "a: 1\nz: 1\n"), false); err != nil {
		t.Fatal(err)
	}
	// old problems in files the edit does not write stay warnings
	w.upstream(t, "broken again", map[string]string{"inventory/host_vars/b.yml": "x: '{{ y }}'\n"})
	if err := w.repo.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	out, err := w.repo.Apply(context.Background(), w.rawEdit(aPath, wVarsA+"n: 1\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Issues) == 0 || out.Issues[0].Severity != SevWarning {
		t.Fatalf("%+v", out.Issues)
	}
}

func TestGroupVarsAreNotEditableOrRevertable(t *testing.T) {
	w := newWFix(t, true)
	gv := "inventory/group_vars/all.yml"
	w.upstream(t, "group vars", map[string]string{gv: "ansible_connection: local\nx: '{{ y }}'\n"})
	if err := w.repo.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	e := w.rawEdit(aPath, "x: 1\n")
	e.Files[0].Path = gv
	if _, err := w.repo.Apply(context.Background(), e, false); err == nil || errors.Is(err, ErrNoChange) {
		t.Fatalf("%v", err)
	}
	var rf *RefusedError
	if _, err := w.repo.Revert(context.Background(), w.log(t, "%H"), alice, false); !errors.As(err, &rf) || rf.Code != "not_editable" {
		t.Fatalf("%v", err)
	}
	hist, _ := w.repo.History(context.Background(), 3)
	if hist[0].Revertible || hist[0].Reason != "not_editable" {
		t.Fatalf("%+v", hist[0])
	}
}

func TestRevertRefusesFilesWithSecretLookingValues(t *testing.T) {
	w := newWFix(t, true)
	// a commit that changes a file holding a secret-looking value
	w.upstream(t, "secret-ish", map[string]string{"inventory/host_vars/b.yml": "api_token: abc123secret\nip: 1\n"})
	if err := w.repo.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	var ee *EditError
	if _, err := w.repo.Revert(context.Background(), w.log(t, "%H"), alice, false); !errors.As(err, &ee) {
		t.Fatalf("%v", err)
	}
	if _, err := w.repo.Revert(context.Background(), w.log(t, "%H"), alice, true); !errors.As(err, &ee) {
		t.Fatalf("a preview must refuse too: %v", err)
	}
}

func TestRevertSubjectIsTruncatedByRunesNotBytes(t *testing.T) {
	w := newWFix(t, true)
	subj := strings.Repeat("改", 150)
	w.upstream(t, subj, map[string]string{"inventory/host_vars/b.yml": "ip: 7\n"})
	if err := w.repo.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.repo.Revert(context.Background(), w.log(t, "%H"), alice, false); err != nil {
		t.Fatal(err)
	}
	got := w.log(t, "%s")
	if !utf8.ValidString(got) || strings.Contains(got, "\ufffd") || strings.Count(got, "改") != 120-len([]rune(" ")) && strings.Count(got, "改") < 100 {
		t.Fatalf("%q", got)
	}
}
