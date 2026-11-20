package ansiblerepo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const inventory = `
all:
  children:
    managed:
      hosts:
        alpha:
          ansible_host: 100.64.0.1
        beta:
    web:
      hosts:
        alpha:
    outer:
      children:
        inner:
          hosts:
            gamma:
        empty:
  hosts:
    direct:
`

func TestParseInventoryGroupsAndVarsFile(t *testing.T) {
	hosts, err := ParseInventory([]byte(inventory), func(h string) bool { return h == "alpha" })
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	vars := map[string]bool{}
	for _, h := range hosts {
		got[h.Name] = h.Groups
		vars[h.Name] = h.HasVars
	}
	want := map[string][]string{
		"alpha":  {"managed", "web"},
		"beta":   {"managed"},
		"gamma":  {"inner", "outer"}, // a child group's hosts belong to its parent
		"direct": {},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("groups: %v\nwant %v", got, want)
	}
	if !vars["alpha"] || vars["beta"] {
		t.Fatalf("hasVars: %v", vars)
	}
	if hosts[0].Name != "alpha" || hosts[len(hosts)-1].Name != "gamma" {
		t.Fatalf("not sorted: %+v", hosts)
	}
}

func TestParseInventoryRejectsBadInput(t *testing.T) {
	for name, in := range map[string]string{
		"not yaml":     "all: [",
		"hosts a list": "all:\n  hosts: [a]\n",
	} {
		if _, err := ParseInventory([]byte(in), nil); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if hosts, err := ParseInventory([]byte(""), nil); err != nil || len(hosts) != 0 {
		t.Errorf("empty: %v %v", hosts, err)
	}
}

func TestParseInventorySkipsNamesThatAreNotPlainHostNames(t *testing.T) {
	in := "all:\n  hosts:\n    ok-host:\n    ../etc:\n    a/b:\n    'web[01:03]':\n    ok2:\n"
	hosts, err := ParseInventory([]byte(in), nil)
	if err != nil || len(hosts) != 2 || hosts[0].Name != "ok-host" || hosts[1].Name != "ok2" {
		t.Fatalf("%v %+v", err, hosts)
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=T", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-c", "protocol.file.allow=always"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const alphaVars = `# the first host
tailscale_ip: 100.64.0.1
api_token: abc123
features:
  beszel-agent:
    mode: websocket
    key: "ssh-ed25519 AAAA"
    token: shouldnotshow
  old:
    enabled: false
  off: false
note: |
  -----BEGIN OPENSSH PRIVATE KEY-----
  xyz
`

type fixture struct {
	bare, seed, work string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	root := t.TempDir()
	f := fixture{bare: filepath.Join(root, "origin.git"), seed: filepath.Join(root, "seed"), work: filepath.Join(root, "work")}
	git(t, root, "init", "--bare", "--initial-branch=main", f.bare)
	git(t, root, "clone", f.bare, f.seed)
	write(t, f.seed, "inventory/hosts.yml", inventory)
	write(t, f.seed, "inventory/host_vars/alpha.yml", alphaVars)
	git(t, f.seed, "add", ".")
	git(t, f.seed, "commit", "-m", "first")
	git(t, f.seed, "push", "origin", "HEAD:refs/heads/main")
	git(t, root, "clone", "--branch", "main", f.bare, f.work)
	return f
}

func TestRefreshFollowsOriginAndReadsTheClone(t *testing.T) {
	f := newFixture(t)
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	r, err := New(Options{Dir: f.work, Branch: "main", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	st := r.State()
	if st.Head != git(t, f.seed, "rev-parse", "HEAD") || !st.SyncedAt.Equal(now) || st.Error != "" {
		t.Fatalf("state: %+v", st)
	}

	// origin moves on: a host appears
	write(t, f.seed, "inventory/hosts.yml", inventory+"    late:\n")
	git(t, f.seed, "commit", "-am", "second")
	git(t, f.seed, "push", "origin", "HEAD:refs/heads/main")
	if err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if r.State().Head != git(t, f.seed, "rev-parse", "HEAD") {
		t.Fatal("head did not move")
	}
	hosts, err := r.Hosts()
	if err != nil || len(hosts) != 5 {
		t.Fatalf("hosts: %v %+v", err, hosts)
	}
	commits, err := r.Commits(ctx, 50)
	if err != nil || len(commits) != 2 || commits[0].Subject != "second" {
		t.Fatalf("commits: %v %+v", err, commits)
	}
}

func TestRefreshFailureIsReportedAndRecovers(t *testing.T) {
	f := newFixture(t)
	r, _ := New(Options{Dir: f.work, Branch: "main"})
	git(t, f.work, "remote", "set-url", "origin", filepath.Join(filepath.Dir(f.work), "gone.git"))
	if err := r.Refresh(context.Background()); err == nil {
		t.Fatal("want an error")
	}
	if st := r.State(); st.Error == "" || !st.SyncedAt.IsZero() {
		t.Fatalf("state: %+v", st)
	}
	git(t, f.work, "remote", "set-url", "origin", f.bare)
	if err := r.Refresh(context.Background()); err != nil || r.State().Error != "" {
		t.Fatalf("recover: %v %+v", err, r.State())
	}
}

func TestRefreshNeverWritesToTheRemote(t *testing.T) {
	f := newFixture(t)
	before := git(t, f.bare, "for-each-ref")
	r, _ := New(Options{Dir: f.work, Branch: "main"})
	// a local commit and an untracked edit in the clone must not reach origin
	write(t, f.work, "inventory/hosts.yml", "all: {}\n")
	git(t, f.work, "commit", "-am", "local")
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if after := git(t, f.bare, "for-each-ref"); after != before {
		t.Fatalf("remote changed:\n%s\n%s", before, after)
	}
	if hosts, _ := r.Hosts(); len(hosts) != 4 {
		t.Fatalf("local commit was not discarded: %+v", hosts)
	}
}

func TestRunRefreshesRepeatedly(t *testing.T) {
	f := newFixture(t)
	r, _ := New(Options{Dir: f.work, Branch: "main", Interval: 20 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(5 * time.Second)
	for r.State().Head == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	write(t, f.seed, "inventory/hosts.yml", inventory+"    late:\n")
	git(t, f.seed, "commit", "-am", "second")
	git(t, f.seed, "push", "origin", "HEAD:refs/heads/main")
	want := git(t, f.seed, "rev-parse", "HEAD")
	for r.State().Head != want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.State().Head != want {
		t.Fatalf("Run did not pick up the new commit: %+v", r.State())
	}
}

func TestHostDetailRedactsSecretsAndReadsFeatures(t *testing.T) {
	f := newFixture(t)
	r, _ := New(Options{Dir: f.work, Branch: "main"})
	d, err := r.Host("alpha")
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "alpha" || !reflect.DeepEqual(d.Groups, []string{"managed", "web"}) {
		t.Fatalf("%+v", d.Host)
	}
	for _, leak := range []string{"abc123", "shouldnotshow", "PRIVATE KEY", "xyz"} {
		if strings.Contains(d.Vars, leak) {
			t.Errorf("vars leak %q:\n%s", leak, d.Vars)
		}
	}
	for _, keep := range []string{"# the first host", "tailscale_ip: 100.64.0.1", "ssh-ed25519 AAAA", "mode: websocket"} {
		if !strings.Contains(d.Vars, keep) {
			t.Errorf("vars lost %q:\n%s", keep, d.Vars)
		}
	}
	if d.Hidden != 3 {
		t.Errorf("hidden = %d", d.Hidden)
	}
	got := map[string]bool{}
	for _, ft := range d.Features {
		got[ft.Name] = ft.Enabled
		if ft.Name == "beszel-agent" && ft.Settings["token"] != Hidden {
			t.Errorf("settings: %+v", ft.Settings)
		}
	}
	if !reflect.DeepEqual(got, map[string]bool{"beszel-agent": true, "old": false, "off": false}) {
		t.Fatalf("features: %v", got)
	}

	// a host without a file, and one that is not in the inventory
	if d, err := r.Host("beta"); err != nil || d.Vars != "" || len(d.Features) != 0 || d.HasVars {
		t.Fatalf("beta: %+v %v", d, err)
	}
	for _, name := range []string{"nope", "../alpha", "alpha/../alpha", ""} {
		if _, err := r.Host(name); err != ErrNoHost {
			t.Errorf("%q: %v", name, err)
		}
	}
}

func TestSymlinkedHostVarsAreNotFollowed(t *testing.T) {
	f := newFixture(t)
	outside := filepath.Join(t.TempDir(), "secret.yml")
	write(t, filepath.Dir(outside), "secret.yml", "leak: yes\n")
	if err := os.Remove(filepath.Join(f.work, "inventory/host_vars/alpha.yml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(f.work, "inventory/host_vars/alpha.yml")); err != nil {
		t.Skip("no symlinks")
	}
	r, _ := New(Options{Dir: f.work, Branch: "main"})
	d, err := r.Host("alpha")
	if err != nil || d.HasVars || strings.Contains(d.Vars, "leak") {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestRedactionFollowsAliasesAndScrubsComments(t *testing.T) {
	f := newFixture(t)
	vars := "# api_token: ghp_abcdefghijklmnopqrstuvwxyz0123456789\n" +
		"shared: &a s3cretvalue\n" +
		"password: *a\n" +
		"other: fine # token = abc\n" +
		"list:\n  - one\n" +
		"# the foot comment is harmless\n"
	write(t, f.work, "inventory/host_vars/alpha.yml", vars)
	r, _ := New(Options{Dir: f.work, Branch: "main"})
	d, err := r.Host("alpha")
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"s3cretvalue", "ghp_", "abc"} {
		if strings.Contains(d.Vars, leak) {
			t.Errorf("leaks %q:\n%s", leak, d.Vars)
		}
	}
	for _, keep := range []string{"other: fine", "- one", "harmless"} {
		if !strings.Contains(d.Vars, keep) {
			t.Errorf("lost %q:\n%s", keep, d.Vars)
		}
	}
	if d.Hidden < 3 {
		t.Errorf("hidden = %d\n%s", d.Hidden, d.Vars)
	}
}

func TestSymlinkedDirectoryOutsideTheCloneIsNotFollowed(t *testing.T) {
	f := newFixture(t)
	outside := t.TempDir()
	write(t, outside, "alpha.yml", "leak: yes\n")
	hv := filepath.Join(f.work, "inventory/host_vars")
	if err := os.RemoveAll(hv); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, hv); err != nil {
		t.Skip("no symlinks")
	}
	r, _ := New(Options{Dir: f.work, Branch: "main"})
	d, err := r.Host("alpha")
	if err != nil || d.HasVars || strings.Contains(d.Vars, "leak") {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestHostDetailsReadsTheInventoryOnceForAllHosts(t *testing.T) {
	f := newFixture(t)
	r, _ := New(Options{Dir: f.work, Branch: "main"})
	ds, err := r.HostDetails()
	if err != nil || len(ds) != 4 {
		t.Fatalf("%v %d", err, len(ds))
	}
	for _, d := range ds {
		if d.Name == "alpha" && (len(d.Features) != 3 || d.Vars == "") {
			t.Errorf("alpha: %+v", d)
		}
	}
}
