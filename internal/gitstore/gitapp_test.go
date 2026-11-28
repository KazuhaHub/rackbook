package gitstore

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/githubapp"
	"github.com/kazuhahub/rackbook/internal/githubapp/githubapptest"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

// spy records every command with its environment and delegates to the real
// runner (through the suite's recorder).
type spy struct {
	mu   sync.Mutex
	cmds []Cmd
}

func (s *spy) Run(ctx context.Context, c Cmd) (string, string, error) {
	s.mu.Lock()
	s.cmds = append(s.cmds, Cmd{Dir: c.Dir, Args: append([]string{}, c.Args...), Env: append([]string{}, c.Env...)})
	s.mu.Unlock()
	return defaultRunner.Run(ctx, c)
}

func (s *spy) all() []Cmd {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Cmd{}, s.cmds...)
}

type appClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *appClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *appClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// appWorld is a fake GitHub (API + smart-HTTP git) holding org/ledger seeded
// with the example ledger, and a server clone whose origin is the https URL.
type appWorld struct {
	clk    *appClock
	api    *githubapptest.API
	git    *githubapptest.Git
	app    *githubapp.App
	bare   string
	server string
	spy    *spy
}

func newAppWorld(t *testing.T) *appWorld {
	t.Helper()
	w := &appWorld{clk: &appClock{t: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}, spy: &spy{}}
	w.api = githubapptest.NewAPI(t, "4242", w.clk.now)
	w.git = gitServer(t, w.api)
	key, err := githubapp.ParseKey(w.api.KeyPEM())
	if err != nil {
		t.Fatal(err)
	}
	w.app, err = githubapp.New(githubapp.Options{AppID: "4242", Key: key, API: w.api.URL, Now: w.clk.now})
	if err != nil {
		t.Fatal(err)
	}
	w.bare = bareRepo(t, w.git, "org/ledger")
	root := t.TempDir()
	seed := testutil.CopyExample(t)
	sh(t, seed, "init", "-b", "main")
	sh(t, seed, "add", ".")
	sh(t, seed, "commit", "-m", "seed")
	sh(t, seed, "remote", "add", "origin", w.bare)
	sh(t, seed, "push", "origin", "main")
	w.server = filepath.Join(root, "server")
	sh(t, root, "clone", w.bare, w.server)
	sh(t, w.server, "remote", "set-url", "origin", w.git.URL("org/ledger"))
	return w
}

func (w *appWorld) open(t *testing.T, logs *bytes.Buffer) *Store {
	t.Helper()
	return open(t, w.server, func(o *Options) {
		o.GitHubApp, o.GitHubAPI, o.Runner = w.app, w.api.URL, w.spy
		if logs != nil {
			o.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		}
	})
}

// noSecretAnywhere checks that no installation token is in any argv, in the
// clone's config or in the log, and that every token reached git only through
// the environment.
func (w *appWorld) noSecretAnywhere(t *testing.T, logs string) {
	t.Helper()
	issued := w.api.Issued()
	if len(issued) == 0 {
		t.Fatal("no token was issued")
	}
	cfg, _ := os.ReadFile(filepath.Join(w.server, ".git", "config"))
	for _, i := range issued {
		if strings.Contains(string(cfg), i.Token) || strings.Contains(logs, i.Token) {
			t.Fatalf("token %s leaked into .git/config or the log", i.Token)
		}
		for _, c := range w.spy.all() {
			for _, a := range c.Args {
				if strings.Contains(a, i.Token) {
					t.Fatalf("token in argv: %v", c.Args)
				}
			}
		}
	}
	if strings.Contains(string(cfg), "extraheader") || strings.Contains(string(cfg), "Authorization") {
		t.Fatalf(".git/config holds credentials:\n%s", cfg)
	}
	if strings.Contains(logs, "PRIVATE KEY") {
		t.Fatal("key material in the log")
	}
}

func TestAppPushesAndFetchesOverHTTPS(t *testing.T) {
	t.Parallel()
	w := newAppWorld(t)
	var logs bytes.Buffer
	s := w.open(t, &logs)
	if !s.git {
		t.Fatal("not a git store")
	}
	res, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), editor)
	if err != nil {
		t.Fatalf("write: %v\n%s", err, logs.String())
	}
	if len(res.Commit) < 7 {
		t.Fatalf("%+v", res)
	}
	if got := sh(t, w.bare, "log", "-1", "--format=%s"); !strings.Contains(got, "edit web-hostco-ashburn-va-us-dc/SSH") {
		t.Fatalf("push did not arrive: %s", got)
	}
	for _, i := range w.api.Issued() {
		if i.Repo != "org/ledger" || len(i.Perms) != 1 || i.Perms["contents"] != "write" {
			t.Fatalf("token not narrowed: %+v", i)
		}
	}
	if w.git.Served() == 0 {
		t.Fatal("the smart-HTTP server saw nothing")
	}
	w.noSecretAnywhere(t, logs.String())
	// The token reached git through GIT_CONFIG_* in the environment.
	seen := false
	for _, c := range w.spy.all() {
		for _, e := range c.Env {
			if strings.HasPrefix(e, "GIT_CONFIG_KEY_0=http.") && strings.HasSuffix(e, ".extraheader") {
				seen = true
			}
		}
	}
	if !seen {
		t.Fatal("no extraheader in any command environment")
	}
}

func TestAppTokenRefreshesAcrossTheHour(t *testing.T) {
	t.Parallel()
	w := newAppWorld(t)
	s := w.open(t, nil)
	if _, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), editor); err != nil {
		t.Fatal(err)
	}
	first := len(w.api.Issued())
	// Past expiry the old token is refused by the git server; the App must have
	// minted a new one, so this write still goes through.
	w.clk.add(61 * time.Minute)
	if _, err := s.Write(context.Background(), sshEdit(t, s, "TCP 23"), editor); err != nil {
		t.Fatalf("write after the token expired: %v", err)
	}
	if len(w.api.Issued()) <= first {
		t.Fatal("no new token after expiry")
	}
	if w.api.Lookups() != 1 {
		t.Fatalf("installation looked up %d times", w.api.Lookups())
	}
	w.noSecretAnywhere(t, "")
}

func TestAppWithoutAValidTokenCannotPush(t *testing.T) {
	t.Parallel()
	w := newAppWorld(t)
	// The same server clone without the App: the git server refuses.
	s := open(t, w.server, func(o *Options) { o.Runner = w.spy })
	if _, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), editor); err == nil {
		t.Fatal("a push without a token must fail")
	}
	if w.git.Denied() == 0 {
		t.Fatal("the server should have refused")
	}
}

func TestAppPRModeUsesAPullRequestToken(t *testing.T) {
	t.Parallel()
	w := newAppWorld(t)
	// the clone is already at the seed commit
	testutil.Replace(t, w.server, "rackbook.yml", "mode: push", "mode: pr")
	sh(t, w.server, "-c", "user.name=T", "-c", "user.email=t@example.com", "commit", "-qam", "pr mode")
	// publish the mode change straight to the bare repository
	sh(t, w.server, "push", "--quiet", w.bare, "HEAD:refs/heads/main")
	s := w.open(t, nil)
	res, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), editor)
	if err != nil {
		t.Fatal(err)
	}
	if !res.PullRequest || !strings.HasPrefix(res.Commit, "https://github.com/org/ledger/pull/") {
		t.Fatalf("%+v", res)
	}
	var contents, pr bool
	for _, i := range w.api.Issued() {
		if i.Perms["contents"] == "write" && len(i.Perms) == 1 {
			contents = true
		}
		if i.Perms["pull_requests"] == "write" && len(i.Perms) == 1 {
			pr = true
		}
	}
	if !contents || !pr {
		t.Fatalf("expected separate contents and pull_requests tokens: %+v", w.api.Issued())
	}
	if len(w.api.PullRequests()) != 1 {
		t.Fatalf("pull requests: %v", w.api.PullRequests())
	}
	w.noSecretAnywhere(t, "")
}

func TestMirrorFetchesOverHTTPSWithAReadOnlyToken(t *testing.T) {
	t.Parallel()
	w := newAppWorld(t)
	infra := bareRepo(t, w.git, "org/infra")
	seed := t.TempDir()
	sh(t, seed, "init", "-b", "main")
	if err := os.WriteFile(filepath.Join(seed, "site.yml"), []byte("- hosts: all\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sh(t, seed, "add", ".")
	sh(t, seed, "commit", "-m", "infra seed")
	sh(t, seed, "push", infra, "HEAD:refs/heads/main")
	work := filepath.Join(t.TempDir(), "infra")
	sh(t, filepath.Dir(work), "clone", infra, work)
	sh(t, work, "remote", "set-url", "origin", w.git.URL("org/infra"))

	m := &Mirror{Dir: work, Branch: "main", Runner: w.spy, Auth: &GitAuth{Source: w.app, Perms: githubapp.Permissions{Contents: "read"}}}
	head, err := m.Sync(context.Background())
	if err != nil || head != sh(t, seed, "rev-parse", "HEAD") {
		t.Fatalf("sync: %v %s", err, head)
	}
	var infraTokens int
	for _, i := range w.api.Issued() {
		if i.Repo == "org/infra" {
			infraTokens++
			if len(i.Perms) != 1 || i.Perms["contents"] != "read" {
				t.Fatalf("the read-only clone got %v", i.Perms)
			}
		}
	}
	if infraTokens != 1 {
		t.Fatalf("infra tokens: %d", infraTokens)
	}
	// The token narrowed to infra cannot read the ledger, and is not valid there.
	for _, i := range w.api.Issued() {
		if i.Repo == "org/infra" && w.api.Valid(i.Token, "org/ledger", "contents", "read") {
			t.Fatal("an infra token must not be valid for the ledger")
		}
	}
}

// stubSource is an App for github.com that never touches the network.
type stubSource struct{}

func (stubSource) Token(context.Context, string, string, githubapp.Permissions) (string, error) {
	return "ghs_stub", nil
}
func (stubSource) API() string { return githubapp.DefaultAPI }

func TestGitAuthEnvScopesTheHeaderAndRefusesUnsafeRemotes(t *testing.T) {
	t.Parallel()
	w := newAppWorld(t)
	w.api.Install("org/ledger")
	a := &GitAuth{Source: stubSource{}, Perms: githubapp.Permissions{Contents: "write"}}
	ctx := context.Background()

	// An ssh origin is spoken to over https for these commands only.
	env, err := a.env(ctx, "git@github.com:org/ledger.git")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(env, "\n")
	for _, want := range []string{"GIT_CONFIG_COUNT=3", "GIT_CONFIG_KEY_0=http.https://github.com/org/ledger.git.extraheader",
		"GIT_CONFIG_KEY_2=url.https://github.com/org/ledger.git.insteadOf", "GIT_CONFIG_VALUE_2=git@github.com:org/ledger.git"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in\n%s", want, joined)
		}
	}
	if err := refuseEnv(env); err != nil {
		t.Fatalf("the allow-list refuses its own environment: %v", err)
	}
	// A host other than the API's, plain http to a remote host, a local path.
	if _, err := a.env(ctx, "https://git.example.org/org/ledger.git"); err == nil {
		t.Error("sent a token to a host the API does not serve")
	}
	if _, err := a.env(ctx, "/some/local/path"); err == nil {
		t.Error("accepted a local path")
	}
	// Redirects are off in the same environment.
	if !strings.Contains(joined, "http.followRedirects") {
		t.Error("followRedirects not set")
	}
}

func TestGitHubRepoMustMatchOrigin(t *testing.T) {
	t.Parallel()
	w := newAppWorld(t)
	_, err := Open(context.Background(), Options{ConfigPath: filepath.Join(w.server, "rackbook.yml"), GitHubApp: w.app, GitHubRepo: "org/other", Runner: w.spy})
	if err == nil || !strings.Contains(err.Error(), "does not match the origin") {
		t.Fatalf("want a clear refusal, got %v", err)
	}
}

func TestInheritedEnvIsScrubbed(t *testing.T) {
	t.Parallel()
	in := []string{"PATH=/bin", "GIT_TRACE=1", "GIT_TRACE_CURL=/x", "GIT_CURL_VERBOSE=1", "GIT_SSL_NO_VERIFY=1", "GIT_CONFIG_PARAMETERS='a'",
		"GIT_ASKPASS=/x", "SSH_ASKPASS=/x", "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=a", "GIT_TRACE_REDACT=0", "HOME=/h",
		"RACKBOOK_STATE_KEY=k", "RACKBOOK_SESSION_KEY=k", "RACKBOOK_OIDC_CLIENT_SECRET=s"}
	got := inheritedEnv(in)
	if len(got) != 2 || got[0] != "PATH=/bin" || got[1] != "HOME=/h" {
		t.Fatalf("%v", got)
	}
}

func TestEnvAllowList(t *testing.T) {
	t.Parallel()
	ok := [][]string{
		{"GIT_SSH_COMMAND=ssh -i k", "GIT_AUTHOR_NAME=x"},
		{"GIT_CONFIG_COUNT=2", "GIT_CONFIG_KEY_0=http.https://h/o/r.git.extraheader", "GIT_CONFIG_VALUE_0=Authorization: Basic eA==", "GIT_CONFIG_KEY_1=http.followRedirects", "GIT_CONFIG_VALUE_1=false"},
	}
	for _, e := range ok {
		if err := refuseEnv(e); err != nil {
			t.Errorf("%v: %v", e, err)
		}
	}
	bad := [][]string{
		{"LD_PRELOAD=/x.so"},
		{"GIT_EXTERNAL_DIFF=/bin/sh"},
		{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=core.sshCommand", "GIT_CONFIG_VALUE_0=evil"},
		{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=core.hooksPath", "GIT_CONFIG_VALUE_0=/tmp"},
		{"GIT_CONFIG_PARAMETERS='x'"},
	}
	for _, e := range bad {
		if err := refuseEnv(e); err == nil {
			t.Errorf("accepted %v", e)
		}
	}
}

// gitServer starts the fake smart-HTTP git server, skipping when git has no
// http-backend.
func gitServer(t *testing.T, api *githubapptest.API) *githubapptest.Git {
	t.Helper()
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Skip("git not installed")
	}
	backend := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git http-backend not available")
	}
	return githubapptest.NewGit(t, api, backend)
}

// bareRepo creates the bare repository owner/repo on the fake server.
func bareRepo(t *testing.T, g *githubapptest.Git, repo string) string {
	t.Helper()
	dir := g.Path(t, repo)
	for _, args := range [][]string{{"init", "--bare", "--initial-branch=main", dir}, {"-C", dir, "config", "http.receivepack", "true"}} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}
