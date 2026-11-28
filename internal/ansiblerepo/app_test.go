package ansiblerepo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/githubapp"
	"github.com/kazuhahub/rackbook/internal/githubapp/githubapptest"
	"github.com/kazuhahub/rackbook/internal/gitstore"
)

// The infra clone refreshes over https with a GitHub App token that can only
// read, and never needs an SSH key.
func TestRefreshOverHTTPSWithAReadOnlyAppToken(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	api := githubapptest.NewAPI(t, "77", nil)
	srv := gitServer(t, api)
	bare := bareRepo(t, srv, "org/infra")
	git(t, f.seed, "push", bare, "HEAD:refs/heads/main")
	git(t, f.work, "remote", "set-url", "origin", srv.URL("org/infra"))
	key, err := githubapp.ParseKey(api.KeyPEM())
	if err != nil {
		t.Fatal(err)
	}
	app, err := githubapp.New(githubapp.Options{AppID: "77", Key: key, API: api.URL})
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(Options{Dir: f.work, Branch: "main",
		Auth: &gitstore.GitAuth{Source: app, Perms: githubapp.Permissions{Contents: "read"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if st := r.State(); st.Error != "" || st.Head == "" {
		t.Fatalf("state: %+v", st)
	}
	iss := api.Issued()
	if len(iss) != 1 || iss[0].Repo != "org/infra" || len(iss[0].Perms) != 1 || iss[0].Perms["contents"] != "read" {
		t.Fatalf("tokens: %+v", iss)
	}
	if srv.Served() == 0 {
		t.Fatal("nothing reached the git server")
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
