package gitstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/edit"
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

// env is a bare origin, a server clone and a second "laptop" clone.
type env struct {
	bare, server, laptop string
}

func newEnv(t *testing.T) env {
	t.Helper()
	root := t.TempDir()
	e := env{bare: filepath.Join(root, "origin.git"), server: filepath.Join(root, "server"), laptop: filepath.Join(root, "laptop")}
	sh(t, root, "init", "--bare", "-b", "main", e.bare)
	seed := testutil.CopyExample(t)
	sh(t, seed, "init", "-b", "main")
	sh(t, seed, "add", ".")
	sh(t, seed, "commit", "-m", "seed")
	sh(t, seed, "remote", "add", "origin", e.bare)
	sh(t, seed, "push", "origin", "main")
	sh(t, root, "clone", e.bare, e.server)
	sh(t, root, "clone", e.bare, e.laptop)
	return e
}

func open(t *testing.T, dir string, mut func(*Options)) *Store {
	t.Helper()
	o := Options{ConfigPath: filepath.Join(dir, "rackbook.yml"), Committer: Identity{"Rackbook", "rackbook@example.org"}}
	if mut != nil {
		mut(&o)
	}
	s, err := Open(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var editor = &auth.Identity{ID: "ann@example.com", Name: "Ann Editor", Email: "ann@example.com", Method: auth.MethodCloudflareAccess}

func sshEdit(t *testing.T, s *Store, port string) edit.Op {
	t.Helper()
	id := "web-hostco-ashburn-va-us-dc/SSH"
	r := s.Ledger().Collection("services").Get(id)
	return edit.Op{Kind: edit.Edit, Collection: "services", ID: id, Hash: r.Hash,
		Data: map[string]any{"device": "web-hostco-ashburn-va-us-dc", "service": "SSH", "port": port, "exposure": "公网 + Tailscale", "notes": "仅密钥"}}
}

func TestWritePushesCommitWithAuthorAndTrailers(t *testing.T) {
	e := newEnv(t)
	s := open(t, e.server, nil)
	res, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), editor)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Commit) < 7 || res.ID != "web-hostco-ashburn-va-us-dc/SSH" {
		t.Fatalf("%+v", res)
	}
	got := sh(t, e.bare, "log", "-1", "--format=%an <%ae>|%cn <%ce>|%B")
	want := "Ann Editor <ann@example.com>|Rackbook <rackbook@example.org>|ledger(services): edit web-hostco-ashburn-va-us-dc/SSH\n\nEdited-by: ann@example.com\nEdited-via: rackbook (cloudflare-access)\nRecord: services/web-hostco-ashburn-va-us-dc/SSH"
	if got != want {
		t.Fatalf("commit:\n%s\nwant:\n%s", got, want)
	}
	if sh(t, e.bare, "rev-list", "--count", "main") != "2" {
		t.Fatal("expected seed + one commit")
	}
	if r := s.Ledger().Collection("services").Get("web-hostco-ashburn-va-us-dc/SSH"); r.Data["port"] != "TCP 22" {
		t.Fatal("ledger not reloaded")
	}
	// One line changed in the pushed commit.
	if n := strings.Count(sh(t, e.bare, "show", "--format=", "--numstat", "HEAD"), "\n"); n != 0 {
		t.Fatal("expected a single changed file")
	}
	if stat := sh(t, e.bare, "show", "--format=", "--numstat", "HEAD"); !strings.HasPrefix(stat, "1\t1\t") {
		t.Fatalf("numstat: %s", stat)
	}
	// An unchanged edit makes no commit.
	res, err = s.Write(context.Background(), sshEdit(t, s, "TCP 22"), editor)
	if err != nil || res.Commit != "" {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestPushRaceReplaysEditOnNewTip(t *testing.T) {
	e := newEnv(t)
	s := open(t, e.server, nil)
	raced := 0
	s.beforePush = func() {
		if raced > 0 {
			return
		}
		raced++
		// Someone else changes an unrelated record and pushes first.
		sh(t, e.laptop, "pull", "--quiet")
		p := filepath.Join(e.laptop, "docs/ledger/todo.yml")
		b, _ := os.ReadFile(p)
		os.WriteFile(p, []byte(strings.Replace(string(b), "status: 待决定}", "status: 完成}", 1)), 0o644)
		sh(t, e.laptop, "commit", "-qam", "laptop edit")
		sh(t, e.laptop, "push", "--quiet", "origin", "main")
	}
	res, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), editor)
	if err != nil {
		t.Fatal(err)
	}
	if raced != 1 || res.Commit == "" {
		t.Fatalf("raced=%d %+v", raced, res)
	}
	log := sh(t, e.bare, "log", "--format=%s", "main")
	if log != "ledger(services): edit web-hostco-ashburn-va-us-dc/SSH\nlaptop edit\nseed" {
		t.Fatalf("history:\n%s", log)
	}
	l := s.Ledger()
	if l.Collection("services").Get("web-hostco-ashburn-va-us-dc/SSH").Data["port"] != "TCP 22" ||
		!strings.HasPrefix(l.Collection("todo").Records[0].Data["status"].(string), "完成") {
		t.Fatal("both changes must be present after the replay")
	}
	if sh(t, e.server, "status", "--porcelain") != "" {
		t.Fatal("work tree must be clean")
	}
}

func TestPushRaceOnSameRecordConflicts(t *testing.T) {
	e := newEnv(t)
	s := open(t, e.server, nil)
	s.beforePush = func() {
		sh(t, e.laptop, "pull", "--quiet")
		p := filepath.Join(e.laptop, "docs/ledger/services.yml")
		b, _ := os.ReadFile(p)
		os.WriteFile(p, []byte(strings.Replace(string(b), "service: SSH, port: TCP 10511, exposure: 公网 + Tailscale, notes: 仅密钥", "service: SSH, port: TCP 2222, exposure: 公网 + Tailscale, notes: 仅密钥", 1)), 0o644)
		sh(t, e.laptop, "commit", "-qam", "laptop edit")
		sh(t, e.laptop, "push", "--quiet", "origin", "main")
	}
	_, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), editor)
	var ce *edit.ConflictError
	if !errors.As(err, &ce) || ce.Current == nil || ce.Current.Data["port"] != "TCP 2222" {
		t.Fatalf("expected conflict with the upstream record, got %v", err)
	}
	if sh(t, e.bare, "rev-list", "--count", "main") != "2" || sh(t, e.server, "status", "--porcelain") != "" {
		t.Fatal("nothing of ours may be pushed and the tree must be clean")
	}
}

func TestStaleHashIs409AndInvalidIs422(t *testing.T) {
	e := newEnv(t)
	s := open(t, e.server, nil)
	op := sshEdit(t, s, "TCP 22")
	// Remote change to the same record after the client read it.
	sh(t, e.laptop, "pull", "--quiet")
	p := filepath.Join(e.laptop, "docs/ledger/services.yml")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(b), "notes: 仅密钥}", "notes: 仅密钥登录}", 1)), 0o644)
	sh(t, e.laptop, "commit", "-qam", "laptop edit")
	sh(t, e.laptop, "push", "--quiet", "origin", "main")

	var ce *edit.ConflictError
	if _, err := s.Write(context.Background(), op, editor); !errors.As(err, &ce) || ce.Current.Data["notes"] != "仅密钥登录" {
		t.Fatalf("409: %v", err)
	}
	var ie *edit.InvalidError
	_, err := s.Write(context.Background(), edit.Op{Kind: edit.Add, Collection: "services", Data: map[string]any{"device": "ghost", "service": "x", "port": "TCP 1"}}, editor)
	if !errors.As(err, &ie) {
		t.Fatalf("422: %v", err)
	}
	if sh(t, e.server, "status", "--porcelain") != "" {
		t.Fatal("tree must stay clean")
	}
}

func TestDirtyCloneIsRefused(t *testing.T) {
	e := newEnv(t)
	s := open(t, e.server, nil)
	f := filepath.Join(e.server, "docs/ledger/todo.yml")
	b, _ := os.ReadFile(f)
	os.WriteFile(f, append(b, "# hand edit\n"...), 0o644)
	if _, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), editor); err == nil || !strings.Contains(err.Error(), "uncommitted") {
		t.Fatalf("%v", err)
	}
}

func TestPullFastForwardsAndReloads(t *testing.T) {
	e := newEnv(t)
	s := open(t, e.server, nil)
	p := filepath.Join(e.laptop, "docs/ledger/todo.yml")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append(b, "- {item: from laptop, status: 待办}\n"...), 0o644)
	sh(t, e.laptop, "commit", "-qam", "laptop edit")
	sh(t, e.laptop, "push", "--quiet", "origin", "main")
	if err := s.Pull(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.Ledger().Collection("todo").Get("from laptop") == nil {
		t.Fatal("pull did not reload")
	}
}

func TestHistory(t *testing.T) {
	e := newEnv(t)
	s := open(t, e.server, nil)
	if _, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), editor); err != nil {
		t.Fatal(err)
	}
	h, err := s.History(context.Background(), 10, "", "")
	if err != nil || len(h) != 2 || h[0].Author != "Ann Editor" || h[0].Email != "ann@example.com" || h[0].Subject != "ledger(services): edit web-hostco-ashburn-va-us-dc/SSH" || !strings.HasSuffix(h[0].Date, "Z") {
		t.Fatalf("%v %+v", err, h)
	}
	h, _ = s.History(context.Background(), 10, "todo", "")
	if len(h) != 1 || h[0].Subject != "seed" {
		t.Fatalf("filtered: %+v", h)
	}
}

func TestPRMode(t *testing.T) {
	e := newEnv(t)
	sh(t, e.server, "pull", "--quiet")
	testutil.Replace(t, e.server, "rackbook.yml", "mode: push", "mode: pr")
	sh(t, e.server, "commit", "-qam", "pr mode")
	sh(t, e.server, "push", "--quiet", "origin", "main")

	var got map[string]string
	var auth string
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if r.Method != http.MethodPost || r.URL.Path != "/repos/acme/ledger/pulls" {
			http.NotFound(w, r)
			return
		}
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"html_url":"https://github.com/acme/ledger/pull/7"}`))
	}))
	defer gh.Close()
	s := open(t, e.server, func(o *Options) { o.GitHubToken, o.GitHubRepo, o.GitHubAPI = "tok", "acme/ledger", gh.URL })
	res, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), editor)
	if err != nil {
		t.Fatal(err)
	}
	if res.Commit != "https://github.com/acme/ledger/pull/7" || auth != "Bearer tok" {
		t.Fatalf("%+v auth=%q", res, auth)
	}
	if !strings.HasPrefix(got["head"], "rackbook/ann/") || got["base"] != "main" || got["title"] != "ledger(services): edit web-hostco-ashburn-va-us-dc/SSH" {
		t.Fatalf("payload: %v", got)
	}
	branches := sh(t, e.bare, "branch", "--list", "rackbook/*")
	if !strings.Contains(branches, got["head"]) {
		t.Fatalf("branch not pushed: %s", branches)
	}
	if sh(t, e.bare, "rev-list", "--count", "main") != "2" {
		t.Fatal("main must not move in pr mode")
	}
	if s.Ledger().Collection("services").Get("web-hostco-ashburn-va-us-dc/SSH").Data["port"] != "TCP 10511" {
		t.Fatal("the server checkout must stay on origin/main in pr mode")
	}
	// Missing token fails early.
	s2 := open(t, e.server, nil)
	if _, err := s2.Write(context.Background(), sshEdit(t, s2, "TCP 22"), editor); err == nil || !strings.Contains(err.Error(), "TOKEN") {
		t.Fatalf("%v", err)
	}
}

func TestNoGitMode(t *testing.T) {
	dir := testutil.CopyExample(t)
	s := open(t, dir, nil)
	if s.GitEnabled() {
		t.Fatal("not a repo")
	}
	res, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), nil)
	if err != nil || res.Commit != "" || !res.Changed() {
		t.Fatalf("%v %+v", err, res)
	}
	if h, err := s.History(context.Background(), 5, "", ""); err != nil || len(h) != 0 {
		t.Fatalf("%v %v", h, err)
	}
	// Hand edits show up without a reload step.
	testutil.Replace(t, dir, "docs/ledger/todo.yml", "status: 推迟}", "status: 完成}")
	if got := s.Ledger().Collection("todo").Records[2].Data["status"]; got != "完成" {
		t.Fatalf("got %v", got)
	}
	// --no-git inside a repository behaves the same.
	e := newEnv(t)
	s = open(t, e.server, func(o *Options) { o.NoGit = true })
	if _, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), nil); err != nil || sh(t, e.bare, "rev-list", "--count", "main") != "1" {
		t.Fatalf("%v", err)
	}
}

func TestParseRemoteAndIdentity(t *testing.T) {
	for in, want := range map[string]string{
		"git@github.com:acme/ledger.git":          "github.com acme ledger",
		"https://github.com/acme/ledger":          "github.com acme ledger",
		"https://user:pw@github.com/acme/ledger/": "github.com acme ledger",
		"ssh://git@ghe.example.com:2222/a/b.git":  "ghe.example.com a b",
	} {
		h, o, r, err := ParseRemote(in)
		if err != nil || h+" "+o+" "+r != want {
			t.Errorf("%s: %s %s %s %v", in, h, o, r, err)
		}
	}
	if _, _, _, err := ParseRemote("/tmp/origin.git"); err == nil {
		t.Error("local path must fail")
	}
	if id, err := ParseIdentity("Ann <ann@example.com>"); err != nil || id != (Identity{"Ann", "ann@example.com"}) {
		t.Errorf("%v %v", id, err)
	}
	if id, _ := ParseIdentity("bob@example.com"); id.Name != "bob" {
		t.Errorf("%v", id)
	}
	if _, err := ParseIdentity("nonsense"); err == nil {
		t.Error("expected error")
	}
}

func TestCommitFilesInWorkingTree(t *testing.T) {
	e := newEnv(t)
	sh(t, e.server, "config", "user.name", "Me")
	sh(t, e.server, "config", "user.email", "me@example.com")
	testutil.Replace(t, e.server, "docs/ledger/todo.yml", "status: 推迟}", "status: 完成}")
	testutil.Replace(t, e.server, "docs/ledger/ports.yml", "TCP 10510", "TCP 10509")
	short, err := CommitFiles(context.Background(), e.server, []string{"docs/ledger/todo.yml"}, "ledger(todo): edit x", nil, "todo/x")
	if err != nil || short == "" {
		t.Fatal(err)
	}
	if got := sh(t, e.server, "log", "-1", "--format=%an|%cn|%B"); !strings.HasPrefix(got, "Me|Me|ledger(todo): edit x\n\nEdited-by: me@example.com\nEdited-via: rackbook (cli)\nRecord: todo/x") {
		t.Fatal(got)
	}
	if st := sh(t, e.server, "status", "--porcelain"); st != "M docs/ledger/ports.yml" && st != " M docs/ledger/ports.yml" {
		t.Fatalf("other changes must stay uncommitted: %q", st)
	}
	if err := PushCurrent(context.Background(), e.server); err != nil {
		t.Fatal(err)
	}
	if sh(t, e.bare, "rev-list", "--count", "main") != "2" {
		t.Fatal("not pushed")
	}
}

func localRepo(t *testing.T) string {
	t.Helper()
	dir := testutil.CopyExample(t)
	sh(t, dir, "init", "-b", "main")
	sh(t, dir, "add", ".")
	sh(t, dir, "commit", "-m", "seed")
	return dir
}

func TestDirtyTreeRefusedWithoutRemoteToo(t *testing.T) {
	dir := localRepo(t)
	s := open(t, dir, nil)
	if !s.GitEnabled() || s.HasRemote() {
		t.Fatal("expected git without a remote")
	}
	f := filepath.Join(dir, "docs/ledger/todo.yml")
	b, _ := os.ReadFile(f)
	hand := append(b, "# hand edit\n"...)
	os.WriteFile(f, hand, 0o644)
	if _, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), editor); err == nil || !strings.Contains(err.Error(), "uncommitted") {
		t.Fatalf("%v", err)
	}
	if got, _ := os.ReadFile(f); string(got) != string(hand) {
		t.Fatal("the hand edit must survive")
	}
	// Clean tree: the write commits locally.
	os.WriteFile(f, b, 0o644)
	if res, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), editor); err != nil || res.Commit == "" {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestDiscardOnlyTouchesTheEditedFiles(t *testing.T) {
	dir := localRepo(t)
	s := open(t, dir, nil)
	parent, _ := s.repo.Head(context.Background())
	ssh := filepath.Join(dir, "docs/ledger/services.yml")
	other := filepath.Join(dir, "docs/ledger/todo.yml")
	orig, _ := os.ReadFile(ssh)
	os.WriteFile(ssh, append(append([]byte{}, orig...), "# ours\n"...), 0o644)
	ob, _ := os.ReadFile(other)
	mine := append(append([]byte{}, ob...), "# not ours\n"...)
	os.WriteFile(other, mine, 0o644)
	s.discard(context.Background(), parent, []string{"docs/ledger/services.yml"})
	if got, _ := os.ReadFile(ssh); string(got) != string(orig) {
		t.Fatal("edited file must be restored")
	}
	if got, _ := os.ReadFile(other); string(got) != string(mine) {
		t.Fatal("unrelated changes must not be reset")
	}
}

func TestPushThatSucceededDespiteErrorIsNotReplayed(t *testing.T) {
	e := newEnv(t)
	s := open(t, e.server, nil)
	r := &Repo{Dir: e.server}
	s.pushFn = func(ctx context.Context, branch string) error {
		if err := r.Push(ctx, branch); err != nil {
			return err
		}
		return errors.New("connection reset after the remote accepted the push")
	}
	res, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), editor)
	if err != nil || res.Commit == "" {
		t.Fatalf("%v %+v", err, res)
	}
	if sh(t, e.bare, "rev-list", "--count", "main") != "2" {
		t.Fatal("the edit must be committed exactly once")
	}
}

func TestPRModeNeverSendsTheTokenToAnUnknownHost(t *testing.T) {
	e := newEnv(t)
	testutil.Replace(t, e.server, "rackbook.yml", "mode: push", "mode: pr")
	sh(t, e.server, "commit", "-qam", "pr mode")
	sh(t, e.server, "push", "--quiet", "origin", "main")
	calls := 0
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer gh.Close()
	// Origin is a local path and no API URL is configured: refuse instead of guessing a host.
	s := open(t, e.server, func(o *Options) { o.GitHubToken, o.GitHubRepo = "tok", "acme/ledger" })
	_, err := s.Write(context.Background(), sshEdit(t, s, "TCP 22"), editor)
	if err == nil || !strings.Contains(err.Error(), "--github-api") || calls != 0 {
		t.Fatalf("%v calls=%d", err, calls)
	}
	sh(t, e.server, "remote", "set-url", "origin", "https://git.example.com/acme/ledger.git")
	s = open(t, e.server, func(o *Options) { o.GitHubToken = "tok"; o.NoGit = false })
	s.remote = "https://git.example.com/acme/ledger.git"
	if _, err := s.createPR(context.Background(), "h", "main", "t", "b"); err == nil || !strings.Contains(err.Error(), "refusing to send") {
		t.Fatalf("%v", err)
	}
}
