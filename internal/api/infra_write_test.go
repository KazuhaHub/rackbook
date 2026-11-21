package api_test

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/ansiblerepo"
	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/githubapp"
	"github.com/kazuhahub/rackbook/internal/githubapp/githubapptest"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/mcpserver"
)

const wInventory = `all:
  children:
    managed:
      hosts:
        alpha:
        beta:
    derp:
      hosts:
        alpha:
`

const wAlpha = "# alpha\ntailscale_ip: 100.64.0.1\n\nfeatures:\n  demo:\n    name: one\n"

const wFeature = `name: demo
description: demo
type: package
settings:
  name: {type: string, required: true, pattern: "[a-z]+"}
  port: {type: int, min: 1, max: 65535}
  mode: {type: enum, enum: [a, b], default: a}
  token: {type: string, secret: true}
`

type wAudit struct {
	mu sync.Mutex
	e  []ansiblerepo.AuditEntry
}

func (a *wAudit) Record(e ansiblerepo.AuditEntry) { a.mu.Lock(); a.e = append(a.e, e); a.mu.Unlock() }
func (a *wAudit) outcomes() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var o []string
	for _, e := range a.e {
		o = append(o, e.Outcome)
	}
	return o
}

type wEnv struct {
	*fixture
	bare, seed, work string
	repo             *ansiblerepo.Repo
	audit            *wAudit
	now              time.Time
}

func newWEnv(t *testing.T, mut func(o *api.Options, io *api.InfraOptions), admins ...string) *wEnv {
	t.Helper()
	return newWEnvX(t, wExtra{}, mut, admins...)
}

// wExtra changes what newWEnv seeds: files replaced or added (an empty body
// leaves the file out) and the sops runner of the repository.
type wExtra struct {
	seed map[string]string
	sops ansiblerepo.Sopser
}

func newWEnvX(t *testing.T, x wExtra, mut func(o *api.Options, io *api.InfraOptions), admins ...string) *wEnv {
	t.Helper()
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Skip("git not installed")
	}
	backend := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git http-backend not available")
	}
	root := t.TempDir()
	gh := githubapptest.NewAPI(t, "9", nil)
	srv := githubapptest.NewGit(t, gh, backend)
	bare := srv.Path(t, "org/infra")
	for _, a := range [][]string{{"init", "--bare", "--initial-branch=main", bare}, {"-C", bare, "config", "http.receivepack", "true"}} {
		if b, err := exec.Command("git", a...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", a, err, b)
		}
	}
	e := &wEnv{bare: bare, seed: filepath.Join(root, "seed"), work: filepath.Join(root, "work"), audit: &wAudit{}, now: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	sh(t, root, "clone", bare, e.seed)
	files := map[string]string{
		"inventory/hosts.yml":           wInventory,
		"inventory/host_vars/alpha.yml": wAlpha,
		"inventory/host_vars/beta.yml":  "tailscale_ip: 100.64.0.2\n",
		"secrets/alpha.sops.yaml":       "sops: {}\n",
		"secrets/beta.sops.yaml":        "sops: {}\n",
		"features/demo/feature.yml":     wFeature,
	}
	for rel, body := range x.seed {
		files[rel] = body
	}
	for rel, body := range files {
		if body == "" {
			continue
		}
		p := filepath.Join(e.seed, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sh(t, e.seed, "add", ".")
	sh(t, e.seed, "commit", "-m", "seed")
	sh(t, e.seed, "push", "origin", "HEAD:refs/heads/main")
	sh(t, root, "clone", "--branch", "main", bare, e.work)
	sh(t, e.work, "remote", "set-url", "origin", srv.URL("org/infra"))
	key, err := githubapp.ParseKey(gh.KeyPEM())
	if err != nil {
		t.Fatal(err)
	}
	app, err := githubapp.New(githubapp.Options{AppID: "9", Key: key, API: gh.URL})
	if err != nil {
		t.Fatal(err)
	}
	e.repo, err = ansiblerepo.New(ansiblerepo.Options{Dir: e.work, Branch: "main", Audit: e.audit,
		Committer: gitstore.Identity{Name: "Rackbook", Email: "rackbook@kazuha.org"},
		Auth:      &gitstore.GitAuth{Source: app, Perms: githubapp.Permissions{Contents: "read"}},
		WriteAuth: &gitstore.GitAuth{Source: app, Perms: githubapp.Permissions{Contents: "write"}}, Sops: x.sops})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.repo.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(admins) == 0 {
		admins = []string{"me@kazuha.org"}
	}
	ia, err := auth.NewInfraAdmins(admins)
	if err != nil {
		t.Fatal(err)
	}
	if err := ia.Pin(testIssuer, testClient, "", testTenant, 12*time.Hour); err != nil {
		t.Fatal(err)
	}
	e.fixture = newFixture(t, func(o *api.Options) {
		a, err := auth.New(context.Background(), auth.Config{Mode: auth.ModeOIDC, Sessions: testSessions{now: func() time.Time { return e.now }}, Config: o.Store.Config})
		if err != nil {
			t.Fatal(err)
		}
		a.SetBearer(testBearer{})
		o.Auth, o.Now = a, func() time.Time { return e.now }
		io := &api.InfraOptions{Repo: e.repo, Admins: ia, Write: true, Audit: e.audit}
		o.MCP = mcpserver.Handler(mcpserver.New(o.Store.Ledger, "test"), false)
		if mut != nil {
			mut(o, io)
		}
		o.Infra = io
	}, "")
	return e
}

var me = map[string]string{"X-User": "me@kazuha.org"}

func (e *wEnv) remote(t *testing.T, format string) string {
	return sh(t, e.bare, "log", "-1", "--format="+format)
}

func (e *wEnv) base(t *testing.T, path string) string {
	t.Helper()
	code, body, _ := e.do(t, "GET", path, nil, me)
	if code != 200 {
		t.Fatalf("%s: %d %v", path, code, body)
	}
	return body["base"].(string)
}

func TestInfraWriteAuthorization(t *testing.T) {
	e := newWEnv(t, nil)
	path := "/api/infra/hosts/alpha/vars"
	base := e.base(t, path)
	post := func(hdr map[string]string) (int, map[string]any) {
		code, body, _ := e.do(t, "POST", path, map[string]any{"base": base, "content": wAlpha + "x: 1\n", "preview": true}, hdr)
		return code, body
	}
	if code, body := post(me); code != 200 {
		t.Fatalf("the listed, freshly signed-in person: %d %v", code, body)
	}
	denied := map[string]map[string]string{
		"signed-in person who is not an infra admin": {"X-User": "editor@kazuha.org"},
		"listed person, API token":                   {"Authorization": "Bearer token"},
		"listed person, OAuth token":                 {"Authorization": "Bearer oauth"},
		"listed person, MCP token":                   {"Authorization": "Bearer mcphub"},
		"listed person, passkey":                     {"X-User": "me@kazuha.org", "X-Method": auth.MethodPasskey},
		"listed person, another issuer":              {"X-User": "me@kazuha.org", "X-Issuer": "https://evil.test"},
		"listed person, another client":              {"X-User": "me@kazuha.org", "X-Client": "other-app"},
	}
	for name, hdr := range denied {
		if code, body := post(hdr); code != http.StatusForbidden || body["error"] != "forbidden" {
			t.Errorf("%s: %d %v", name, code, body)
		}
		// the same people cannot read either
		if code, _, _ := e.do(t, "GET", path, nil, hdr); code != http.StatusForbidden {
			t.Errorf("%s may read: %d", name, code)
		}
	}
	if code, _, _ := e.do(t, "POST", path, map[string]any{"base": base, "content": "x: 1\n"}, nil); code != http.StatusUnauthorized {
		t.Errorf("no session: %d", code)
	}
	if e.remote(t, "%s") != "seed" {
		t.Fatal("a refused request committed something")
	}
}

func TestInfraWriteNeedsARecentSignIn(t *testing.T) {
	e := newWEnv(t, nil)
	path := "/api/infra/hosts/alpha/vars"
	base := e.base(t, path)
	old := map[string]string{"X-User": "me@kazuha.org", "X-Signed-In-Age": "46800"} // 13 hours
	code, body, _ := e.do(t, "POST", path, map[string]any{"base": base, "content": wAlpha + "x: 1\n"}, old)
	if code != http.StatusForbidden || body["error"] != "reauth_required" || body["maxAgeSeconds"].(float64) != 43200 {
		t.Fatalf("%d %v", code, body)
	}
	// a preview is a write path too
	if code, body, _ := e.do(t, "POST", path, map[string]any{"base": base, "content": wAlpha + "x: 1\n", "preview": true}, old); code != http.StatusForbidden || body["error"] != "reauth_required" {
		t.Fatalf("preview: %d %v", code, body)
	}
	// reading still works with the old session, and says what to do
	if code, _, _ := e.do(t, "GET", path, nil, old); code != 200 {
		t.Fatalf("read: %d", code)
	}
	code, st, _ := e.do(t, "GET", "/api/infra/write", nil, old)
	if code != 200 || st["enabled"] != true || st["fresh"] != false {
		t.Fatalf("%d %v", code, st)
	}
	if _, st, _ := e.do(t, "GET", "/api/infra/write", nil, me); st["fresh"] != true {
		t.Fatalf("%v", st)
	}
	// just inside the window
	if code, _, _ := e.do(t, "POST", path, map[string]any{"base": base, "content": wAlpha + "x: 1\n", "preview": true}, map[string]string{"X-User": "me@kazuha.org", "X-Signed-In-Age": "43000"}); code != 200 {
		t.Fatalf("%d", code)
	}
	if got := e.audit.outcomes(); len(got) != 2 || got[0] != "reauth_required" {
		t.Fatalf("audit %v", got)
	}
	if e.remote(t, "%s") != "seed" {
		t.Fatal("committed")
	}
}

func TestInfraWriteOffByDefaultAndOnAReadOnlyServer(t *testing.T) {
	for name, mut := range map[string]func(o *api.Options, io *api.InfraOptions){
		"editors off":      func(o *api.Options, io *api.InfraOptions) { io.Write = false },
		"read-only server": func(o *api.Options, io *api.InfraOptions) { o.ReadOnly = true },
	} {
		e := newWEnv(t, mut)
		base := e.base(t, "/api/infra/hosts/alpha/vars")
		code, body, _ := e.do(t, "POST", "/api/infra/hosts/alpha/vars", map[string]any{"base": base, "content": "x: 1\n"}, me)
		if code != http.StatusForbidden || body["error"] != "read_only" {
			t.Errorf("%s: %d %v", name, code, body)
		}
		_, meta, _ := e.do(t, "GET", "/api/meta", nil, me)
		if u, _ := meta["user"].(map[string]any); u["canInfra"] != true || u["canInfraWrite"] == true {
			t.Errorf("%s: meta %v", name, meta["user"])
		}
	}
	e := newWEnv(t, nil)
	_, meta, _ := e.do(t, "GET", "/api/meta", nil, me)
	if u, _ := meta["user"].(map[string]any); u["canInfraWrite"] != true {
		t.Errorf("meta %v", meta["user"])
	}
	_, meta, _ = e.do(t, "GET", "/api/meta", nil, map[string]string{"X-User": "editor@kazuha.org"})
	if u, _ := meta["user"].(map[string]any); u["canInfra"] == true || u["canInfraWrite"] == true {
		t.Errorf("meta %v", meta["user"])
	}
}

func TestInfraWriteIsNeverOnMCP(t *testing.T) {
	e := newWEnv(t, nil)
	for _, p := range []string{"/mcp/api/infra/hosts/alpha/vars", "/mcp/infra/groups"} {
		if code, _, _ := e.do(t, "POST", p, map[string]any{}, me); code == 200 {
			t.Errorf("%s answered 200", p)
		}
	}
}

func TestInfraEditHostVarsCommitsAsThePerson(t *testing.T) {
	e := newWEnv(t, nil)
	path := "/api/infra/hosts/alpha/vars"
	code, st, _ := e.do(t, "GET", path, nil, me)
	if code != 200 || st["content"] != wAlpha || st["exists"] != true {
		t.Fatalf("%d %v", code, st)
	}
	base := st["base"].(string)
	body := map[string]any{"base": base, "content": wAlpha + "x: 1\n", "preview": true}
	code, pv, _ := e.do(t, "POST", path, body, me)
	if code != 200 || pv["blocked"] != false || pv["commit"] != nil || !strings.Contains(arr(t, pv["diffs"])[0].(map[string]any)["diff"].(string), "+x: 1") {
		t.Fatalf("preview %d %v", code, pv)
	}
	if e.remote(t, "%s") != "seed" {
		t.Fatal("a preview committed")
	}
	body["preview"] = false
	code, res, _ := e.do(t, "POST", path, body, map[string]string{"X-User": "me@kazuha.org"})
	if code != 200 || res["commit"] == nil || res["commit"] == "" {
		t.Fatalf("%d %v", code, res)
	}
	if e.remote(t, "%s") != "infra(host_vars/alpha): edit" || e.remote(t, "%an <%ae>") != "me@kazuha.org <me@kazuha.org>" || e.remote(t, "%cn") != "Rackbook" {
		t.Fatalf("%s | %s | %s", e.remote(t, "%s"), e.remote(t, "%an <%ae>"), e.remote(t, "%cn"))
	}
	msg := e.remote(t, "%B")
	for _, w := range []string{"Edited-by: me@kazuha.org", "Edited-via: rackbook (oidc)", "Files: inventory/host_vars/alpha.yml"} {
		if !strings.Contains(msg, w) {
			t.Errorf("%q missing:\n%s", w, msg)
		}
	}
	if n := len(strings.Split(strings.TrimSpace(msg), "\n")); n != 5 {
		t.Errorf("the message is the subject and three trailers, got %d lines:\n%s", n, msg)
	}
	// the same base again: the file moved on, so this is a conflict with a diff
	code, c, _ := e.do(t, "POST", path, map[string]any{"base": base, "content": wAlpha + "y: 2\n"}, me)
	if code != http.StatusConflict || c["error"] != "conflict" || len(arr(t, c["diffs"])) != 1 || arr(t, c["files"])[0] != "inventory/host_vars/alpha.yml" {
		t.Fatalf("%d %v", code, c)
	}
	// invalid content: 422 with issues, nothing committed
	head := e.remote(t, "%H")
	base = e.base(t, path)
	code, inv, _ := e.do(t, "POST", path, map[string]any{"base": base, "content": "a: 1\na: 2\n"}, me)
	issues := arr(t, inv["issues"])
	if code != http.StatusUnprocessableEntity || inv["error"] != "invalid" || issues[0].(map[string]any)["code"] != "yaml.duplicate_key" || e.remote(t, "%H") != head {
		t.Fatalf("%d %v", code, inv)
	}
	if got := e.audit.outcomes(); len(got) != 2 || got[0] != "conflict" || got[1] != "validation_failed" {
		t.Fatalf("audit %v", got)
	}
	// nothing changed
	if code, nc, _ := e.do(t, "POST", path, map[string]any{"base": base, "content": wAlpha + "x: 1\n"}, me); code != http.StatusUnprocessableEntity || nc["error"] != "no_change" {
		t.Fatalf("%d %v", code, nc)
	}
	// unknown host
	if code, _, _ := e.do(t, "GET", "/api/infra/hosts/nope/vars", nil, me); code != 404 {
		t.Fatalf("%d", code)
	}
	if code, _, _ := e.do(t, "POST", "/api/infra/hosts/nope/vars", map[string]any{"content": "x: 1\n"}, me); code != 404 {
		t.Fatalf("%d", code)
	}
}

func TestInfraRawEditorRefusesAFileWithSecretLookingValues(t *testing.T) {
	e := newWEnv(t, nil)
	e.upstream(t, "inventory/host_vars/beta.yml", "api_token: abc123secret\nip: 1\n")
	if err := e.repo.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	code, st, _ := e.do(t, "GET", "/api/infra/hosts/beta/vars", nil, me)
	if code != 200 || st["content"] != "" || st["hidden"].(float64) != 1 {
		t.Fatalf("%d %v", code, st)
	}
	code, body, _ := e.do(t, "POST", "/api/infra/hosts/beta/vars", map[string]any{"base": st["base"], "content": "ip: 2\n"}, me)
	if code != http.StatusUnprocessableEntity || body["error"] != "edit_failed" {
		t.Fatalf("%d %v", code, body)
	}
}

func (e *wEnv) upstream(t *testing.T, rel, body string) {
	t.Helper()
	sh(t, e.seed, "pull", "--quiet", "origin", "main")
	p := filepath.Join(e.seed, rel)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	sh(t, e.seed, "add", ".")
	sh(t, e.seed, "commit", "-m", "upstream "+rel)
	sh(t, e.seed, "push", "origin", "HEAD:refs/heads/main")
}

func TestInfraFeaturesFormEdits(t *testing.T) {
	e := newWEnv(t, nil)
	code, fl, _ := e.do(t, "GET", "/api/infra/features", nil, me)
	feats := arr(t, fl["features"])
	if code != 200 || len(feats) != 1 || feats[0].(map[string]any)["name"] != "demo" {
		t.Fatalf("%d %v", code, fl)
	}
	set := feats[0].(map[string]any)["settings"].([]any)
	if len(set) != 4 || set[3].(map[string]any)["secret"] != true {
		t.Fatalf("%v", set)
	}
	path := "/api/infra/hosts/alpha/features/demo"
	base := e.base(t, "/api/infra/hosts/alpha/vars")
	code, res, _ := e.do(t, "POST", path, map[string]any{"base": base, "enabled": true, "settings": map[string]any{"name": "two", "port": 8080, "mode": "b"}}, me)
	if code != 200 {
		t.Fatalf("%d %v", code, res)
	}
	got := sh(t, e.bare, "show", "HEAD:inventory/host_vars/alpha.yml")
	if !strings.Contains(got, "# alpha\n") || !strings.Contains(got, "name: two") || !strings.Contains(got, "port: 8080") || !strings.Contains(got, "mode: b") || !strings.Contains(got, "100.64.0.1\n\nfeatures:") {
		t.Fatalf("%s", got)
	}
	if e.remote(t, "%s") != "infra(host_vars/alpha): update demo" {
		t.Fatalf("%s", e.remote(t, "%s"))
	}
	// a secret setting is refused while no age key is configured, nothing is committed
	head := e.remote(t, "%H")
	base = e.base(t, "/api/infra/hosts/alpha/vars")
	code, res, _ = e.do(t, "POST", path, map[string]any{"base": base, "enabled": true, "settings": map[string]any{"name": "two", "token": "supersecret"}}, me)
	iss := arr(t, res["issues"])
	if code != http.StatusUnprocessableEntity || iss[0].(map[string]any)["code"] != "feature.secret_unavailable" || e.remote(t, "%H") != head {
		t.Fatalf("%d %v", code, res)
	}
	// a bad value is refused by the checks (pattern: lowercase letters)
	code, res, _ = e.do(t, "POST", path, map[string]any{"base": base, "enabled": true, "settings": map[string]any{"name": "NOPE"}}, me)
	if code != http.StatusUnprocessableEntity || arr(t, res["issues"])[0].(map[string]any)["code"] != "feature.bad_value" {
		t.Fatalf("%d %v", code, res)
	}
	// an unknown feature
	if code, _, _ := e.do(t, "POST", "/api/infra/hosts/beta/features/nope", map[string]any{"base": "", "enabled": true, "settings": map[string]any{}}, me); code != 404 {
		t.Fatalf("%d", code)
	}
	// enable on beta, then disable
	base = e.base(t, "/api/infra/hosts/beta/vars")
	if code, res, _ := e.do(t, "POST", "/api/infra/hosts/beta/features/demo", map[string]any{"base": base, "enabled": true, "settings": map[string]any{"name": "beta"}}, me); code != 200 {
		t.Fatalf("%d %v", code, res)
	}
	if e.remote(t, "%s") != "infra(host_vars/beta): enable demo" {
		t.Fatalf("%s", e.remote(t, "%s"))
	}
	base = e.base(t, "/api/infra/hosts/beta/vars")
	if code, res, _ := e.do(t, "POST", "/api/infra/hosts/beta/features/demo", map[string]any{"base": base, "enabled": false}, me); code != 200 {
		t.Fatalf("%d %v", code, res)
	}
	if got := sh(t, e.bare, "show", "HEAD:inventory/host_vars/beta.yml"); strings.Contains(got, "features") {
		t.Fatalf("%s", got)
	}
}

func TestInfraGroupsEditor(t *testing.T) {
	e := newWEnv(t, nil)
	code, inv, _ := e.do(t, "GET", "/api/infra/groups", nil, me)
	m := inv["membership"].(map[string]any)
	if code != 200 || len(arr(t, m["groups"])) != 2 || len(arr(t, m["hosts"])) != 2 {
		t.Fatalf("%d %v", code, inv)
	}
	base := inv["base"].(string)
	code, res, _ := e.do(t, "POST", "/api/infra/groups", map[string]any{"base": base, "changes": []map[string]any{{"host": "beta", "group": "derp", "member": true}}}, me)
	if code != 200 {
		t.Fatalf("%d %v", code, res)
	}
	if got := sh(t, e.bare, "show", "HEAD:inventory/hosts.yml"); !strings.Contains(got, "    derp:\n      hosts:\n        alpha:\n        beta:") {
		t.Fatalf("%s", got)
	}
	if e.remote(t, "%s") != "infra(inventory/hosts): groups +beta derp" {
		t.Fatalf("%s", e.remote(t, "%s"))
	}
	// unknown group / host, empty change, stale base
	base = e.base(t, "/api/infra/groups")
	for name, ch := range map[string][]map[string]any{
		"unknown group": {{"host": "beta", "group": "nope", "member": true}},
		"unknown host":  {{"host": "ghost", "group": "derp", "member": true}},
		"empty":         {},
	} {
		if code, body, _ := e.do(t, "POST", "/api/infra/groups", map[string]any{"base": base, "changes": ch}, me); code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d %v", name, code, body)
		}
	}
	if code, body, _ := e.do(t, "POST", "/api/infra/groups", map[string]any{"base": "0000000000000000000000000000000000000000", "changes": []map[string]any{{"host": "alpha", "group": "derp", "member": false}}}, me); code != http.StatusConflict || body["error"] != "conflict" {
		t.Errorf("stale: %d %v", code, body)
	}
	// breaking a rule is refused: alpha out of managed leaves it in derp
	code, body, _ := e.do(t, "POST", "/api/infra/groups", map[string]any{"base": base, "changes": []map[string]any{{"host": "alpha", "group": "managed", "member": false}}}, me)
	if code != http.StatusUnprocessableEntity || arr(t, body["issues"])[0].(map[string]any)["code"] != "inventory.not_managed" {
		t.Fatalf("%d %v", code, body)
	}
}

func TestInfraHistoryAndRevert(t *testing.T) {
	e := newWEnv(t, nil)
	base := e.base(t, "/api/infra/hosts/alpha/vars")
	if code, b, _ := e.do(t, "POST", "/api/infra/hosts/alpha/vars", map[string]any{"base": base, "content": wAlpha + "x: 1\n"}, me); code != 200 {
		t.Fatalf("%d %v", code, b)
	}
	code, h, _ := e.do(t, "GET", "/api/infra/commits", nil, me)
	cs := arr(t, h["commits"])
	if code != 200 || h["canRevert"] != true || len(cs) != 2 {
		t.Fatalf("%d %v", code, h)
	}
	top := cs[0].(map[string]any)
	if top["revertible"] != true || arr(t, top["files"])[0] != "inventory/host_vars/alpha.yml" {
		t.Fatalf("%v", top)
	}
	if cs[1].(map[string]any)["revertible"] != false || cs[1].(map[string]any)["reason"] != "root" {
		t.Fatalf("%v", cs[1])
	}
	hash := top["hash"].(string)
	// the revert is a write: not for a stale sign-in, not for others
	rp := "/api/infra/commits/" + hash + "/revert"
	if code, b, _ := e.do(t, "POST", rp, map[string]any{}, map[string]string{"X-User": "me@kazuha.org", "X-Signed-In-Age": "90000"}); code != 403 || b["error"] != "reauth_required" {
		t.Fatalf("%d %v", code, b)
	}
	if code, _, _ := e.do(t, "POST", rp, map[string]any{}, map[string]string{"Authorization": "Bearer token"}); code != 403 {
		t.Fatalf("%d", code)
	}
	if code, pv, _ := e.do(t, "POST", rp, map[string]any{"preview": true}, me); code != 200 || pv["commit"] != nil || len(arr(t, pv["diffs"])) != 1 {
		t.Fatalf("%d %v", code, pv)
	}
	// someone else touches the file after: the revert button turns into a 409
	e.upstream(t, "inventory/host_vars/alpha.yml", wAlpha+"x: 1\nz: 3\n")
	if err := e.repo.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	code, c, _ := e.do(t, "POST", rp, map[string]any{}, me)
	if code != http.StatusConflict || c["error"] != "conflict" || c["reason"] != "later_commits" || len(arr(t, c["later"])) != 1 {
		t.Fatalf("%d %v", code, c)
	}
	// the newest commit (upstream) can be reverted by anyone with access
	_, h, _ = e.do(t, "GET", "/api/infra/commits", nil, me)
	newest := arr(t, h["commits"])[0].(map[string]any)["hash"].(string)
	if code, b, _ := e.do(t, "POST", "/api/infra/commits/"+newest+"/revert", map[string]any{}, me); code != 200 {
		t.Fatalf("%d %v", code, b)
	}
	if got := sh(t, e.bare, "show", "HEAD:inventory/host_vars/alpha.yml"); got != strings.TrimRight(wAlpha+"x: 1\n", "\n") {
		t.Fatalf("%q", got)
	}
	// not a commit
	if code, _, _ := e.do(t, "POST", "/api/infra/commits/zzzz/revert", map[string]any{}, me); code == 200 {
		t.Fatal("zzzz")
	}
}

func TestInfraWriteRoutesAreAbsentWithoutInfra(t *testing.T) {
	f := newFixture(t, nil, "")
	for _, p := range []string{"/api/infra/groups", "/api/infra/features", "/api/infra/write"} {
		if code, _, _ := f.do(t, "GET", p, nil, nil); code != 404 {
			t.Errorf("%s: %d", p, code)
		}
	}
}
