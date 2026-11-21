package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/ansiblerepo"
	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/mcpserver"
	"github.com/kazuhahub/rackbook/internal/roles"
)

const (
	testIssuer = "https://idp.test"
	testClient = "rackbook-console"
	testTenant = "tenant-1"
)

// testSessions signs a caller in from headers: X-User names the identity and
// X-Method the login method (default oidc). An oidc session was issued under
// testIssuer and testClient, X-Issuer and X-Client change that, and
// X-Signed-In-Age is how many seconds ago the person signed in (default 60).
type testSessions struct{ now func() time.Time }

func (ts testSessions) Identify(w http.ResponseWriter, r *http.Request) (*auth.Identity, error) {
	u := r.Header.Get("X-User")
	if u == "" {
		return nil, auth.ErrUnauthenticated
	}
	m := r.Header.Get("X-Method")
	if m == "" {
		m = auth.MethodOIDC
	}
	id := &auth.Identity{ID: u, Email: u, Name: u, Method: m}
	if m == auth.MethodOIDC {
		id.OIDCIssuer, id.OIDCClient, id.OIDCClaim, id.OIDCTenant = testIssuer, testClient, "preferred_username", testTenant
		if v := r.Header.Get("X-Claim"); v != "" {
			id.OIDCClaim = v
		}
		if v := r.Header.Get("X-Tenant"); v != "" {
			id.OIDCTenant = v
		}
		if v := r.Header.Get("X-Issuer"); v != "" {
			id.OIDCIssuer = v
		}
		if v := r.Header.Get("X-Client"); v != "" {
			id.OIDCClient = v
		}
		age := 60
		if v := r.Header.Get("X-Signed-In-Age"); v != "" {
			fmt.Sscan(v, &age)
		}
		id.OIDCAt = ts.now().Add(-time.Duration(age) * time.Second)
	}
	return id, nil
}
func (testSessions) Public(r *http.Request) bool { return false }
func (testSessions) Reject(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, "login", http.StatusUnauthorized)
}
func (testSessions) NoRole(w http.ResponseWriter, r *http.Request, id *auth.Identity) {
	http.Error(w, "no role", http.StatusForbidden)
}

// testBearer turns "Authorization: Bearer <kind>" into an admin-role identity
// of the listed person with that method.
type testBearer struct{}

func (testBearer) AuthenticateBearer(r *http.Request) (*auth.Identity, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return nil, nil
	}
	id := &auth.Identity{ID: "me@kazuha.org", Email: "me@kazuha.org", Role: roles.Admin}
	switch strings.TrimPrefix(h, "Bearer ") {
	case "token":
		id.Method, id.Token = auth.MethodToken, "ci"
	case "oauth":
		id.Method = auth.MethodOAuth
	case "mcphub":
		id.Method = auth.MethodMCPHub
	}
	return id, nil
}
func (testBearer) Challenge(r *http.Request) string { return "" }

const infraInventory = `all:
  children:
    managed:
      hosts:
        alpha:
        beta:
    hub:
      hosts:
        alpha:
`

const infraAlphaVars = "tailscale_ip: 100.64.0.1\nfeatures:\n  beszel-agent:\n    mode: websocket\n    token: nope\n"

type infraEnv struct {
	*fixture
	work, seed, status string
	repo               *ansiblerepo.Repo
	now                time.Time
}

func newInfraEnv(t *testing.T, admins ...string) *infraEnv {
	t.Helper()
	root := t.TempDir()
	bare, seed, work := filepath.Join(root, "o.git"), filepath.Join(root, "seed"), filepath.Join(root, "work")
	sh(t, root, "init", "--bare", "--initial-branch=main", bare)
	sh(t, root, "clone", bare, seed)
	for rel, body := range map[string]string{"inventory/hosts.yml": infraInventory, "inventory/host_vars/alpha.yml": infraAlphaVars} {
		p := filepath.Join(seed, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sh(t, seed, "add", ".")
	sh(t, seed, "commit", "-m", "add hosts")
	sh(t, seed, "push", "origin", "HEAD:refs/heads/main")
	sh(t, root, "clone", "--branch", "main", bare, work)

	e := &infraEnv{seed: seed, work: work, status: filepath.Join(root, "status.json"), now: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	repo, err := ansiblerepo.New(ansiblerepo.Options{Dir: work, Branch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	ia, err := auth.NewInfraAdmins(admins)
	if err != nil {
		t.Fatal(err)
	}
	if err := ia.Pin(testIssuer, testClient, "", testTenant, 0); err != nil {
		t.Fatal(err)
	}
	e.repo = repo
	e.fixture = newFixture(t, func(o *api.Options) {
		a, err := auth.New(context.Background(), auth.Config{Mode: auth.ModeOIDC, Sessions: testSessions{now: func() time.Time { return e.now }}, Config: o.Store.Config})
		if err != nil {
			t.Fatal(err)
		}
		a.SetBearer(testBearer{})
		o.Auth, o.Now = a, func() time.Time { return e.now }
		o.Infra = &api.InfraOptions{Repo: repo, Admins: ia, StatusFile: e.status}
		o.MCP = mcpserver.Handler(mcpserver.New(o.Store.Ledger, "test"), false)
	}, "")
	return e
}

func (e *infraEnv) head(t *testing.T) string { return sh(t, e.seed, "rev-parse", "HEAD") }

func (e *infraEnv) writeStatus(t *testing.T, at time.Time, applied string) {
	t.Helper()
	doc := map[string]any{
		"apiVersion": "v1", "time": at.UTC().Format(time.RFC3339), "main": applied,
		"hosts": []any{
			map[string]any{"name": "alpha", "report": map[string]any{"appliedCommit": applied, "result": "ok", "time": at.UTC().Format(time.RFC3339), "message": "applied"}},
			map[string]any{"name": "beta"},
		},
		"certs":   []any{map[string]any{"name": "a.example", "owner": "alpha", "notAfter": "2027-01-01T00:00:00Z", "failing": true, "lastError": "dns", "failures": 3}},
		"iplists": map[string]any{"providers": []any{}, "lists": []any{map[string]any{"name": "cloudflare", "entries": 22, "version": "v9", "warnings": []string{"shrunk"}, "history": []any{}}}},
	}
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(e.status, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

var infraPaths = []string{"/api/infra/hosts", "/api/infra/hosts/alpha", "/api/infra/certs", "/api/infra/iplists", "/api/infra/commits"}

func TestInfraOnlyForListedOIDCSessions(t *testing.T) {
	e := newInfraEnv(t, "me@kazuha.org")
	e.writeStatus(t, e.now, e.head(t))
	admin := map[string]string{"X-User": "me@kazuha.org"}
	for _, p := range infraPaths {
		if code, body, _ := e.do(t, "GET", p, nil, admin); code != 200 {
			t.Errorf("admin %s: %d %v", p, code, body)
		}
	}
	denied := map[string]map[string]string{
		"another signed-in person (editor)": {"X-User": "editor@kazuha.org"},
		"listed person, passkey login":      {"X-User": "me@kazuha.org", "X-Method": auth.MethodPasskey},
		"listed person, API token":          {"Authorization": "Bearer token"},
		"listed person, OAuth token":        {"Authorization": "Bearer oauth"},
		"listed person, MCP token":          {"Authorization": "Bearer mcphub"},
	}
	for name, hdr := range denied {
		for _, p := range infraPaths {
			code, body, _ := e.do(t, "GET", p, nil, hdr)
			if code != http.StatusForbidden || body["error"] != "forbidden" {
				t.Errorf("%s %s: %d %v", name, p, code, body)
			}
		}
	}
	if code, _, _ := e.do(t, "GET", "/api/infra/hosts", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("no session: %d", code)
	}
	// nothing writes
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		if code, _, _ := e.do(t, m, "/api/infra/hosts", map[string]string{}, admin); code == 200 {
			t.Errorf("%s answered 200", m)
		}
	}
}

func TestInfraAdminIsNotTakenFromTheLedgerRoles(t *testing.T) {
	// The ledger grants me@ admin and everybody else editor (no roles block);
	// the infra list names somebody else, so the ledger admin is refused.
	e := newInfraEnv(t, "someone-else@kazuha.org")
	if code, _, _ := e.do(t, "GET", "/api/infra/hosts", nil, map[string]string{"X-User": "me@kazuha.org"}); code != http.StatusForbidden {
		t.Fatalf("%d", code)
	}
}

func TestInfraNeverOnMCP(t *testing.T) {
	e := newInfraEnv(t, "me@kazuha.org")
	for _, p := range []string{"/mcp/api/infra/hosts", "/mcp/infra"} {
		if code, _, _ := e.do(t, "GET", p, nil, map[string]string{"X-User": "me@kazuha.org"}); code == 200 {
			t.Errorf("%s answered 200", p)
		}
	}
	// the MCP tool list names nothing of infra
	req, _ := http.NewRequest("POST", e.ts.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("X-User", "me@kazuha.org")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	if strings.Contains(strings.ToLower(b.String()), "infra") {
		t.Errorf("MCP mentions infra: %s", b.String())
	}
}

func TestInfraHostsJoinTheHubStatus(t *testing.T) {
	e := newInfraEnv(t, "me@kazuha.org")
	admin := map[string]string{"X-User": "me@kazuha.org"}
	head := e.head(t)

	e.writeStatus(t, e.now.Add(-time.Minute), head)
	code, body, _ := e.do(t, "GET", "/api/infra/hosts", nil, admin)
	if code != 200 {
		t.Fatal(code, body)
	}
	hub := body["hub"].(map[string]any)
	if hub["state"] != "ok" || hub["ageSeconds"].(float64) != 60 {
		t.Fatalf("hub: %v", hub)
	}
	hosts := arr(t, body["hosts"])
	if len(hosts) != 2 {
		t.Fatalf("hosts: %v", hosts)
	}
	alpha, beta := hosts[0].(map[string]any), hosts[1].(map[string]any)
	if alpha["name"] != "alpha" || alpha["behind"] != false || alpha["report"].(map[string]any)["result"] != "ok" || fmt.Sprint(alpha["groups"]) != "[hub managed]" {
		t.Fatalf("alpha: %v", alpha)
	}
	if fmt.Sprint(alpha["features"]) != "[beszel-agent]" || alpha["hasVars"] != true || beta["report"] != nil || beta["hasVars"] != false {
		t.Fatalf("alpha/beta: %v %v", alpha, beta)
	}
	if body["repo"].(map[string]any)["head"] != head {
		t.Fatalf("repo: %v", body["repo"])
	}

	// the host applied an older commit: behind main
	e.writeStatus(t, e.now, "0123456789abcdef0123456789abcdef01234567")
	_, body, _ = e.do(t, "GET", "/api/infra/hosts", nil, admin)
	if arr(t, body["hosts"])[0].(map[string]any)["behind"] != true {
		t.Fatalf("not behind: %v", body["hosts"])
	}
	// an abbreviated applied commit still equals the head
	e.writeStatus(t, e.now, head[:12])
	_, body, _ = e.do(t, "GET", "/api/infra/hosts", nil, admin)
	if arr(t, body["hosts"])[0].(map[string]any)["behind"] != false {
		t.Fatalf("short hash behind: %v", body["hosts"])
	}
}

func TestInfraStatusUnavailable(t *testing.T) {
	e := newInfraEnv(t, "me@kazuha.org")
	admin := map[string]string{"X-User": "me@kazuha.org"}
	check := func(state string) {
		t.Helper()
		for _, p := range []string{"/api/infra/hosts", "/api/infra/hosts/alpha", "/api/infra/certs", "/api/infra/iplists"} {
			code, body, _ := e.do(t, "GET", p, nil, admin)
			if code != 200 || body["hub"].(map[string]any)["state"] != state {
				t.Errorf("%s: %d %v", p, code, body)
			}
			if body["report"] != nil || body["certs"] != nil && len(arr(t, body["certs"])) != 0 || body["lists"] != nil && len(arr(t, body["lists"])) != 0 {
				t.Errorf("%s shows data of a status that is %s: %v", p, state, body)
			}
		}
		_, body, _ := e.do(t, "GET", "/api/infra/hosts", nil, admin)
		for _, h := range arr(t, body["hosts"]) {
			if h.(map[string]any)["report"] != nil || h.(map[string]any)["behind"] != false {
				t.Errorf("report shown while %s: %v", state, h)
			}
		}
	}
	check("missing") // no file yet
	e.writeStatus(t, e.now.Add(-4*time.Minute), e.head(t))
	check("stale") // older than three minutes
	if err := os.WriteFile(e.status, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	check("invalid")
}

func TestInfraHostPageCertsListsAndCommits(t *testing.T) {
	e := newInfraEnv(t, "me@kazuha.org")
	admin := map[string]string{"X-User": "me@kazuha.org"}
	e.writeStatus(t, e.now, e.head(t))

	code, body, _ := e.do(t, "GET", "/api/infra/hosts/alpha", nil, admin)
	host := body["host"].(map[string]any)
	if code != 200 || host["name"] != "alpha" || body["report"].(map[string]any)["message"] != "applied" {
		t.Fatalf("%d %v", code, body)
	}
	vars := host["vars"].(string)
	if !strings.Contains(vars, "tailscale_ip: 100.64.0.1") || strings.Contains(vars, "nope") || host["hidden"].(float64) != 1 {
		t.Fatalf("vars: %q hidden %v", vars, host["hidden"])
	}
	if code, _, _ := e.do(t, "GET", "/api/infra/hosts/nope", nil, admin); code != 404 {
		t.Fatalf("unknown host: %d", code)
	}
	if code, _, _ := e.do(t, "GET", "/api/infra/hosts/..%2Fetc", nil, admin); code != 404 && code != 400 {
		t.Fatalf("traversal: %d", code)
	}

	_, body, _ = e.do(t, "GET", "/api/infra/certs", nil, admin)
	c := arr(t, body["certs"])[0].(map[string]any)
	if c["name"] != "a.example" || c["owner"] != "alpha" || c["failing"] != true || c["lastError"] != "dns" || c["notAfter"] != "2027-01-01T00:00:00Z" {
		t.Fatalf("cert: %v", c)
	}
	_, body, _ = e.do(t, "GET", "/api/infra/iplists", nil, admin)
	l := arr(t, body["lists"])[0].(map[string]any)
	if l["name"] != "cloudflare" || l["entries"].(float64) != 22 || l["version"] != "v9" || fmt.Sprint(l["warnings"]) != "[shrunk]" {
		t.Fatalf("list: %v", l)
	}
	_, body, _ = e.do(t, "GET", "/api/infra/commits", nil, admin)
	cs := arr(t, body["commits"])
	if len(cs) != 1 || cs[0].(map[string]any)["subject"] != "add hosts" || cs[0].(map[string]any)["hash"] != e.head(t) {
		t.Fatalf("commits: %v", cs)
	}
}

func TestInfraOffWithoutOptions(t *testing.T) {
	f := newFixture(t, nil, "")
	if code, _, _ := f.do(t, "GET", "/api/infra/hosts", nil, nil); code != http.StatusNotFound {
		t.Fatalf("%d", code)
	}
}

func TestMetaTellsOnlyInfraAdmins(t *testing.T) {
	e := newInfraEnv(t, "me@kazuha.org")
	user := func(hdr map[string]string) map[string]any {
		_, body, _ := e.do(t, "GET", "/api/meta", nil, hdr)
		return body["user"].(map[string]any)
	}
	if user(map[string]string{"X-User": "me@kazuha.org"})["canInfra"] != true {
		t.Error("the infra admin is not told")
	}
	if v, ok := user(map[string]string{"X-User": "x@kazuha.org"})["canInfra"]; ok {
		t.Errorf("another person is told: %v", v)
	}
	if v, ok := user(map[string]string{"Authorization": "Bearer token"})["canInfra"]; ok {
		t.Errorf("a token is told: %v", v)
	}
}

func TestInfraBehindNeedsAFullEnoughHashAndAWorkingRefresh(t *testing.T) {
	e := newInfraEnv(t, "me@kazuha.org")
	admin := map[string]string{"X-User": "me@kazuha.org"}
	head := e.head(t)
	first := func() map[string]any {
		_, body, _ := e.do(t, "GET", "/api/infra/hosts", nil, admin)
		return arr(t, body["hosts"])[0].(map[string]any)
	}
	// "a" must not count as every commit starting with a
	e.writeStatus(t, e.now, head[:1])
	if first()["behind"] != true {
		t.Error("a one-character hash was taken for the head")
	}
	// the refresh fails: the head may be old, so no host is called behind
	sh(t, e.work, "remote", "set-url", "origin", filepath.Join(filepath.Dir(e.work), "gone.git"))
	if err := e.repo.Refresh(context.Background()); err == nil {
		t.Fatal("the refresh should fail")
	}
	e.writeStatus(t, e.now, "0123456789abcdef0123456789abcdef01234567")
	if first()["behind"] != false {
		t.Error("behind is claimed against a head that may be out of date")
	}
	_, body, _ := e.do(t, "GET", "/api/infra/hosts", nil, admin)
	if body["repo"].(map[string]any)["error"] == nil {
		t.Errorf("the refresh error is not shown: %v", body["repo"])
	}
}
