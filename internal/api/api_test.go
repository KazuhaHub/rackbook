package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/mcpserver"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

type fixture struct {
	dir string
	ts  *httptest.Server
}

func newFixture(t *testing.T, mut func(*api.Options), dir string) *fixture {
	t.Helper()
	if dir == "" {
		dir = testutil.CopyExample(t)
	}
	st, err := gitstore.Open(context.Background(), gitstore.Options{ConfigPath: filepath.Join(dir, "rackbook.yml"), Committer: gitstore.Identity{Name: "Rackbook", Email: "rackbook@example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	o := api.Options{Store: st, Web: fstest.MapFS{"index.html": {Data: []byte("<html>console</html>")}, "assets/app.js": {Data: []byte("js")}}}
	if mut != nil {
		mut(&o)
	}
	ts := httptest.NewServer(api.New(o))
	t.Cleanup(ts.Close)
	return &fixture{dir: dir, ts: ts}
}

func (f *fixture) do(t *testing.T, method, path string, body any, hdr map[string]string) (int, map[string]any, http.Header) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, f.ts.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s %s: bad JSON %q", method, path, raw)
		}
	} else {
		out = map[string]any{"_body": string(raw)}
	}
	return resp.StatusCode, out, resp.Header
}

func arr(t *testing.T, v any) []any {
	t.Helper()
	a, ok := v.([]any)
	if !ok {
		t.Fatalf("not an array: %#v", v)
	}
	return a
}

func TestMetaListGetCheck(t *testing.T) {
	f := newFixture(t, nil, "")
	code, m, _ := f.do(t, "GET", "/api/meta", nil, nil)
	if code != 200 || m["title"] != "示例网络台账" || m["writeMode"] != "push" || m["readOnly"] != false || m["alert"] != nil {
		t.Fatalf("%d %v", code, m)
	}
	cols := arr(t, m["collections"])
	if len(cols) != 9 {
		t.Fatalf("collections: %d", len(cols))
	}
	svc := cols[2].(map[string]any)
	if svc["name"] != "services" || svc["count"] != float64(9) || svc["group"] != "" {
		t.Fatalf("%v", svc)
	}
	if arr(t, svc["refs"])[0].(map[string]any)["toField"] != "name" || arr(t, svc["backrefs"]) == nil || arr(t, svc["notes"]) == nil {
		t.Fatalf("%v", svc)
	}
	facets := arr(t, svc["facets"])
	if facets[2].(map[string]any)["match"] != "contains" || len(arr(t, facets[0].(map[string]any)["values"])) != 0 {
		t.Fatalf("%v", facets)
	}
	schema := svc["schema"].(map[string]any)
	if schema["title"] != "服务端口" {
		t.Fatalf("%v", schema)
	}
	dev := cols[0].(map[string]any)
	if len(arr(t, dev["backrefs"])) != 2 {
		t.Fatalf("%v", dev["backrefs"])
	}
	docker := cols[6].(map[string]any)
	if n := arr(t, docker["notes"]); len(n) != 1 || n[0].(map[string]any)["title"] != "Docker 地址池规则" {
		t.Fatalf("%v", docker["notes"])
	}

	code, l, _ := f.do(t, "GET", "/api/c/devices", nil, nil)
	recs := arr(t, l["records"])
	if code != 200 || len(recs) != 5 || recs[0].(map[string]any)["id"] != "gw-example-springfield-or-us-home" || len(recs[0].(map[string]any)["hash"].(string)) != 16 {
		t.Fatalf("%d %v", code, l)
	}

	id := url.PathEscape("web-hostco-ashburn-va-us-dc/SSH")
	code, g, _ := f.do(t, "GET", "/api/c/services/"+id, nil, nil)
	if code != 200 || g["id"] != "web-hostco-ashburn-va-us-dc/SSH" {
		t.Fatalf("%d %v", code, g)
	}
	code, g, _ = f.do(t, "GET", "/api/c/devices/web-hostco-ashburn-va-us-dc", nil, nil)
	br := g["backrefs"].(map[string]any)
	if code != 200 || len(arr(t, br["services"])) != 4 || len(arr(t, br["addresses"])) != 2 {
		t.Fatalf("%d %v", code, g)
	}
	if code, e, _ := f.do(t, "GET", "/api/c/devices/nope", nil, nil); code != 404 || e["error"] != "not_found" {
		t.Fatalf("%d %v", code, e)
	}
	if code, e, _ := f.do(t, "GET", "/api/c/nope", nil, nil); code != 404 || e["error"] != "not_found" {
		t.Fatalf("%d %v", code, e)
	}
	if code, e, _ := f.do(t, "GET", "/api/nothing", nil, nil); code != 404 || e["error"] != "not_found" {
		t.Fatalf("%d %v", code, e)
	}
	code, c, _ := f.do(t, "GET", "/api/check", nil, nil)
	if code != 200 || c["ok"] != true || len(arr(t, c["errors"])) != 0 {
		t.Fatalf("%v", c)
	}
	code, h, _ := f.do(t, "GET", "/api/history", nil, nil)
	if code != 200 || len(arr(t, h["commits"])) != 0 {
		t.Fatalf("%v", h)
	}
}

func TestCheckReportsErrors(t *testing.T) {
	dir := testutil.CopyExample(t)
	testutil.Replace(t, dir, "docs/ledger/addresses.yml", "{device: laptop-me-pc, network", "{device: ghost, network")
	f := newFixture(t, nil, dir)
	_, c, _ := f.do(t, "GET", "/api/check", nil, nil)
	errs := arr(t, c["errors"])
	e := errs[0].(map[string]any)
	if c["ok"] != false || e["collection"] != "addresses" || e["rule"] != "ref" || e["path"] != "/device" || e["id"] != "ghost/Tailscale" {
		t.Fatalf("%v", c)
	}
}

func TestWriteFlow(t *testing.T) {
	f := newFixture(t, nil, "")
	id := url.PathEscape("web-hostco-ashburn-va-us-dc/SSH")
	_, g, _ := f.do(t, "GET", "/api/c/services/"+id, nil, nil)
	hash := g["hash"].(string)

	data := map[string]any{"device": "web-hostco-ashburn-va-us-dc", "service": "SSH", "port": "TCP 22", "exposure": "公网 + Tailscale", "notes": "仅密钥"}
	code, r, _ := f.do(t, "PUT", "/api/c/services/"+id, map[string]any{"data": data, "hash": hash}, nil)
	if code != 200 || r["id"] != "web-hostco-ashburn-va-us-dc/SSH" || r["commit"] != "" || r["hash"] == hash {
		t.Fatalf("%d %v", code, r)
	}
	newHash := r["hash"].(string)
	b, _ := os.ReadFile(filepath.Join(f.dir, "docs/ledger/services.yml"))
	if !strings.Contains(string(b), "service: SSH, port: TCP 22, exposure: 公网 + Tailscale, notes: 仅密钥}") {
		t.Fatal(string(b))
	}

	// Stale hash: 409 with the current record.
	code, r, _ = f.do(t, "PUT", "/api/c/services/"+id, map[string]any{"data": data, "hash": hash}, nil)
	cur, _ := r["current"].(map[string]any)
	if code != 409 || r["error"] != "conflict" || cur["hash"] != newHash {
		t.Fatalf("%d %v", code, r)
	}

	// Add, then duplicate add is a 409, invalid is a 422 with field errors.
	add := map[string]any{"data": map[string]any{"device": "all", "service": "NTP", "port": "UDP 123", "managed": true}}
	code, r, _ = f.do(t, "POST", "/api/c/services", add, nil)
	if code != 201 || r["id"] != "all/NTP" || r["data"].(map[string]any)["managed"] != true {
		t.Fatalf("%d %v", code, r)
	}
	if code, r, _ = f.do(t, "POST", "/api/c/services", add, nil); code != 409 || r["current"] == nil {
		t.Fatalf("%d %v", code, r)
	}
	code, r, _ = f.do(t, "POST", "/api/c/services", map[string]any{"data": map[string]any{"device": "ghost", "service": "x", "port": "TCP 1"}}, nil)
	errs := arr(t, r["errors"])
	if code != 422 || r["error"] != "invalid" || errs[0].(map[string]any)["rule"] != "ref" {
		t.Fatalf("%d %v", code, r)
	}
	code, r, _ = f.do(t, "POST", "/api/c/services", map[string]any{"data": map[string]any{"device": "all", "service": "y", "port": 5}}, nil)
	if code != 422 || arr(t, r["errors"])[0].(map[string]any)["path"] != "/port" {
		t.Fatalf("%d %v", code, r)
	}

	// Bad requests.
	if code, _, _ = f.do(t, "PUT", "/api/c/services/"+id, map[string]any{"data": data}, nil); code != 400 {
		t.Fatalf("missing hash: %d", code)
	}
	if code, _, _ = f.do(t, "POST", "/api/c/services", map[string]any{"nope": 1}, nil); code != 400 {
		t.Fatalf("empty data: %d", code)
	}

	// Delete: needs the hash.
	nid := url.PathEscape("all/NTP")
	if code, _, _ = f.do(t, "DELETE", "/api/c/services/"+nid, nil, nil); code != 400 {
		t.Fatalf("delete without hash: %d", code)
	}
	code, r, _ = f.do(t, "DELETE", "/api/c/services/"+nid+"?hash="+r0(t, f, "services", "all/NTP"), nil, nil)
	if code != 200 || r["commit"] != "" {
		t.Fatalf("%d %v", code, r)
	}
	if code, r, _ = f.do(t, "DELETE", "/api/c/services/"+nid+"?hash=abc", nil, nil); code != 409 || r["current"] != nil {
		t.Fatalf("%d %v", code, r)
	}
}

func r0(t *testing.T, f *fixture, coll, id string) string {
	_, g, _ := f.do(t, "GET", "/api/c/"+coll+"/"+url.PathEscape(id), nil, nil)
	return g["hash"].(string)
}

func TestIDsWithSlashAndPercent(t *testing.T) {
	f := newFixture(t, nil, "")
	code, r, _ := f.do(t, "POST", "/api/c/todo", map[string]any{"data": map[string]any{"item": "50% of a/b", "status": "待办"}}, nil)
	if code != 201 || r["id"] != "50%25 of a%2Fb" {
		t.Fatalf("%d %v", code, r)
	}
	code, g, _ := f.do(t, "GET", "/api/c/todo/"+url.PathEscape(r["id"].(string)), nil, nil)
	if code != 200 || g["data"].(map[string]any)["item"] != "50% of a/b" {
		t.Fatalf("%d %v", code, g)
	}
}

func TestReadOnlyAndEditors(t *testing.T) {
	f := newFixture(t, func(o *api.Options) { o.ReadOnly = true }, "")
	code, r, _ := f.do(t, "POST", "/api/c/todo", map[string]any{"data": map[string]any{"item": "x", "status": "待办"}}, nil)
	if code != 403 || r["error"] != "read_only" {
		t.Fatalf("%d %v", code, r)
	}
	_, m, _ := f.do(t, "GET", "/api/meta", nil, nil)
	if m["readOnly"] != true {
		t.Fatal(m)
	}

	a, err := auth.New(context.Background(), auth.Config{Mode: auth.ModeNone, Editor: "Ann <ann@example.com>", Editors: []string{"other@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	f = newFixture(t, func(o *api.Options) { o.Auth = a }, "")
	code, r, _ = f.do(t, "POST", "/api/c/todo", map[string]any{"data": map[string]any{"item": "x", "status": "待办"}}, nil)
	if code != 403 || r["error"] != "forbidden" {
		t.Fatalf("%d %v", code, r)
	}
	_, m, _ = f.do(t, "GET", "/api/meta", nil, nil)
	if u := m["user"].(map[string]any); u["email"] != "ann@example.com" || u["canEdit"] != false || u["role"] != "viewer" {
		t.Fatalf("%v", u)
	}
}

func TestAuthRequiredAndHealthz(t *testing.T) {
	a, _ := auth.New(context.Background(), auth.Config{Mode: auth.ModeCloudflareAccess, Team: "t", Audience: "a"})
	f := newFixture(t, func(o *api.Options) { o.Auth = a }, "")
	for _, p := range []string{"/api/meta", "/", "/llms.txt", "/export.json"} {
		if code, r, _ := f.do(t, "GET", p, nil, nil); code != 401 || r["error"] != "unauthorized" {
			t.Fatalf("%s: %d %v", p, code, r)
		}
	}
	if code, _, _ := f.do(t, "GET", "/healthz", nil, nil); code != 200 {
		t.Fatal("healthz must be open")
	}
}

func TestExports(t *testing.T) {
	f := newFixture(t, nil, "")
	for path, want := range map[string]string{
		"/export.md":     "text/markdown; charset=utf-8",
		"/llms-full.txt": "text/plain; charset=utf-8",
		"/llms.txt":      "text/plain; charset=utf-8",
		"/export.json":   "application/json; charset=utf-8",
	} {
		resp, err := http.Get(f.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != want || len(b) == 0 {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		if path == "/llms.txt" && !strings.Contains(string(b), f.ts.URL+"/api/c/devices") {
			t.Fatalf("llms.txt must link to the request's own base URL:\n%s", b)
		}
	}
	_, j, _ := f.do(t, "GET", "/export.json", nil, nil)
	if len(arr(t, j["collections"].(map[string]any)["devices"])) != 5 || len(arr(t, j["notes"])) != 2 {
		t.Fatalf("%v", j)
	}
}

func TestConsoleAndSecurityHeaders(t *testing.T) {
	f := newFixture(t, nil, "")
	for path, want := range map[string]string{"/": "console", "/c/services/foo": "console", "/assets/app.js": "js"} {
		resp, err := http.Get(f.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(b), want) {
			t.Fatalf("%s: %d %q", path, resp.StatusCode, b)
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Content-Security-Policy") == "" {
			t.Fatalf("%s: missing security headers", path)
		}
	}
	if resp, _ := http.Get(f.ts.URL + "/assets/missing.js"); resp.StatusCode != 404 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("missing asset: %d %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	// index.html must be revalidated so a new release's chunk names reach open
	// tabs; hashed assets never change, so they may be cached for good.
	for path, want := range map[string]string{
		"/":               "no-cache",
		"/index.html":     "no-cache",
		"/c/services/foo": "no-cache",
		"/assets/app.js":  "public, max-age=31536000, immutable",
	} {
		resp, err := http.Get(f.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("Cache-Control"); got != want {
			t.Fatalf("%s: Cache-Control %q, want %q", path, got, want)
		}
	}

	f = newFixture(t, func(o *api.Options) { o.Web = fstest.MapFS{".gitkeep": {}} }, "")
	resp, _ := http.Get(f.ts.URL + "/anything")
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), "not built") {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	f = newFixture(t, func(o *api.Options) { o.Web = nil }, "")
	if code, _, _ := f.do(t, "GET", "/api/meta", nil, nil); code != 200 {
		t.Fatal("API must work without a console")
	}
}

func TestMCPMounted(t *testing.T) {
	f := newFixture(t, func(o *api.Options) {
		o.MCP = mcpserver.Handler(mcpserver.New(o.Store.Ledger, "test"), false)
	}, "")
	req, _ := http.NewRequest("POST", f.ts.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"rackbook"`) {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
}

func sh(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Seed", "GIT_AUTHOR_EMAIL=s@e.com", "GIT_COMMITTER_NAME=Seed", "GIT_COMMITTER_EMAIL=s@e.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestGitBackedWriteAndHistory(t *testing.T) {
	root := t.TempDir()
	bare := filepath.Join(root, "origin.git")
	sh(t, root, "init", "--bare", "-b", "main", bare)
	seed := testutil.CopyExample(t)
	sh(t, seed, "init", "-b", "main")
	sh(t, seed, "add", ".")
	sh(t, seed, "commit", "-m", "seed")
	sh(t, seed, "remote", "add", "origin", bare)
	sh(t, seed, "push", "origin", "main")
	server := filepath.Join(root, "server")
	sh(t, root, "clone", bare, server)

	a, _ := auth.New(context.Background(), auth.Config{Editor: "Ann Editor <ann@example.com>"})
	f := newFixture(t, func(o *api.Options) { o.Auth = a }, server)
	id := url.PathEscape("web-hostco-ashburn-va-us-dc/SSH")
	_, g, _ := f.do(t, "GET", "/api/c/services/"+id, nil, nil)
	data := map[string]any{"device": "web-hostco-ashburn-va-us-dc", "service": "SSH", "port": "TCP 22", "exposure": "公网 + Tailscale", "notes": "仅密钥"}
	code, r, _ := f.do(t, "PUT", "/api/c/services/"+id, map[string]any{"data": data, "hash": g["hash"]}, nil)
	if code != 200 || len(r["commit"].(string)) < 7 {
		t.Fatalf("%d %v", code, r)
	}
	if got := sh(t, bare, "log", "-1", "--format=%an <%ae>|%cn|%s"); got != "Ann Editor <ann@example.com>|Rackbook|ledger(services): edit web-hostco-ashburn-va-us-dc/SSH" {
		t.Fatal(got)
	}
	_, h, _ := f.do(t, "GET", "/api/history?limit=5&collection=services", nil, nil)
	c := arr(t, h["commits"])
	if len(c) != 2 || c[0].(map[string]any)["email"] != "ann@example.com" {
		t.Fatalf("%v", h)
	}
}

func TestWriteGuards(t *testing.T) {
	f := newFixture(t, nil, "")
	body := `{"data":{"item":"x","status":"待办"}}`
	post := func(hdr map[string]string) int {
		req, _ := http.NewRequest("POST", f.ts.URL+"/api/c/todo", strings.NewReader(body))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := post(map[string]string{"Content-Type": "text/plain"}); c != 415 {
		t.Errorf("text/plain: %d", c)
	}
	if c := post(nil); c != 415 {
		t.Errorf("no content type: %d", c)
	}
	if c := post(map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"}); c != 403 {
		t.Errorf("cross-site: %d", c)
	}
	if c := post(map[string]string{"Content-Type": "application/json", "Origin": "https://evil.example"}); c != 403 {
		t.Errorf("foreign origin: %d", c)
	}
	if c := post(map[string]string{"Content-Type": "application/json", "Origin": f.ts.URL, "Sec-Fetch-Site": "same-origin"}); c != 201 {
		t.Errorf("same origin: %d", c)
	}
	// Deletes are guarded too.
	req, _ := http.NewRequest("DELETE", f.ts.URL+"/api/c/todo/x?hash=abc", nil)
	req.Header.Set("Origin", "https://evil.example")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 403 {
		t.Errorf("cross-origin delete: %d", resp.StatusCode)
	}
}

func TestHostRestrictionWithoutAuth(t *testing.T) {
	f := newFixture(t, func(o *api.Options) { o.RestrictHost = true; o.BaseURL = "https://ledger.example.com" }, "")
	get := func(host string) int {
		req, _ := http.NewRequest("GET", f.ts.URL+"/api/meta", nil)
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for host, want := range map[string]int{"127.0.0.1:8080": 200, "localhost:8080": 200, "[::1]:8080": 200, "app.localhost": 200, "ledger.example.com": 200, "attacker.example": 403, "127.0.0.1.attacker.example": 403} {
		if got := get(host); got != want {
			t.Errorf("Host %s: %d, want %d", host, got, want)
		}
	}
}

func TestInternalErrorsAreGeneric(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not apply to root")
	}
	testutil.SkipOnWindows(t, "making a directory read-only with chmod 0555 does not stop file creation on Windows")
	dir := testutil.CopyExample(t)
	f := newFixture(t, nil, dir)
	ledgerDir := filepath.Join(dir, "docs/ledger")
	os.Chmod(ledgerDir, 0o555)
	t.Cleanup(func() { os.Chmod(ledgerDir, 0o755) })
	code, r, _ := f.do(t, "POST", "/api/c/todo", map[string]any{"data": map[string]any{"item": "x", "status": "待办"}}, nil)
	msg, _ := r["message"].(string)
	if code != 500 || r["error"] != "internal" || strings.Contains(msg, dir) || r["requestId"] == "" || !strings.Contains(msg, r["requestId"].(string)) {
		t.Fatalf("%d %v", code, r)
	}
}

func TestDirtyCloneIs503(t *testing.T) {
	root := t.TempDir()
	seed := testutil.CopyExample(t)
	sh(t, seed, "init", "-b", "main")
	sh(t, seed, "add", ".")
	sh(t, seed, "commit", "-m", "seed")
	server := filepath.Join(root, "s")
	sh(t, root, "clone", seed, server)
	f := newFixture(t, nil, server)
	add := map[string]any{"data": map[string]any{"item": "x", "status": "待办"}}
	os.WriteFile(filepath.Join(server, "docs/ledger/todo.yml"), []byte("- {item: dirty, status: 待办}\n"), 0o644)
	code, r, _ := f.do(t, "POST", "/api/c/todo", add, nil)
	if code != 503 || r["error"] != "repo_dirty" || !strings.Contains(r["message"].(string), "administrator") {
		t.Fatalf("%d %v", code, r)
	}
	sh(t, server, "checkout", "--", ".")
	// Local commit that is not on the remote: diverged.
	b, _ := os.ReadFile(filepath.Join(server, "docs/ledger/todo.yml"))
	os.WriteFile(filepath.Join(server, "docs/ledger/todo.yml"), append(b, "# local\n"...), 0o644)
	sh(t, server, "commit", "-qam", "local")
	code, r, _ = f.do(t, "POST", "/api/c/todo", add, nil)
	if code != 503 || r["error"] != "repo_diverged" {
		t.Fatalf("%d %v", code, r)
	}
}

func TestWriteGuardBehindRewritingProxy(t *testing.T) {
	f := newFixture(t, func(o *api.Options) { o.BaseURL = "https://ledger.example.com" }, "")
	do := func(hdr map[string]string) int {
		req, _ := http.NewRequest("POST", f.ts.URL+"/api/c/todo", strings.NewReader(`{"data":{"item":"`+hdr["item"]+`","status":"待办"}}`))
		delete(hdr, "item")
		req.Header.Set("Content-Type", "application/json")
		req.Host = "127.0.0.1:9999" // nginx default: Host rewritten to the upstream
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	cases := []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"same-origin fetch metadata decides alone", map[string]string{"item": "a", "Sec-Fetch-Site": "same-origin", "Origin": "https://ledger.example.com"}, 201},
		{"same-site is rejected", map[string]string{"item": "b", "Sec-Fetch-Site": "same-site", "Origin": "https://ledger.example.com"}, 403},
		{"cross-site is rejected", map[string]string{"item": "c", "Sec-Fetch-Site": "cross-site"}, 403},
		{"origin matches base-url host", map[string]string{"item": "d", "Origin": "https://ledger.example.com"}, 201},
		{"origin matches X-Forwarded-Host", map[string]string{"item": "e", "Origin": "https://wiki.example.org", "X-Forwarded-Host": "wiki.example.org, other"}, 201},
		{"foreign origin", map[string]string{"item": "f", "Origin": "https://evil.example"}, 403},
		{"non-browser client", map[string]string{"item": "g"}, 201},
	}
	for _, c := range cases {
		if got := do(c.hdr); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}
