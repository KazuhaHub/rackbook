package mcpauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/auth/oauth"
	"github.com/kazuhahub/rackbook/internal/auth/oauth/oauthtest"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/mcpauth"
	"github.com/kazuhahub/rackbook/internal/mcpserver"
	"github.com/kazuhahub/rackbook/internal/testutil"
	"github.com/kazuhahub/rackbook/internal/tokens"
)

const resourceURL = "http://localhost:9999/mcp"

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Seed", "GIT_AUTHOR_EMAIL=seed@example.com", "GIT_COMMITTER_NAME=Seed", "GIT_COMMITTER_EMAIL=seed@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// fakeGitHub records pull requests.
type fakeGitHub struct {
	srv *httptest.Server
	mu  sync.Mutex
	prs []map[string]string
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	g := &fakeGitHub{}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/repos/acme/ledger/pulls" {
			http.NotFound(w, r)
			return
		}
		var p map[string]string
		json.NewDecoder(r.Body).Decode(&p)
		g.mu.Lock()
		g.prs = append(g.prs, p)
		n := len(g.prs)
		g.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"html_url": "https://github.com/acme/ledger/pull/" + string(rune('0'+n))})
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGitHub) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.prs)
}

type harness struct {
	t        *testing.T
	iss      *oauthtest.Issuer
	ts       *httptest.Server
	gh       *fakeGitHub
	reg      *tokens.Registry
	store    *gitstore.Store
	dir      string // the server's checkout
	bare     string
	now      time.Time
	resource *mcpauth.Resource
}

type hopts struct {
	git       bool
	rolesYAML string // replaces the default roles block body
	mcpYAML   string // extra lines under auth.mcp
	// extraIssuer is a second trusted issuer (YAML flow mapping body without braces).
	extraIssuer string
}

const defaultRoles = `    admin: [boss@example.com]
    editor: ["mcphub:alice", "mcphub:ed"]
    viewer: ["mcphub:vic"]
`

func newHarness(t *testing.T, o hopts) *harness {
	t.Helper()
	h := &harness{t: t, iss: oauthtest.New(t), gh: newFakeGitHub(t), now: time.Now()}
	if o.rolesYAML == "" {
		o.rolesYAML = defaultRoles
	}
	seed := testutil.CopyExample(t)
	cfgPath := filepath.Join(seed, "rackbook.yml")
	b, _ := os.ReadFile(cfgPath)
	b = append(b, []byte("\nauth:\n  roles:\n"+o.rolesYAML+"  mcp:\n    resource: "+resourceURL+"\n    trusted_issuers:\n      - {issuer: "+h.iss.URL+", kind: mcphub}\n"+issuerLine(o.extraIssuer)+o.mcpYAML)...)
	os.WriteFile(cfgPath, b, 0o644)
	h.dir = seed
	sopts := gitstore.Options{ConfigPath: cfgPath, Committer: gitstore.Identity{Name: "Rackbook", Email: "rackbook@example.org"}}
	if o.git {
		root := t.TempDir()
		h.bare = filepath.Join(root, "origin.git")
		h.dir = filepath.Join(root, "server")
		git(t, root, "init", "--bare", "-b", "main", h.bare)
		git(t, seed, "init", "-b", "main")
		git(t, seed, "add", ".")
		git(t, seed, "commit", "-m", "seed")
		git(t, seed, "remote", "add", "origin", h.bare)
		git(t, seed, "push", "origin", "main")
		git(t, root, "clone", h.bare, h.dir)
		sopts.ConfigPath = filepath.Join(h.dir, "rackbook.yml")
		sopts.GitHubToken, sopts.GitHubRepo, sopts.GitHubAPI = "ghtok", "acme/ledger", h.gh.srv.URL
	}
	st, err := gitstore.Open(context.Background(), sopts)
	if err != nil {
		t.Fatal(err)
	}
	h.store = st
	authn, err := auth.New(context.Background(), auth.Config{Mode: auth.ModeNone, Editor: "Boss <boss@example.com>", Config: st.Config, Degraded: func() bool { return st.ConfigProblem() != "" }})
	if err != nil {
		t.Fatal(err)
	}
	h.reg = &tokens.Registry{Store: st, Now: func() time.Time { return h.now }}
	h.resource = &mcpauth.Resource{Config: st.Config, Auth: authn, Verifier: &oauth.Verifier{Now: func() time.Time { return h.now }}, Tokens: h.reg, Limiter: &tokens.Limiter{}}
	authn.SetBearer(h.resource)
	meta := h.resource.MetadataHandler()
	srv := mcpserver.NewWithOptions(mcpserver.Options{Source: st.Ledger, Version: "test", Backend: st})
	h.ts = httptest.NewServer(api.New(api.Options{
		Store: st, Auth: authn, Web: fstest.MapFS{"index.html": {Data: []byte("<html>")}},
		MCP:    mcpauth.Handler(mcpserver.Handler(srv, true)),
		Public: map[string]http.Handler{mcpauth.MetadataPath: meta, mcpauth.MetadataPathMCP: meta},
		Tokens: h.reg,
	}))
	t.Cleanup(h.ts.Close)
	return h
}

// jwt mints an access token for the resource.
func (h *harness) jwt(o oauthtest.Options) string {
	if o.Audience == nil {
		o.Audience = resourceURL
	}
	o.Now = h.now
	return h.iss.Mint(o)
}

func (h *harness) do(method, path, bearer string, body any, hdr ...string) (int, map[string]any, http.Header) {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.ts.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, resp.Header
}

type bearerTransport struct{ tok string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if b.tok != "" {
		r.Header.Set("Authorization", "Bearer "+b.tok)
	}
	return http.DefaultTransport.RoundTrip(r)
}

// mcpSession connects an MCP client with the given bearer token.
func (h *harness) mcpSession(bearer string) *mcp.ClientSession {
	h.t.Helper()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil).Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: h.ts.URL + "/mcp", HTTPClient: &http.Client{Transport: bearerTransport{bearer}}}, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { cs.Close() })
	return cs
}

// call runs a tool and returns its JSON text and whether it was an error.
func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(sb.String()), &out); err != nil {
		t.Fatalf("%s: not JSON: %q", name, sb.String())
	}
	return out, res.IsError
}

func todoRecord(t *testing.T, cs *mcp.ClientSession, item string) (hash string) {
	t.Helper()
	out, isErr := call(t, cs, "get_record", map[string]any{"collection": "todo", "id": item})
	if isErr {
		t.Fatalf("get_record: %v", out)
	}
	return out["hash"].(string)
}

func issuerLine(body string) string {
	if body == "" {
		return ""
	}
	return "      - {" + body + "}\n"
}
