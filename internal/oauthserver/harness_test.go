package oauthserver_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
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
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/mcpauth"
	"github.com/kazuhahub/rackbook/internal/mcpserver"
	"github.com/kazuhahub/rackbook/internal/oauthserver"
	"github.com/kazuhahub/rackbook/internal/prefs"
	"github.com/kazuhahub/rackbook/internal/roles"
	"github.com/kazuhahub/rackbook/internal/testutil"
	"github.com/kazuhahub/rackbook/internal/tokens"
)

const testRedirect = "http://localhost:7777/callback"

// userStub stands in for the console login: the X-Test-User header names the
// signed-in person (login method oidc), no header means signed out.
type userStub struct{}

func (userStub) Identify(_ http.ResponseWriter, r *http.Request) (*auth.Identity, error) {
	u := r.Header.Get("X-Test-User")
	if u == "" {
		return nil, auth.ErrUnauthenticated
	}
	id := &auth.Identity{ID: u, Name: strings.SplitN(u, "@", 2)[0], Email: u, Method: auth.MethodOIDC}
	if g := r.Header.Get("X-Test-Groups"); g != "" {
		id.Groups = strings.Split(g, ",")
	}
	return id, nil
}
func (userStub) Public(*http.Request) bool { return false }
func (userStub) Reject(w http.ResponseWriter, r *http.Request, _ error) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, "/auth/login?return="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
}
func (userStub) NoRole(w http.ResponseWriter, _ *http.Request, _ *auth.Identity) {
	w.WriteHeader(http.StatusForbidden)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type opts struct {
	builtinYAML string // extra lines under builtin_issuer (indented 6)
	cimdClient  *http.Client
	cimdSafe    bool // use the server's own CIMD client (refuses private addresses)
	stateDir    string
	mcpYAML     string // extra lines under auth.mcp (indented 4)
	trusted     bool   // trust CF-Connecting-IP from the loopback proxy
	git         bool   // make the ledger a Git repository (writes become commits)
}

type env struct {
	t        *testing.T
	o        opts
	clock    *clock
	dir      string // state directory
	repo     string // the ledger checkout
	addr     string
	base     string // issuer
	resource string
	cfg      *config.Config
	cfgMu    sync.Mutex
	store    *gitstore.Store
	srv      *oauthserver.Server
	res      *mcpauth.Resource
	ts       *httptest.Server
	prefs    *prefs.Store // the console languages people saved
}

func (e *env) config() *config.Config {
	e.cfgMu.Lock()
	defer e.cfgMu.Unlock()
	return e.cfg
}

// setRoles replaces auth.roles from now on (a config reload).
func (e *env) setRoles(spec *roles.Spec) {
	e.cfgMu.Lock()
	defer e.cfgMu.Unlock()
	c := *e.cfg
	c.Auth.Roles = spec
	e.cfg = &c
}

// setAllowed replaces auth.mcp.builtin_issuer.allowed_clients from now on.
func (e *env) setAllowed(list []string) {
	e.cfgMu.Lock()
	defer e.cfgMu.Unlock()
	c := *e.cfg
	c.Auth.MCP.BuiltinIssuer.AllowedClients = list
	e.cfg = &c
}

func newEnv(t *testing.T, o opts) *env {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, o: o, clock: &clock{t: time.Now()}, addr: ln.Addr().String(), prefs: &prefs.Store{}}
	e.base = "http://" + e.addr
	e.resource = e.base + "/mcp"
	e.dir = o.stateDir
	if e.dir == "" {
		e.dir = t.TempDir()
	}
	seed := testutil.CopyExample(t)
	cfgPath := filepath.Join(seed, "rackbook.yml")
	b, _ := os.ReadFile(cfgPath)
	b = append(b, []byte("\nauth:\n  roles:\n    admin: [boss@example.com]\n    editor: [ed@example.com]\n    viewer: [vic@example.com]\n  mcp:\n    resource: "+e.resource+"\n    builtin_issuer:\n      enabled: true\n"+o.builtinYAML+o.mcpYAML)...)
	if err := os.WriteFile(cfgPath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if o.git {
		for _, args := range [][]string{{"init", "-b", "main"}, {"config", "user.email", "t@example.org"}, {"config", "user.name", "t"}, {"add", "."}, {"commit", "-m", "seed"}} {
			cmd := exec.Command("git", args...)
			cmd.Dir = seed
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v\n%s", args, err, out)
			}
		}
	}
	st, err := gitstore.Open(context.Background(), gitstore.Options{ConfigPath: cfgPath, Committer: gitstore.Identity{Name: "Rackbook", Email: "rackbook@example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	e.store, e.cfg = st, st.Config()
	e.repo = seed
	e.start(ln)
	return e
}

// start serves on ln with a new Server over the same state directory.
func (e *env) start(ln net.Listener) {
	e.t.Helper()
	cimd := e.o.cimdClient
	var proxies []netip.Prefix
	if e.o.trusted {
		proxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	}
	if e.o.cimdSafe {
		cimd = nil
	}
	authn, err := auth.New(context.Background(), auth.Config{Mode: auth.ModeOIDC, Sessions: userStub{}, Config: e.config})
	if err != nil {
		e.t.Fatal(err)
	}
	srv, err := oauthserver.New(oauthserver.Options{Issuer: e.base, Resource: e.resource, StateDir: e.dir, Config: e.config, Auth: authn,
		Now: e.clock.now, CIMDClient: cimd, TrustedProxies: proxies, Getenv: func(string) string { return "" }, Prefs: e.prefs})
	if err != nil {
		e.t.Fatal(err)
	}
	e.srv = srv
	e.res = &mcpauth.Resource{Config: e.config, Auth: authn, Verifier: &oauth.Verifier{}, Tokens: &tokens.Registry{Store: e.store}, Limiter: &tokens.Limiter{}, Builtin: srv}
	authn.SetBearer(e.res)
	meta := e.res.MetadataHandler()
	mcpSrv := mcpserver.NewWithOptions(mcpserver.Options{Source: e.store.Ledger, Version: "test", Backend: e.store})
	h := api.New(api.Options{
		Store: e.store, Auth: authn, Web: fstest.MapFS{"index.html": {Data: []byte("<html>")}}, BaseURL: e.base,
		MCP:    mcpauth.Handler(mcpserver.Handler(mcpSrv, true)),
		Public: map[string]http.Handler{mcpauth.MetadataPath: meta, mcpauth.MetadataPathMCP: meta},
		OAuth:  srv,
		Prefs:  e.prefs,
	})
	e.ts = httptest.NewUnstartedServer(h)
	e.ts.Listener.Close()
	e.ts.Listener = ln
	e.ts.Start()
	e.t.Cleanup(e.ts.Close)
}

// restart stops the server and starts a new one on the same address and directory.
func (e *env) restart() {
	e.t.Helper()
	e.ts.Close()
	ln, err := net.Listen("tcp", e.addr)
	if err != nil {
		e.t.Fatal(err)
	}
	e.start(ln)
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

type resp struct {
	*http.Response
	body []byte
}

func (r resp) json() map[string]any {
	var m map[string]any
	_ = json.Unmarshal(r.body, &m)
	return m
}

func (r resp) str(k string) string { s, _ := r.json()[k].(string); return s }

// do sends a request as user ("" = signed out).
func (e *env) do(user, method, path string, body io.Reader, hdr ...string) resp {
	e.t.Helper()
	req, err := http.NewRequest(method, e.ts.URL+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	if user != "" {
		req.Header.Set("X-Test-User", user)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	r, err := noRedirect.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return resp{r, b}
}

func (e *env) get(user, path string, hdr ...string) resp {
	return e.do(user, http.MethodGet, path, nil, hdr...)
}

func (e *env) postJSON(user, path string, v any, hdr ...string) resp {
	b, _ := json.Marshal(v)
	return e.do(user, http.MethodPost, path, bytes.NewReader(b), append([]string{"Content-Type", "application/json", "Sec-Fetch-Site", "same-origin"}, hdr...)...)
}

func (e *env) form(path string, v url.Values) resp {
	return e.do("", http.MethodPost, path, strings.NewReader(v.Encode()), "Content-Type", "application/x-www-form-urlencoded")
}

// pkce is a verifier and its S256 challenge.
func pkce() (verifier, challenge string) {
	verifier = strings.Repeat("v", 20) + base64.RawURLEncoding.EncodeToString([]byte("rackbook-test-verifier"))
	h := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(h[:])
}

// authParams are the query parameters of a valid authorization request.
type authParams struct {
	clientID, redirect, challenge, resource, scope, state, method, responseType string
}

func (e *env) params(clientID, redirect, challenge string) authParams {
	return authParams{clientID: clientID, redirect: redirect, challenge: challenge, resource: e.resource, scope: "rackbook:write", state: "st-1", method: "S256", responseType: "code"}
}

func (p authParams) query() string {
	v := url.Values{}
	set := func(k, s string) {
		if s != "" {
			v.Set(k, s)
		}
	}
	set("client_id", p.clientID)
	set("redirect_uri", p.redirect)
	set("code_challenge", p.challenge)
	set("code_challenge_method", p.method)
	set("resource", p.resource)
	set("scope", p.scope)
	set("state", p.state)
	set("response_type", p.responseType)
	return v.Encode()
}

// register registers a client (RFC 7591) and returns its id.
func (e *env) register(name string, redirects ...string) string {
	e.t.Helper()
	if len(redirects) == 0 {
		redirects = []string{testRedirect}
	}
	r := e.postJSON("", "/oauth/register", map[string]any{"client_name": name, "redirect_uris": redirects, "token_endpoint_auth_method": "none"})
	if r.StatusCode != http.StatusCreated && r.StatusCode != http.StatusOK {
		e.t.Fatalf("register: %d %s", r.StatusCode, r.body)
	}
	return r.str("client_id")
}

// startAuth runs the authorization request as user and returns the response.
func (e *env) startAuth(user string, p authParams, hdr ...string) resp {
	return e.get(user, "/oauth/authorize?"+p.query(), hdr...)
}

// approve runs the authorization request and the consent page as user and
// returns the authorization code.
func (e *env) approve(user string, p authParams) (code string) {
	e.t.Helper()
	r := e.startAuth(user, p)
	loc := r.Header.Get("Location")
	if r.StatusCode != http.StatusFound || !strings.HasPrefix(loc, "/oauth/consent?req=") {
		e.t.Fatalf("authorize: %d %q %s", r.StatusCode, loc, r.body)
	}
	req := strings.TrimPrefix(loc, "/oauth/consent?req=")
	if info := e.get(user, "/api/oauth/consent?req="+req); info.StatusCode != 200 {
		e.t.Fatalf("consent info: %d %s", info.StatusCode, info.body)
	}
	d := e.postJSON(user, "/api/oauth/consent", map[string]any{"req": req, "approve": true})
	if d.StatusCode != 200 {
		e.t.Fatalf("consent: %d %s", d.StatusCode, d.body)
	}
	u, err := url.Parse(d.str("redirect"))
	if err != nil || !strings.HasPrefix(d.str("redirect"), p.redirect) {
		e.t.Fatalf("redirect %q", d.str("redirect"))
	}
	q := u.Query()
	if q.Get("iss") != e.base || q.Get("state") != p.state {
		e.t.Fatalf("iss/state wrong in %q", d.str("redirect"))
	}
	return q.Get("code")
}

func (e *env) exchange(clientID, code, verifier string) resp {
	return e.form("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier}})
}

func (e *env) refresh(clientID, refresh string) resp {
	return e.form("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}})
}

type tokenPair struct{ access, refresh, grant string }

// login runs the whole flow for user with a freshly registered client.
func (e *env) login(user, name string) (clientID string, t tokenPair) {
	e.t.Helper()
	clientID = e.register(name)
	v, ch := pkce()
	code := e.approve(user, e.params(clientID, testRedirect, ch))
	r := e.exchange(clientID, code, v)
	if r.StatusCode != 200 {
		e.t.Fatalf("token: %d %s", r.StatusCode, r.body)
	}
	t = tokenPair{access: r.str("access_token"), refresh: r.str("refresh_token")}
	t.grant, _, _ = strings.Cut(t.refresh, ".")
	return clientID, t
}

// mcpStatus calls /mcp with a bearer token and returns the status.
func (e *env) mcpStatus(token string) resp {
	return e.do("", http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`),
		"Authorization", "Bearer "+token, "Content-Type", "application/json", "Accept", "application/json, text/event-stream")
}

type bearerTransport struct{ tok string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

// mcpTools lists the tools through a real MCP session with the token.
func (e *env) mcpTools(token string) error {
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil).Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: e.ts.URL + "/mcp", HTTPClient: &http.Client{Transport: bearerTransport{token}}}, nil)
	if err != nil {
		return err
	}
	defer cs.Close()
	_, err = cs.ListTools(context.Background(), nil)
	return err
}
