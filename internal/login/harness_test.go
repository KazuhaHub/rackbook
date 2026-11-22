package login

import (
	"context"
	"crypto/x509"
	"encoding/json"
	authoidc "github.com/KazuhaHub/authcore/oidc"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/login/testidp"
	"github.com/kazuhahub/rackbook/internal/prefs"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

const (
	clientID     = "rackbook-test"
	clientSecret = "s3cret-for-tests"
	tenant       = "11111111-2222-3333-4444-555555555555"
)

var testKey = []byte("0123456789abcdef0123456789abcdef-test-key")

// clock is a settable time source shared by the Service and the tests.
type clock struct{ t atomic.Int64 }

func newClock() *clock {
	c := &clock{}
	c.t.Store(time.Now().Unix())
	return c
}
func (c *clock) Now() time.Time          { return time.Unix(c.t.Load(), 0) }
func (c *clock) Advance(d time.Duration) { c.t.Add(int64(d.Seconds())) }

type env struct {
	t     *testing.T
	idp   *testidp.IdP
	idpS  *httptest.Server
	app   *httptest.Server
	base  string // https://localhost:<port>: the base URL (WebAuthn needs a domain, not an IP)
	svc   *Service
	store *gitstore.Store
	dir   string
	bare  string
	clk   *clock
	pool  *x509.CertPool
	logs  *logBuf
	audit string // directory of the audit log every Service of the env writes to
}

type logBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *logBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

type options struct {
	passkeys  bool
	remote    bool // data repo with a bare origin
	nogit     bool
	roles     string // YAML under auth:
	tenants   []string
	readOnly  bool
	uv        string
	cfgExtras string
	oidc      string            // extra lines under auth.oidc
	files     map[string]string // extra files in the data repository
}

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

const defaultRoles = `  roles:
    admin: [kazuha@kazuha.org]
    editor: ["*@kazuha.org"]
    viewer: [guest@example.com]
`

func newEnv(t *testing.T, o options) *env {
	t.Helper()
	e := &env{t: t, clk: newClock(), logs: &logBuf{}}
	// the app server first (its URL is the base URL), the handler later
	var h atomic.Pointer[http.Handler]
	e.app = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hp := h.Load(); hp != nil {
			(*hp).ServeHTTP(w, r)
			return
		}
		http.Error(w, "starting", http.StatusServiceUnavailable)
	}))
	e.app.StartTLS()
	e.base = "https://localhost:" + e.app.Listener.Addr().(*net.TCPAddr).AddrPort().String()[len("127.0.0.1:"):]
	t.Cleanup(e.app.Close)

	e.idp = testidp.New("", clientID, clientSecret, e.base+"/auth/oidc/callback")
	e.idpS = httptest.NewTLSServer(e.idp.Handler())
	t.Cleanup(e.idpS.Close)
	e.idp.Issuer = e.idpS.URL
	e.idp.Users = map[string]testidp.Claims{
		"admin":   {"sub": "sub-admin", "preferred_username": "Kazuha@Kazuha.org", "name": "Kazuha M", "tid": tenant},
		"editor":  {"sub": "sub-ed", "preferred_username": "ed@kazuha.org", "name": "Ed", "tid": tenant},
		"viewer":  {"sub": "sub-v", "preferred_username": "guest@example.com", "name": "Guest", "tid": tenant},
		"nobody":  {"sub": "sub-n", "preferred_username": "nobody@elsewhere.net", "name": "Nobody", "tid": tenant},
		"foreign": {"sub": "sub-f", "preferred_username": "ed@kazuha.org", "name": "Ed", "tid": "99999999-0000-0000-0000-000000000000"},
		"kelvin":  {"sub": "sub-k", "preferred_username": "Kazuha@kazuha.org", "name": "Fake", "tid": tenant},
	}
	e.idp.User = "admin"

	e.pool = x509.NewCertPool()
	e.pool.AddCert(e.app.Certificate())
	e.pool.AddCert(e.idpS.Certificate())

	// data repository
	if o.remote {
		root := t.TempDir()
		e.bare = filepath.Join(root, "origin.git")
		git(t, root, "init", "--bare", "-b", "main", e.bare)
	}
	e.dir = testutil.CopyExample(t)
	roles := o.roles
	if roles == "" {
		roles = defaultRoles
	}
	tenants := "[" + strings.Join(append([]string{}, o.tenants...), ", ") + "]"
	if len(o.tenants) == 0 {
		tenants = "[" + tenant + "]"
	}
	pk := "false"
	if o.passkeys {
		pk = "true"
		if o.uv != "" {
			pk = "{user_verification: " + o.uv + "}"
		}
	}
	cfgPath := filepath.Join(e.dir, "rackbook.yml")
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	block := "\nauth:\n  mode: oidc\n  oidc:\n    issuer: " + e.idpS.URL + "\n    client_id: " + clientID + "\n    allowed_tenants: " + tenants + "\n" + o.oidc + "  passkeys: " + pk + "\n  session:\n    idle: 12h\n    absolute: 7d\n" + roles + o.cfgExtras
	if err := os.WriteFile(cfgPath, append(b, []byte(block)...), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, content := range o.files {
		p := filepath.Join(e.dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if !o.nogit {
		git(t, e.dir, "init", "-b", "main")
		git(t, e.dir, "add", ".")
		git(t, e.dir, "commit", "-m", "seed")
		if o.remote {
			git(t, e.dir, "remote", "add", "origin", e.bare)
			git(t, e.dir, "push", "--quiet", "origin", "main")
		}
	}
	logger := slogTo(e.logs)
	st, err := gitstore.Open(context.Background(), gitstore.Options{
		ConfigPath: cfgPath, NoGit: o.nogit, Committer: gitstore.Identity{Name: "Rackbook", Email: "rackbook@example.org"}, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.store = st
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	ps := &prefs.Store{}
	e.audit = filepath.Join(t.TempDir(), "audit")
	al, err := audit.Open(e.audit, audit.Options{Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(al.Close)
	lo := Options{
		Prefs: ps, Audit: al,
		Login: cfg.Auth.Login, BaseURL: e.base, Key: testKey, ClientSecret: clientSecret,
		Config: st.Config, HTTPClient: e.idpS.Client(), ReadOnly: o.readOnly, Logger: logger, Now: e.clk.Now,
	}
	if cfg.Auth.Passkeys.Enabled {
		lo.Files = st
	}
	e.svc, err = New(lo)
	if err != nil {
		t.Fatal(err)
	}
	authn, err := auth.New(context.Background(), auth.Config{Mode: auth.ModeOIDC, Sessions: e.svc, Config: st.Config})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.Bind(authn)
	web := fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>console</title>")}, "favicon.svg": {Data: []byte("<svg xmlns=\"http://www.w3.org/2000/svg\"/>")}}
	handler := api.New(api.Options{Store: st, Auth: authn, BaseURL: e.base, Web: web, Logger: logger, Login: e.svc, Prefs: ps})
	h.Store(&handler)
	return e
}

// browser is an HTTP client with its own cookie jar that never follows
// redirects on its own and trusts both test servers.
type browser struct {
	t   *testing.T
	e   *env
	c   *http.Client
	jar http.CookieJar
}

func (e *env) browser() *browser {
	jar, _ := cookiejar.New(nil)
	tr := e.app.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.RootCAs = e.pool
	tr.TLSClientConfig.ServerName = "example.com" // the test certificates are valid for it and for 127.0.0.1
	addr := e.app.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, a string) (net.Conn, error) {
		if strings.HasPrefix(a, "localhost:") {
			a = addr
		}
		return (&net.Dialer{}).DialContext(ctx, network, a)
	}
	c := &http.Client{Jar: jar, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &browser{t: e.t, e: e, c: c, jar: jar}
}

type resp struct {
	*http.Response
	Body string
}

func (r resp) Loc() string { return r.Header.Get("Location") }

func (b *browser) do(method, target string, hdr map[string]string, body io.Reader) resp {
	b.t.Helper()
	if strings.HasPrefix(target, "/") {
		target = b.e.base + target
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		b.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return resp{res, string(data)}
}

func (b *browser) get(target string) resp { b.t.Helper(); return b.do("GET", target, nil, nil) }

func (b *browser) postJSON(target, body string) resp {
	b.t.Helper()
	return b.do("POST", target, map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"}, strings.NewReader(body))
}

func (b *browser) cookie(name string) *http.Cookie {
	u, _ := url.Parse(b.e.base)
	for _, c := range b.jar.Cookies(u) {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (b *browser) setCookie(name, value string) {
	u, _ := url.Parse(b.e.base)
	b.jar.SetCookies(u, []*http.Cookie{{Name: name, Value: value, Path: "/", Secure: true}})
}

// login drives the whole flow as user and returns the final response
// (the redirect issued by the callback).
func (b *browser) login(user, ret string) resp {
	b.t.Helper()
	start := "/auth/oidc/start"
	if ret != "" {
		start += "?return=" + url.QueryEscape(ret)
	}
	r1 := b.get(start)
	if r1.StatusCode != 302 {
		b.t.Fatalf("start: %d %s", r1.StatusCode, r1.Body)
	}
	az, _ := url.Parse(r1.Loc())
	q := az.Query()
	q.Set("user", user)
	az.RawQuery = q.Encode()
	r2 := b.get(az.String())
	if r2.StatusCode != 302 {
		b.t.Fatalf("authorize: %d %s", r2.StatusCode, r2.Body)
	}
	return b.get(r2.Loc())
}

func (b *browser) meta() (int, map[string]any) {
	b.t.Helper()
	r := b.get("/api/meta")
	var m map[string]any
	_ = json.Unmarshal([]byte(r.Body), &m)
	return r.StatusCode, m
}

// rewriteRoles replaces the auth.roles block of the data repo's rackbook.yml
// (without Git: the store re-reads files on every call).
func (e *env) rewriteRoles(block string) {
	e.t.Helper()
	p := filepath.Join(e.dir, "rackbook.yml")
	b, _ := os.ReadFile(p)
	s := string(b)
	i := strings.Index(s, "  roles:\n")
	if i < 0 {
		e.t.Fatal("no roles block")
	}
	if err := os.WriteFile(p, []byte(s[:i]+block), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func writeFile(p, s string) error { return os.WriteFile(p, []byte(s), 0o600) }

func testState(v string) authoidc.State { return authoidc.State{Value: v} }
