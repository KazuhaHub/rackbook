package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/roles"
)

type idp struct {
	key    *rsa.PrivateKey
	srv    *httptest.Server
	issuer string
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &idp{key: key, issuer: "https://team.cloudflareaccess.com"}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *idp) token(t *testing.T, key *rsa.PrivateKey, claims map[string]any, exp time.Duration, iss, aud string) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	std := jwt.Claims{Issuer: iss, Audience: jwt.Audience{aud}, IssuedAt: jwt.NewNumericDate(time.Now()), Expiry: jwt.NewNumericDate(time.Now().Add(exp))}
	s, err := jwt.Signed(sig).Claims(std).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (p *idp) auth(t *testing.T, editors ...string) *Authenticator {
	a, err := New(context.Background(), Config{Mode: ModeCloudflareAccess, Audience: "aud-1", JWKSURL: p.srv.URL, Issuer: p.issuer, Editors: editors})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func req(token, cookie string) *http.Request {
	r := httptest.NewRequest("GET", "/api/meta", nil)
	if token != "" {
		r.Header.Set("Cf-Access-Jwt-Assertion", token)
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: "CF_Authorization", Value: cookie})
	}
	return r
}

func TestCloudflareAccess(t *testing.T) {
	p := newIDP(t)
	a := p.auth(t, "ann@example.com", "svc.access")
	good := p.token(t, p.key, map[string]any{"email": "ann@example.com"}, time.Hour, p.issuer, "aud-1")

	u, err := a.Authenticate(req(good, ""))
	if err != nil || u.ID != "ann@example.com" || u.Email != "ann@example.com" || u.Name != "ann" ||
		u.Method != MethodCloudflareAccess || u.Role != roles.Editor || !u.Can(roles.Write) {
		t.Fatalf("header: %+v %v", u, err)
	}
	// Cookie works too.
	if u, err := a.Authenticate(req("", good)); err != nil || u.Email != "ann@example.com" {
		t.Fatalf("cookie: %+v %v", u, err)
	}
	// Service token: common_name identity, allow-listed.
	svc := p.token(t, p.key, map[string]any{"common_name": "svc.access"}, time.Hour, p.issuer, "aud-1")
	if u, err := a.Authenticate(req(svc, "")); err != nil || u.ID != "svc.access" || u.Email != "" || !u.Can(roles.Write) {
		t.Fatalf("service token: %+v %v", u, err)
	}
	// Reader: valid but not an editor, so a viewer.
	other := p.token(t, p.key, map[string]any{"email": "Bob@example.com"}, time.Hour, p.issuer, "aud-1")
	if u, err := a.Authenticate(req(other, "")); err != nil || u.ID != "bob@example.com" || u.Role != roles.Viewer || u.Can(roles.Write) || !u.Can(roles.Read) {
		t.Fatalf("reader: %+v %v", u, err)
	}
	// Allow-list is case-insensitive.
	up := p.token(t, p.key, map[string]any{"email": "ANN@example.com"}, time.Hour, p.issuer, "aud-1")
	if u, _ := a.Authenticate(req(up, "")); !u.Can(roles.Write) {
		t.Fatal("case-insensitive allow-list")
	}
}

func TestRejections(t *testing.T) {
	p := newIDP(t)
	a := p.auth(t)
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := map[string]string{
		"missing":      "",
		"garbage":      "not-a-jwt",
		"expired":      p.token(t, p.key, map[string]any{"email": "a@example.com"}, -time.Hour, p.issuer, "aud-1"),
		"wrong aud":    p.token(t, p.key, map[string]any{"email": "a@example.com"}, time.Hour, p.issuer, "other"),
		"wrong issuer": p.token(t, p.key, map[string]any{"email": "a@example.com"}, time.Hour, "https://evil.example.com", "aud-1"),
		"wrong key":    p.token(t, wrongKey, map[string]any{"email": "a@example.com"}, time.Hour, p.issuer, "aud-1"),
		"no identity":  p.token(t, p.key, map[string]any{}, time.Hour, p.issuer, "aud-1"),
	}
	for name, tok := range cases {
		if u, err := a.Authenticate(req(tok, "")); err == nil {
			t.Errorf("%s accepted as %+v", name, u)
		}
	}
}

func TestMiddleware(t *testing.T) {
	p := newIDP(t)
	a := p.auth(t)
	var seen *Identity
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = FromContext(r.Context())
		w.WriteHeader(204)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req("", ""))
	if rec.Code != 401 || rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var body map[string]string
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "unauthorized" {
		t.Fatalf("%v", body)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req(p.token(t, p.key, map[string]any{"email": "ann@example.com"}, time.Hour, p.issuer, "aud-1"), ""))
	if rec.Code != 204 || seen == nil || seen.Email != "ann@example.com" {
		t.Fatalf("%d %+v", rec.Code, seen)
	}
}

// cfgWith returns a config source whose roles can be swapped, like a reload.
func cfgWith(t *testing.T, spec *roles.Spec, editors ...string) (func() *config.Config, func(*roles.Spec)) {
	t.Helper()
	var cur atomic.Pointer[config.Config]
	set := func(s *roles.Spec) { cur.Store(&config.Config{Auth: config.Auth{Roles: s, Editors: editors}}) }
	set(spec)
	return cur.Load, set
}

func TestRolesFollowConfigReloads(t *testing.T) {
	p := newIDP(t)
	src, set := cfgWith(t, &roles.Spec{Admin: []string{"ann@example.com"}, Viewer: []string{"*@example.com"}})
	a, err := New(context.Background(), Config{Mode: ModeCloudflareAccess, Audience: "aud-1", JWKSURL: p.srv.URL, Issuer: p.issuer, Config: src})
	if err != nil {
		t.Fatal(err)
	}
	tok := func(email string) *http.Request {
		return req(p.token(t, p.key, map[string]any{"email": email}, time.Hour, p.issuer, "aud-1"), "")
	}
	if u, _ := a.Authenticate(tok("ann@example.com")); u.Role != roles.Admin {
		t.Fatalf("%+v", u)
	}
	if u, _ := a.Authenticate(tok("bob@example.com")); u.Role != roles.Viewer {
		t.Fatalf("%+v", u)
	}
	// Somebody outside every entry gets 403 no_role from the middleware.
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tok("eve@elsewhere.org"))
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), `"no_role"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// A reload promotes bob and drops ann; no restart needed.
	set(&roles.Spec{Admin: []string{"bob@example.com"}})
	if u, _ := a.Authenticate(tok("bob@example.com")); u.Role != roles.Admin {
		t.Fatalf("after reload: %+v", u)
	}
	if u, _ := a.Authenticate(tok("ann@example.com")); u.Role != roles.None {
		t.Fatalf("after reload: %+v", u)
	}
}

func TestEffectiveRoleNarrowingOnlyLowers(t *testing.T) {
	id := &Identity{ID: "a@b.c", Role: roles.Editor}
	if id.EffectiveRole() != roles.Editor || !id.Can(roles.Delete) {
		t.Fatal("no hook, no change")
	}
	id.Narrow = func(roles.Role) roles.Role { return roles.Viewer }
	if id.EffectiveRole() != roles.Viewer || id.Can(roles.Write) || !id.Can(roles.Read) {
		t.Fatalf("%v", id.EffectiveRole())
	}
	id.Narrow = func(roles.Role) roles.Role { return roles.Admin } // must not widen
	if id.EffectiveRole() != roles.Editor || id.Can(roles.Manage) {
		t.Fatalf("a scope widened the role to %v", id.EffectiveRole())
	}
	var nilID *Identity
	if nilID.Can(roles.Read) || Can(context.Background(), roles.Read) {
		t.Fatal("nobody must not read")
	}
	ctx := WithIdentity(context.Background(), &Identity{Role: roles.Admin})
	if !Can(ctx, roles.Manage) || FromContext(ctx) == nil {
		t.Fatal("context round trip")
	}
}

func TestNoneMode(t *testing.T) {
	a, err := New(context.Background(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	u, err := a.Authenticate(req("", ""))
	if err != nil || !u.Anonymous() || u.Method != MethodNone || u.Role != roles.Editor {
		t.Fatalf("%+v %v", u, err)
	}
	a, err = New(context.Background(), Config{Mode: ModeNone, Editor: "Ann Editor <Ann@example.com>", Editors: []string{"someone@else.com"}})
	if err != nil {
		t.Fatal(err)
	}
	u, _ = a.Authenticate(req("", ""))
	if u.Name != "Ann Editor" || u.Email != "Ann@example.com" || u.ID != "ann@example.com" || u.Can(roles.Write) || u.Role != roles.Viewer {
		t.Fatalf("%+v", u)
	}
	a, _ = New(context.Background(), Config{Editors: []string{"x@y.z"}})
	if u, _ := a.Authenticate(req("", "")); u.Can(roles.Write) || !u.Can(roles.Read) {
		t.Fatal("anonymous must not edit when an allow-list exists, but may read")
	}
	// With a roles block an anonymous local user is still a viewer (nobody to refuse).
	src, _ := cfgWith(t, &roles.Spec{Admin: []string{"boss@example.com"}})
	a, _ = New(context.Background(), Config{Config: src})
	if u, _ := a.Authenticate(req("", "")); u.Role != roles.Viewer {
		t.Fatalf("%+v", u)
	}
	for _, bad := range []Config{{Mode: "bogus"}, {Mode: ModeCloudflareAccess, Audience: "a"}, {Mode: ModeCloudflareAccess, Team: "t"}, {Editor: "nonsense"}, {Editors: []string{"*@"}}} {
		if _, err := New(context.Background(), bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestDegradedConfigCapsEveryoneAtViewer(t *testing.T) {
	src, _ := cfgWith(t, &roles.Spec{Admin: []string{"boss@example.com"}, Editor: []string{"ed@example.com"}})
	bad := false
	a, err := New(context.Background(), Config{Config: src, Degraded: func() bool { return bad }, Editor: "Boss <boss@example.com>"})
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := a.Authenticate(req("", "")); u.Role != roles.Admin {
		t.Fatalf("%v", u.Role)
	}
	bad = true
	if u, _ := a.Authenticate(req("", "")); u.Role != roles.Viewer || u.Can(roles.Write) || u.Can(roles.Manage) || !u.Can(roles.Read) {
		t.Fatalf("a config that does not load must fail closed for writes and admin: %v", u.Role)
	}
	// Somebody with no role stays without one (no widening to viewer).
	a, _ = New(context.Background(), Config{Config: src, Degraded: func() bool { return true }})
	id := a.Evaluate(&Identity{ID: "eve@elsewhere.org", Method: MethodOIDC})
	if id.Role != roles.None {
		t.Fatal(id.Role)
	}
}

func TestKelvinSignIdentityIsNotAnASCIIAdmin(t *testing.T) {
	src, _ := cfgWith(t, &roles.Spec{Admin: []string{"kazuha@kazuha.org"}})
	a, _ := New(context.Background(), Config{Config: src})
	id := a.Evaluate(&Identity{ID: roles.FoldASCII("\u212Aazuha@kazuha.org"), Method: MethodOIDC})
	if id.Role != roles.None {
		t.Fatal(id.Role)
	}
	if id = a.Evaluate(&Identity{ID: roles.FoldASCII("KAZUHA@kazuha.org"), Method: MethodOIDC}); id.Role != roles.Admin {
		t.Fatal(id.Role)
	}
}

type fakeSessions struct{ rejected bool }

func (f *fakeSessions) Identify(http.ResponseWriter, *http.Request) (*Identity, error) {
	return nil, ErrUnauthenticated
}
func (f *fakeSessions) Public(r *http.Request) bool { return strings.HasPrefix(r.URL.Path, "/auth/") }
func (f *fakeSessions) Reject(w http.ResponseWriter, r *http.Request, _ error) {
	f.rejected = true
	http.Redirect(w, r, "/auth/login", http.StatusFound)
}
func (f *fakeSessions) NoRole(http.ResponseWriter, *http.Request, *Identity) {}

type fakeBearer struct{}

func (fakeBearer) AuthenticateBearer(r *http.Request) (*Identity, error) {
	if r.Header.Get("Authorization") == "Bearer good" && strings.HasPrefix(r.URL.Path, "/mcp") {
		return &Identity{ID: "bot@example.com", Method: MethodOAuth, Role: roles.Editor}, nil
	}
	return nil, nil
}
func (fakeBearer) Challenge(r *http.Request) string {
	if strings.HasPrefix(r.URL.Path, "/mcp") {
		return `Bearer resource_metadata="https://x/.well-known/oauth-protected-resource"`
	}
	return ""
}

// In oidc mode /mcp is answered with an OAuth challenge (or a bearer identity),
// never a redirect to the login page; console routes still redirect.
func TestOIDCModeKeepsMCPOutOfTheLoginRedirect(t *testing.T) {
	sess := &fakeSessions{}
	a, err := New(context.Background(), Config{Mode: ModeOIDC, Sessions: sess})
	if err != nil {
		t.Fatal(err)
	}
	a.SetBearer(fakeBearer{})
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	do := func(path, authz string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		if authz != "" {
			r.Header.Set("Authorization", authz)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := do("/mcp", "Bearer good"); w.Code != http.StatusOK {
		t.Fatalf("bearer on /mcp: %d", w.Code)
	}
	if w := do("/mcp", ""); w.Code != http.StatusUnauthorized || !strings.Contains(w.Header().Get("WWW-Authenticate"), "resource_metadata") || sess.rejected {
		t.Fatalf("anonymous /mcp: %d %v rejected=%v", w.Code, w.Header(), sess.rejected)
	}
	if w := do("/c/devices", ""); w.Code != http.StatusFound || !sess.rejected {
		t.Fatalf("console route: %d", w.Code)
	}
	if w := do("/auth/login", ""); w.Code != http.StatusOK {
		t.Fatalf("public path: %d", w.Code)
	}
}

func TestCanonicalPath(t *testing.T) {
	for target, want := range map[string]bool{
		"/auth/login": true, "/assets/app.js": true, "/auth/": true, "/": true,
		"/assets/../api/meta": false, "/assets/%2e%2e/api/meta": false, "/auth/%2E%2E/api/meta": false,
		"/auth%2fx": false, "/assets//x": false, "/assets/./x": false, "/auth/..%5capi": false,
	} {
		r := httptest.NewRequest("GET", "http://x"+target, nil)
		if _, ok := CanonicalPath(r); ok != want {
			t.Errorf("%s: canonical = %v, want %v", target, ok, want)
		}
	}
}

func TestRoleForViaFindsSubjectIdentities(t *testing.T) {
	cfg := &config.Config{Auth: config.Auth{Roles: &roles.Spec{Admin: []string{"oidc:sub-1"}}}}
	a, err := New(context.Background(), Config{Mode: ModeNone, Config: func() *config.Config { return cfg }})
	if err != nil {
		t.Fatal(err)
	}
	if got := a.RoleForVia("oidc:sub-1", MethodOIDC); got != roles.Admin {
		t.Fatalf("oidc creator: %v", got)
	}
	if got := a.RoleFor("oidc:sub-1"); got != roles.None {
		t.Fatalf("a token without a recorded method keeps the old behaviour: %v", got)
	}
}

// authWith is an authenticator over a config whose roles and auditors can be
// swapped, like a reload.
func authWith(t *testing.T, spec *roles.Spec, auditors []string, degraded *atomic.Bool) (*Authenticator, func(*roles.Spec, []string)) {
	t.Helper()
	var cur atomic.Pointer[config.Config]
	set := func(s *roles.Spec, a []string) { cur.Store(&config.Config{Auth: config.Auth{Roles: s, Auditors: a}}) }
	set(spec, auditors)
	c := Config{Mode: ModeNone, Config: cur.Load}
	if degraded != nil {
		c.Degraded = degraded.Load
	}
	a, err := New(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	return a, set
}

func TestAuditorViewerFloorAndRolesAreKept(t *testing.T) {
	spec := &roles.Spec{Admin: []string{"boss@example.com"}, Editor: []string{"ed@example.com"}, Viewer: []string{"vic@example.com"}}
	a, set := authWith(t, spec, []string{"aud@example.com", "ed@example.com", "vic@example.com", "boss@example.com"}, nil)
	for _, c := range []struct {
		who  string
		role roles.Role
		aud  bool
	}{
		{"aud@example.com", roles.Viewer, true}, // no role: the viewer floor
		{"ed@example.com", roles.Editor, true},  // keeps the role
		{"vic@example.com", roles.Viewer, true},
		{"boss@example.com", roles.Admin, true},
		{"other@example.com", roles.None, false}, // not listed: refused as before
	} {
		id := a.Evaluate(&Identity{ID: c.who, Email: c.who, Method: MethodOIDC})
		if id.EffectiveRole() != c.role || id.IsAuditor() != c.aud {
			t.Errorf("%s: %v %v", c.who, id.EffectiveRole(), id.IsAuditor())
		}
	}
	// the floor is a viewer: no write, no admin
	id := a.Evaluate(&Identity{ID: "aud@example.com", Method: MethodOIDC})
	if !id.Can(roles.Read) || id.Can(roles.Write) || id.Can(roles.Delete) || id.Can(roles.Manage) {
		t.Fatalf("%v", id.EffectiveRole())
	}
	// an admin is not an auditor unless listed
	set(spec, []string{"aud@example.com"})
	if b := a.Evaluate(&Identity{ID: "boss@example.com", Method: MethodOIDC}); b.EffectiveRole() != roles.Admin || b.IsAuditor() {
		t.Fatalf("admin %v auditor %v", b.EffectiveRole(), b.IsAuditor())
	}
	// no roles block: v0.1 behaviour is untouched
	set(nil, []string{"aud@example.com"})
	if e := a.Evaluate(&Identity{ID: "anyone@example.com", Method: MethodOIDC}); e.EffectiveRole() != roles.Editor || e.IsAuditor() {
		t.Fatalf("%v", e.EffectiveRole())
	}
}

func TestAuditorFollowsConfigReloadsAndScopeNarrowing(t *testing.T) {
	a, set := authWith(t, &roles.Spec{Admin: []string{"boss@example.com"}}, []string{"aud@example.com"}, nil)
	ev := func() *Identity { return a.Evaluate(&Identity{ID: "aud@example.com", Method: MethodOIDC}) }
	if !ev().IsAuditor() {
		t.Fatal("listed")
	}
	set(&roles.Spec{Admin: []string{"boss@example.com"}}, nil) // removed from the list
	if id := ev(); id.IsAuditor() || id.EffectiveRole() != roles.None {
		t.Fatalf("after removal: %v %v", id.IsAuditor(), id.EffectiveRole())
	}
	set(&roles.Spec{Admin: []string{"boss@example.com"}}, []string{"aud@example.com"})
	// a credential whose scope leaves nothing readable carries no capability
	id := ev()
	id.Narrow = func(roles.Role) roles.Role { return roles.None }
	if id.IsAuditor() {
		t.Fatal("a scope that narrows the role to nothing takes the capability with it")
	}
	// a nil identity and a context without one are no auditor
	var nilID *Identity
	if nilID.IsAuditor() || IsAuditor(context.Background()) {
		t.Fatal("nobody")
	}
	if !IsAuditor(WithIdentity(context.Background(), ev())) {
		t.Fatal("context")
	}
}

func TestAuditorCreatorOfATokenIsEvaluatedLikeTheRole(t *testing.T) {
	spec := &roles.Spec{Admin: []string{"oidc:sub-1", "boss@example.com"}}
	a, set := authWith(t, spec, []string{"boss@example.com", "oidc:sub-1"}, nil)
	role, aud := a.CapabilitiesForVia("Boss@Example.com", MethodNone)
	if role != roles.Admin || !aud {
		t.Fatalf("%v %v", role, aud)
	}
	if role, aud = a.CapabilitiesForVia("oidc:sub-1", MethodOIDC); role != roles.Admin || !aud {
		t.Fatalf("a subject creator: %v %v", role, aud)
	}
	if a.RoleForVia("boss@example.com", MethodNone) != roles.Admin {
		t.Fatal("RoleForVia")
	}
	set(spec, nil) // removed from the list: the token loses the capability, keeps the role
	if role, aud = a.CapabilitiesForVia("boss@example.com", MethodNone); role != roles.Admin || aud {
		t.Fatalf("%v %v", role, aud)
	}
	// an auditor with no role at all: the creator's role is the viewer floor
	set(spec, []string{"aud@example.com"})
	if role, aud = a.CapabilitiesForVia("aud@example.com", MethodNone); role != roles.Viewer || !aud {
		t.Fatalf("%v %v", role, aud)
	}
}

func TestDegradedConfigStillCapsAnAuditorAtViewer(t *testing.T) {
	var degraded atomic.Bool
	a, _ := authWith(t, &roles.Spec{Editor: []string{"ed@example.com"}}, []string{"ed@example.com", "aud@example.com"}, &degraded)
	degraded.Store(true)
	if id := a.Evaluate(&Identity{ID: "ed@example.com", Method: MethodOIDC}); id.EffectiveRole() != roles.Viewer || !id.IsAuditor() {
		t.Fatalf("%v %v", id.EffectiveRole(), id.IsAuditor())
	}
	if id := a.Evaluate(&Identity{ID: "aud@example.com", Method: MethodOIDC}); id.EffectiveRole() != roles.Viewer {
		t.Fatalf("%v", id.EffectiveRole())
	}
}

// A token's creator is evaluated by identity alone: groups and app roles never count,
// and oauth: and mcphub: entries never match a creator, whatever method signed them in.
func TestTokenCreatorsAreEvaluatedByIdentityOnly(t *testing.T) {
	spec := &roles.Spec{
		Admin:  []string{"group:ops", "app-role:Rackbook.Admin", "mcphub:boss", "oauth:corp:boss"},
		Editor: []string{"ed@example.com"},
		Viewer: []string{"*@example.org", "oidc:sub-9"},
	}
	a, _ := authWith(t, spec, []string{"app-role:Aud", "aud@example.com"}, nil)
	for _, c := range []struct {
		identity, method string
		want             roles.Role
		aud              bool
	}{
		{"ed@example.com", MethodOIDC, roles.Editor, false},
		{"x@example.org", MethodOIDC, roles.Viewer, false}, // *@domain
		{"oidc:sub-9", MethodOIDC, roles.Viewer, false},
		{"boss", MethodOIDC, roles.None, false}, // mcphub: and oauth: never match a creator
		{"boss", MethodNone, roles.None, false},
		{"aud@example.com", MethodOIDC, roles.Viewer, true},
		{"claims@example.com", MethodOIDC, roles.None, false}, // would be admin by group, auditor by app role
	} {
		r, aud := a.CapabilitiesForVia(c.identity, c.method)
		if r != c.want || aud != c.aud {
			t.Errorf("%s (%s): %v %v, want %v %v", c.identity, c.method, r, aud, c.want, c.aud)
		}
	}
}

func TestEvaluateSetsFromClaimsOnlyWhenTheClaimsMadeTheDifference(t *testing.T) {
	spec := &roles.Spec{Admin: []string{"boss@example.com"}, Editor: []string{"group:eng", "app-role:Eng"}, Viewer: []string{"vic@example.com"}}
	a, _ := authWith(t, spec, []string{"group:audit"}, nil)
	for _, c := range []struct {
		name string
		id   Identity
		role roles.Role
		from bool
	}{
		{"identity entry only", Identity{ID: "boss@example.com", Method: MethodOIDC}, roles.Admin, false},
		{"identity entry wins over a matching group", Identity{ID: "boss@example.com", Method: MethodOIDC, Groups: []string{"eng"}}, roles.Admin, false},
		{"group beats a lower identity entry", Identity{ID: "vic@example.com", Method: MethodOIDC, Groups: []string{"eng"}}, roles.Editor, true},
		{"app role only", Identity{ID: "z@example.com", Method: MethodOIDC, AppRoles: []string{"Eng"}}, roles.Editor, true},
		{"claims that match nothing", Identity{ID: "boss@example.com", Method: MethodOIDC, Groups: []string{"x"}, AppRoles: []string{"y"}}, roles.Admin, false},
		{"auditor by group makes the session claim-derived", Identity{ID: "boss@example.com", Method: MethodOIDC, Groups: []string{"audit"}}, roles.Admin, true},
		{"no claims at all", Identity{ID: "vic@example.com", Method: MethodOIDC}, roles.Viewer, false},
	} {
		id := a.Evaluate(&c.id)
		if id.Role != c.role || id.FromClaims != c.from {
			t.Errorf("%s: role %v fromClaims %v, want %v %v", c.name, id.Role, id.FromClaims, c.role, c.from)
		}
	}
}

func TestGenerationChangesWithTheConfig(t *testing.T) {
	a, set := authWith(t, &roles.Spec{Admin: []string{"a@x.org"}}, nil, nil)
	g1 := a.Generation()
	if a.Generation() != g1 {
		t.Fatal("stable while the config is")
	}
	set(&roles.Spec{Admin: []string{"a@x.org"}}, nil)
	if a.Generation() == g1 {
		t.Fatal("a reload is a new generation")
	}
}
