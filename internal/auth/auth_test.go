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
