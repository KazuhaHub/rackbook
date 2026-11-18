package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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
	if err != nil || u.Email != "ann@example.com" || u.Name != "ann" || !u.CanEdit {
		t.Fatalf("header: %+v %v", u, err)
	}
	// Cookie works too.
	if u, err := a.Authenticate(req("", good)); err != nil || u.Email != "ann@example.com" {
		t.Fatalf("cookie: %+v %v", u, err)
	}
	// Service token: common_name identity, allow-listed.
	svc := p.token(t, p.key, map[string]any{"common_name": "svc.access"}, time.Hour, p.issuer, "aud-1")
	if u, err := a.Authenticate(req(svc, "")); err != nil || u.Email != "svc.access" || !u.CanEdit {
		t.Fatalf("service token: %+v %v", u, err)
	}
	// Reader: valid but not an editor.
	other := p.token(t, p.key, map[string]any{"email": "Bob@example.com"}, time.Hour, p.issuer, "aud-1")
	if u, err := a.Authenticate(req(other, "")); err != nil || u.CanEdit || a.CanEdit(u) {
		t.Fatalf("reader: %+v %v", u, err)
	}
	// Allow-list is case-insensitive.
	up := p.token(t, p.key, map[string]any{"email": "ANN@example.com"}, time.Hour, p.issuer, "aud-1")
	if u, _ := a.Authenticate(req(up, "")); !u.CanEdit {
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
	var seen *User
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = UserFrom(r.Context())
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

func TestNoneMode(t *testing.T) {
	a, err := New(context.Background(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	u, err := a.Authenticate(req("", ""))
	if err != nil || u != nil || !a.CanEdit(nil) {
		t.Fatalf("%+v %v", u, err)
	}
	a, err = New(context.Background(), Config{Mode: ModeNone, Editor: "Ann Editor <ann@example.com>", Editors: []string{"someone@else.com"}})
	if err != nil {
		t.Fatal(err)
	}
	u, _ = a.Authenticate(req("", ""))
	if u.Name != "Ann Editor" || u.Email != "ann@example.com" || u.CanEdit {
		t.Fatalf("%+v", u)
	}
	a, _ = New(context.Background(), Config{Editors: []string{"x@y.z"}})
	if a.CanEdit(nil) {
		t.Fatal("anonymous must not edit when an allow-list exists")
	}
	for _, bad := range []Config{{Mode: "bogus"}, {Mode: ModeCloudflareAccess, Audience: "a"}, {Mode: ModeCloudflareAccess, Team: "t"}, {Editor: "nonsense"}} {
		if _, err := New(context.Background(), bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}
