package oauthserver_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

const boss = "boss@example.com"

func TestMetadata(t *testing.T) {
	e := newEnv(t, opts{})
	r := e.get("", "/.well-known/oauth-authorization-server")
	if r.StatusCode != 200 {
		t.Fatalf("status %d", r.StatusCode)
	}
	m := r.json()
	if m["issuer"] != e.base || m["authorization_endpoint"] != e.base+"/oauth/authorize" || m["token_endpoint"] != e.base+"/oauth/token" ||
		m["jwks_uri"] != e.base+"/oauth/jwks" || m["registration_endpoint"] != e.base+"/oauth/register" {
		t.Fatalf("endpoints: %v", m)
	}
	if m["client_id_metadata_document_supported"] != true || m["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("flags: %v", m)
	}
	if got := m["code_challenge_methods_supported"].([]any); len(got) != 1 || got[0] != "S256" {
		t.Fatalf("code_challenge_methods_supported: %v", got)
	}
	if r.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("metadata is not open to other origins")
	}
	// The protected resource names the built-in server, and the challenge asks for the scope.
	prm := e.get("", "/.well-known/oauth-protected-resource/mcp").json()
	if as := prm["authorization_servers"].([]any); len(as) != 1 || as[0] != e.base {
		t.Fatalf("authorization_servers: %v", as)
	}
	c := e.mcpStatus("junk")
	if c.StatusCode != 401 || !strings.Contains(c.Header.Get("WWW-Authenticate"), `scope="rackbook:write"`) ||
		!strings.Contains(c.Header.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("challenge %d %q", c.StatusCode, c.Header.Get("WWW-Authenticate"))
	}
	// Registration is not advertised when it is off.
	off := newEnv(t, opts{builtinYAML: "      dynamic_registration: false\n"})
	if _, ok := off.get("", "/.well-known/oauth-authorization-server").json()["registration_endpoint"]; ok {
		t.Fatal("registration_endpoint advertised although dynamic_registration is false")
	}
	if r := off.postJSON("", "/oauth/register", map[string]any{"redirect_uris": []string{testRedirect}}); r.StatusCode != 404 {
		t.Fatalf("register while off: %d", r.StatusCode)
	}
}

func TestCORSOnlyOnPublicEndpoints(t *testing.T) {
	e := newEnv(t, opts{})
	for _, p := range []string{"/.well-known/oauth-authorization-server", "/oauth/jwks"} {
		if e.get("", p, "Origin", "https://app.example").Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("%s: not open", p)
		}
	}
	for _, p := range []string{"/oauth/token", "/oauth/register"} {
		r := e.do("", http.MethodOptions, p, nil, "Origin", "https://app.example", "Access-Control-Request-Method", "POST")
		if r.StatusCode != 204 || r.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("%s preflight: %d %v", p, r.StatusCode, r.Header)
		}
	}
	// A browser on another site can call the token endpoint (no cookies involved).
	cid := e.register("c")
	r := e.do("", http.MethodPost, "/oauth/token", strings.NewReader(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x.y"}, "client_id": {cid}}.Encode()),
		"Content-Type", "application/x-www-form-urlencoded", "Sec-Fetch-Site", "cross-site", "Origin", "https://app.example")
	if r.StatusCode != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("cross-site token request: %d %s", r.StatusCode, r.body)
	}
	// The authorization and consent endpoints are not open to other origins.
	if e.get(boss, "/oauth/authorize?client_id=x").Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("authorize sends CORS headers")
	}
	if e.get(boss, "/api/oauth/consent?req=x").Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("consent sends CORS headers")
	}
	// ...and the consent decision refuses another site.
	if r := e.postJSON(boss, "/api/oauth/consent", map[string]any{"req": "x", "approve": true}, "Sec-Fetch-Site", "cross-site"); r.StatusCode != 403 {
		t.Fatalf("cross-site consent: %d", r.StatusCode)
	}
}

func TestAuthorizeRequiresSignIn(t *testing.T) {
	e := newEnv(t, opts{})
	cid := e.register("c")
	_, ch := pkce()
	p := e.params(cid, testRedirect, ch)
	r := e.startAuth("", p)
	loc := r.Header.Get("Location")
	if r.StatusCode != 302 || !strings.HasPrefix(loc, "/auth/login?return=") {
		t.Fatalf("signed out: %d %q", r.StatusCode, loc)
	}
	back, _ := url.QueryUnescape(strings.TrimPrefix(loc, "/auth/login?return="))
	if back != "/oauth/authorize?"+p.query() {
		t.Fatalf("return_to = %q", back)
	}
}

func TestAuthorizeChecks(t *testing.T) {
	e := newEnv(t, opts{})
	cid := e.register("c")
	_, ch := pkce()
	ok := e.params(cid, testRedirect, ch)

	// Errors that are shown to the person, never redirected: the client or the
	// redirect URI cannot be trusted.
	page := map[string]authParams{}
	p := ok
	p.clientID = "rbc_unknown"
	page["unknown client"] = p
	p = ok
	p.redirect = "http://localhost:7777/other"
	page["redirect not registered"] = p
	p = ok
	p.redirect = "http://127.0.0.1:7777/callback" // localhost is not 127.0.0.1: exact match only
	page["redirect not exact (127.0.0.1)"] = p
	p = ok
	p.redirect = testRedirect + "/"
	page["redirect not exact (slash)"] = p
	p = ok
	p.redirect = ""
	page["no redirect"] = p
	for name, p := range page {
		r := e.startAuth(boss, p)
		if r.StatusCode != 400 || r.Header.Get("Location") != "" || !strings.Contains(string(r.body), "Authorization failed") {
			t.Errorf("%s: %d %q", name, r.StatusCode, r.Header.Get("Location"))
		}
	}

	// Errors sent back to the client, with state and iss.
	back := map[string]struct {
		mod  func(*authParams)
		code string
	}{
		"PKCE missing":        {func(p *authParams) { p.challenge, p.method = "", "" }, "invalid_request"},
		"PKCE plain":          {func(p *authParams) { p.method = "plain" }, "invalid_request"},
		"PKCE method missing": {func(p *authParams) { p.method = "" }, "invalid_request"},
		"PKCE wrong shape":    {func(p *authParams) { p.challenge = "short" }, "invalid_request"},
		"resource missing":    {func(p *authParams) { p.resource = "" }, "invalid_target"},
		"resource wrong":      {func(p *authParams) { p.resource = e.base + "/other" }, "invalid_target"},
		"response_type token": {func(p *authParams) { p.responseType = "token" }, "unsupported_response_type"},
	}
	for name, c := range back {
		p := ok
		c.mod(&p)
		r := e.startAuth(boss, p)
		loc := r.Header.Get("Location")
		u, _ := url.Parse(loc)
		if r.StatusCode != 302 || !strings.HasPrefix(loc, testRedirect) || u.Query().Get("error") != c.code ||
			u.Query().Get("state") != "st-1" || u.Query().Get("iss") != e.base {
			t.Errorf("%s: %d %q", name, r.StatusCode, loc)
		}
	}
}

func TestTokenChecks(t *testing.T) {
	e := newEnv(t, opts{})
	cid := e.register("c")
	v, ch := pkce()
	fresh := func() string { return e.approve(boss, e.params(cid, testRedirect, ch)) }

	if r := e.exchange(cid, fresh(), "wrong-verifier-wrong-verifier-wrong-verifier-wrong"); r.str("error") != "invalid_grant" {
		t.Errorf("wrong verifier: %s", r.body)
	}
	if r := e.exchange(cid, fresh(), ""); r.str("error") != "invalid_grant" {
		t.Errorf("no verifier: %s", r.body)
	}
	if r := e.exchange(e.register("other", "http://localhost:1/x"), fresh(), v); r.str("error") != "invalid_grant" {
		t.Errorf("code of another client: %s", r.body)
	}
	if r := e.form("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {fresh()}, "client_id": {cid}, "redirect_uri": {testRedirect + "x"}, "code_verifier": {v}}); r.str("error") != "invalid_grant" {
		t.Errorf("other redirect_uri: %s", r.body)
	}
	if r := e.form("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {fresh()}, "client_id": {cid}, "redirect_uri": {testRedirect}, "code_verifier": {v}, "resource": {e.base + "/other"}}); r.str("error") != "invalid_target" {
		t.Errorf("other resource: %s", r.body)
	}
	if r := e.form("/oauth/token", url.Values{"grant_type": {"password"}}); r.str("error") != "unsupported_grant_type" {
		t.Errorf("password grant: %s", r.body)
	}
	if r := e.form("/oauth/token", url.Values{"grant_type": {"client_credentials"}}); r.str("error") != "unsupported_grant_type" {
		t.Errorf("client_credentials: %s", r.body)
	}
	if r := e.form("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_secret": {"s"}}); r.str("error") != "invalid_client" {
		t.Errorf("client secret: %s", r.body)
	}
	if r := e.postJSON("", "/oauth/token", map[string]string{"grant_type": "refresh_token"}); r.StatusCode != 400 {
		t.Errorf("json body: %d", r.StatusCode)
	}
	// The right request works, with no-store.
	r := e.exchange(cid, fresh(), v)
	if r.StatusCode != 200 || r.Header.Get("Cache-Control") != "no-store" || r.str("token_type") != "Bearer" || r.json()["expires_in"] != float64(600) {
		t.Fatalf("good exchange: %d %s", r.StatusCode, r.body)
	}
}

func TestCodeIsSingleUseAndExpires(t *testing.T) {
	e := newEnv(t, opts{})
	cid := e.register("c")
	v, ch := pkce()
	code := e.approve(boss, e.params(cid, testRedirect, ch))
	first := e.exchange(cid, code, v)
	if first.StatusCode != 200 {
		t.Fatal(string(first.body))
	}
	if again := e.exchange(cid, code, v); again.str("error") != "invalid_grant" {
		t.Fatalf("second use: %s", again.body)
	}
	// Presenting a used code again ends the grant it made.
	if e.mcpStatus(first.str("access_token")).StatusCode == 200 {
		t.Fatal("grant of a replayed code still works")
	}

	code = e.approve(boss, e.params(cid, testRedirect, ch))
	e.clock.advance(61 * time.Second)
	if r := e.exchange(cid, code, v); r.str("error") != "invalid_grant" {
		t.Fatalf("expired code: %s", r.body)
	}
	// A failed attempt also uses the code up.
	code = e.approve(boss, e.params(cid, testRedirect, ch))
	e.exchange(cid, code, "wrong-verifier-wrong-verifier-wrong-verifier-wrong")
	if r := e.exchange(cid, code, v); r.str("error") != "invalid_grant" {
		t.Fatalf("code after a failed attempt: %s", r.body)
	}
}

func TestConsentIsBoundToThePerson(t *testing.T) {
	e := newEnv(t, opts{})
	cid := e.register("My Client")
	_, ch := pkce()
	r := e.startAuth(boss, e.params(cid, testRedirect, ch))
	req := strings.TrimPrefix(r.Header.Get("Location"), "/oauth/consent?req=")

	info := e.get(boss, "/api/oauth/consent?req="+req).json()
	if info["clientName"] != "My Client" || info["redirectHost"] != "localhost:7777" || info["canWrite"] != true ||
		info["user"].(map[string]any)["id"] != boss {
		t.Fatalf("consent info: %v", info)
	}
	if got := e.get("ed@example.com", "/api/oauth/consent?req="+req); got.StatusCode != 404 {
		t.Fatalf("another person reads the request: %d", got.StatusCode)
	}
	if got := e.postJSON("ed@example.com", "/api/oauth/consent", map[string]any{"req": req, "approve": true}); got.StatusCode != 404 {
		t.Fatalf("another person approves: %d", got.StatusCode)
	}
	if got := e.postJSON("", "/api/oauth/consent", map[string]any{"req": req, "approve": true}); got.StatusCode != 401 {
		t.Fatalf("signed out approves: %d", got.StatusCode)
	}
	// Not JSON: refused by the API guard.
	if got := e.do(boss, http.MethodPost, "/api/oauth/consent", strings.NewReader("req="+req+"&approve=true"), "Content-Type", "application/x-www-form-urlencoded", "Sec-Fetch-Site", "same-origin"); got.StatusCode != 415 {
		t.Fatalf("form post: %d", got.StatusCode)
	}
	// Deny sends access_denied, and the request is gone afterwards.
	d := e.postJSON(boss, "/api/oauth/consent", map[string]any{"req": req, "approve": false})
	if u, _ := url.Parse(d.str("redirect")); d.StatusCode != 200 || u.Query().Get("error") != "access_denied" || u.Query().Get("iss") != e.base || u.Query().Get("state") != "st-1" {
		t.Fatalf("deny: %d %s", d.StatusCode, d.body)
	}
	if got := e.postJSON(boss, "/api/oauth/consent", map[string]any{"req": req, "approve": true}); got.StatusCode != 404 {
		t.Fatalf("decided twice: %d", got.StatusCode)
	}
	// Consent is asked every time: nothing is remembered.
	r2 := e.startAuth(boss, e.params(cid, testRedirect, ch))
	if !strings.HasPrefix(r2.Header.Get("Location"), "/oauth/consent?req=") {
		t.Fatalf("second authorization skipped the consent page: %q", r2.Header.Get("Location"))
	}
	// A request that waits too long expires.
	r3 := e.startAuth(boss, e.params(cid, testRedirect, ch))
	e.clock.advance(11 * time.Minute)
	if got := e.get(boss, "/api/oauth/consent?req="+strings.TrimPrefix(r3.Header.Get("Location"), "/oauth/consent?req=")); got.StatusCode != 404 {
		t.Fatalf("expired request: %d", got.StatusCode)
	}
}

func TestOnlyPeopleCanAuthorize(t *testing.T) {
	e := newEnv(t, opts{})
	_, tok := e.login(boss, "c")
	cid := e.register("c2")
	_, ch := pkce()
	// An access token is not a sign-in: the authorization endpoint is not on /mcp.
	r := e.do("", http.MethodGet, "/oauth/authorize?"+e.params(cid, testRedirect, ch).query(), nil, "Authorization", "Bearer "+tok.access)
	if r.StatusCode == 302 && strings.HasPrefix(r.Header.Get("Location"), "/oauth/consent") {
		t.Fatalf("an access token started an authorization: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
}

func TestScopes(t *testing.T) {
	e := newEnv(t, opts{})
	cid := e.register("c")
	v, ch := pkce()
	p := e.params(cid, testRedirect, ch)
	if r := e.exchange(cid, e.approve(boss, p), v); r.str("scope") != "rackbook:write" {
		t.Fatalf("scope %q", r.str("scope"))
	}
	// A scope the server does not have is invalid_scope, sent back to the client.
	for _, sc := range []string{"rackbook:write something-else", "openid", "rackbook:admin"} {
		p.scope = sc
		r := e.startAuth(boss, p)
		u, _ := url.Parse(r.Header.Get("Location"))
		if r.StatusCode != 302 || u.Query().Get("error") != "invalid_scope" || u.Query().Get("state") != "st-1" || u.Query().Get("iss") != e.base {
			t.Errorf("scope %q: %d %q", sc, r.StatusCode, r.Header.Get("Location"))
		}
	}
	// No scope asked: everything the server supports (the role still decides).
	p.scope = ""
	v2, ch2 := pkce()
	p.challenge = ch2
	if r := e.exchange(cid, e.approve(boss, p), v2); r.str("scope") != "rackbook:write" {
		t.Fatalf("default scope %q", r.str("scope"))
	}
}
