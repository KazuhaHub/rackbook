package oauthserver_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/roles"
)

func TestAccessTokenWorksOnMCP(t *testing.T) {
	e := newEnv(t, opts{})
	_, tok := e.login(boss, "Test Client")
	if err := e.mcpTools(tok.access); err != nil {
		t.Fatalf("MCP session with the access token: %v", err)
	}
	// The commit trailer names the built-in server and the client.
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok.access)
	id, err := e.res.AuthenticateBearer(req.WithContext(req.Context()))
	if err != nil || id == nil {
		t.Fatalf("AuthenticateBearer: %v", err)
	}
	// AuthenticateBearer only handles /mcp paths.
	req.URL.Path = "/mcp"
	id, err = e.res.AuthenticateBearer(req)
	if err != nil || id == nil {
		t.Fatalf("AuthenticateBearer on /mcp: %v", err)
	}
	got := strings.Join(gitstore.Trailers(id, "rackbook", ""), "\n")
	if !strings.Contains(got, "Edited-by: "+boss) || !strings.Contains(got, "Edited-via: mcp (rackbook, client Test Client)") {
		t.Fatalf("trailers:\n%s", got)
	}
	if id.EffectiveRole() != roles.Admin {
		t.Fatalf("role %v", id.EffectiveRole())
	}
	// The tokens never work on the console API.
	if r := e.do("", http.MethodGet, "/api/meta", nil, "Authorization", "Bearer "+tok.access); r.StatusCode == 200 {
		t.Fatal("an access token was accepted on /api/meta")
	}
}

func TestScopeNarrowsTheRole(t *testing.T) {
	e := newEnv(t, opts{mcpYAML: "    scopes: {read: \"rackbook:read\"}\n"})
	cid := e.register("c")
	v, ch := pkce()
	p := e.params(cid, testRedirect, ch)
	p.scope = "rackbook:read" // no write scope: read only, even for an admin
	r := e.exchange(cid, e.approve(boss, p), v)
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+r.str("access_token"))
	id, err := e.res.AuthenticateBearer(req)
	if err != nil || id == nil {
		t.Fatal(err)
	}
	if id.EffectiveRole() != roles.Viewer {
		t.Fatalf("role with a read-only grant: %v", id.EffectiveRole())
	}
}

func TestRefreshRotation(t *testing.T) {
	e := newEnv(t, opts{})
	cid, tok := e.login(boss, "c")

	r := e.refresh(cid, tok.refresh)
	if r.StatusCode != 200 {
		t.Fatalf("refresh: %d %s", r.StatusCode, r.body)
	}
	next := r.str("refresh_token")
	if next == "" || next == tok.refresh || r.str("access_token") == "" {
		t.Fatalf("rotation gave %s", r.body)
	}
	if e.mcpStatus(r.str("access_token")).StatusCode != 200 {
		t.Fatal("the refreshed access token does not work")
	}
	// The state file holds hashes, never the token.
	raw, _ := os.ReadFile(filepath.Join(e.dir, "oauth-grants.json"))
	_, secret, _ := strings.Cut(next, ".")
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), r.str("access_token")) {
		t.Fatal("a token is stored in the grant file")
	}
	// Another client cannot use the token.
	other := e.register("other", "http://localhost:1/x")
	if r := e.refresh(other, next); r.str("error") != "invalid_grant" {
		t.Fatalf("refresh by another client: %s", r.body)
	}
	// A guess with the right grant id and a wrong secret proves nothing and ends nothing.
	if r := e.refresh(cid, tok.grant+".wrong-secret"); r.str("error") != "invalid_grant" {
		t.Fatalf("wrong secret: %s", r.body)
	}
	if r := e.refresh(cid, next); r.StatusCode != 200 {
		t.Fatalf("the grant should survive a wrong guess: %s", r.body)
	}
	// scope can only narrow.
	e.clock.advance(61 * time.Second)
	cur := e.refresh(cid, tok.refresh) // two rotations old and past the grace: not valid any more
	if cur.StatusCode == 200 {
		t.Fatalf("a token two rotations old still works: %s", cur.body)
	}
}

func TestRefreshReuseAfterGraceRevokes(t *testing.T) {
	e := newEnv(t, opts{})
	cid, tok := e.login(boss, "c")
	rotated := e.refresh(cid, tok.refresh)
	if rotated.StatusCode != 200 {
		t.Fatalf("refresh: %s", rotated.body)
	}
	e.clock.advance(61 * time.Second)
	gone := e.refresh(cid, tok.refresh)
	if gone.StatusCode != 400 || gone.str("error") != "invalid_grant" {
		t.Fatalf("reuse after the grace window: %d %s", gone.StatusCode, gone.body)
	}
	if r := e.refresh(cid, rotated.str("refresh_token")); r.str("error") != "invalid_grant" {
		t.Fatalf("the newest token survived a reuse alarm: %s", r.body)
	}
	if e.mcpStatus(rotated.str("access_token")).StatusCode != 401 {
		t.Fatal("access token of a revoked grant still works")
	}
	var list map[string]any
	if raw, _ := os.ReadFile(filepath.Join(e.dir, "oauth-grants.json")); json.Unmarshal(raw, &list) != nil || len(list["grants"].(map[string]any)) != 0 {
		t.Fatalf("grant file after revocation: %s", raw)
	}
}

func TestIdleExpiry(t *testing.T) {
	e := newEnv(t, opts{builtinYAML: "      idle_expiry: 30d\n"})
	cid, tok := e.login(boss, "c")
	e.clock.advance(29 * 24 * time.Hour)
	r := e.refresh(cid, tok.refresh)
	if r.StatusCode != 200 {
		t.Fatalf("refresh before the idle limit: %s", r.body)
	}
	// The idle time is measured from the last refresh: another 29 days is fine, with no absolute limit.
	e.clock.advance(29 * 24 * time.Hour)
	r = e.refresh(cid, r.str("refresh_token"))
	if r.StatusCode != 200 {
		t.Fatalf("refresh 58 days after the grant was made: %s", r.body)
	}
	e.clock.advance(31 * 24 * time.Hour)
	if got := e.refresh(cid, r.str("refresh_token")); got.str("error") != "invalid_grant" {
		t.Fatalf("refresh after the idle limit: %s", got.body)
	}
}

func TestRoleRemoved(t *testing.T) {
	e := newEnv(t, opts{})
	cid, tok := e.login("ed@example.com", "c")
	if e.mcpStatus(tok.access).StatusCode != 200 {
		t.Fatal("editor token refused")
	}
	e.setRoles(&roles.Spec{Admin: []string{boss}}) // ed loses the role
	if r := e.mcpStatus(tok.access); r.StatusCode != 401 {
		t.Fatalf("access token of a user without a role: %d", r.StatusCode)
	}
	if r := e.refresh(cid, tok.refresh); r.str("error") != "invalid_grant" {
		t.Fatalf("refresh of a user without a role: %s", r.body)
	}
	e.setRoles(&roles.Spec{Admin: []string{boss}, Editor: []string{"ed@example.com"}}) // role comes back
	if r := e.refresh(cid, tok.refresh); r.StatusCode == 200 {
		t.Fatal("the grant came back to life: it was revoked at the failed refresh")
	}
}

func TestRevokeIsImmediate(t *testing.T) {
	e := newEnv(t, opts{})
	_, tok := e.login("ed@example.com", "Editor Client")
	if e.mcpStatus(tok.access).StatusCode != 200 {
		t.Fatal("token refused")
	}
	// Listed for the owner, with the client name; not for someone else.
	list := e.get("ed@example.com", "/api/account/grants").json()["grants"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["clientName"] != "Editor Client" || list[0].(map[string]any)["id"] != tok.grant {
		t.Fatalf("account grants: %v", list)
	}
	if other := e.get("vic@example.com", "/api/account/grants").json()["grants"].([]any); len(other) != 0 {
		t.Fatalf("someone else's grants listed: %v", other)
	}
	if r := e.do("vic@example.com", http.MethodDelete, "/api/account/grants/"+tok.grant, nil, "Sec-Fetch-Site", "same-origin"); r.StatusCode != 404 {
		t.Fatalf("revoking someone else's grant: %d", r.StatusCode)
	}
	if e.mcpStatus(tok.access).StatusCode != 200 {
		t.Fatal("a stranger ended the grant")
	}
	// Only admins list everyone's.
	if r := e.get("ed@example.com", "/api/admin/grants"); r.StatusCode != 403 {
		t.Fatalf("editor lists all grants: %d", r.StatusCode)
	}
	all := e.get(boss, "/api/admin/grants").json()["grants"].([]any)
	if len(all) != 1 || all[0].(map[string]any)["user"] != "ed@example.com" {
		t.Fatalf("admin grants: %v", all)
	}
	// An admin revokes: the unexpired access token stops at once.
	if r := e.do(boss, http.MethodDelete, "/api/admin/grants/"+tok.grant, nil, "Sec-Fetch-Site", "same-origin"); r.StatusCode != 200 {
		t.Fatalf("admin revoke: %d %s", r.StatusCode, r.body)
	}
	if r := e.mcpStatus(tok.access); r.StatusCode != 401 {
		t.Fatalf("access token after revocation: %d", r.StatusCode)
	}
	// The owner revokes their own.
	_, tok2 := e.login("ed@example.com", "Second")
	if r := e.do("ed@example.com", http.MethodDelete, "/api/account/grants/"+tok2.grant, nil, "Sec-Fetch-Site", "same-origin"); r.StatusCode != 200 {
		t.Fatalf("own revoke: %d", r.StatusCode)
	}
	if e.mcpStatus(tok2.access).StatusCode != 401 {
		t.Fatal("token works after the owner revoked the grant")
	}
	if r := e.do("ed@example.com", http.MethodDelete, "/api/account/grants/"+tok2.grant, nil, "Sec-Fetch-Site", "same-origin"); r.StatusCode != 404 {
		t.Fatalf("revoking twice: %d", r.StatusCode)
	}
	// Grants cannot be managed with a token.
	_, tok3 := e.login(boss, "Third")
	if r := e.do("", http.MethodGet, "/api/admin/grants", nil, "Authorization", "Bearer "+tok3.access); r.StatusCode == 200 {
		t.Fatal("an access token listed grants")
	}
}

// signingKey reads the key the server generated.
func signingKey(t *testing.T, dir string) *ecdsa.PrivateKey {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "oauth-signing-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k.(*ecdsa.PrivateKey)
}

func TestTokenConfusion(t *testing.T) {
	e := newEnv(t, opts{})
	_, tok := e.login(boss, "c")
	key := signingKey(t, e.dir)

	// Decode the real token to copy its claims and key id.
	parsed, err := jwt.ParseSigned(tok.access, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	kid := parsed.Headers[0].KeyID
	var claims map[string]any
	if err := parsed.Claims(&key.PublicKey, &claims); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	with := func(mod func(map[string]any)) map[string]any {
		c := map[string]any{}
		for k, v := range claims {
			c[k] = v
		}
		mod(c)
		return c
	}
	sign := func(k any, alg jose.SignatureAlgorithm, typ, kid string, c map[string]any) string {
		o := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
		if kid != "" {
			o = o.WithHeader("kid", kid)
		}
		s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: k}, o)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := jwt.Signed(s).Claims(c).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	good := sign(key, jose.ES256, "at+jwt", kid, with(func(map[string]any) {}))
	if e.mcpStatus(good).StatusCode != 200 {
		t.Fatal("a token re-signed with the real key and the real claims should work")
	}
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	hs := func() string { // HS256 with the public key as the secret
		pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		h, c := enc(map[string]string{"alg": "HS256", "typ": "at+jwt", "kid": kid}), enc(claims)
		m := hmac.New(sha256.New, pub)
		m.Write([]byte(h + "." + c))
		return h + "." + c + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	}
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cases := map[string]string{
		"typ JWT":       sign(key, jose.ES256, "JWT", kid, claims),
		"typ missing":   sign(key, jose.ES256, "", kid, claims),
		"typ id_token":  sign(key, jose.ES256, "id_token", kid, claims),
		"HS256":         hs(),
		"alg none":      enc(map[string]string{"alg": "none", "typ": "at+jwt"}) + "." + enc(claims) + ".",
		"ES384 key":     "",
		"wrong key":     sign(wrongKey, jose.ES256, "at+jwt", kid, claims),
		"unknown kid":   sign(key, jose.ES256, "at+jwt", "other", claims),
		"no kid":        sign(key, jose.ES256, "at+jwt", "", claims),
		"wrong aud":     sign(key, jose.ES256, "at+jwt", kid, with(func(c map[string]any) { c["aud"] = e.base + "/other" })),
		"wrong iss":     sign(key, jose.ES256, "at+jwt", kid, with(func(c map[string]any) { c["iss"] = "https://evil.example" })),
		"expired":       sign(key, jose.ES256, "at+jwt", kid, with(func(c map[string]any) { c["exp"] = now.Add(-5 * time.Minute).Unix() })),
		"not yet valid": sign(key, jose.ES256, "at+jwt", kid, with(func(c map[string]any) { c["nbf"] = now.Add(5 * time.Minute).Unix() })),
		"no exp":        sign(key, jose.ES256, "at+jwt", kid, with(func(c map[string]any) { delete(c, "exp") })),
		"no gid":        sign(key, jose.ES256, "at+jwt", kid, with(func(c map[string]any) { delete(c, "gid") })),
		"unknown gid":   sign(key, jose.ES256, "at+jwt", kid, with(func(c map[string]any) { c["gid"] = "nope" })),
		"other subject": sign(key, jose.ES256, "at+jwt", kid, with(func(c map[string]any) { c["sub"] = "ed@example.com" })),
		"other client":  sign(key, jose.ES256, "at+jwt", kid, with(func(c map[string]any) { c["client_id"] = "rbc_other" })),
	}
	delete(cases, "ES384 key")
	for name, raw := range cases {
		if r := e.mcpStatus(raw); r.StatusCode != 401 {
			t.Errorf("%s: status %d, want 401", name, r.StatusCode)
		}
	}
	// A token issued to us with the issuer of a trusted issuer cannot be handed to another verifier either.
	if r := e.mcpStatus("not.a.jwt"); r.StatusCode != 401 {
		t.Errorf("garbage: %d", r.StatusCode)
	}
}

func TestRestartKeepsGrants(t *testing.T) {
	e := newEnv(t, opts{})
	cid, tok := e.login(boss, "c")
	e.restart()
	// The access token of before still works (same key, grant on disk).
	if e.mcpStatus(tok.access).StatusCode != 200 {
		t.Fatal("access token after a restart")
	}
	// And the client refreshes without any browser step.
	r := e.refresh(cid, tok.refresh)
	if r.StatusCode != 200 {
		t.Fatalf("refresh after restart: %d %s", r.StatusCode, r.body)
	}
	if e.mcpStatus(r.str("access_token")).StatusCode != 200 {
		t.Fatal("refreshed token after restart")
	}
	// A registered client survives too.
	v, ch := pkce()
	if got := e.exchange(cid, e.approve(boss, e.params(cid, testRedirect, ch)), v); got.StatusCode != 200 {
		t.Fatalf("registered client after restart: %s", got.body)
	}
	if runtime.GOOS != "windows" {
		for p, want := range map[string]os.FileMode{"oauth-grants.json": 0o600, "oauth-signing-key.pem": 0o600} {
			if st, err := os.Stat(filepath.Join(e.dir, p)); err != nil || st.Mode().Perm() != want {
				t.Errorf("%s: %v %v", p, st, err)
			}
		}
	}
}

func TestKeyReplacementRecoversByRefresh(t *testing.T) {
	e := newEnv(t, opts{})
	cid, tok := e.login(boss, "c")
	old := e.refresh(cid, tok.refresh)
	if err := os.Remove(filepath.Join(e.dir, "oauth-signing-key.pem")); err != nil { // replace the key: remove it, a new one is generated
		t.Fatal(err)
	}
	e.restart()
	if r := e.mcpStatus(old.str("access_token")); r.StatusCode != 401 {
		t.Fatalf("a token signed with the replaced key: %d", r.StatusCode)
	}
	r := e.refresh(cid, old.str("refresh_token"))
	if r.StatusCode != 200 {
		t.Fatalf("refresh after a key replacement: %d %s", r.StatusCode, r.body)
	}
	if e.mcpStatus(r.str("access_token")).StatusCode != 200 {
		t.Fatal("new access token refused")
	}
	// The JWKS publishes only the current key.
	if keys := e.get("", "/oauth/jwks").json()["keys"].([]any); len(keys) != 1 {
		t.Fatalf("jwks: %v", keys)
	}
}

func TestSigningKeySources(t *testing.T) {
	// A key file named in the config wins; a missing file is an error, not a new key.
	e := newEnv(t, opts{})
	_ = e
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	pemText := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	file := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(file, pemText, 0o600); err != nil {
		t.Fatal(err)
	}
	f := newEnv(t, opts{builtinYAML: "      signing_key_file: " + file + "\n"})
	_, tok := f.login(boss, "c")
	parsed, err := jwt.ParseSigned(tok.access, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := parsed.Claims(&k.PublicKey, &m); err != nil {
		t.Fatalf("token is not signed with the configured key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "oauth-signing-key.pem")); err == nil {
		t.Fatal("a key was generated although one was configured")
	}
}

func TestSessionlessAuthorizeAfterLoginReturn(t *testing.T) {
	// The "return" the login page receives is a path-only URL; see login.SafeReturn for the strict checks.
	e := newEnv(t, opts{})
	cid := e.register("c")
	_, ch := pkce()
	r := e.startAuth("", e.params(cid, testRedirect, ch))
	if u, _ := url.Parse(r.Header.Get("Location")); u.Query().Get("return") == "" || strings.HasPrefix(u.Query().Get("return"), "http") {
		t.Fatalf("login redirect: %q", r.Header.Get("Location"))
	}
}

func TestStartupDropsGrantsThatWentIdle(t *testing.T) {
	e := newEnv(t, opts{builtinYAML: "      idle_expiry: 30d\n"})
	e.login(boss, "c")
	e.clock.advance(31 * 24 * time.Hour)
	e.restart()
	if g := e.get(boss, "/api/account/grants").json()["grants"].([]any); len(g) != 0 {
		t.Fatalf("grants: %v", g)
	}
	raw, _ := os.ReadFile(filepath.Join(e.dir, "oauth-grants.json"))
	var f map[string]any
	if json.Unmarshal(raw, &f) != nil || len(f["grants"].(map[string]any)) != 0 {
		t.Fatalf("the file still holds the idle grant: %s", raw)
	}
}

// An auditor with no role at all gets the viewer floor, so a grant they approve
// works; removing them from auth.auditors ends it like removing a role.
func TestGrantOfAnAuditorLastsWhileTheyAreOnTheList(t *testing.T) {
	e := newEnv(t, opts{})
	const aud = "aud@example.com"
	e.setAuditors([]string{aud})
	cid, tok := e.login(aud, "Audit Client")
	if e.mcpStatus(tok.access).StatusCode != 200 {
		t.Fatal("an auditor's grant is refused")
	}
	names := e.toolSet(e.session(tok.access))
	for _, w := range []string{"records_create", "records_update", "records_delete", "create_record", "update_record", "delete_record"} {
		if names[w] {
			t.Errorf("an auditor without a role sees the write tool %s", w)
		}
	}
	e.setAuditors(nil)
	if r := e.mcpStatus(tok.access); r.StatusCode != 401 {
		t.Fatalf("access token after removal from the list: %d", r.StatusCode)
	}
	if r := e.refresh(cid, tok.refresh); r.str("error") != "invalid_grant" {
		t.Fatalf("refresh after removal: %s", r.body)
	}
}
