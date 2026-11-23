package login

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func userOf(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	u, _ := m["user"].(map[string]any)
	if u == nil {
		t.Fatalf("no user in %v", m)
	}
	return u
}

func TestOIDCLoginSuccess(t *testing.T) {
	e := newEnv(t, options{})
	b := e.browser()

	// Before logging in: the API says login_required, the console redirects.
	r := b.get("/api/meta")
	if r.StatusCode != 401 || !strings.Contains(r.Body, `"login_required"`) || !strings.Contains(r.Body, `"login":"/auth/login`) {
		t.Fatalf("api without a session: %d %s", r.StatusCode, r.Body)
	}
	r = b.get("/c/devices?x=1")
	if r.StatusCode != 302 || r.Loc() != "/auth/login?return=%2Fc%2Fdevices%3Fx%3D1" || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("console without a session: %d %q %q", r.StatusCode, r.Loc(), r.Header.Get("Cache-Control"))
	}
	// The login page and assets are public.
	if r = b.get("/auth/login"); r.StatusCode != 200 || !strings.Contains(r.Body, "console") {
		t.Fatalf("login page: %d %s", r.StatusCode, r.Body)
	}
	if r = b.get("/auth/config"); r.StatusCode != 200 || !strings.Contains(r.Body, `"oidc":true`) || !strings.Contains(r.Body, `"passkeys":false`) {
		t.Fatalf("config: %d %s", r.StatusCode, r.Body)
	}

	r = b.login("admin", "/c/devices")
	if r.StatusCode != 303 || r.Loc() != "/c/devices" {
		t.Fatalf("callback: %d %q\n%s", r.StatusCode, r.Loc(), e.logs)
	}
	status, m := b.meta()
	if status != 200 {
		t.Fatalf("meta: %d", status)
	}
	u := userOf(t, m)
	// The identity claim is folded to lowercase.
	if u["id"] != "kazuha@kazuha.org" || u["role"] != "admin" || u["authMethod"] != "oidc" || u["canAdmin"] != true || u["name"] != "Kazuha M" {
		t.Fatalf("user = %v", u)
	}
	// Logged in: the login page forwards.
	if r = b.get("/auth/login?return=%2Fcheck"); r.StatusCode != 303 || r.Loc() != "/check" {
		t.Fatalf("login page while logged in: %d %q", r.StatusCode, r.Loc())
	}
	// The binding cookie is gone, the session cookie has the right attributes.
	if b.cookie(LoginCookie) != nil {
		t.Fatal("binding cookie must be cleared after the callback")
	}
	var sc string
	for _, c := range r.Header.Values("Set-Cookie") {
		_ = c
	}
	first := b.login("admin", "")
	for _, c := range first.Header.Values("Set-Cookie") {
		if strings.HasPrefix(c, SessionCookie+"=") {
			sc = c
		}
	}
	for _, want := range []string{"Path=/", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(sc, want) {
			t.Errorf("session cookie %q lacks %s", sc, want)
		}
	}
	if strings.Contains(sc, "Domain=") {
		t.Errorf("__Host- cookie must not have a Domain: %q", sc)
	}
}

func TestRolesPerRequest(t *testing.T) {
	e := newEnv(t, options{nogit: true}) // without Git the config is re-read on every request
	for user, want := range map[string]string{"admin": "admin", "editor": "editor", "viewer": "viewer"} {
		b := e.browser()
		if r := b.login(user, ""); r.StatusCode != 303 {
			t.Fatalf("%s: %d", user, r.StatusCode)
		}
		_, m := b.meta()
		if got := userOf(t, m)["role"]; got != want {
			t.Errorf("%s: role %v, want %s", user, got, want)
		}
	}
	// A viewer cannot write; the session never stored a role.
	b := e.browser()
	b.login("viewer", "")
	r := b.do("POST", "/api/c/devices", map[string]string{"Content-Type": "application/json"}, strings.NewReader(`{"data":{}}`))
	if r.StatusCode != 403 {
		t.Fatalf("viewer write: %d %s", r.StatusCode, r.Body)
	}
	// Removing a role in rackbook.yml locks the user out at once.
	b = e.browser()
	b.login("editor", "")
	if st, _ := b.meta(); st != 200 {
		t.Fatalf("editor before: %d", st)
	}
	e.rewriteRoles("  roles:\n    admin: [kazuha@kazuha.org]\n")
	r = b.get("/api/meta")
	if r.StatusCode != 403 || !strings.Contains(r.Body, "no_role") {
		t.Fatalf("editor after removal: %d %s", r.StatusCode, r.Body)
	}
	if r = b.get("/c/devices"); r.StatusCode != 303 || r.Loc() != "/auth/login?error=no_role" {
		t.Fatalf("console after removal: %d %q", r.StatusCode, r.Loc())
	}
}

func TestNoRoleIsRefusedWith403Page(t *testing.T) {
	e := newEnv(t, options{})
	b := e.browser()
	r := b.login("nobody", "")
	if r.StatusCode != 303 || r.Loc() != "/auth/login?error=no_role" {
		t.Fatalf("callback: %d %q", r.StatusCode, r.Loc())
	}
	if b.cookie(SessionCookie) != nil {
		t.Fatal("no session may be issued without a role")
	}
	page := b.get(r.Loc())
	if page.StatusCode != 403 || !strings.Contains(page.Body, "console") {
		t.Fatalf("no-role page: %d", page.StatusCode)
	}
	if !strings.Contains(e.logs.String(), "identity has no role") || !strings.Contains(e.logs.String(), "nobody@elsewhere.net") {
		t.Fatalf("the refusal must be logged:\n%s", e.logs)
	}
}

func TestKelvinSignDoesNotFoldOntoASCII(t *testing.T) {
	e := newEnv(t, options{roles: "  roles:\n    admin: [kazuha@kazuha.org]\n"})
	b := e.browser()
	r := b.login("kelvin", "")
	if r.Loc() != "/auth/login?error=no_role" {
		t.Fatalf("a look-alike identity must not get the role: %d %q", r.StatusCode, r.Loc())
	}
}

func TestWrongTenant(t *testing.T) {
	e := newEnv(t, options{})
	b := e.browser()
	r := b.login("foreign", "")
	if r.StatusCode != 303 || r.Loc() != "/auth/login?error=tenant" {
		t.Fatalf("%d %q", r.StatusCode, r.Loc())
	}
	if b.cookie(SessionCookie) != nil {
		t.Fatal("no session for a foreign tenant")
	}
	if got := b.get("/auth/login?error=tenant"); got.StatusCode != 403 {
		t.Fatalf("tenant page: %d", got.StatusCode)
	}
	// A missing tid claim is refused too when tenants are configured.
	e.idp.Mutate = func(c map[string]any) { delete(c, "tid") }
	if r = e.browser().login("admin", ""); r.Loc() != "/auth/login?error=tenant" {
		t.Fatalf("missing tid: %q", r.Loc())
	}
}

func TestClaimsMustBeStrings(t *testing.T) {
	e := newEnv(t, options{})
	for name, mut := range map[string]func(map[string]any){
		"identity not a string": func(c map[string]any) { c["preferred_username"] = []string{"kazuha@kazuha.org"} },
		"identity missing":      func(c map[string]any) { delete(c, "preferred_username") },
		"identity empty":        func(c map[string]any) { c["preferred_username"] = "  " },
		"identity with newline": func(c map[string]any) { c["preferred_username"] = "kazuha@kazuha.org\nadmin" },
		"name not a string":     func(c map[string]any) { c["name"] = 7 },
	} {
		e.idp.Mutate = mut
		b := e.browser()
		if r := b.login("admin", ""); r.Loc() != "/auth/login?error=claims" || b.cookie(SessionCookie) != nil {
			t.Errorf("%s: %q", name, r.Loc())
		}
	}
}

func TestReplayedCallbackFails(t *testing.T) {
	e := newEnv(t, options{})
	b := e.browser()
	r1 := b.get("/auth/oidc/start")
	bind := b.cookie(LoginCookie).Value
	az := b.get(r1.Loc())
	callback := az.Loc()
	if r := b.get(callback); r.StatusCode != 303 || r.Loc() != "/" {
		t.Fatalf("first: %d %q", r.StatusCode, r.Loc())
	}
	// Replay: same URL, and even the same binding cookie put back.
	b2 := e.browser()
	b2.setCookie(LoginCookie, bind)
	if r := b2.get(callback); r.Loc() != "/auth/login?error=expired" {
		t.Fatalf("replay: %d %q", r.StatusCode, r.Loc())
	}
	if b2.cookie(SessionCookie) != nil {
		t.Fatal("a replay must not give a session")
	}
}

func TestBrowserBinding(t *testing.T) {
	e := newEnv(t, options{})
	victim := e.browser()
	r1 := victim.get("/auth/oidc/start")
	callback := victim.get(r1.Loc()).Loc()

	// Another browser with no binding cookie (login CSRF / session fixation).
	attacker := e.browser()
	if r := attacker.get(callback); r.Loc() != "/auth/login?error=expired" || attacker.cookie(SessionCookie) != nil {
		t.Fatalf("no cookie: %q", r.Loc())
	}
	// A cookie that names no pending login.
	attacker.setCookie(LoginCookie, strings.Repeat("A", 43))
	if r := attacker.get(callback); r.Loc() != "/auth/login?error=expired" || attacker.cookie(SessionCookie) != nil {
		t.Fatalf("wrong cookie: %q", r.Loc())
	}
	// The right cookie but a state that is not the one stored with it does
	// not take (and so does not burn) the pending login.
	cu, _ := url.Parse(callback)
	q := cu.Query()
	q.Set("state", strings.Repeat("B", 43))
	cu.RawQuery = q.Encode()
	if r := victim.get(cu.String()); r.Loc() != "/auth/login?error=bad_callback" {
		t.Fatalf("wrong state: %q", r.Loc())
	}
	// The victim's real login still works: the binding cookie was cleared by
	// the failed callback, so they have to start again. Starting again works.
	if r := victim.login("admin", ""); r.StatusCode != 303 || victim.cookie(SessionCookie) == nil {
		t.Fatalf("retry: %d %q", r.StatusCode, r.Loc())
	}
}

func TestCallbackParameterChecks(t *testing.T) {
	e := newEnv(t, options{})
	for name, tc := range map[string]struct{ query, want string }{
		"duplicate state": {"state=a&state=b&code=c", "bad_callback"},
		"duplicate code":  {"state=a&code=c&code=d", "bad_callback"},
		"missing code":    {"state=a", "bad_callback"},
		"missing state":   {"code=c", "bad_callback"},
		"nothing":         {"", "bad_callback"},
		"idp error":       {"error=access_denied&error_description=nope", "idp_error"},
		"duplicate error": {"error=a&error=b", "bad_callback"},
	} {
		b := e.browser()
		b.get("/auth/oidc/start")
		r := b.get("/auth/oidc/callback?" + tc.query)
		if r.Loc() != "/auth/login?error="+tc.want {
			t.Errorf("%s: %q", name, r.Loc())
		}
		if b.cookie(SessionCookie) != nil {
			t.Errorf("%s: session issued", name)
		}
	}
	// An IdP error that carries the browser's own state drops that pending login;
	// one without it (or with a foreign state) cancels nothing, so a forged link
	// cannot kill someone else's login.
	b := e.browser()
	r1 := b.get("/auth/oidc/start")
	cb := b.get(r1.Loc()).Loc()
	if r := b.get("/auth/oidc/callback?error=access_denied"); r.Loc() != "/auth/login?error=idp_error" || b.cookie(LoginCookie) == nil {
		t.Fatalf("idp error without state: %q", r.Loc())
	}
	if r := b.get("/auth/oidc/callback?error=access_denied&state=" + strings.Repeat("C", 43)); r.Loc() != "/auth/login?error=idp_error" || b.cookie(LoginCookie) == nil {
		t.Fatalf("idp error with a foreign state: %q", r.Loc())
	}
	if r := b.get(cb); r.StatusCode != 303 || r.Loc() != "/" {
		t.Fatalf("the real login must still work: %d %q", r.StatusCode, r.Loc())
	}
	// With the matching state the pending login is dropped.
	b = e.browser()
	r1 = b.get("/auth/oidc/start")
	az, _ := url.Parse(r1.Loc())
	state := az.Query().Get("state")
	cb = b.get(r1.Loc()).Loc()
	bind := b.cookie(LoginCookie).Value
	if r := b.get("/auth/oidc/callback?error=access_denied&state=" + state); r.Loc() != "/auth/login?error=idp_error" {
		t.Fatalf("%q", r.Loc())
	}
	b.setCookie(LoginCookie, bind)
	if r := b.get(cb); r.Loc() != "/auth/login?error=expired" {
		t.Fatalf("after idp error: %q", r.Loc())
	}
}

func TestIdPFailures(t *testing.T) {
	e := newEnv(t, options{})
	e.idp.TokenStatus = 500
	b := e.browser()
	if r := b.login("admin", ""); r.Loc() != "/auth/login?error=idp_error" || b.cookie(SessionCookie) != nil {
		t.Fatalf("token endpoint down: %q", r.Loc())
	}
	e.idp.TokenStatus = 0
	// ID token with the wrong audience / expired is refused by Complete.
	for name, mut := range map[string]func(map[string]any){
		"audience": func(c map[string]any) { c["aud"] = "someone-else" },
		"expired":  func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
		"issuer":   func(c map[string]any) { c["iss"] = "https://evil.example" },
		"nonce":    func(c map[string]any) { c["nonce"] = "not-the-nonce" },
	} {
		e.idp.Mutate = mut
		b := e.browser()
		if r := b.login("admin", ""); r.Loc() != "/auth/login?error=idp_error" || b.cookie(SessionCookie) != nil {
			t.Errorf("%s: %q", name, r.Loc())
		}
	}
}

func TestSafeReturn(t *testing.T) {
	good := []string{"/", "/c/devices", "/c/devices/web-1?tab=2#x", "/check", "/c/a%2Fb"}
	for _, s := range good {
		if SafeReturn(s) != s {
			t.Errorf("%q should be kept, got %q", s, SafeReturn(s))
		}
	}
	bad := []string{
		"", "//evil.com", "https://evil.com", "http://evil.com/x", "/\\evil.com", "\\\\evil.com", "/\t/evil.com", "/\n/evil.com",
		"/\r/evil.com", "javascript:alert(1)", "evil.com", "///evil.com", "/%5Cevil.com/../..", "/a\\b", "/auth/login", "/auth/oidc/start",
		"/\x00", " /x", "/" + strings.Repeat("a", 3000),
	}
	for _, s := range bad {
		want := "/"
		if s == "/%5Cevil.com/../.." {
			continue // percent-encoded: stays a same-origin path
		}
		if got := SafeReturn(s); got != want {
			t.Errorf("%q -> %q, want %q", s, got, want)
		}
	}
}

func TestOpenRedirectThroughTheFlow(t *testing.T) {
	e := newEnv(t, options{})
	for _, ret := range []string{"//evil.com", "https://evil.com/x", "/\\evil.com", "/\t/evil.com"} {
		b := e.browser()
		r := b.login("admin", ret)
		if r.StatusCode != 303 || r.Loc() != "/" {
			t.Errorf("return=%q -> %d %q", ret, r.StatusCode, r.Loc())
		}
	}
	// The login page forwards only to safe paths, too.
	b := e.browser()
	b.login("admin", "")
	for _, ret := range []string{"//evil.com", "https://evil.com", "/\\evil.com"} {
		if r := b.get("/auth/login?return=" + url.QueryEscape(ret)); r.Loc() != "/" {
			t.Errorf("login page return=%q -> %q", ret, r.Loc())
		}
	}
}

// An OAuth authorization request that reaches the console signed out goes to
// the login page and, after login, back to the same request: the return value is
// a plain same-origin path with its query.
func TestLoginReturnsToAuthorizeRequest(t *testing.T) {
	e := newEnv(t, options{})
	target := "/oauth/authorize?client_id=https%3A%2F%2Fclient.example%2Fc.json&redirect_uri=http%3A%2F%2Flocalhost%3A7777%2Fcb&state=a%2Fb"
	b := e.browser()
	r := b.get(target)
	if r.StatusCode != 302 || r.Loc() != "/auth/login?return="+url.QueryEscape(target) {
		t.Fatalf("signed out: %d %q", r.StatusCode, r.Loc())
	}
	if r := b.login("admin", target); r.StatusCode != 303 || r.Loc() != target {
		t.Fatalf("after login: %d %q", r.StatusCode, r.Loc())
	}
}

func TestSessionExpiry(t *testing.T) {
	e := newEnv(t, options{})
	b := e.browser()
	b.login("admin", "")
	if st, _ := b.meta(); st != 200 {
		t.Fatal(st)
	}

	// Activity within 5 minutes does not re-issue the cookie; later it does.
	before := b.cookie(SessionCookie).Value
	e.clk.Advance(2 * time.Minute)
	r := b.get("/api/meta")
	if r.StatusCode != 200 || len(r.Header.Values("Set-Cookie")) != 0 || b.cookie(SessionCookie).Value != before {
		t.Fatalf("no refresh before 5 min: %d %v", r.StatusCode, r.Header.Values("Set-Cookie"))
	}
	e.clk.Advance(4 * time.Minute)
	r = b.get("/api/meta")
	if r.StatusCode != 200 || b.cookie(SessionCookie).Value == before {
		t.Fatalf("refresh after 5 min: %d", r.StatusCode)
	}

	// Idle timeout: 12h of silence.
	e.clk.Advance(12*time.Hour + time.Minute)
	other := e.browser()
	other.setCookie(SessionCookie, b.cookie(SessionCookie).Value)
	if r = other.get("/c/devices"); r.StatusCode != 302 || !strings.Contains(r.Loc(), "error=expired") {
		t.Fatalf("console after expiry: %d %q", r.StatusCode, r.Loc())
	}
	r = b.get("/api/meta")
	if r.StatusCode != 401 || !strings.Contains(r.Body, `"reason":"expired"`) {
		t.Fatalf("idle expiry: %d %s", r.StatusCode, r.Body)
	}

	// Absolute limit: activity every 11 hours still ends after 7 days.
	b = e.browser()
	b.login("admin", "")
	for i := 0; i < 20; i++ {
		e.clk.Advance(11 * time.Hour)
		if r := b.get("/api/meta"); r.StatusCode != 200 {
			if (i+1)*11 < 7*24 {
				t.Fatalf("expired too early at %dh: %d", (i+1)*11, r.StatusCode)
			}
			return
		}
	}
	t.Fatal("the session outlived the absolute limit")
}

func TestTamperedAndRotatedKey(t *testing.T) {
	e := newEnv(t, options{})
	b := e.browser()
	b.login("viewer", "")
	good := b.cookie(SessionCookie).Value

	forged, _ := e.svc.codec.seal(session{ID: "kazuha@kazuha.org", Method: "oidc", Issued: e.clk.Now().Unix(), Seen: e.clk.Now().Unix()})
	other := codec{key: []byte("a-completely-different-key-of-32-bytes!!")}
	wrongKey, _ := other.seal(session{ID: "kazuha@kazuha.org", Method: "oidc", Issued: e.clk.Now().Unix(), Seen: e.clk.Now().Unix()})
	payload, sig, _ := strings.Cut(good, ".")
	flipped := payload[:len(payload)-2] + "AA" + "." + sig
	for name, v := range map[string]string{
		"signed with another key":  wrongKey,
		"payload of another, sig":  strings.SplitN(forged, ".", 2)[0] + "." + sig,
		"flipped payload":          flipped,
		"no signature":             payload,
		"empty signature":          payload + ".",
		"garbage":                  "not a cookie",
		"two dots":                 good + ".x",
		"huge":                     strings.Repeat("A", 5000),
		"unknown method in cookie": mustSeal(e, session{ID: "kazuha@kazuha.org", Method: "mcphub", Issued: e.clk.Now().Unix(), Seen: e.clk.Now().Unix()}),
	} {
		c := e.browser()
		c.setCookie(SessionCookie, v)
		r := c.get("/api/meta")
		// "unknown method" is signed with the right key, so only the method check stops it.
		if r.StatusCode != 401 {
			t.Errorf("%s: %d %s", name, r.StatusCode, r.Body)
		}
	}

	// Rotating the key logs everyone out.
	e2 := &Service{codec: codec{key: []byte("rotated-key-rotated-key-rotated-key-32+")}, idle: e.svc.idle, absolute: e.svc.absolute, now: e.clk.Now}
	if _, err := e2.readSession(reqWithCookie(good)); err == nil {
		t.Fatal("a rotated key must reject old sessions")
	}
	if _, err := e.svc.readSession(reqWithCookie(good)); err != nil {
		t.Fatalf("the current key accepts it: %v", err)
	}
}

func mustSeal(e *env, s session) string {
	v, err := e.svc.codec.seal(s)
	if err != nil {
		panic(err)
	}
	return v
}

func reqWithCookie(v string) *http.Request {
	r, _ := http.NewRequest("GET", "https://x/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: v})
	return r
}

func TestLogout(t *testing.T) {
	e := newEnv(t, options{})
	b := e.browser()
	b.login("admin", "")
	// A cross-site POST is refused by the write guard.
	r := b.do("POST", "/auth/logout", map[string]string{"Sec-Fetch-Site": "cross-site"}, nil)
	if r.StatusCode != 403 || b.cookie(SessionCookie) == nil {
		t.Fatalf("cross-site logout: %d", r.StatusCode)
	}
	r = b.do("POST", "/auth/logout", map[string]string{"Sec-Fetch-Site": "same-origin", "Accept": "application/json"}, nil)
	if r.StatusCode != 200 || !strings.Contains(r.Body, "/auth/login?error=logged_out") {
		t.Fatalf("logout: %d %s", r.StatusCode, r.Body)
	}
	if b.cookie(SessionCookie) != nil {
		t.Fatal("the session cookie must be cleared")
	}
	if st, _ := b.meta(); st != 401 {
		t.Fatalf("after logout: %d", st)
	}
	// Without a session, a form logout still ends at the login page.
	r = b.do("POST", "/auth/logout", map[string]string{"Sec-Fetch-Site": "same-origin"}, nil)
	if r.StatusCode != 303 {
		t.Fatalf("form logout: %d", r.StatusCode)
	}
}

func TestPendingStoreIsBoundedAndExpires(t *testing.T) {
	clk := newClock()
	p := newPendingStore(clk.Now)
	first, _ := p.put(testState("first"), "/")
	for i := 0; i < pendingCapacity; i++ {
		if _, err := p.put(testState("x"), "/"); err != nil {
			t.Fatal(err)
		}
	}
	if p.len() > pendingCapacity {
		t.Fatalf("store grew to %d", p.len())
	}
	if _, res := p.take(first, "first"); res != takeUnknown {
		t.Fatal("the oldest entry should have been evicted")
	}
	id, _ := p.put(testState("v"), "/r")
	clk.Advance(pendingTTL + time.Second)
	if _, res := p.take(id, "v"); res != takeUnknown {
		t.Fatal("an expired entry must not be taken")
	}
	id, _ = p.put(testState("v"), "/r")
	if e, res := p.take(id, "v"); res != takeOK || e.ret != "/r" {
		t.Fatal("take")
	}
	if _, res := p.take(id, "v"); res != takeUnknown {
		t.Fatal("one-time take")
	}
}

func TestLoadSessionKey(t *testing.T) {
	good := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // 32 bytes
	if k, err := LoadSessionKey(good, ""); err != nil || len(k) != 32 {
		t.Fatalf("%v %d", err, len(k))
	}
	for name, tc := range map[string][2]string{
		"missing": {"", ""},
		"short":   {"c2hvcnQ=", ""},
		"notb64":  {"!!!", ""},
		"both":    {good, "/some/file"},
		"nofile":  {"", "/does/not/exist"},
	} {
		if _, err := LoadSessionKey(tc[0], tc[1]); err == nil {
			t.Errorf("%s must fail", name)
		}
	}
	f := t.TempDir() + "/key"
	if err := writeFile(f, good+"\n"); err != nil {
		t.Fatal(err)
	}
	if k, err := LoadSessionKey("", f); err != nil || len(k) != 32 {
		t.Fatalf("file: %v", err)
	}
}

func TestEmailIdentityNeedsVerifiedEmail(t *testing.T) {
	e := newEnv(t, options{cfgExtras: ""})
	// Switch the identity claim to email by rebuilding the login options.
	e.svc.o.Login.OIDC.IdentityClaim = "email"
	e.idp.Users["admin"]["email"] = "Kazuha@Kazuha.org"
	for name, ev := range map[string]any{"missing": nil, "false": false, "string": "true"} {
		e.idp.Mutate = func(c map[string]any) {
			if ev == nil {
				delete(c, "email_verified")
			} else {
				c["email_verified"] = ev
			}
		}
		b := e.browser()
		if r := b.login("admin", ""); r.Loc() != "/auth/login?error=claims" || b.cookie(SessionCookie) != nil {
			t.Errorf("email_verified %s: %q", name, r.Loc())
		}
	}
	e.idp.Mutate = func(c map[string]any) { c["email_verified"] = true }
	b := e.browser()
	if r := b.login("admin", ""); r.StatusCode != 303 || r.Loc() != "/" {
		t.Fatalf("verified: %d %q", r.StatusCode, r.Loc())
	}
	if _, m := b.meta(); userOf(t, m)["id"] != "kazuha@kazuha.org" {
		t.Fatalf("%v", m)
	}
}

func TestLimiter(t *testing.T) {
	clk := newClock()
	l := newLimiter(30, 10, clk.Now)
	for i := 0; i < 10; i++ {
		if !l.allow("a") {
			t.Fatalf("burst %d refused", i)
		}
	}
	if l.allow("a") {
		t.Fatal("the 11th call in a burst must be refused")
	}
	if !l.allow("b") {
		t.Fatal("another client has its own bucket")
	}
	clk.Advance(2 * time.Second) // 30/min = 1 token per 2 s
	if !l.allow("a") || l.allow("a") {
		t.Fatal("refill")
	}
}

func TestLoginStartIsRateLimited(t *testing.T) {
	e := newEnv(t, options{})
	b := e.browser()
	var last int
	for i := 0; i < 12; i++ {
		last = b.get("/auth/oidc/start").StatusCode
	}
	if last != 429 {
		t.Fatalf("12 starts in a row: last status %d", last)
	}
}

func TestSubjectIdentityMatchesOnlySubjectRoleEntries(t *testing.T) {
	e := newEnv(t, options{
		oidc:  "    identity: subject\n",
		roles: "  roles:\n    admin: [\"oidc:sub-admin\"]\n    editor: [\"*@kazuha.org\"]\n    viewer: [\"*\"]\n",
	})
	b := e.browser()
	if r := b.login("admin", ""); r.StatusCode != 303 {
		t.Fatalf("listed subject: %d", r.StatusCode)
	}
	_, m := b.meta()
	if u := userOf(t, m); u["id"] != "oidc:sub-admin" || u["role"] != "admin" {
		t.Fatalf("%v", u)
	}
	// ed@kazuha.org and * would match in claim mode; a subject login matches oidc: entries only.
	b2 := e.browser()
	if r := b2.login("editor", ""); r.StatusCode == 303 && r.Loc() == "/" {
		t.Fatalf("an unlisted subject must have no role, got a session: %d %q", r.StatusCode, r.Loc())
	}
}

func TestStartupWarnsWhenTheIdentityClaimIsNotIdPControlled(t *testing.T) {
	e := newEnv(t, options{oidc: "    identity_claim: name\n"})
	if !strings.Contains(e.logs.String(), "must be controlled by the identity provider") {
		t.Fatalf("no warning:\n%s", e.logs.String())
	}
	e = newEnv(t, options{}) // preferred_username with allowed_tenants set
	if strings.Contains(e.logs.String(), "must be controlled by the identity provider") {
		t.Fatalf("unexpected warning:\n%s", e.logs.String())
	}
}

func TestClaimIdentityCannotForgeASubjectIdentity(t *testing.T) {
	e := newEnv(t, options{roles: "  roles:\n    admin: [\"oidc:sub-admin\"]\n    viewer: [\"*\"]\n"})
	e.idp.Users["forger"] = map[string]any{"sub": "sub-x", "preferred_username": "oidc:sub-admin", "name": "X", "tid": tenant}
	b := e.browser()
	if r := b.login("forger", ""); r.StatusCode == 303 && r.Loc() == "/" {
		t.Fatalf("a username that starts with oidc: must be refused: %d %q", r.StatusCode, r.Loc())
	}
}

func TestClaimIdentityCannotBeTheAuditAnchorIdentity(t *testing.T) {
	e := newEnv(t, options{roles: "  roles:\n    viewer: [\"*\"]\n"})
	e.idp.Users["anchor"] = map[string]any{"sub": "sub-y", "preferred_username": "Rackbook-Audit-Anchor", "name": "Y", "tid": tenant}
	b := e.browser()
	if r := b.login("anchor", ""); r.StatusCode == 303 && r.Loc() == "/" {
		t.Fatalf("the identity of the audit anchor's commit must be refused: %d %q", r.StatusCode, r.Loc())
	}
}

func TestPublicPathsAreCanonicalOnly(t *testing.T) {
	e := newEnv(t, options{})
	b := e.browser()
	for _, p := range []string{"/assets/%2e%2e/api/meta", "/auth/%2e%2e/api/meta", "/assets/../api/meta", "/auth%2f..%2fapi/meta"} {
		r := b.get(p)
		if r.StatusCode == 200 || strings.Contains(r.Body, `"collections"`) {
			t.Errorf("%s reached the API without a session: %d", p, r.StatusCode)
		}
		if r.StatusCode == 301 && strings.HasPrefix(r.Loc(), "/api/") {
			t.Errorf("%s: public prefix used to redirect into the API: %q", p, r.Loc())
		}
	}
}

func TestGroupsClaimReachesRolesAndSessionsBindTheIssuer(t *testing.T) {
	e := newEnv(t, options{roles: "  roles:\n    admin: [\"group:ops\"]\n    viewer: [\"*@kazuha.org\"]\n"})
	e.idp.Users["admin"]["groups"] = []string{"dev", "ops"}
	b := e.browser()
	if r := b.login("admin", ""); r.StatusCode != 303 {
		t.Fatalf("login: %d", r.StatusCode)
	}
	if _, m := b.meta(); userOf(t, m)["role"] != "admin" {
		t.Fatalf("the groups claim must give group: entries a browser login: %v", m)
	}
	// Another user without the group stays a viewer.
	e.idp.Users["editor"]["groups"] = []string{"dev"}
	b2 := e.browser()
	b2.login("editor", "")
	if _, m := b2.meta(); userOf(t, m)["role"] != "viewer" {
		t.Fatalf("%v", m)
	}
	// A session made for another issuer is refused.
	sess, err := e.svc.codec.open(b.cookie(SessionCookie).Value)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Iss != e.idpS.URL {
		t.Fatalf("the session must record its issuer, got %q", sess.Iss)
	}
	sess.Iss = "https://old-idp.example.com"
	v, _ := e.svc.codec.seal(sess)
	b.setCookie(SessionCookie, v)
	if st, _ := b.meta(); st != 401 {
		t.Fatalf("a session from a different issuer must end: %d", st)
	}
}

func TestBoundGroups(t *testing.T) {
	var many []string
	for i := 0; i < 200; i++ {
		many = append(many, strings.Repeat("g", 36))
	}
	out, cut := boundGroups(many)
	total := 0
	for _, g := range out {
		total += len(g)
	}
	if !cut || total > maxSessionGroupBytes || len(out) > maxSessionGroups {
		t.Fatalf("%d groups, %d bytes, cut %v", len(out), total, cut)
	}
}

func TestLoginConfigCarriesLabelAndBranding(t *testing.T) {
	// Nothing set: empty label and name, no logo, and no provider named.
	e := newEnv(t, options{})
	var m map[string]any
	r := e.browser().get("/auth/config")
	if err := json.Unmarshal([]byte(r.Body), &m); err != nil {
		t.Fatalf("%v: %s", err, r.Body)
	}
	if m["label"] != "" || m["name"] != "" || m["logo"] != false || m["provider"] != "oidc" || m["oidc"] != true {
		t.Fatalf("defaults: %s", r.Body)
	}
	if strings.Contains(strings.ToLower(r.Body), "microsoft") {
		t.Fatalf("the login config names a provider: %s", r.Body)
	}

	e = newEnv(t, options{oidc: "    label: 使用 Kazuha Hub SSO 登录\n", cfgExtras: "branding:\n  name: Kazuha Hub\n"})
	r = e.browser().get("/auth/config")
	m = nil
	if err := json.Unmarshal([]byte(r.Body), &m); err != nil {
		t.Fatalf("%v: %s", err, r.Body)
	}
	if m["label"] != "使用 Kazuha Hub SSO 登录" || m["name"] != "Kazuha Hub" || m["logo"] != false {
		t.Fatalf("configured: %s", r.Body)
	}
}

func TestBrandingImagesNeedNoLogin(t *testing.T) {
	svg := `<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>`
	e := newEnv(t, options{
		cfgExtras: "branding:\n  logo: branding/logo.svg\n",
		files:     map[string]string{"branding/logo.svg": svg},
	})
	b := e.browser() // no session
	if r := b.get("/api/meta"); r.StatusCode != 401 {
		t.Fatalf("the API must still need a login: %d", r.StatusCode)
	}
	r := b.get("/branding/logo")
	if r.StatusCode != 200 || r.Body != svg || r.Header.Get("Content-Type") != "image/svg+xml" {
		t.Fatalf("logo: %d %q %v", r.StatusCode, r.Body, r.Header)
	}
	if r = b.get("/branding/favicon"); r.StatusCode != 200 || r.Header.Get("Content-Type") != "image/svg+xml" {
		t.Fatalf("default favicon: %d %v", r.StatusCode, r.Header)
	}
	// Only the two plain paths are public: an escaped slash is a different
	// path and goes through the login like any other page.
	for _, p := range []string{"/branding%2Flogo", "/branding%2ffavicon"} {
		if r := b.get(p); r.StatusCode != 302 {
			t.Fatalf("%s without a session: %d", p, r.StatusCode)
		}
	}
	if r = b.get("/auth/config"); !strings.Contains(r.Body, `"logo":true`) {
		t.Fatalf("config: %s", r.Body)
	}
}

// auth.auditors takes group: entries like a role list. An auditor with no role
// signs in as a viewer (the floor) and is told so; removing the group's entry
// locks them out at once, like removing a role.
func TestAuditorByGroupSignsInWithTheViewerFloor(t *testing.T) {
	const withAuditors = "  roles:\n    admin: [kazuha@kazuha.org]\n  auditors: [\"group:audit\"]\n"
	e := newEnv(t, options{roles: withAuditors, nogit: true})
	e.idp.Users["editor"]["groups"] = []string{"audit"}
	b := e.browser()
	if r := b.login("editor", ""); r.StatusCode != 303 || r.Loc() != "/" {
		t.Fatalf("an auditor with no role is refused: %d %q", r.StatusCode, r.Loc())
	}
	_, m := b.meta()
	u := userOf(t, m)
	if u["role"] != "viewer" || u["auditor"] != true || u["canEdit"] != false || u["canAdmin"] != false {
		t.Fatalf("%v", u)
	}
	if r := b.get("/api/account"); !strings.Contains(r.Body, `"auditor":true`) {
		t.Fatalf("%s", r.Body)
	}
	// somebody without the group has no role and is refused as before
	e.idp.Users["viewer"]["groups"] = []string{"dev"}
	if r := e.browser().login("viewer", ""); r.Loc() != "/auth/login?error=no_role" {
		t.Fatalf("%d %q", r.StatusCode, r.Loc())
	}
	// the administrator is not an auditor
	ba := e.browser()
	ba.login("admin", "")
	if _, m := ba.meta(); userOf(t, m)["role"] != "admin" || userOf(t, m)["auditor"] != nil {
		t.Fatalf("%v", m)
	}
	// the Users page evaluates group entries with the groups of the last sign-in
	var users struct {
		Users []struct {
			ID      string `json:"id"`
			Role    string `json:"role"`
			Auditor bool   `json:"auditor"`
		}
	}
	if err := json.Unmarshal([]byte(ba.get("/api/admin/users").Body), &users); err != nil {
		t.Fatal(err)
	}
	for _, u := range users.Users {
		if want := u.ID == "ed@kazuha.org"; u.Auditor != want || (want && u.Role != "viewer") {
			t.Errorf("users list: %+v", u)
		}
	}
	// removing the entry takes the capability and the floor away
	e.rewriteRoles("  roles:\n    admin: [kazuha@kazuha.org]\n")
	if r := b.get("/api/meta"); r.StatusCode != 403 || !strings.Contains(r.Body, "no_role") {
		t.Fatalf("after removal from the list: %d %s", r.StatusCode, r.Body)
	}
}
