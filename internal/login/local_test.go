package login

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/tokens"
)

// ---- the codec ----

// fakeSessions is a store of live accounts: username -> session id and secret.
type fakeSessions struct {
	mu sync.Mutex
	m  map[string]struct {
		sid    string
		secret []byte
	}
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{m: map[string]struct {
		sid    string
		secret []byte
	}{}}
}

func (f *fakeSessions) put(name, sid string, secret []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[name] = struct {
		sid    string
		secret []byte
	}{sid, secret}
}

func (f *fakeSessions) drop(name string) { f.mu.Lock(); delete(f.m, name); f.mu.Unlock() }

func (f *fakeSessions) LiveSession(name string) (string, []byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.m[name]
	return e.sid, append([]byte(nil), e.secret...), ok
}

func localSession(sid string) session {
	return session{ID: "local:alice", Name: "Alice", Method: auth.MethodLocal, Issued: 100, Seen: 100, Sid: sid, AuthAt: 100, Factor: "totp"}
}

func TestLocalSessionRoundTrip(t *testing.T) {
	t.Parallel()
	fs := newFakeSessions()
	fs.put("alice", "sid-1", []byte("secret-of-alice-0123456789abcdef"))
	c := codec{key: testKey, local: fs}
	v, err := c.seal(localSession("sid-1"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.open(v)
	if err != nil || got.ID != "local:alice" || got.Method != auth.MethodLocal || got.Sid != "sid-1" || got.AuthAt != 100 || got.Factor != "totp" {
		t.Fatalf("%+v %v", got, err)
	}
	// the cookie is the payload and a MAC; the MAC is not the one the other methods use
	p, sig, _ := strings.Cut(v, ".")
	other := codec{key: testKey}
	if base64.RawURLEncoding.EncodeToString(other.mac(p)) == sig {
		t.Fatal("a local session is signed with the key of the other methods")
	}
}

func TestLocalSessionForgeriesAreRefused(t *testing.T) {
	t.Parallel()
	fs := newFakeSessions()
	fs.put("alice", "sid-1", []byte("secret-of-alice-0123456789abcdef"))
	fs.put("bob", "sid-2", []byte("secret-of-bob-0123456789abcdefgh"))
	c := codec{key: testKey, local: fs}
	good, err := c.seal(localSession("sid-1"))
	if err != nil {
		t.Fatal(err)
	}
	p, sig, _ := strings.Cut(good, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(p)
	reencode := func(mutate func(m map[string]any)) string {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		mutate(m)
		b, _ := json.Marshal(m)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	// an altered payload under the old signature: another account, another id, a later time
	for name, alt := range map[string]string{
		"another account": reencode(func(m map[string]any) { m["id"] = "local:bob" }),
		"another sid":     reencode(func(m map[string]any) { m["sid"] = "sid-2" }),
		"later":           reencode(func(m map[string]any) { m["iat"] = 200 }),
		"another factor":  reencode(func(m map[string]any) { m["fac"] = "passkey" }),
	} {
		if _, err := c.open(alt + "." + sig); err == nil {
			t.Errorf("%s: an altered session was accepted", name)
		}
	}
	// the signature of the session key (what every other method uses) does not make a local session
	forged := reencode(func(m map[string]any) {})
	if _, err := c.open(forged + "." + base64.RawURLEncoding.EncodeToString(c.mac(forged))); err == nil {
		t.Error("a local payload signed with the session key alone was accepted")
	}
	// bob's key does not sign alice's session, and neither does a guessed one
	bobKey, _ := c.localKey([]byte("secret-of-bob-0123456789abcdefgh"), "sid-2")
	if _, err := c.open(forged + "." + base64.RawURLEncoding.EncodeToString(localMAC(bobKey, forged))); err == nil {
		t.Error("a session signed with another account's key was accepted")
	}
	// the reverse: a payload of another method that is signed with an account's key is no session
	oidc := session{ID: "x@kazuha.org", Method: auth.MethodOIDC, Issued: 100, Seen: 100, Iss: "https://i"}
	v, _ := c.seal(oidc)
	op, _, _ := strings.Cut(v, ".")
	aliceKey, _ := c.localKey([]byte("secret-of-alice-0123456789abcdef"), "sid-1")
	if _, err := c.open(op + "." + base64.RawURLEncoding.EncodeToString(localMAC(aliceKey, op))); err == nil {
		t.Error("an OIDC payload signed with an account's key was accepted")
	}
	// a session of an account that does not exist, and one without a session id
	if _, err := c.seal(session{ID: "local:ghost", Method: auth.MethodLocal, Issued: 1, Seen: 1, Sid: "x"}); err == nil {
		t.Error("sealed a session for an unknown account")
	}
	if _, err := c.seal(localSession("")); err == nil {
		t.Error("sealed a session with no session id")
	}
	if _, err := c.seal(localSession("sid-wrong")); err == nil {
		t.Error("sealed a session with a session id that is not the account's")
	}
	// the identity must be local:<username> in the form the account has
	for _, id := range []string{"alice", "local:", "LOCAL:alice", "local:Alice", "oidc:alice", "local:alice@x"} {
		s := localSession("sid-1")
		s.ID = id
		if _, err := c.seal(s); err == nil {
			t.Errorf("sealed a local session for %q", id)
		}
	}
	// no store of local accounts: no local session is valid, however it was made
	if _, err := (codec{key: testKey}).open(good); err == nil {
		t.Error("a local session was accepted without local accounts")
	}
	// the cookie is bounded and well formed
	for _, bad := range []string{"", ".", good + ".x", p, p + "." + sig[:10], strings.Repeat("a", maxCookieBytes+1)} {
		if _, err := c.open(bad); err == nil {
			t.Errorf("%.20q was accepted", bad)
		}
	}
}

func TestLocalSessionEndsWhenTheAccountsKeyMaterialChanges(t *testing.T) {
	t.Parallel()
	secret := []byte("secret-of-alice-0123456789abcdef")
	for name, change := range map[string]func(fs *fakeSessions){
		"a new secret and id (reset, rekey of the account)": func(fs *fakeSessions) { fs.put("alice", "sid-2", []byte("another-secret-0123456789abcdefg")) },
		"a new secret alone": func(fs *fakeSessions) { fs.put("alice", "sid-1", []byte("another-secret-0123456789abcdefg")) },
		"a new id alone":     func(fs *fakeSessions) { fs.put("alice", "sid-2", secret) },
		"the account cannot hold sessions (disabled, removed)": func(fs *fakeSessions) { fs.drop("alice") },
	} {
		fs := newFakeSessions()
		fs.put("alice", "sid-1", secret)
		c := codec{key: testKey, local: fs}
		v, err := c.seal(localSession("sid-1"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.open(v); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		change(fs)
		if _, err := c.open(v); err == nil {
			t.Errorf("%s: the old session is still accepted", name)
		}
	}
	// the key of a session is derived from the session key too: another session key verifies nothing
	fs := newFakeSessions()
	fs.put("alice", "sid-1", secret)
	v, _ := (codec{key: testKey, local: fs}).seal(localSession("sid-1"))
	if _, err := (codec{key: []byte("another session key 0123456789abcdef"), local: fs}).open(v); err == nil {
		t.Error("a session verified under another session key")
	}
	// and the keys of two accounts that share a secret and an id differ only by what the design puts in: nothing is shared
	c := codec{key: testKey}
	k1, _ := c.localKey(secret, "sid-1")
	k2, _ := c.localKey(secret, "sid-2")
	k3, _ := c.localKey([]byte("another-secret-0123456789abcdefg"), "sid-1")
	if hmac.Equal(k1, k2) || hmac.Equal(k1, k3) || len(k1) != 32 {
		t.Error("the MAC key does not depend on the id and the secret")
	}
}

// ---- the service ----

// a local account is evaluated from auth.roles like anybody, by its local: entries
func TestLocalSessionsAreEvaluatedByLocalEntries(t *testing.T) {
	e := newEnv(t, options{local: true, nogit: true, roles: localRoles})
	for _, n := range []string{"alice", "bob", "carol", "dave"} {
		e.addLocal(n, accounts.StateActive)
	}
	for _, c := range []struct {
		name, role string
		auditor    bool
	}{{"alice", "admin", false}, {"bob", "editor", false}, {"carol", "viewer", true}, {"dave", "viewer", false}} {
		b := e.localBrowser(c.name)
		st, m := b.meta()
		if st != 200 {
			t.Fatalf("%s: %d", c.name, st)
		}
		u := userOf(t, m)
		if u["id"] != "local:"+c.name || u["role"] != c.role || u["authMethod"] != "local" || (u["auditor"] == true) != c.auditor {
			t.Errorf("%s: %v", c.name, u)
		}
	}
	// the account page says which entries grant the role
	b := e.localBrowser("alice")
	if r := b.get("/api/account"); r.StatusCode != 200 || !strings.Contains(r.Body, `"roleFrom":["identity"]`) || !strings.Contains(r.Body, `"authMethod":"local"`) {
		t.Fatalf("%d %s", r.StatusCode, r.Body)
	}
	// the role follows the file: take local:bob away and the session stays, with no role
	e.rewriteRoles("  roles:\n    admin: [\"local:alice\"]\n")
	if st, _ := e.localBrowser("bob").meta(); st != 403 {
		t.Fatalf("a local account no entry names: %d", st)
	}
	// the session cookie of a local account is refreshed under its own key, and still opens
	e.clk.Advance(6 * time.Minute)
	b = e.localBrowser("alice")
	e.clk.Advance(6 * time.Minute)
	r := b.get("/api/meta")
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	if st, _ := b.meta(); st != 200 {
		t.Fatalf("after the refresh: %d", st)
	}
}

func TestLocalSessionStopsWithTheAccount(t *testing.T) {
	e := newEnv(t, options{local: true, roles: localRoles})
	for _, n := range []string{"alice", "bob", "carol", "dave", "erin"} {
		e.addLocal(n, accounts.StateActive)
	}
	cookies := map[string]string{}
	for _, n := range []string{"alice", "bob", "carol", "dave", "erin"} {
		cookies[n] = e.localCookie(n)
	}
	use := func(n string) int {
		b := e.browser()
		b.setCookie(SessionCookie, cookies[n])
		st, _ := b.meta()
		return st
	}
	for n := range cookies {
		if st := use(n); st != 200 {
			t.Fatalf("%s: %d", n, st)
		}
	}
	// disable, remove, end the sessions (a reset or a rekey of the account renews both), reset
	e.disableLocal("alice")
	e.removeLocal("bob")
	e.renewLocal("carol")
	e.changeLocal("dave", "account_reset_issued", func(a *accounts.Account) { a.State = accounts.StateResetPending; _ = a.RenewSessions() })
	for _, n := range []string{"alice", "bob", "carol", "dave"} {
		if st := use(n); st != 401 {
			t.Errorf("%s: an old session after the account changed: %d", n, st)
		}
	}
	if st := use("erin"); st != 200 {
		t.Errorf("an untouched account lost its session: %d", st)
	}
	// enabling a disabled account does not bring the old session back: the secret and the id were renewed
	e.enableLocal("alice")
	if st := use("alice"); st != 401 {
		t.Errorf("the old session of an account that was enabled again: %d", st)
	}
	// a new session works; carol's account is active and was only renewed
	b := e.localBrowser("carol")
	if st, _ := b.meta(); st != 200 {
		t.Errorf("a new session after the renewal: %d", st)
	}
	// the old cookie is cleared by the answer, not kept
	old := e.browser()
	old.setCookie(SessionCookie, cookies["bob"])
	if r := old.get("/api/meta"); r.StatusCode != 401 {
		t.Fatalf("%d", r.StatusCode)
	}
}

// restricted and passkey_only limit new sign-ins only; live sessions keep working (6)
func TestRestrictedAccountsKeepTheirSessions(t *testing.T) {
	e := newEnv(t, options{local: true, roles: localRoles})
	e.addLocal("alice", accounts.StateActive)
	b := e.localBrowser("alice")
	for _, st := range []string{accounts.StateRestricted, accounts.StatePasskeyOnly} {
		e.changeLocal("alice", "account_enabled", func(a *accounts.Account) { a.State = st })
		if code, _ := b.meta(); code != 200 {
			t.Errorf("%s: %d", st, code)
		}
	}
	for _, st := range []string{accounts.StateInvited, accounts.StateResetPending, accounts.StateDisabled} {
		e.changeLocal("alice", "account_enabled", func(a *accounts.Account) { a.State = st })
		if code, _ := b.meta(); code != 401 {
			t.Errorf("%s: %d", st, code)
		}
	}
}

// the identity of an OIDC login can never be taken for a local account
func TestOIDCIdentityNamedLikeALocalAccountIsRefusedAndMatchesNothing(t *testing.T) {
	e := newEnv(t, options{local: true, roles: localRoles + "    # nothing else\n"})
	e.addLocal("alice", accounts.StateActive)
	e.idp.Users["forger"] = map[string]any{"sub": "sub-x", "preferred_username": "local:alice", "name": "X", "tid": tenant}
	e.idp.Users["forger2"] = map[string]any{"sub": "sub-y", "preferred_username": "LOCAL:Alice", "name": "X", "tid": tenant}
	for _, u := range []string{"forger", "forger2"} {
		b := e.browser()
		if r := b.login(u, ""); r.StatusCode == 303 && r.Loc() == "/" {
			t.Fatalf("%s: an identity that starts with local: was let in: %d %q", u, r.StatusCode, r.Loc())
		}
		if st, _ := b.meta(); st != 401 {
			t.Fatalf("%s: signed in as %d", u, st)
		}
	}
}

// the sign-in is not here: no route issues a session of a local account
func TestNoRouteIssuesALocalSession(t *testing.T) {
	e := newEnv(t, options{local: true, roles: localRoles, passkeys: true})
	e.addLocal("alice", accounts.StateActive)
	e.addLocal("bob", accounts.StateActive)
	pats := api.RoutePatterns(e.apiOpts)
	if len(pats) < 20 {
		t.Fatalf("only %d routes", len(pats))
	}
	// what a sign-in of a local account could look like, sent to every route with every method, as nobody, as
	// an SSO administrator and as a local administrator
	bodies := []struct{ ct, body string }{
		{"application/json", `{}`},
		{"application/json", `{"username":"alice","password":"x","code":"123456","totp":"123456","passkey":{},"name":"alice","identity":"local:alice","method":"local","id":"local:alice"}`},
		{"application/x-www-form-urlencoded", `username=alice&password=x&code=123456&user=local:alice&method=local`},
	}
	braces := regexp.MustCompile(`\{[^}]*\}`)
	setUp := map[string]func(b *browser){
		"nobody": func(b *browser) {},
		"sso":    func(b *browser) { b.login("admin", "") },
		"local":  func(b *browser) { b.setCookie(SessionCookie, e.localCookie("alice")) },
	}
	requests := 0
	for who, up := range setUp {
		b := e.browser()
		up(b)
		for _, pat := range pats {
			method, path, ok := strings.Cut(pat, " ")
			if !ok {
				method, path = "GET", pat
			}
			path = braces.ReplaceAllString(path, "x")
			if path == "/auth/logout" || strings.HasPrefix(path, "/mcp") {
				continue // logout only ends the session of the walk; /mcp is not this service's
			}
			for i, bd := range bodies {
				if path == "/auth/oidc/start" && (who != "nobody" || i > 0) {
					continue // rate limited, and the sign-ins of the walk need the allowance
				}
				if b.cookie(SessionCookie) == nil && who != "nobody" {
					up(b) // a route ended the session of the walk: start it again
				}
				r := b.do(method, path, map[string]string{"Content-Type": bd.ct, "Sec-Fetch-Site": "same-origin"}, strings.NewReader(bd.body))
				requests++
				for _, c := range r.Cookies() {
					if c.Name != SessionCookie || c.MaxAge < 0 || c.Value == "" {
						continue
					}
					if s, err := e.svc.codec.open(c.Value); err == nil && s.Method == auth.MethodLocal {
						t.Errorf("%s %s (as %s) set a local session for %s", method, path, who, s.ID)
					}
				}
			}
		}
	}
	if requests < 3*len(pats) {
		t.Fatalf("walked %d requests over %d routes", requests, len(pats))
	}
	// and the service itself refuses to make one
	if _, _, err := e.svc.issue(httptest.NewRecorder(), &auth.Identity{ID: "local:alice", Method: auth.MethodLocal}, auth.MethodLocal, ""); err == nil {
		t.Fatal("issue made a local session")
	}
}

// A token created by a local account is that account's: the creator's method is recorded as local, so its
// local: entries decide, and the token stops when the account does.
func TestTokenOfALocalAccountFollowsTheAccount(t *testing.T) {
	e := newEnv(t, options{local: true, roles: localRoles})
	e.addLocal("alice", accounts.StateActive)
	mk := func(name, tok string) string {
		b := e.localBrowser(name)
		r := b.postJSON("/api/admin/tokens", `{"name":"`+tok+`","scope":"read"}`)
		if r.StatusCode != 201 {
			t.Fatalf("%s: %d %s", name, r.StatusCode, r.Body)
		}
		var out struct {
			Secret string `json:"secret"`
			Token  struct {
				CreatorRole    string `json:"creatorRole"`
				CreatorAuditor bool   `json:"creatorAuditor"`
			} `json:"token"`
		}
		if err := json.Unmarshal([]byte(r.Body), &out); err != nil || out.Secret == "" {
			t.Fatalf("%v %s", err, r.Body)
		}
		if out.Token.CreatorRole != "admin" {
			t.Fatalf("the creator is evaluated as %q, not as the local admin", out.Token.CreatorRole)
		}
		return out.Secret
	}
	secret := mk("alice", "t-alice")
	use := func(secret string) (int, map[string]any) {
		r := e.browser().do("GET", "/api/meta", map[string]string{"Authorization": "Bearer " + secret}, nil)
		var m map[string]any
		_ = json.Unmarshal([]byte(r.Body), &m)
		return r.StatusCode, m
	}
	st, m := use(secret)
	if st != 200 || userOf(t, m)["role"] != "viewer" || userOf(t, m)["authMethod"] != "token" {
		t.Fatalf("%d %v", st, m)
	}
	// the tokens file says how the creator logged in
	b, _ := os.ReadFile(filepath.Join(e.dir, tokens.File))
	if !strings.Contains(string(b), "created_via: local") || !strings.Contains(string(b), "created_by: local:alice") {
		t.Fatalf("tokens.yml:\n%s", b)
	}
	// the account is disabled: the token stops, with no change to the token
	e.disableLocal("alice")
	if st, _ := use(secret); st != 403 && st != 401 {
		t.Fatalf("a token of a disabled account: %d", st)
	}
	e.enableLocal("alice")
	e.removeLocal("alice")
	if st, _ := use(secret); st != 403 && st != 401 {
		t.Fatalf("a token of a removed account: %d", st)
	}
}

// ---- local accounts without single sign-on ----

func TestServiceWithLocalAccountsAndNoSSO(t *testing.T) {
	t.Parallel()
	o := Options{Login: config.Login{}, BaseURL: "https://ledger.example.com", Key: testKey}
	if _, err := New(o); err == nil || !strings.Contains(err.Error(), "neither") {
		t.Fatalf("a login with no SSO and no local accounts: %v", err)
	}
	o.Local = newFakeSessions()
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.Mount(mux, http.NotFoundHandler())
	for _, p := range []string{"/auth/oidc/start", "/auth/oidc/callback?code=x&state=y"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		if w.Code != 404 || !strings.Contains(w.Body.String(), "sso_off") {
			t.Errorf("%s: %d %s", p, w.Code, w.Body)
		}
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/auth/config", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"oidc":false`) {
		t.Errorf("/auth/config: %d %s", w.Code, w.Body)
	}
	s.Warm() // nothing to discover, and no panic
	// a half-written auth.oidc is still an error, with or without local accounts
	o.Login.OIDC.ClientID = "x"
	if _, err := New(o); err == nil {
		t.Error("auth.oidc with a client id and no issuer was accepted")
	}
}

// ---- the role editor ----

func TestRoleEditorWithLocalAdmins(t *testing.T) {
	e := newEnv(t, options{local: true, roles: localRoles})
	for n, st := range map[string]string{"alice": accounts.StateActive, "bob": accounts.StateActive, "erin": accounts.StateDisabled} {
		e.addLocal(n, st)
	}
	b := e.localBrowser("alice")
	r := b.get("/api/admin/roles")
	if r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, r.Body)
	}
	var view struct {
		Version string `json:"version"`
		Local   struct {
			Available bool               `json:"available"`
			Accounts  []api.LocalAccount `json:"accounts"`
		} `json:"local"`
		You struct {
			Role string `json:"role"`
		} `json:"you"`
		Roles struct {
			Admin []struct {
				Value string `json:"value"`
				Kind  string `json:"kind"`
				Notes []struct{ Code string }
			} `json:"admin"`
		} `json:"roles"`
	}
	if err := json.Unmarshal([]byte(r.Body), &view); err != nil {
		t.Fatal(err)
	}
	if !view.Local.Available || len(view.Local.Accounts) != 3 || view.Local.Accounts[0].Username != "alice" || view.Local.Accounts[2].State != accounts.StateDisabled {
		t.Fatalf("accounts offered by name: %+v", view.Local)
	}
	if view.You.Role != "admin" || len(view.Roles.Admin) != 2 || view.Roles.Admin[1].Value != "local:alice" || view.Roles.Admin[1].Kind != "local" || len(view.Roles.Admin[1].Notes) != 0 {
		t.Fatalf("%+v", view)
	}
	if strings.Contains(r.Body, "password") || strings.Contains(r.Body, "secret") || strings.Contains(r.Body, "sid") {
		t.Fatalf("the editor shows nothing of an account's credentials: %s", r.Body)
	}
	body := func(admin, editor, viewer, auditors string) string {
		return `{"version":"` + view.Version + `","roles":{"admin":[` + admin + `],"editor":[` + editor + `],"viewer":[` + viewer + `]},"auditors":[` + auditors + `]}`
	}
	refused := func(path, payload, code string) {
		t.Helper()
		r := b.postJSON(path, payload)
		if path == "/api/admin/roles/preview" {
			if r.StatusCode != 200 || !strings.Contains(r.Body, `"code":"`+code+`"`) {
				t.Fatalf("%s preview: %d %s", code, r.StatusCode, r.Body)
			}
			return
		}
		if r.StatusCode != 422 || !strings.Contains(r.Body, `"error":"`+code+`"`) {
			t.Fatalf("%s: %d %s", code, r.StatusCode, r.Body)
		}
	}
	// the person who saves may not stop being an administrator: alice removes herself and adds bob
	refused("/api/admin/roles/preview", body(`"kazuha@kazuha.org","local:bob"`, `"*@kazuha.org"`, `"guest@example.com","local:*"`, `"local:carol"`), "self_lockout")
	refused("/api/admin/roles", body(`"kazuha@kazuha.org","local:bob"`, `"*@kazuha.org"`, `"guest@example.com","local:*"`, `"local:carol"`), "self_lockout")
	// the last admin who can sign in: a disabled account is not one (the caller is alice, but the rule is named first)
	refused("/api/admin/roles", body(`"local:erin"`, `"*@kazuha.org"`, `"guest@example.com"`, ``), "last_admin")
	refused("/api/admin/roles", body(``, `"*@kazuha.org"`, `"guest@example.com"`, ``), "last_admin")
	// a local entry is added, and another removed
	ok := b.postJSON("/api/admin/roles", body(`"kazuha@kazuha.org","local:alice"`, `"*@kazuha.org","local:bob","local:erin"`, `"guest@example.com"`, `"local:carol"`))
	if ok.StatusCode != 200 || !strings.Contains(ok.Body, `"changed":true`) {
		t.Fatalf("%d %s", ok.StatusCode, ok.Body)
	}
	if got, _ := os.ReadFile(filepath.Join(e.dir, "rackbook.yml")); !strings.Contains(string(got), "local:erin") || strings.Contains(string(got), `"local:*"`) {
		t.Fatalf("rackbook.yml:\n%s", got)
	}
	// the new entry is a warning, not an error: erin's account is disabled
	if !strings.Contains(ok.Body, `"version"`) {
		t.Fatalf("%s", ok.Body)
	}
	// bob now edits (editor by his entry), and an editor may not use the role editor
	if st, m := e.localBrowser("bob").meta(); st != 200 || userOf(t, m)["role"] != "editor" {
		t.Fatalf("%d %v", st, m)
	}
	if r := e.localBrowser("bob").get("/api/admin/roles"); r.StatusCode != 403 {
		t.Fatalf("%d", r.StatusCode)
	}
}
