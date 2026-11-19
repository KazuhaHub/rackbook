package oauthserver_test

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func (e *env) registerFrom(ip, name string, redirects ...string) resp {
	hdr := []string{"Content-Type", "application/json", "Sec-Fetch-Site", "same-origin"}
	if ip != "" {
		hdr = append(hdr, "CF-Connecting-IP", ip)
	}
	uris := `"` + strings.Join(redirects, `","`) + `"`
	return e.do("", http.MethodPost, "/oauth/register", strings.NewReader(`{"client_name":"`+name+`","redirect_uris":[`+uris+`]}`), hdr...)
}

func TestDCRRateIsPerAddress(t *testing.T) {
	e := newEnv(t, opts{trusted: true})
	for i := 0; i < 30; i++ {
		if r := e.registerFrom("203.0.113.1", fmt.Sprint("c", i), "https://a.example/cb"); r.StatusCode != 201 {
			t.Fatalf("registration %d: %d %s", i, r.StatusCode, r.body)
		}
	}
	if r := e.registerFrom("203.0.113.1", "extra", "https://a.example/cb"); r.StatusCode != 429 || r.Header.Get("Retry-After") == "" {
		t.Fatalf("31st registration from one address: %d", r.StatusCode)
	}
	// Registering something that exists costs nothing and is never limited.
	if r := e.registerFrom("203.0.113.1", "c3", "https://a.example/cb"); r.StatusCode != 200 {
		t.Fatalf("repeat registration while limited: %d %s", r.StatusCode, r.body)
	}
	// Another address has its own allowance.
	if r := e.registerFrom("203.0.113.2", "other", "https://a.example/cb"); r.StatusCode != 201 {
		t.Fatalf("another address: %d %s", r.StatusCode, r.body)
	}
	// The window passes.
	e.clock.advance(11 * time.Minute)
	if r := e.registerFrom("203.0.113.1", "extra", "https://a.example/cb"); r.StatusCode != 201 {
		t.Fatalf("after the window: %d", r.StatusCode)
	}
}

func TestDCRCapEvictsOldestUnused(t *testing.T) {
	e := newEnv(t, opts{trusted: true})
	var first string
	for i := 0; i < 100; i++ {
		if i%25 == 0 {
			e.clock.advance(11 * time.Minute)
		}
		r := e.registerFrom(fmt.Sprintf("198.51.100.%d", i%200+1), fmt.Sprint("c", i), "https://a.example/cb")
		if r.StatusCode != 201 {
			t.Fatalf("registration %d: %d %s", i, r.StatusCode, r.body)
		}
		if i == 0 {
			first = r.str("client_id")
		}
		e.clock.advance(time.Second)
	}
	// The cap is full: the oldest registration nobody used makes room.
	r := e.registerFrom("192.0.2.1", "newcomer", "https://a.example/cb")
	if r.StatusCode != 201 {
		t.Fatalf("registration at the cap: %d %s", r.StatusCode, r.body)
	}
	_, ch := pkce()
	if got := e.startAuth(boss, e.params(first, "https://a.example/cb", ch)); got.StatusCode != 400 {
		t.Fatalf("the evicted client still exists: %d", got.StatusCode)
	}
	if got := e.startAuth(boss, e.params(r.str("client_id"), "https://a.example/cb", ch)); got.StatusCode != 302 {
		t.Fatalf("the newcomer: %d", got.StatusCode)
	}
}

func TestDCRCapRefusesWhenAllInUse(t *testing.T) {
	e := newEnv(t, opts{trusted: true})
	for i := 0; i < 100; i++ {
		e.clock.advance(time.Minute)
		cid := e.registerFrom(fmt.Sprintf("198.51.100.%d", i+1), fmt.Sprint("c", i), testRedirect).str("client_id")
		v, ch := pkce()
		code := e.approve(boss, e.params(cid, testRedirect, ch))
		if r := e.exchange(cid, code, v); r.StatusCode != 200 {
			t.Fatalf("login %d: %s", i, r.body)
		}
	}
	if r := e.registerFrom("192.0.2.1", "newcomer", "https://a.example/cb"); r.StatusCode != 503 {
		t.Fatalf("registration with every client in use: %d %s", r.StatusCode, r.body)
	}
}

func TestDCRRefusesLookalikeRedirects(t *testing.T) {
	e := newEnv(t, opts{})
	for _, u := range []string{"https://аpp.example/cb", "https://app.example/cb‮", "https://app​.example/cb", "cursor://аnysphere.cursor/cb"} {
		if r := e.postJSON("", "/oauth/register", map[string]any{"redirect_uris": []string{u}}); r.StatusCode != 400 || r.str("error") != "invalid_redirect_uri" {
			t.Errorf("%q: %d %s", u, r.StatusCode, r.body)
		}
	}
	// Punycode is allowed, and the consent page is told to warn.
	cid := e.register("Punycode Client", "https://xn--e1afmkfd.example/cb")
	_, ch := pkce()
	r := e.startAuth(boss, e.params(cid, "https://xn--e1afmkfd.example/cb", ch))
	info := e.get(boss, "/api/oauth/consent?req="+strings.TrimPrefix(r.Header.Get("Location"), "/oauth/consent?req=")).json()
	if info["punycode"] != true {
		t.Fatalf("consent info for a punycode host: %v", info)
	}
	plain := e.register("Plain", "https://app.example/cb")
	r = e.startAuth(boss, e.params(plain, "https://app.example/cb", ch))
	if info := e.get(boss, "/api/oauth/consent?req="+strings.TrimPrefix(r.Header.Get("Location"), "/oauth/consent?req=")).json(); info["punycode"] != false {
		t.Fatalf("consent info for a plain host: %v", info)
	}
}

func TestCIMDLookalikeClientIDsAndFetchErrors(t *testing.T) {
	doc := newCIMD(t, goodDoc(testRedirect))
	e := newEnv(t, opts{cimdClient: doc.Client()})
	_, ch := pkce()
	for _, id := range []string{"https://аpp.example/c.json", "https://app.example/c‮.json"} {
		if r := e.startAuth(boss, e.params(id, testRedirect, ch)); r.StatusCode != 400 {
			t.Errorf("%q: %d", id, r.StatusCode)
		}
	}
	// A document with a look-alike redirect is refused.
	bad := newCIMD(t, goodDoc("https://аpp.example/cb"))
	e2 := newEnv(t, opts{cimdClient: bad.Client()})
	if r := e2.startAuth(boss, e2.params(bad.URL+"/client.json", "https://аpp.example/cb", ch)); r.StatusCode != 400 {
		t.Fatalf("look-alike redirect in a document: %d", r.StatusCode)
	}
	// A fetch that fails shows a generic message, not the dial error with addresses.
	e3 := newEnv(t, opts{cimdSafe: true})
	r := e3.startAuth(boss, e3.params(doc.URL+"/client.json", testRedirect, ch))
	body := string(r.body)
	if r.StatusCode != 400 || !strings.Contains(body, "could not fetch the client&#39;s metadata document") {
		t.Fatalf("fetch failure: %d %s", r.StatusCode, body)
	}
	for _, leak := range []string{"127.0.0.1", "dial", "not allowed", "connect"} {
		if strings.Contains(body, leak) {
			t.Errorf("the error page leaks %q: %s", leak, body)
		}
	}
}

func TestAllowedClientsTurnsRegistrationOff(t *testing.T) {
	c := newCIMD(t, goodDoc(testRedirect))
	allowed := c.URL + "/client.json"
	e := newEnv(t, opts{cimdClient: c.Client(), builtinYAML: "      allowed_clients: [\"" + allowed + "\"]\n"})
	if r := e.postJSON("", "/oauth/register", map[string]any{"redirect_uris": []string{testRedirect}}); r.StatusCode != 404 {
		t.Fatalf("register with allowed_clients set: %d %s", r.StatusCode, r.body)
	}
	if _, ok := e.get("", "/.well-known/oauth-authorization-server").json()["registration_endpoint"]; ok {
		t.Fatal("registration_endpoint advertised although allowed_clients is set")
	}
	// A registered client may not authorize either.
	_, ch := pkce()
	if r := e.startAuth(boss, e.params("rbc_old", testRedirect, ch)); r.StatusCode != 400 {
		t.Fatalf("registered client with allowed_clients set: %d", r.StatusCode)
	}
	if r := e.startAuth(boss, e.params(allowed, testRedirect, ch)); r.StatusCode != 302 {
		t.Fatalf("listed client: %d", r.StatusCode)
	}
}

// The consent page shows what the grant can do: the role, limited by the scopes.
func TestConsentShowsRoleLimitedPermission(t *testing.T) {
	e := newEnv(t, opts{})
	cid := e.register("c")
	_, ch := pkce()
	for user, want := range map[string]bool{boss: true, "ed@example.com": true, "vic@example.com": false} {
		r := e.startAuth(user, e.params(cid, testRedirect, ch))
		info := e.get(user, "/api/oauth/consent?req="+strings.TrimPrefix(r.Header.Get("Location"), "/oauth/consent?req=")).json()
		if info["canWrite"] != want {
			t.Errorf("%s: canWrite %v, want %v", user, info["canWrite"], want)
		}
	}
	// The grants list agrees.
	v, ch2 := pkce()
	code := e.approve("vic@example.com", e.params(cid, testRedirect, ch2))
	e.exchange(cid, code, v)
	g := e.get("vic@example.com", "/api/account/grants").json()["grants"].([]any)
	if len(g) != 1 || g[0].(map[string]any)["canWrite"] != false {
		t.Fatalf("viewer's grant: %v", g)
	}
}

// A burst of concurrent registrations cannot exceed the per-address allowance.
func TestDCRBurstStaysWithinTheLimit(t *testing.T) {
	e := newEnv(t, opts{trusted: true})
	var wg sync.WaitGroup
	codes := make([]int, 60)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = e.registerFrom("203.0.113.9", fmt.Sprint("burst", i), "https://a.example/cb").StatusCode
		}()
	}
	wg.Wait()
	created := 0
	for _, c := range codes {
		if c == 201 {
			created++
		}
	}
	if created != 30 {
		t.Fatalf("%d registrations created from one address in a burst, want 30", created)
	}
}
