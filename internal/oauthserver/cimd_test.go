package oauthserver_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// cimdServer serves client metadata documents over TLS on a loopback address.
type cimdServer struct {
	*httptest.Server
	hits atomic.Int32
	// doc returns the document for the request; nil = 404.
	doc func(self string) any
	raw string // when set, served as is
}

func newCIMD(t *testing.T, doc func(self string) any) *cimdServer {
	c := &cimdServer{doc: doc}
	c.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if c.raw != "" {
			w.Write([]byte(c.raw))
			return
		}
		d := c.doc("https://" + r.Host + r.URL.Path)
		if d == nil {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(d)
	}))
	t.Cleanup(c.Close)
	return c
}

func goodDoc(redirects ...string) func(string) any {
	return func(self string) any {
		return map[string]any{"client_id": self, "client_name": "Doc Client", "redirect_uris": redirects, "token_endpoint_auth_method": "none"}
	}
}

func TestCIMD(t *testing.T) {
	doc := newCIMD(t, goodDoc(testRedirect))
	e := newEnv(t, opts{cimdClient: doc.Client()})
	id := doc.URL + "/client.json"
	_, ch := pkce()

	// A document whose client_id is the URL it was fetched from works, and the
	// consent page shows the name from the document.
	r := e.startAuth(boss, e.params(id, testRedirect, ch))
	loc := r.Header.Get("Location")
	if r.StatusCode != 302 || !strings.HasPrefix(loc, "/oauth/consent?req=") {
		t.Fatalf("authorize with a CIMD client: %d %q %s", r.StatusCode, loc, r.body)
	}
	info := e.get(boss, "/api/oauth/consent?req="+strings.TrimPrefix(loc, "/oauth/consent?req=")).json()
	if info["clientName"] != "Doc Client" || info["redirectHost"] != "localhost:7777" || info["clientId"] != id {
		t.Fatalf("consent info: %v", info)
	}
	// ...and the whole flow, including the token endpoint, accepts the URL as client_id.
	v, ch2 := pkce()
	code := e.approve(boss, e.params(id, testRedirect, ch2))
	if tr := e.exchange(id, code, v); tr.StatusCode != 200 {
		t.Fatalf("exchange: %s", tr.body)
	}
	// The document is cached for a while.
	before := doc.hits.Load()
	e.startAuth(boss, e.params(id, testRedirect, ch))
	if doc.hits.Load() != before {
		t.Error("the document was fetched again within the cache time")
	}
	e.clock.advance(2 * time.Hour)
	e.startAuth(boss, e.params(id, testRedirect, ch))
	if doc.hits.Load() == before {
		t.Error("the document was not fetched again after the cache time")
	}
	// A redirect URI that the document does not list is refused, even if it is a fine URL.
	p := e.params(id, "http://localhost:7777/elsewhere", ch)
	if r := e.startAuth(boss, p); r.StatusCode != 400 {
		t.Fatalf("redirect not listed: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
}

func TestCIMDRefusals(t *testing.T) {
	_, ch := pkce()
	tests := map[string]func(c *cimdServer){
		"client_id mismatch": func(c *cimdServer) {
			c.doc = func(string) any {
				return map[string]any{"client_id": "https://other.example/client.json", "redirect_uris": []string{testRedirect}}
			}
		},
		"no client_id": func(c *cimdServer) {
			c.doc = func(string) any { return map[string]any{"redirect_uris": []string{testRedirect}} }
		},
		"oversize": func(c *cimdServer) {
			c.doc = func(self string) any {
				return map[string]any{"client_id": self, "client_name": strings.Repeat("x", 12<<10), "redirect_uris": []string{testRedirect}}
			}
		},
		"not JSON":  func(c *cimdServer) { c.raw = "<html>nope</html>" },
		"not found": func(c *cimdServer) { c.doc = func(string) any { return nil } },
		"client secret": func(c *cimdServer) {
			c.doc = func(self string) any {
				return map[string]any{"client_id": self, "client_secret": "s", "redirect_uris": []string{testRedirect}}
			}
		},
		"confidential client": func(c *cimdServer) {
			c.doc = func(self string) any {
				return map[string]any{"client_id": self, "token_endpoint_auth_method": "client_secret_basic", "redirect_uris": []string{testRedirect}}
			}
		},
		"no redirect_uris": func(c *cimdServer) {
			c.doc = func(self string) any { return map[string]any{"client_id": self} }
		},
		"bad redirect (javascript)": func(c *cimdServer) {
			c.doc = func(self string) any {
				return map[string]any{"client_id": self, "redirect_uris": []string{"javascript:alert(1)"}}
			}
		},
		"bad redirect (http, not localhost)": func(c *cimdServer) {
			c.doc = func(self string) any {
				return map[string]any{"client_id": self, "redirect_uris": []string{"http://evil.example/cb"}}
			}
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			c := newCIMD(t, goodDoc(testRedirect))
			setup(c)
			e := newEnv(t, opts{cimdClient: c.Client()})
			r := e.startAuth(boss, e.params(c.URL+"/client.json", testRedirect, ch))
			if r.StatusCode != 400 || r.Header.Get("Location") != "" {
				t.Fatalf("%d %q %s", r.StatusCode, r.Header.Get("Location"), r.body)
			}
		})
	}
}

func TestCIMDRefusesPrivateAddresses(t *testing.T) {
	// The default client refuses to connect to loopback, private and link-local
	// addresses, whatever name or address the client_id uses.
	c := newCIMD(t, goodDoc(testRedirect))
	e := newEnv(t, opts{cimdSafe: true})
	_, ch := pkce()
	port := c.Listener.Addr().String()[strings.LastIndex(c.Listener.Addr().String(), ":")+1:]
	for _, host := range []string{"127.0.0.1", "localhost", "[::1]", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "[fe80::1]", "[fd00::1]", "[::ffff:127.0.0.1]"} {
		id := "https://" + host + ":" + port + "/client.json"
		r := e.startAuth(boss, e.params(id, testRedirect, ch))
		if r.StatusCode != 400 {
			t.Errorf("%s: status %d", host, r.StatusCode)
		}
	}
	if c.hits.Load() != 0 {
		t.Fatalf("the loopback server was reached %d times", c.hits.Load())
	}
}

func TestCIMDAllowList(t *testing.T) {
	c := newCIMD(t, goodDoc(testRedirect))
	allowed := c.URL + "/client.json"
	e := newEnv(t, opts{cimdClient: c.Client(), builtinYAML: "      allowed_clients: [\"" + allowed + "\"]\n"})
	_, ch := pkce()
	if r := e.startAuth(boss, e.params(allowed, testRedirect, ch)); r.StatusCode != 302 {
		t.Fatalf("listed client: %d %s", r.StatusCode, r.body)
	}
	hits := c.hits.Load()
	if r := e.startAuth(boss, e.params(c.URL+"/other.json", testRedirect, ch)); r.StatusCode != 400 || !strings.Contains(string(r.body), "allowed_clients") {
		t.Fatalf("unlisted client: %d %s", r.StatusCode, r.body)
	}
	if c.hits.Load() != hits {
		t.Error("an unlisted client_id was fetched")
	}
}

func TestCIMDClientIDShape(t *testing.T) {
	e := newEnv(t, opts{cimdSafe: true})
	_, ch := pkce()
	for _, id := range []string{"https://example.com", "https://example.com/", "https://example.com/a/../b", "https://user@example.com/c", "https://example.com/c#frag", "http://example.com/c", "https://" + strings.Repeat("a", 600) + ".example/c"} {
		if r := e.startAuth(boss, e.params(id, testRedirect, ch)); r.StatusCode != 400 {
			t.Errorf("%q: status %d", id, r.StatusCode)
		}
	}
}

func TestDCR(t *testing.T) {
	e := newEnv(t, opts{})
	post := func(v any) resp { return e.postJSON("", "/oauth/register", v) }

	r := post(map[string]any{"client_name": "My Tool", "redirect_uris": []string{testRedirect, "https://app.example/cb", "cursor://anysphere.cursor/oauth/callback"}, "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}})
	if r.StatusCode != 201 || !strings.HasPrefix(r.str("client_id"), "rbc_") || r.str("token_endpoint_auth_method") != "none" || r.json()["client_secret"] != nil {
		t.Fatalf("register: %d %s", r.StatusCode, r.body)
	}
	// Same registration again: the same client, so a client that registers at every start costs nothing.
	again := post(map[string]any{"client_name": "My Tool", "redirect_uris": []string{testRedirect, "https://app.example/cb", "cursor://anysphere.cursor/oauth/callback"}})
	if again.StatusCode != 200 || again.str("client_id") != r.str("client_id") {
		t.Fatalf("repeat registration: %d %s", again.StatusCode, again.body)
	}

	bad := map[string]any{
		"no redirect":          map[string]any{"client_name": "x"},
		"http not localhost":   map[string]any{"redirect_uris": []string{"http://evil.example/cb"}},
		"javascript":           map[string]any{"redirect_uris": []string{"javascript:alert(1)"}},
		"data":                 map[string]any{"redirect_uris": []string{"data:text/html,x"}},
		"fragment":             map[string]any{"redirect_uris": []string{"https://a.example/cb#x"}},
		"credentials":          map[string]any{"redirect_uris": []string{"https://u:p@a.example/cb"}},
		"relative":             map[string]any{"redirect_uris": []string{"/cb"}},
		"backslash":            map[string]any{"redirect_uris": []string{"https://a.example\\@b.example/"}},
		"too many":             map[string]any{"redirect_uris": []string{"https://a/1", "https://a/2", "https://a/3", "https://a/4", "https://a/5", "https://a/6", "https://a/7", "https://a/8", "https://a/9", "https://a/10", "https://a/11"}},
		"client secret method": map[string]any{"redirect_uris": []string{testRedirect}, "token_endpoint_auth_method": "client_secret_basic"},
		"password grant":       map[string]any{"redirect_uris": []string{testRedirect}, "grant_types": []string{"password"}},
		"implicit":             map[string]any{"redirect_uris": []string{testRedirect}, "response_types": []string{"token"}},
	}
	for name, body := range bad {
		if r := post(body); r.StatusCode != 400 || !strings.HasPrefix(r.str("error"), "invalid_") {
			t.Errorf("%s: %d %s", name, r.StatusCode, r.body)
		}
	}
	// Big bodies are cut off.
	if r := e.do("", http.MethodPost, "/oauth/register", strings.NewReader(`{"client_name":"`+strings.Repeat("x", 40<<10)+`"}`), "Content-Type", "application/json"); r.StatusCode != 400 {
		t.Errorf("oversize body: %d", r.StatusCode)
	}
	// The name is cleaned.
	n := post(map[string]any{"client_name": "<b>Evil\n</b>" + strings.Repeat("y", 300), "redirect_uris": []string{"https://n.example/cb"}})
	if name := n.str("client_name"); strings.ContainsAny(name, "<>\n") || len([]rune(name)) > 100 {
		t.Errorf("client_name %q", name)
	}
}

func TestDCRPruneKeepsClientsWithGrants(t *testing.T) {
	e := newEnv(t, opts{})
	cid, tok := e.login(boss, "keeper")
	e.clock.advance(40 * 24 * time.Hour) // far beyond both prune times
	e.register("trigger", "https://t.example/cb")
	if r := e.refresh(cid, tok.refresh); r.StatusCode != 200 {
		t.Fatalf("a client with a grant must stay registered: %s", r.body)
	}
	v, ch := pkce()
	if got := e.exchange(cid, e.approve(boss, e.params(cid, testRedirect, ch)), v); got.StatusCode != 200 {
		t.Fatalf("client pruned although it has a grant: %s", got.body)
	}
}
