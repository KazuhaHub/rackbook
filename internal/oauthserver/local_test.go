package oauthserver_test

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/roles"
)

// fakeLocal says which local accounts can hold a grant now.
type fakeLocal struct {
	mu     sync.Mutex
	active map[string]bool
}

func (f *fakeLocal) LocalActive(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active[name]
}

func (f *fakeLocal) set(name string, on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active[name] = on
}

// A grant approved by a local account is that account's: its access token and its refresh follow the account
// and the local: entries, and stop when the account does (design-local-accounts.md, 7).
func TestGrantOfALocalAccountFollowsTheAccount(t *testing.T) {
	t.Parallel()
	fl := &fakeLocal{active: map[string]bool{"alice": true, "dave": true}}
	e := newEnv(t, opts{local: fl})
	e.setRoles(&roles.Spec{Admin: []string{"local:alice"}, Viewer: []string{"local:*"}})
	e.setAuditors([]string{"local:dave"})
	e.method = "local"

	clientAlice, tok := e.login("local:alice", "Alice's client")
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok.access)
	req.URL.Path = "/mcp"
	id, err := e.res.AuthenticateBearer(req)
	if err != nil || id == nil || id.Role != roles.Admin || id.Auditor {
		t.Fatalf("the grant of a local admin: %+v %v", id, err)
	}
	// the auditor capability by a local: entry, on the grant too
	_, dave := e.login("local:dave", "Dave's client")
	req.Header.Set("Authorization", "Bearer "+dave.access)
	if id, err = e.res.AuthenticateBearer(req); err != nil || id == nil || id.Role != roles.Viewer || !id.Auditor {
		t.Fatalf("the grant of a local auditor: %+v %v", id, err)
	}

	// the account is disabled or removed: the grant stops, and a refresh is refused
	fl.set("alice", false)
	if r := e.mcpStatus(tok.access); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an access token of a disabled account: %d %s", r.StatusCode, r.body)
	}
	if r := e.refresh(clientAlice, tok.refresh); r.StatusCode == http.StatusOK {
		t.Fatalf("a refresh for a disabled account: %d", r.StatusCode)
	}
	// and it cannot start a new one
	_, ch := pkce()
	if r := e.startAuth("local:alice", e.params(e.register("late"), testRedirect, ch)); consentRedirect(r) {
		t.Fatalf("a disabled account started an authorization: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
}

// An identity of another method that is named like a local account gets no grant: it matches no local: entry, and
// the entries for everybody (*) are not for the identity local:alice either.
func TestLookAlikeOfALocalAccountHasNoGrant(t *testing.T) {
	t.Parallel()
	fl := &fakeLocal{active: map[string]bool{"alice": true}}
	e := newEnv(t, opts{local: fl})
	e.setRoles(&roles.Spec{Admin: []string{"local:alice"}, Viewer: []string{"*"}})
	// method oidc (the default): local:alice here is just a claim some provider sent
	_, ch := pkce()
	r := e.startAuth("local:alice", e.params(e.register("look-alike"), testRedirect, ch))
	if consentRedirect(r) {
		t.Fatalf("an OIDC identity named local:alice started an authorization: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
}

// consentRedirect says the authorization request was taken to the consent page.
func consentRedirect(r resp) bool {
	return r.StatusCode == http.StatusFound && strings.HasPrefix(r.Header.Get("Location"), "/oauth/consent")
}

// Approving a client hands out a credential: a local account that did not fully authenticate recently is asked to again
// (403 reauth_required), before the request is used up, so the same consent page works after the re-authentication.
func TestApprovingAClientNeedsARecentAuthenticationOfALocalAccount(t *testing.T) {
	t.Parallel()
	fl := &fakeLocal{active: map[string]bool{"alice": true}}
	e := newEnv(t, opts{local: fl})
	e.setRoles(&roles.Spec{Admin: []string{"local:alice"}})
	e.method = "local"
	clientID := e.register("stale")
	_, ch := pkce()
	r := e.startAuth("local:alice", e.params(clientID, testRedirect, ch))
	req := strings.TrimPrefix(r.Header.Get("Location"), "/oauth/consent?req=")
	old := e.clock.now().Add(-time.Hour).UTC().Format(time.RFC3339)
	d := e.postJSON("local:alice", "/api/oauth/consent", map[string]any{"req": req, "approve": true}, "X-Test-Signin", old)
	if d.StatusCode != http.StatusForbidden || d.str("error") != "reauth_required" || !strings.HasPrefix(d.str("reauth"), "/auth/local/reauth?return=") {
		t.Fatalf("%d %s", d.StatusCode, d.body)
	}
	// denying needs nothing, and the request was not used up: approving after a re-authentication works
	d = e.postJSON("local:alice", "/api/oauth/consent", map[string]any{"req": req, "approve": true})
	if d.StatusCode != http.StatusOK {
		t.Fatalf("after re-authenticating: %d %s", d.StatusCode, d.body)
	}
}

// Revoking a person's grants (design-local-accounts.md, 5.11): the access token and the refresh of every grant of the identity
// are refused, and another person's grant is left alone.
func TestGrantsOfAnIdentityAreRevokedWithTheAccount(t *testing.T) {
	t.Parallel()
	fl := &fakeLocal{active: map[string]bool{"alice": true, "bob": true}}
	e := newEnv(t, opts{local: fl})
	e.setRoles(&roles.Spec{Admin: []string{"local:alice", "local:bob"}})
	e.method = "local"
	clientAlice, tokA := e.login("local:alice", "Alice's client")
	_, tokB := e.login("local:bob", "Bob's client")
	ids := e.srv.GrantsOf("local:alice")
	if len(ids) != 1 || ids[0] != tokA.grant {
		t.Fatalf("%v (grant %s)", ids, tokA.grant)
	}
	if r := e.mcpStatus(tokA.access); r.StatusCode != http.StatusOK {
		t.Fatalf("before: %d", r.StatusCode)
	}
	if err := e.srv.RevokeGrant(ids[0], "revoked with the local account"); err != nil {
		t.Fatal(err)
	}
	if r := e.mcpStatus(tokA.access); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an access token of a revoked grant: %d", r.StatusCode)
	}
	if r := e.refresh(clientAlice, tokA.refresh); r.StatusCode == http.StatusOK {
		t.Fatal("a refresh of a revoked grant was accepted")
	}
	if r := e.mcpStatus(tokB.access); r.StatusCode != http.StatusOK {
		t.Fatalf("another person's grant: %d", r.StatusCode)
	}
	if got := e.srv.GrantsOf("local:alice"); len(got) != 0 {
		t.Fatalf("%v", got)
	}
	if err := e.srv.RevokeGrant("no-such-grant", "x"); err != nil {
		t.Fatalf("a grant that is gone is not an error: %v", err)
	}
}

// The revocation list of the local accounts blocks a grant at once, with its entry still in the state file: the access token,
// the refresh and the account's grant list all stop seeing it (design-local-accounts.md, 5.11).
func TestAGrantOnTheRevocationListIsRefusedWhateverTheStateFileHolds(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	blocked := map[string]bool{}
	fl := &fakeLocal{active: map[string]bool{"alice": true}}
	e := newEnv(t, opts{local: fl, blocked: func(id string) bool { mu.Lock(); defer mu.Unlock(); return blocked[id] }})
	e.setRoles(&roles.Spec{Admin: []string{"local:alice"}})
	e.method = "local"
	client, tok := e.login("local:alice", "Alice's client")
	if r := e.mcpStatus(tok.access); r.StatusCode != http.StatusOK {
		t.Fatalf("before: %d", r.StatusCode)
	}
	mu.Lock()
	blocked[tok.grant] = true
	mu.Unlock()
	if r := e.mcpStatus(tok.access); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an access token of a blocked grant: %d %s", r.StatusCode, r.body)
	}
	if r := e.refresh(client, tok.refresh); r.StatusCode == http.StatusOK {
		t.Fatal("a refresh of a blocked grant was accepted")
	}
	if got := e.srv.GrantsOf("local:alice"); len(got) != 0 {
		t.Fatalf("a blocked grant is listed: %v", got)
	}
}
