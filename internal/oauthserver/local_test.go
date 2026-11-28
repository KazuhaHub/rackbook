package oauthserver_test

import (
	"net/http"
	"strings"
	"sync"
	"testing"

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
