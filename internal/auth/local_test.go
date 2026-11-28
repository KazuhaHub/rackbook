package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/roles"
)

// fakeLocal is a store of local accounts: the names that can hold a session now.
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

func localAuth(t *testing.T, local LocalAccounts) *Authenticator {
	t.Helper()
	cfg := &config.Config{Auth: config.Auth{
		Roles:    &roles.Spec{Admin: []string{"local:alice"}, Editor: []string{"local:bob"}, Viewer: []string{"local:*", "*"}},
		Auditors: []string{"local:carol", "*"},
	}}
	a, err := New(context.Background(), Config{Mode: ModeNone, Config: func() *config.Config { return cfg }, Local: local})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestPolicyRoleGatesLocalIdentities(t *testing.T) {
	t.Parallel()
	store := &fakeLocal{active: map[string]bool{"alice": true, "bob": true, "carol": true, "dave": true}}
	a := localAuth(t, store)
	eval := func(id, method string) (roles.Role, bool) { return a.CapabilitiesForVia(id, method) }

	// a live local account has what its entries give it, by every path
	for _, c := range []struct {
		id   string
		role roles.Role
		aud  bool
	}{{"local:alice", roles.Admin, false}, {"local:bob", roles.Editor, false}, {"local:carol", roles.Viewer, true}, {"local:dave", roles.Viewer, false}} {
		if r, aud := eval(c.id, MethodLocal); r != c.role || aud != c.aud {
			t.Errorf("%s: %v %v, want %v %v", c.id, r, aud, c.role, c.aud)
		}
		id := a.Evaluate(&Identity{ID: c.id, Method: MethodLocal})
		if id.Role != c.role || id.Auditor != c.aud {
			t.Errorf("Evaluate %s: %v %v", c.id, id.Role, id.Auditor)
		}
		sub := a.EvaluateSubject(&Identity{ID: c.id, Method: MethodToken}, roles.Subject{ID: c.id, Method: MethodLocal})
		if sub.Role != c.role || sub.Auditor != c.aud {
			t.Errorf("EvaluateSubject %s: %v %v", c.id, sub.Role, sub.Auditor)
		}
	}

	// a look-alike from another method has nothing: not by the * entries either
	for _, m := range []string{MethodOIDC, MethodPasskey, MethodNone, MethodCloudflareAccess, MethodOAuth, MethodMCPHub, MethodToken, ""} {
		if r, aud := eval("local:alice", m); r != roles.None || aud {
			t.Errorf("an identity named local:alice by %q has %v %v", m, r, aud)
		}
		id := a.EvaluateSubject(&Identity{ID: "local:alice", Method: MethodOAuth}, roles.Subject{ID: "local:alice", Method: m})
		if id.Role != roles.None || id.Auditor {
			t.Errorf("EvaluateSubject, method %q: %v %v", m, id.Role, id.Auditor)
		}
	}
	// a subject of method local that is not a local identity is stopped too
	if r, _ := eval("alice@example.com", MethodLocal); r != roles.None {
		t.Errorf("method local with an e-mail: %v", r)
	}
	if r, _ := eval("local:1x", MethodLocal); r != roles.None {
		t.Errorf("an invalid username: %v", r)
	}
	// SSO identities are untouched
	if r, _ := eval("x@example.com", MethodOIDC); r != roles.Viewer {
		t.Errorf("an SSO identity: %v", r)
	}

	// the account stops being active: nothing on any path, at once
	store.set("alice", false)
	store.set("carol", false)
	for _, id := range []string{"local:alice", "local:carol"} {
		if r, aud := eval(id, MethodLocal); r != roles.None || aud {
			t.Errorf("%s after it stopped: %v %v", id, r, aud)
		}
	}
	if r := a.RoleForVia("local:alice", MethodLocal); r != roles.None {
		t.Errorf("RoleForVia: %v", r)
	}
	// an account the store does not know
	if r, _ := eval("local:ghost", MethodLocal); r != roles.None {
		t.Errorf("unknown account: %v", r)
	}
}

func TestNoLocalAccountsMeansNoLocalRole(t *testing.T) {
	t.Parallel()
	a := localAuth(t, nil)
	if r, aud := a.CapabilitiesForVia("local:alice", MethodLocal); r != roles.None || aud {
		t.Errorf("without a store: %v %v", r, aud)
	}
}

func TestCapabilitiesUnderGatesLocalCallers(t *testing.T) {
	t.Parallel()
	store := &fakeLocal{active: map[string]bool{"alice": true}}
	a := localAuth(t, store)
	spec := &roles.Spec{Admin: []string{"local:alice"}}
	c, err := a.CapabilitiesUnder(&config.Config{}, spec, nil, roles.Subject{ID: "local:alice", Method: MethodLocal})
	if err != nil || c.Role != roles.Admin || c.ByIdentity != roles.Admin {
		t.Fatalf("%+v %v", c, err)
	}
	// the same lists, an identity that is not that account
	c, _ = a.CapabilitiesUnder(&config.Config{}, spec, nil, roles.Subject{ID: "local:alice", Method: MethodOIDC})
	if c.Role != roles.None {
		t.Fatalf("an OIDC look-alike would be %v", c.Role)
	}
	store.set("alice", false)
	c, _ = a.CapabilitiesUnder(&config.Config{}, spec, nil, roles.Subject{ID: "local:alice", Method: MethodLocal})
	if c.Role != roles.None {
		t.Fatalf("a disabled account would be %v", c.Role)
	}
}

func TestLoginIsTheBuiltInLoginAndOIDCItsAlias(t *testing.T) {
	t.Parallel()
	if ParseMode("login") != ModeOIDC || ParseMode("oidc") != ModeOIDC || ParseMode("none") != ModeNone {
		t.Fatal("ParseMode")
	}
	for _, m := range []string{"login", "oidc"} {
		a, err := New(context.Background(), Config{Mode: m, Sessions: stubSessions{}})
		if err != nil || a.Mode() != ModeOIDC {
			t.Errorf("%s: %v %v", m, err, a)
		}
	}
	if _, err := New(context.Background(), Config{Mode: "local"}); err == nil {
		t.Error("--auth local does not exist")
	}
}

type stubSessions struct{}

func (stubSessions) Identify(http.ResponseWriter, *http.Request) (*Identity, error) {
	return nil, ErrUnauthenticated
}
func (stubSessions) Public(*http.Request) bool                            { return false }
func (stubSessions) Reject(http.ResponseWriter, *http.Request, error)     {}
func (stubSessions) NoRole(http.ResponseWriter, *http.Request, *Identity) {}
