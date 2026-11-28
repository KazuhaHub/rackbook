package roles

import (
	"strings"
	"testing"
)

func localPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := CompileAuditors(&Spec{
		Admin:  []string{"local:Alice", "boss@example.com"},
		Editor: []string{"local:bob"},
		Viewer: []string{"local:*", "*", "*@example.com"},
	}, []string{"local:carol", "*"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLocalEntriesMatchOnlyMethodLocal(t *testing.T) {
	t.Parallel()
	p := localPolicy(t)
	for _, c := range []struct {
		name string
		s    Subject
		role Role
		aud  bool
	}{
		{"local admin, entry in any case", Subject{ID: "local:alice", Method: "local"}, Admin, false},
		{"local editor", Subject{ID: "local:bob", Method: "local"}, Editor, false},
		{"local:* is a viewer", Subject{ID: "local:dave", Method: "local"}, Viewer, false},
		{"local auditor by name", Subject{ID: "local:carol", Method: "local"}, Viewer, true},
		// the entries for everyone else never reach a local identity: * and *@domain are for SSO
		{"* does not make a local auditor", Subject{ID: "local:dave", Method: "local"}, Viewer, false},
		// and the reverse: an identity of another method that is called local:alice is nobody's admin
		{"oidc identity named local:alice", Subject{ID: "local:alice", Method: "oidc"}, Viewer, true}, // only the * entries match it
		{"passkey identity named local:bob", Subject{ID: "local:bob", Method: "passkey"}, Viewer, true},
		{"oauth subject named local:alice", Subject{ID: "local:alice", Method: "oauth", Issuer: "corp"}, None, false},
		{"mcphub user named local:alice", Subject{ID: "local:alice", Method: "mcphub"}, None, false},
		{"token creator without method", Subject{ID: "local:alice", Method: "none"}, Viewer, true},
	} {
		if got := p.Evaluate(c.s); got != c.role {
			t.Errorf("%s: role %v, want %v", c.name, got, c.role)
		}
		if got := p.IsAuditor(c.s); got != c.aud {
			t.Errorf("%s: auditor %v, want %v", c.name, got, c.aud)
		}
	}
	// the entries that name an account never match an identity that is not that account, whatever its case
	if p.Evaluate(Subject{ID: "LOCAL:ALICE", Method: "local"}) != Admin {
		t.Error("an identity is folded like an entry")
	}
	if p.Evaluate(Subject{ID: "local:alicia", Method: "local"}) != Viewer {
		t.Error("local:alice is not local:alicia")
	}
	// an e-mail address of the local identity is no way in
	if p.Evaluate(Subject{ID: "local:zed", Email: "boss@example.com", Method: "local"}) != Viewer {
		t.Error("a local identity is matched by its entry alone, not by an e-mail")
	}
}

func TestLocalIdentityHasNoRoleByDefault(t *testing.T) {
	t.Parallel()
	// no roles block: everybody the file does not know is an editor, but a local account only by a local: entry
	p, err := Compile(nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Evaluate(Subject{ID: "local:alice", Method: "local"}); got != None {
		t.Errorf("no roles block gave a local account %v", got)
	}
	if got := p.Evaluate(Subject{ID: "x@y.org", Method: "oidc"}); got != Editor {
		t.Errorf("v0.1 behaviour changed: %v", got)
	}
	p, err = Compile(nil, Options{}, "local:alice")
	if err != nil {
		t.Fatal(err)
	}
	if p.Evaluate(Subject{ID: "local:alice", Method: "local"}) != Editor || p.Evaluate(Subject{ID: "local:bob", Method: "local"}) != None {
		t.Error("the editors list names a local account")
	}
	if r, _ := mustCompile(t, nil).Sources(Subject{ID: "local:alice", Method: "local"}); len(r) != 0 {
		t.Errorf("sources of a local account with no entry: %v", r)
	}
}

func TestLocalEntryValidation(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"local:alice", "LOCAL:Alice", " local:a.b-c_d9 ", "local:*", "local:" + strings.Repeat("a", 32)} {
		if _, err := Describe(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"local:", "local: ", "local:1abc", "local:a b", "local:a*", "local:*x", "local:a@b", "local:" + strings.Repeat("a", 33), "local:é", "local:aK"} {
		if _, err := Describe(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
		if _, err := Compile(&Spec{Admin: []string{bad}}, Options{}); err == nil {
			t.Errorf("%q compiled", bad)
		}
	}
	got, _ := Describe("local:*")
	if got.Kind != KindLocal || got.Key != "local:*" || got.Value != "*" {
		t.Errorf("%+v", got)
	}
}

func TestLocalUsernameOfIdentity(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"local:alice": "alice", "LOCAL:Alice": "alice"} {
		if n, ok := LocalUsername(in); !ok || n != want {
			t.Errorf("%q: %q %v", in, n, ok)
		}
	}
	for _, in := range []string{"alice", "local:", "local:*", "oidc:local:alice", "local:1"} {
		if _, ok := LocalUsername(in); ok {
			t.Errorf("%q is not a local identity", in)
		}
	}
}
