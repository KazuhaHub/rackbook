package auth

import (
	"testing"

	"github.com/kazuhahub/rackbook/internal/roles"
)

func TestInfraAdminsOnlyOIDCSessionsOfListedPeople(t *testing.T) {
	a, err := NewInfraAdmins([]string{" Me@Kazuha.org ", ""})
	if err != nil {
		t.Fatal(err)
	}
	admin := roles.Admin
	cases := []struct {
		name string
		id   *Identity
		want bool
	}{
		{"listed, oidc session", &Identity{ID: "me@kazuha.org", Method: MethodOIDC, Role: admin}, true},
		{"case folded", &Identity{ID: "ME@kazuha.ORG", Method: MethodOIDC, Role: admin}, true},
		{"admin role but not listed", &Identity{ID: "other@kazuha.org", Method: MethodOIDC, Role: admin}, false},
		{"viewer not listed", &Identity{ID: "v@kazuha.org", Method: MethodOIDC, Role: roles.Viewer}, false},
		{"listed, editor role in rackbook is irrelevant", &Identity{ID: "me@kazuha.org", Method: MethodOIDC, Role: roles.Editor}, true},
		{"API token of the listed person", &Identity{ID: "me@kazuha.org", Method: MethodToken, Token: "t", Role: admin}, false},
		{"token field set", &Identity{ID: "me@kazuha.org", Method: MethodOIDC, Token: "t", Role: admin}, false},
		{"OAuth access token", &Identity{ID: "me@kazuha.org", Method: MethodOAuth, Role: admin}, false},
		{"MCPHub", &Identity{ID: "me@kazuha.org", Method: MethodMCPHub, Role: admin}, false},
		{"passkey", &Identity{ID: "me@kazuha.org", Method: MethodPasskey, Role: admin}, false},
		{"cloudflare access", &Identity{ID: "me@kazuha.org", Method: MethodCloudflareAccess, Role: admin}, false},
		{"auth none", &Identity{ID: "me@kazuha.org", Method: MethodNone, Role: admin}, false},
		{"anonymous", &Identity{Method: MethodOIDC, Role: admin}, false},
		{"only the e-mail field matches", &Identity{ID: "x@kazuha.org", Email: "me@kazuha.org", Method: MethodOIDC, Role: admin}, false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := a.Allows(c.id); got != c.want {
			t.Errorf("%s: Allows = %v, want %v", c.name, got, c.want)
		}
	}
	var none *InfraAdmins
	if none.Allows(&Identity{ID: "me@kazuha.org", Method: MethodOIDC}) {
		t.Error("a nil list allows nobody")
	}
}

func TestInfraAdminsRefusesWildcardsAndEmptyLists(t *testing.T) {
	for _, bad := range [][]string{{"*"}, {"*@kazuha.org"}, {"a b@x.org"}, {}, {" ", ""}} {
		if _, err := NewInfraAdmins(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}
