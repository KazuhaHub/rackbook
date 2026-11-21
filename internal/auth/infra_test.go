package auth

import (
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/roles"
)

func TestInfraAdminsOnlyOIDCSessionsOfListedPeople(t *testing.T) {
	a, err := NewInfraAdmins([]string{" Me@Kazuha.org ", ""})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Pin("https://idp.test", "client-1", 0); err != nil {
		t.Fatal(err)
	}
	admin := roles.Admin
	const iss, cli = "https://idp.test", "client-1"
	cases := []struct {
		name string
		id   *Identity
		want bool
	}{
		{"listed, oidc session", &Identity{ID: "me@kazuha.org", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, Role: admin}, true},
		{"case folded", &Identity{ID: "ME@kazuha.ORG", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, Role: admin}, true},
		{"admin role but not listed", &Identity{ID: "other@kazuha.org", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, Role: admin}, false},
		{"viewer not listed", &Identity{ID: "v@kazuha.org", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, Role: roles.Viewer}, false},
		{"listed, editor role in rackbook is irrelevant", &Identity{ID: "me@kazuha.org", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, Role: roles.Editor}, true},
		{"API token of the listed person", &Identity{ID: "me@kazuha.org", Method: MethodToken, Token: "t", Role: admin}, false},
		{"token field set", &Identity{ID: "me@kazuha.org", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, Token: "t", Role: admin}, false},
		{"OAuth access token", &Identity{ID: "me@kazuha.org", Method: MethodOAuth, Role: admin}, false},
		{"MCPHub", &Identity{ID: "me@kazuha.org", Method: MethodMCPHub, Role: admin}, false},
		{"passkey", &Identity{ID: "me@kazuha.org", Method: MethodPasskey, Role: admin}, false},
		{"cloudflare access", &Identity{ID: "me@kazuha.org", Method: MethodCloudflareAccess, Role: admin}, false},
		{"auth none", &Identity{ID: "me@kazuha.org", Method: MethodNone, Role: admin}, false},
		{"anonymous", &Identity{Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, Role: admin}, false},
		{"only the e-mail field matches", &Identity{ID: "x@kazuha.org", Email: "me@kazuha.org", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, Role: admin}, false},
		{"nil", nil, false},
		{"issued under another issuer", &Identity{ID: "me@kazuha.org", Method: MethodOIDC, OIDCIssuer: "https://evil.test", OIDCClient: cli}, false},
		{"issued under another client", &Identity{ID: "me@kazuha.org", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: "other"}, false},
		{"session without issuer (older cookie)", &Identity{ID: "me@kazuha.org", Method: MethodOIDC}, false},
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

func TestInfraAdminsUnpinnedAllowsNobody(t *testing.T) {
	a, _ := NewInfraAdmins([]string{"me@kazuha.org"})
	if a.Allows(&Identity{ID: "me@kazuha.org", Method: MethodOIDC}) || a.Allows(&Identity{ID: "me@kazuha.org", Method: MethodOIDC, OIDCIssuer: "", OIDCClient: ""}) {
		t.Fatal("without a pin nobody is admitted")
	}
	if err := a.Pin("", "c", 0); err == nil {
		t.Fatal("an empty issuer is refused")
	}
	if err := a.Pin("https://i", "", 0); err == nil {
		t.Fatal("an empty client is refused")
	}
}

func TestInfraAdminsFresh(t *testing.T) {
	a, _ := NewInfraAdmins([]string{"me@kazuha.org"})
	if err := a.Pin("https://i", "c", 0); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	for name, c := range map[string]struct {
		at   time.Time
		want bool
	}{
		"just now":      {now, true},
		"11 hours":      {now.Add(-11 * time.Hour), true},
		"13 hours":      {now.Add(-13 * time.Hour), false},
		"never":         {time.Time{}, false},
		"far in future": {now.Add(time.Hour), false},
	} {
		if got := a.Fresh(&Identity{OIDCAt: c.at}, now); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
	if a.Fresh(nil, now) {
		t.Error("nil identity")
	}
}
