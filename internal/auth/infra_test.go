package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/roles"
)

func TestInfraAdminsOnlyOIDCSessionsOfListedPeople(t *testing.T) {
	a, err := NewInfraAdmins([]string{" Me@Kazuha.org ", ""})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Pin("https://idp.test", "client-1", "", "tenant-1", 0); err != nil {
		t.Fatal(err)
	}
	admin := roles.Admin
	const iss, cli, tid = "https://idp.test", "client-1", "tenant-1"
	cases := []struct {
		name string
		id   *Identity
		want bool
	}{
		{"listed, oidc session", &Identity{ID: "me@kazuha.org", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, OIDCClaim: "preferred_username", OIDCTenant: tid, Role: admin}, true},
		{"case folded", &Identity{ID: "ME@kazuha.ORG", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, OIDCClaim: "preferred_username", OIDCTenant: tid, Role: admin}, true},
		{"admin role but not listed", &Identity{ID: "other@kazuha.org", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, OIDCClaim: "preferred_username", OIDCTenant: tid, Role: admin}, false},
		{"viewer not listed", &Identity{ID: "v@kazuha.org", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, OIDCClaim: "preferred_username", OIDCTenant: tid, Role: roles.Viewer}, false},
		{"listed, editor role in rackbook is irrelevant", &Identity{ID: "me@kazuha.org", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, OIDCClaim: "preferred_username", OIDCTenant: tid, Role: roles.Editor}, true},
		{"API token of the listed person", &Identity{ID: "me@kazuha.org", Method: MethodToken, Token: "t", Role: admin}, false},
		{"token field set", &Identity{ID: "me@kazuha.org", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, OIDCClaim: "preferred_username", OIDCTenant: tid, Token: "t", Role: admin}, false},
		{"OAuth access token", &Identity{ID: "me@kazuha.org", Method: MethodOAuth, Role: admin}, false},
		{"MCPHub", &Identity{ID: "me@kazuha.org", Method: MethodMCPHub, Role: admin}, false},
		{"passkey", &Identity{ID: "me@kazuha.org", Method: MethodPasskey, Role: admin}, false},
		{"cloudflare access", &Identity{ID: "me@kazuha.org", Method: MethodCloudflareAccess, Role: admin}, false},
		{"auth none", &Identity{ID: "me@kazuha.org", Method: MethodNone, Role: admin}, false},
		{"anonymous", &Identity{Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, OIDCClaim: "preferred_username", OIDCTenant: tid, Role: admin}, false},
		{"only the e-mail field matches", &Identity{ID: "x@kazuha.org", Email: "me@kazuha.org", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, OIDCClaim: "preferred_username", OIDCTenant: tid, Role: admin}, false},
		{"nil", nil, false},
		{"issued under another issuer", &Identity{ID: "me@kazuha.org", Method: MethodOIDC, OIDCIssuer: "https://evil.test", OIDCClient: cli}, false},
		{"issued under another client", &Identity{ID: "me@kazuha.org", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: "other"}, false},
		{"identity from another claim", &Identity{ID: "me@kazuha.org", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, OIDCClaim: "email", OIDCTenant: tid}, false},
		{"another tenant", &Identity{ID: "me@kazuha.org", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, OIDCClaim: "preferred_username", OIDCTenant: "other"}, false},
		{"no tenant recorded", &Identity{ID: "me@kazuha.org", Method: MethodOIDC, OIDCIssuer: iss, OIDCClient: cli, OIDCClaim: "preferred_username"}, false},
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
	if err := a.Pin("", "c", "", "", 0); err == nil {
		t.Fatal("an empty issuer is refused")
	}
	if err := a.Pin("https://i", "", "", "", 0); err == nil {
		t.Fatal("an empty client is refused")
	}
}

func TestInfraAdminsFresh(t *testing.T) {
	a, _ := NewInfraAdmins([]string{"me@kazuha.org"})
	if err := a.Pin("https://i", "c", "", "", 0); err != nil {
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

func TestInfraPinTenantRules(t *testing.T) {
	const g = "e72914d3-3d19-486e-be11-15c69540e02a"
	entra := "https://login.microsoftonline.com/" + g + "/v2.0"
	for name, c := range map[string]struct {
		issuer, tenant string
		ok             bool
	}{
		"entra needs a tenant":     {entra, "", false},
		"entra tenant matches":     {entra, g, true},
		"entra tenant, other case": {entra, "E72914D3-3D19-486E-BE11-15C69540E02A", true},
		"entra tenant differs":     {entra, "11111111-1111-1111-1111-111111111111", false},
		"guid in a non-entra path": {"https://idp.example/" + g, "other", false},
		"other idp without tenant": {"https://idp.example", "", true},
		"other idp with a tenant":  {"https://idp.example", "t1", true},
	} {
		a, _ := NewInfraAdmins([]string{"me@kazuha.org"})
		if err := a.Pin(c.issuer, "c", "", c.tenant, 0); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestInfraAuditorsAreTheSameKindOfList(t *testing.T) {
	a, err := NewInfraAuditors([]string{"Aud@Example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Pin("https://idp.test", "client", "", "", 0); err != nil {
		t.Fatal(err)
	}
	ok := &Identity{ID: "aud@example.com", Method: MethodOIDC, OIDCIssuer: "https://idp.test", OIDCClient: "client", OIDCClaim: "preferred_username"}
	if !a.Allows(ok) || a.Len() != 1 {
		t.Fatal("a listed OIDC session under the pinned provider")
	}
	for name, mut := range map[string]func(*Identity){
		"passkey":      func(i *Identity) { i.Method = MethodPasskey },
		"token":        func(i *Identity) { i.Token = "ci" },
		"oauth":        func(i *Identity) { i.Method = MethodOAuth },
		"other issuer": func(i *Identity) { i.OIDCIssuer = "https://evil.test" },
		"other client": func(i *Identity) { i.OIDCClient = "x" },
		"other claim":  func(i *Identity) { i.OIDCClaim = "sub" },
		"other tenant": func(i *Identity) { i.OIDCTenant = "t" },
		"other person": func(i *Identity) { i.ID = "x@example.com" },
	} {
		c := *ok
		mut(&c)
		if a.Allows(&c) {
			t.Errorf("%s: allowed", name)
		}
	}
	if _, err := NewInfraAuditors([]string{"*@example.com"}); err == nil || !strings.Contains(err.Error(), "--infra-auditors") {
		t.Fatalf("%v", err)
	}
	if _, err := NewInfraAuditors(nil); err == nil || !strings.Contains(err.Error(), "--infra-auditors") {
		t.Fatalf("%v", err)
	}
	var none *InfraAdmins
	if none.Allows(ok) || none.Len() != 0 {
		t.Fatal("a nil list allows nobody")
	}
}
