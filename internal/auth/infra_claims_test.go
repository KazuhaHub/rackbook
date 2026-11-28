package auth

import (
	"strings"
	"testing"
	"time"
)

const (
	cIss, cCli, cTid = "https://idp.test", "client-1", "tenant-1"
	cGroup           = "0f6a1d2e-1111-4222-8333-444455556666"
)

var cNow = time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)

func claimList(t *testing.T, entries ...string) *InfraAdmins {
	t.Helper()
	a, err := NewInfraAdmins(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Pin(cIss, cCli, "", cTid, 0); err != nil {
		t.Fatal(err)
	}
	return a
}

// session is an OIDC browser session signed in age ago, with the given claims.
func session(id string, age time.Duration, groups, appRoles []string) *Identity {
	return &Identity{ID: id, Method: MethodOIDC, OIDCIssuer: cIss, OIDCClient: cCli, OIDCClaim: "preferred_username", OIDCTenant: cTid,
		OIDCAt: cNow.Add(-age), Groups: groups, AppRoles: appRoles}
}

func TestInfraListParsesOneClaimEntry(t *testing.T) {
	for _, ok := range [][]string{
		{"group:" + cGroup}, {"app-role:Rackbook.InfraAdmin"}, {"alice@x.org", "app-role:Rackbook.InfraAdmin"},
		{"GROUP:" + strings.ToUpper(cGroup), "a@x.org"}, {"oidc:sub-1", "group:g"},
	} {
		if _, err := NewInfraAdmins(ok); err != nil {
			t.Errorf("%v: %v", ok, err)
		}
		if _, err := NewInfraAuditors(ok); err != nil {
			t.Errorf("auditors %v: %v", ok, err)
		}
	}
	for _, c := range []struct {
		want string
		bad  []string
	}{
		{"at most one", []string{"group:a", "group:b"}},
		{"at most one", []string{"group:a", "app-role:b"}},
		{"no wildcards", []string{"*"}},
		{"is not allowed", []string{"oauth:acme:bob"}},
		{"is not allowed", []string{"mcphub:bob"}},
		{"is not allowed", []string{"local:bob"}},
		{"no wildcards", []string{"*@x.org"}},
		{"group id is empty", []string{"group:"}},
		{"app role value is empty", []string{"app-role:"}},
		{"names nobody", []string{" ", ""}},
	} {
		if _, err := NewInfraAdmins(c.bad); err == nil || !strings.Contains(err.Error(), "--infra-admins") || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v (want %q)", c.bad, err, c.want)
		}
		if _, err := NewInfraAuditors(c.bad); err == nil || !strings.Contains(err.Error(), "--infra-auditors") {
			t.Errorf("auditors %v: %v", c.bad, err)
		}
	}
	a, _ := NewInfraAdmins([]string{"app-role:Rackbook.InfraAdmin"})
	if a.ClaimEntry() != "app-role:Rackbook.InfraAdmin" || a.Len() != 0 {
		t.Fatalf("%q %d", a.ClaimEntry(), a.Len())
	}
	if g, _ := NewInfraAdmins([]string{"group:" + strings.ToUpper(cGroup)}); g.ClaimEntry() != "group:"+cGroup {
		t.Fatalf("a group id is folded: %q", g.ClaimEntry())
	}
}

func TestInfraClaimEntryNeedsEveryPin(t *testing.T) {
	for _, entry := range []string{"group:" + cGroup, "app-role:R"} {
		a, _ := NewInfraAdmins([]string{entry})
		for name, pin := range map[string][3]string{
			"no issuer": {"", cCli, cTid}, "no client": {cIss, "", cTid}, "no tenant": {cIss, cCli, ""},
		} {
			err := a.Pin(pin[0], pin[1], "", pin[2], 0)
			if err == nil {
				t.Errorf("%s with %s: pinned", name, entry)
			}
		}
		if err := a.Pin(cIss, cCli, "", cTid, 0); err != nil {
			t.Errorf("%s: %v", entry, err)
		}
		// the list of identities needs no tenant outside Entra, as before
		if id, _ := NewInfraAdmins([]string{"a@x.org"}); id.Pin(cIss, cCli, "", "", 0) != nil {
			t.Error("an identity list without a tenant must still pin")
		}
	}
	au, _ := NewInfraAuditors([]string{"group:g"})
	if err := au.Pin(cIss, cCli, "", "", 0); err == nil || !strings.Contains(err.Error(), "--infra-auditors") {
		t.Errorf("%v", err)
	}
}

func TestInfraMatchingByGroupAndAppRole(t *testing.T) {
	byGroup := claimList(t, "group:"+cGroup)
	byRole := claimList(t, "app-role:Rackbook.InfraAdmin")
	for _, c := range []struct {
		name string
		l    *InfraAdmins
		id   *Identity
		want string
	}{
		{"in the group", byGroup, session("bob@x.org", time.Hour, []string{"other", cGroup}, nil), InfraViaGroup},
		{"group id case folded", byGroup, session("bob@x.org", time.Hour, []string{strings.ToUpper(cGroup)}, nil), InfraViaGroup},
		{"another group", byGroup, session("bob@x.org", time.Hour, []string{"other"}, nil), ""},
		{"a prefix of the group is not the group", byGroup, session("bob@x.org", time.Hour, []string{cGroup[:20]}, nil), ""},
		{"the group id as an app role", byGroup, session("bob@x.org", time.Hour, nil, []string{cGroup}), ""},
		{"has the app role", byRole, session("bob@x.org", time.Hour, nil, []string{"x", "Rackbook.InfraAdmin"}), InfraViaAppRole},
		{"app role is case sensitive", byRole, session("bob@x.org", time.Hour, nil, []string{"rackbook.infraadmin"}), ""},
		{"app role named as a group", byRole, session("bob@x.org", time.Hour, []string{"Rackbook.InfraAdmin"}, nil), ""},
		{"no claims at all (overage drops them)", byRole, session("bob@x.org", time.Hour, nil, nil), ""},
		{"no claims at all, group", byGroup, session("bob@x.org", time.Hour, nil, nil), ""},
		{"another issuer", byGroup, func() *Identity {
			i := session("bob@x.org", time.Hour, []string{cGroup}, nil)
			i.OIDCIssuer = "https://evil.test"
			return i
		}(), ""},
		{"another client", byGroup, func() *Identity {
			i := session("bob@x.org", time.Hour, []string{cGroup}, nil)
			i.OIDCClient = "other"
			return i
		}(), ""},
		{"another tenant", byGroup, func() *Identity {
			i := session("bob@x.org", time.Hour, []string{cGroup}, nil)
			i.OIDCTenant = "t2"
			return i
		}(), ""},
		{"another identity claim", byGroup, func() *Identity {
			i := session("bob@x.org", time.Hour, []string{cGroup}, nil)
			i.OIDCClaim = "email"
			return i
		}(), ""},
		{"api token", byGroup, func() *Identity {
			i := session("bob@x.org", time.Hour, []string{cGroup}, nil)
			i.Method, i.Token = MethodToken, "ci"
			return i
		}(), ""},
		{"token field on an oidc identity", byGroup, func() *Identity {
			i := session("bob@x.org", time.Hour, []string{cGroup}, nil)
			i.Token = "ci"
			return i
		}(), ""},
		{"oauth grant", byGroup, func() *Identity {
			i := session("bob@x.org", time.Hour, []string{cGroup}, nil)
			i.Method = MethodOAuth
			return i
		}(), ""},
		{"oauth grant, app role", byRole, func() *Identity {
			i := session("bob@x.org", time.Hour, nil, []string{"Rackbook.InfraAdmin"})
			i.Method = MethodOAuth
			return i
		}(), ""},
		{"mcphub", byGroup, func() *Identity {
			i := session("bob@x.org", time.Hour, []string{cGroup}, nil)
			i.Method = MethodMCPHub
			return i
		}(), ""},
		{"passkey", byGroup, func() *Identity {
			i := session("bob@x.org", time.Hour, []string{cGroup}, nil)
			i.Method = MethodPasskey
			return i
		}(), ""},
		{"local account", byGroup, func() *Identity {
			i := session("local:bob", time.Hour, []string{cGroup}, nil)
			i.Method = "local"
			return i
		}(), ""},
		{"a subject login never matches a claim", byGroup, session("oidc:sub-1", time.Hour, []string{cGroup}, nil), ""},
		{"no sign-in time", byGroup, func() *Identity {
			i := session("bob@x.org", time.Hour, []string{cGroup}, nil)
			i.OIDCAt = time.Time{}
			return i
		}(), ""},
	} {
		if got := c.l.Via(c.id, cNow); got != c.want {
			t.Errorf("%s: Via = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestInfraIdentityEntryStillWorksBesideAClaimEntry(t *testing.T) {
	l := claimList(t, "alice@x.org", "app-role:Rackbook.InfraAdmin")
	if got := l.Via(session("ALICE@x.org", time.Hour, nil, nil), cNow); got != InfraViaIdentity {
		t.Fatalf("%q", got)
	}
	// both: the identity wins, so the capability has no claim lifetime
	if got := l.Via(session("alice@x.org", 30*time.Hour, nil, []string{"Rackbook.InfraAdmin"}), cNow); got != InfraViaIdentity {
		t.Fatalf("%q", got)
	}
	if got := l.Via(session("bob@x.org", time.Hour, nil, nil), cNow); got != "" {
		t.Fatalf("%q", got)
	}
}

func TestInfraClaimEntryLapsesAtClaimsAbsolute(t *testing.T) {
	l := claimList(t, "alice@x.org", "group:"+cGroup)
	if err := l.SetClaimsAbsolute(2 * time.Hour); err != nil {
		t.Fatal(err)
	}
	g := []string{cGroup}
	claim := func(age time.Duration) string { return l.Via(session("bob@x.org", age, g, nil), cNow) }
	if claim(time.Hour) != InfraViaGroup || claim(2*time.Hour-time.Second) != InfraViaGroup {
		t.Fatal("inside claims_absolute")
	}
	if claim(2*time.Hour) != "" || claim(5*time.Hour) != "" {
		t.Fatal("past claims_absolute the group no longer counts")
	}
	// a replayed cookie is the same signed values at a later time: it gets nothing back
	if l.Via(session("bob@x.org", time.Hour, g, nil), cNow.Add(3*time.Hour)) != "" {
		t.Fatal("an old cookie replayed later")
	}
	// a clock a long way behind the sign-in is not a session from the future
	if l.Via(session("bob@x.org", -time.Hour, g, nil), cNow) != "" {
		t.Fatal("a sign-in in the future")
	}
	// the listed identity does not lapse
	if got := l.Via(session("alice@x.org", 20*time.Hour, nil, nil), cNow); got != InfraViaIdentity {
		t.Fatalf("%q", got)
	}
	if got := l.ClaimEnds(session("bob@x.org", time.Hour, g, nil)); !got.Equal(cNow.Add(-time.Hour).Add(2 * time.Hour)) {
		t.Fatalf("%v", got)
	}
	// without a setting the default of claims_absolute applies
	d := claimList(t, "group:"+cGroup)
	if d.ClaimsAbsolute() != DefaultClaimsAbsolute || d.Via(session("b@x.org", 23*time.Hour, g, nil), cNow) == "" || d.Via(session("b@x.org", 25*time.Hour, g, nil), cNow) != "" {
		t.Fatal("default lifetime")
	}
	var none *InfraAdmins
	if !none.ClaimEnds(session("b@x.org", 0, g, nil)).IsZero() || none.ClaimEntry() != "" {
		t.Fatal("nil list")
	}
}

func TestInfraAuditorsHaveTheirOwnClaimEntry(t *testing.T) {
	admins, aud := claimList(t, "group:"+cGroup), claimList(t, "app-role:Rackbook.InfraAuditor")
	c := &InfraAccess{Admins: admins, Auditors: aud}
	a, u := c.Via(session("bob@x.org", time.Hour, []string{cGroup}, nil), cNow)
	if a != InfraViaGroup || u != "" {
		t.Fatalf("%q %q", a, u)
	}
	a, u = c.Via(session("bob@x.org", time.Hour, []string{cGroup}, []string{"Rackbook.InfraAuditor"}), cNow)
	if a != InfraViaGroup || u != InfraViaAppRole {
		t.Fatalf("independent lists: %q %q", a, u)
	}
	a, u = c.Via(session("bob@x.org", time.Hour, nil, []string{"Rackbook.InfraAuditor"}), cNow)
	if a != "" || u != InfraViaAppRole {
		t.Fatalf("%q %q", a, u)
	}
	if a, u = (*InfraAccess)(nil).Via(session("bob@x.org", 0, nil, nil), cNow); a != "" || u != "" {
		t.Fatal("nil")
	}
}

func TestInfraOverageIsNamedOnlyWhenItCostSomething(t *testing.T) {
	c := &InfraAccess{Admins: claimList(t, "group:"+cGroup), Auditors: claimList(t, "app-role:R")}
	none := session("bob@x.org", 0, nil, nil)
	for _, k := range []struct {
		name        string
		id          *Identity
		groups, rls bool
		want        string
	}{
		{"nothing cut", none, false, false, ""},
		{"groups dropped", none, true, false, "groups"},
		{"roles cut", none, false, true, "app_roles"},
		{"both", none, true, true, "groups,app_roles"},
		{"matched anyway (a prefix survived the cut)", session("bob@x.org", 0, []string{cGroup}, nil), true, false, ""},
	} {
		if got := c.Overage(k.id, cNow, k.groups, k.rls); got != k.want {
			t.Errorf("%s: %q, want %q", k.name, got, k.want)
		}
	}
	// no claim entry configured: nothing to lose
	if got := (&InfraAccess{Admins: claimList(t, "a@x.org")}).Overage(none, cNow, true, true); got != "" {
		t.Errorf("no claim entry: %q", got)
	}
	// only the list a claim entry needs is named
	if got := (&InfraAccess{Admins: claimList(t, "group:"+cGroup)}).Overage(none, cNow, false, true); got != "" {
		t.Errorf("roles were cut but the entry is a group: %q", got)
	}
}

func TestInfraClaimsAbsoluteIsOneToTwentyFourHours(t *testing.T) {
	l := claimList(t, "group:"+cGroup)
	for _, d := range []time.Duration{time.Hour, 6 * time.Hour, 24 * time.Hour, 0} {
		if err := l.SetClaimsAbsolute(d); err != nil {
			t.Errorf("%s: %v", d, err)
		}
	}
	if l.ClaimsAbsolute() != DefaultClaimsAbsolute {
		t.Fatalf("0 is the default: %s", l.ClaimsAbsolute())
	}
	for _, d := range []time.Duration{-time.Hour, time.Second, 59 * time.Minute, 24*time.Hour + time.Second, 7 * 24 * time.Hour} {
		if err := l.SetClaimsAbsolute(d); err == nil || !strings.Contains(err.Error(), "--infra-claims-absolute") {
			t.Errorf("%s: %v", d, err)
		}
	}
	if l.ClaimsAbsolute() != DefaultClaimsAbsolute {
		t.Fatal("a refused value changes nothing")
	}
}

func TestInfraGroupOnEntraIsAGUID(t *testing.T) {
	const entra = "https://login.microsoftonline.com/e72914d3-3d19-486e-be11-15c69540e02a/v2.0"
	const tid = "e72914d3-3d19-486e-be11-15c69540e02a"
	for entry, ok := range map[string]bool{
		"group:" + cGroup: true, "group:Rackbook Infra": false, "group:" + cGroup + "x": false, "group:{" + cGroup + "}": false,
		"app-role:Rackbook.InfraAdmin": true, "a@x.org": true,
	} {
		for _, mk := range []func([]string) (*InfraAdmins, error){NewInfraAdmins, NewInfraAuditors} {
			a, err := mk([]string{entry})
			if err != nil {
				t.Fatal(err)
			}
			err = a.Pin(entra, cCli, "", tid, 0)
			if (err == nil) != ok {
				t.Errorf("%s: %v", entry, err)
			}
			if err != nil && !strings.Contains(err.Error(), "GUID") {
				t.Errorf("%s: %v", entry, err)
			}
		}
	}
	// other issuers: any group value, and a warning that names may not be unique
	g, _ := NewInfraAdmins([]string{"group:ops-team"})
	if err := g.Pin(cIss, cCli, "", cTid, 0); err != nil || !g.WarnGroupNames() {
		t.Fatalf("%v %v", err, g.WarnGroupNames())
	}
	if e, _ := NewInfraAdmins([]string{"group:" + cGroup}); e.Pin(entra, cCli, "", tid, 0) != nil || e.WarnGroupNames() {
		t.Fatal("a GUID on Entra: no warning")
	}
	if r, _ := NewInfraAdmins([]string{"app-role:R"}); r.Pin(cIss, cCli, "", cTid, 0) != nil || r.WarnGroupNames() {
		t.Fatal("an app role never warns")
	}
}
