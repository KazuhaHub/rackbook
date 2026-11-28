package login

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/auth"
)

const infraGroup = "9c1f3a44-0000-4000-8000-0000000000aa"

// infraLists pins the test provider, as the deployment's --infra-oidc-* flags would, and lists
// kazuha by identity, one group for the administrators and one app role for the auditors.
func infraLists(t *testing.T) func(e *env) *auth.InfraAccess {
	return func(e *env) *auth.InfraAccess {
		admins, err := auth.NewInfraAdmins([]string{"kazuha@kazuha.org", "group:" + infraGroup})
		if err != nil {
			t.Fatal(err)
		}
		auditors, err := auth.NewInfraAuditors([]string{"app-role:Rackbook.InfraAuditor"})
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range []*auth.InfraAdmins{admins, auditors} {
			if err := l.Pin(e.idpS.URL, clientID, "", tenant, 0); err != nil {
				t.Fatal(err)
			}
			if err := l.SetClaimsAbsolute(2 * time.Hour); err != nil {
				t.Fatal(err)
			}
		}
		return &auth.InfraAccess{Admins: admins, Auditors: auditors}
	}
}

func account(t *testing.T, b *browser) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(b.get("/api/account").Body), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestLoginEventSaysHowInfraAdminCame(t *testing.T) {
	roles := "  roles:\n    admin: [kazuha@kazuha.org]\n    viewer: [\"*@kazuha.org\", \"*@example.com\"]\n"
	e := newEnv(t, options{nogit: true, roles: roles, infra: infraLists(t)})

	// by identity
	b := e.browser()
	b.login("admin", "")
	if ev := e.kinds("login")[0]; ev.InfraVia != auth.InfraViaIdentity || ev.InfraAuditorVia != "" || ev.InfraOverage != "" {
		t.Fatalf("%+v", ev)
	}
	if acc := account(t, b); acc["infraFrom"] != "identity" || acc["infraEnds"] != nil || acc["infraClaimsAbsolute"] != nil {
		t.Fatalf("a named administrator has no lapse: %v", acc)
	}

	// by group
	e.idp.Users["editor"]["groups"] = []string{"x", infraGroup}
	b = e.browser()
	b.login("editor", "")
	ev := e.kinds("login")[1]
	if ev.InfraVia != auth.InfraViaGroup || ev.InfraAuditorVia != "" {
		t.Fatalf("%+v", ev)
	}
	raw, _ := json.Marshal(ev)
	var wire map[string]any
	_ = json.Unmarshal(raw, &wire)
	if wire["infra_via"] != "group" || wire["infra_auditor_via"] != nil || wire["infra_overage"] != nil {
		t.Fatalf("%s", raw)
	}
	acc := account(t, b)
	if acc["infraFrom"] != "group" || acc["infraAuditorFrom"] != "" || acc["infraClaimsAbsolute"] != float64(7200) {
		t.Fatalf("%v", acc)
	}
	if end, err := time.Parse(time.RFC3339, acc["infraEnds"].(string)); err != nil || !end.Equal(e.clk.Now().Add(2*time.Hour)) {
		t.Fatalf("%v %v", acc["infraEnds"], err)
	}

	// by app role, as an auditor
	e.idp.Users["viewer"]["roles"] = []string{"Rackbook.InfraAuditor"}
	b = e.browser()
	b.login("viewer", "")
	if ev := e.kinds("login")[2]; ev.InfraVia != "" || ev.InfraAuditorVia != auth.InfraViaAppRole {
		t.Fatalf("%+v", ev)
	}
	if acc := account(t, b); acc["infraFrom"] != "" || acc["infraAuditorFrom"] != "app_role" || acc["infraEnds"] == nil {
		t.Fatalf("%v", acc)
	}

	// matched by nothing: no field at all
	e.idp.Users["foreign"]["tid"] = tenant
	e.idp.Users["foreign"]["groups"] = []string{"other"}
	b = e.browser()
	b.login("foreign", "")
	if ev := e.kinds("login")[3]; ev.InfraVia != "" || ev.InfraAuditorVia != "" || ev.InfraOverage != "" {
		t.Fatalf("%+v", ev)
	}
	if acc := account(t, b); acc["infraFrom"] != nil {
		t.Fatalf("%v", acc)
	}

	// the claim lapses after claims_absolute while the console session goes on
	b = e.browser()
	e.idp.Users["editor"]["groups"] = []string{infraGroup}
	b.login("editor", "")
	e.clk.Advance(3 * time.Hour)
	if st, _ := b.meta(); st != 200 {
		t.Fatalf("the session itself goes on: %d", st)
	}
	if acc := account(t, b); acc["infraFrom"] != nil {
		t.Fatalf("the group no longer counts: %v", acc)
	}
}

func TestLoginEventRecordsAnOverageThatCostInfra(t *testing.T) {
	roles := "  roles:\n    viewer: [\"*@kazuha.org\", \"*@example.com\"]\n    admin: [kazuha@kazuha.org]\n"
	e := newEnv(t, options{nogit: true, roles: roles, infra: infraLists(t)})
	var many []string
	for i := 0; i < 50; i++ {
		many = append(many, fmt.Sprintf("Role.%02d", i))
	}
	// Entra sent no groups at all (the administrators' claim entry is a group) and 50 roles were cut
	// (the auditors' is an app role, here the 51st): both lists are named
	e.idp.Users["editor"]["roles"] = append(many, "Rackbook.InfraAuditor")
	e.idp.Users["editor"]["hasgroups"] = true
	e.browser().login("editor", "")
	ev := e.kinds("login")[0]
	if ev.Groups != "overage" || ev.AppRoles != "overage" || ev.InfraVia != "" || ev.InfraOverage != "groups,app_roles" {
		t.Fatalf("%+v", ev)
	}
	// a listed identity loses nothing by an overage, and the auditors' claim is a role list that was not cut
	e.idp.Users["admin"]["hasgroups"] = true
	e.browser().login("admin", "")
	if ev := e.kinds("login")[1]; ev.Groups != "overage" || ev.InfraVia != auth.InfraViaIdentity || ev.InfraOverage != "" {
		t.Fatalf("%+v", ev)
	}
}

// An administrator by name who also carries the auditor app role is shown as the administrator by
// name: no lapse, and no auditor line (superseded).
func TestAccountShowsTheInfraCapabilityInForce(t *testing.T) {
	roles := "  roles:\n    admin: [kazuha@kazuha.org]\n    viewer: [\"*@kazuha.org\"]\n"
	e := newEnv(t, options{nogit: true, roles: roles, infra: infraLists(t)})
	e.idp.Users["admin"]["roles"] = []string{"Rackbook.InfraAuditor"}
	b := e.browser()
	b.login("admin", "")
	acc := account(t, b)
	if acc["infraFrom"] != "identity" || acc["infraAuditorFrom"] != "" || acc["infraEnds"] != nil {
		t.Fatalf("%v", acc)
	}
	// an administrator by group who is also an auditor by app role: the administrator's lapse
	e.idp.Users["editor"]["groups"] = []string{infraGroup}
	e.idp.Users["editor"]["roles"] = []string{"Rackbook.InfraAuditor"}
	b = e.browser()
	b.login("editor", "")
	if acc := account(t, b); acc["infraFrom"] != "group" || acc["infraAuditorFrom"] != "" || acc["infraEnds"] == nil {
		t.Fatalf("%v", acc)
	}
}

// What rackbook.yml says about session lifetimes does not change how long the infra claim entry counts.
func TestInfraLapseIgnoresRackbookYml(t *testing.T) {
	e := newEnv(t, options{nogit: true, roles: "  roles:\n    viewer: [\"*@kazuha.org\"]\n", session: "    claims_absolute: 7d\n", infra: infraLists(t)})
	e.idp.Users["editor"]["groups"] = []string{infraGroup}
	b := e.browser()
	b.login("editor", "")
	if acc := account(t, b); acc["infraFrom"] != "group" || acc["infraClaimsAbsolute"] != float64(7200) {
		t.Fatalf("%v", acc)
	}
	e.clk.Advance(3 * time.Hour)
	if acc := account(t, b); acc["infraFrom"] != nil {
		t.Fatalf("the flag's 2 hours apply, not the file's 7 days: %v", acc)
	}
}

// An administrator by group who is also an auditor by name: the page says the read-only access remains.
func TestAccountSaysANamedAuditorRemainsAfterTheClaimLapses(t *testing.T) {
	roles := "  roles:\n    viewer: [\"*@kazuha.org\"]\n"
	e := newEnv(t, options{nogit: true, roles: roles, infra: func(e *env) *auth.InfraAccess {
		admins, _ := auth.NewInfraAdmins([]string{"group:" + infraGroup})
		auditors, _ := auth.NewInfraAuditors([]string{"ed@kazuha.org"})
		for _, l := range []*auth.InfraAdmins{admins, auditors} {
			if err := l.Pin(e.idpS.URL, clientID, "", tenant, 0); err != nil {
				t.Fatal(err)
			}
		}
		return &auth.InfraAccess{Admins: admins, Auditors: auditors}
	}})
	e.idp.Users["editor"]["groups"] = []string{infraGroup}
	b := e.browser()
	b.login("editor", "")
	acc := account(t, b)
	if acc["infraFrom"] != "group" || acc["infraAuditorFrom"] != "" || acc["infraAuditorRemains"] != true || acc["infraEnds"] == nil {
		t.Fatalf("%v", acc)
	}
	// without the group they are the auditor by name, with nothing to lapse
	e.idp.Users["editor"]["groups"] = []string{"other"}
	b = e.browser()
	b.login("editor", "")
	if acc := account(t, b); acc["infraFrom"] != "" || acc["infraAuditorFrom"] != "identity" || acc["infraAuditorRemains"] != nil || acc["infraEnds"] != nil {
		t.Fatalf("%v", acc)
	}
}
