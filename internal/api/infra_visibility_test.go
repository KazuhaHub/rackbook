package api_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
)

// How a person is an infra administrator is for the infra administrators and auditors only: a
// ledger administrator or auditor who is not one sees no such field in the activity, in its
// export, or in the sentence the console would build from it.
func TestInfraViaIsHiddenFromThoseWhoAreNotInfra(t *testing.T) {
	t.Parallel()
	ia, _ := auth.NewInfraAdmins([]string{adminU})
	if err := ia.Pin(testIssuer, testClient, "", testTenant, 0); err != nil {
		t.Fatal(err)
	}
	e := newRolesEnv(t, rolesOpts{infra: &api.InfraOptions{Admins: ia}})
	e.log.Record(audit.Event{Event: "login", Identity: "bob@x.org", Method: "oidc", Role: "viewer", InfraVia: "group", InfraAuditorVia: "app_role", InfraOverage: "groups"})
	e.log.Record(audit.Event{Event: "login", Identity: "eve@x.org", Method: "oidc", Role: "viewer", InfraOverage: "app_roles"})

	get := func(who map[string]string, path string) (int, string) {
		req, _ := http.NewRequest("GET", e.ts.URL+path, nil)
		for k, v := range who {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	// a ledger administrator who is not an infra administrator, and a ledger auditor who is not one
	notInfra := map[string]map[string]string{"ledger admin": as("other-admin@example.com"), "ledger auditor": as("audie@example.com")}
	for name, who := range notInfra {
		for _, path := range []string{"/api/activity?area=audit", "/api/activity?format=jsonl&area=audit"} {
			code, body := get(who, path)
			if code != 200 || !strings.Contains(body, "bob@x.org") {
				t.Fatalf("%s %s: %d %s", name, path, code, body)
			}
			if strings.Contains(body, "infra_") || strings.Contains(body, "app_role") {
				t.Errorf("%s %s shows infra fields: %s", name, path, body)
			}
		}
	}
	// the infra administrator (who is also a ledger administrator) sees them
	for _, path := range []string{"/api/activity?area=audit", "/api/activity?format=jsonl&area=audit"} {
		code, body := get(as(adminU), path)
		if code != 200 || !strings.Contains(body, `"infra_via":"group"`) || !strings.Contains(body, `"infra_auditor_via":"app_role"`) || !strings.Contains(body, `"infra_overage":"groups"`) {
			t.Errorf("%s: %d %s", path, code, body)
		}
	}
}
