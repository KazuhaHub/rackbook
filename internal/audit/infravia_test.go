package audit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/ansiblerepo"
	"github.com/kazuhahub/rackbook/internal/auth"
)

// infra_via says how the person was an infra administrator: on an infra commit (through the
// identity the edit carries) and on an infra entry that ended in no commit.
func TestInfraViaIsOnInfraEvents(t *testing.T) {
	var commit Event
	commit.By(&auth.Identity{ID: "bob@x.org", Method: auth.MethodOIDC, InfraVia: auth.InfraViaGroup})
	if commit.InfraVia != "group" {
		t.Fatalf("%+v", commit)
	}
	e := FromInfra(ansiblerepo.AuditEntry{Who: "bob@x.org", Action: "infra(secrets/alpha): reveal k", Outcome: "revealed", Via: auth.InfraViaAppRole})
	if e.Event != "secret_revealed" || e.InfraVia != "app_role" {
		t.Fatalf("%+v", e)
	}
	raw, _ := json.Marshal(e)
	if !strings.Contains(string(raw), `"infra_via":"app_role"`) {
		t.Fatalf("%s", raw)
	}
	// nothing is written for an event that has no such field (every other event, and old entries)
	for _, ev := range []Event{{Event: "login"}, FromInfra(ansiblerepo.AuditEntry{Outcome: "conflict"})} {
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), "infra_") {
			t.Fatalf("%s", raw)
		}
	}
}
