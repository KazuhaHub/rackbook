package api_test

import (
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
)

// The target field of an audit event (design-local-accounts.md, section 10): the account an administrator or
// the command line acted on, when that is not the actor. It reaches the Activity items and the audit log's own
// read, and is absent where there is none.
func TestActivityItemsCarryTheTargetOfAnAuditEvent(t *testing.T) {
	t.Parallel()
	e := newActEnv(t, actOpts{})
	at := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)
	e.log.Record(audit.Event{Event: "account_disabled", Identity: "local:root", Target: "local:alice", Method: "local", Time: at})
	e.log.Record(audit.Event{Event: "login", Identity: editorU, Method: "oidc", Role: "editor", Time: at.Add(time.Minute)})
	_, out := e.get(t, adminU, "/api/activity?limit=50")
	its := items(t, out)
	dis := find(its, "event", "account_disabled")
	if dis == nil || dis["target"] != "local:alice" || dis["identity"] != "local:root" {
		t.Fatalf("%v", dis)
	}
	if login := find(its, "event", "login"); login == nil {
		t.Fatal("no login")
	} else if _, has := login["target"]; has {
		t.Fatalf("an event with no target has none: %v", login)
	}
	// the log itself keeps it, in the line and in the read
	page, err := e.log.Read(audit.Query{Events: []string{"account_disabled"}})
	if err != nil || len(page.Events) != 1 || page.Events[0].Target != "local:alice" {
		t.Fatalf("%v %+v", err, page.Events)
	}
}
