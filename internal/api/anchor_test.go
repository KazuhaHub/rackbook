package api_test

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/anchor"
	"github.com/kazuhahub/rackbook/internal/audit"
)

// raw is a response as text, to look for a commit anywhere in it.
func (e *actEnv) raw(t *testing.T, who, path string) (int, string) {
	t.Helper()
	code, out := e.get(t, who, path)
	b, _ := json.Marshal(out)
	return code, string(b)
}

func TestAnchorCommitsAreForAdministratorsAndAuditorsOnly(t *testing.T) {
	e := newActEnv(t, actOpts{})
	// an ordinary write, so there are records, versions and an audit log to compare with
	code, created, _ := e.do(t, "POST", "/api/c/todo", map[string]any{"data": map[string]any{"item": "first", "status": "待办"}}, map[string]string{"X-User": editorU})
	if code != 201 {
		t.Fatalf("%d %v", code, created)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("%v", created)
	}

	// the anchor, as the anchor job writes it: through the store, as Rackbook itself
	seq, hash := e.log.Head()
	a := audit.Anchor{Day: "2026-11-20", Seq: seq, Hash: hash, At: "2026-11-20T10:00:00Z"}
	subject := "audit: anchor seq " + strconv.FormatInt(seq, 10)
	res, err := e.store.MutateStateFile(context.Background(), audit.AnchorsPath, subject, anchor.Identity,
		func(old []byte, _ bool) ([]byte, error) { return append(old, a.Line()...), nil })
	if err != nil || res.Commit == "" {
		t.Fatalf("%+v %v", res, err)
	}
	// and a deleted record, so the deleted list has something in it too
	if code, out, _ := e.do(t, "DELETE", "/api/c/todo/"+id+"?hash="+created["hash"].(string), nil, map[string]string{"X-User": adminU}); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	_, act := e.get(t, adminU, "/api/activity?limit=200")
	item := find(items(t, act), "subject", subject)
	if item == nil {
		t.Fatalf("administrators must see the anchor commit: %v", act)
	}
	if item["state"] != "only" || item["identity"] != anchor.Identity.ID || item["verified"] != true || item["area"] != "ledger" {
		t.Fatalf("%v", item)
	}
	fullHash := item["hash"].(string)

	paths := []string{
		"/api/activity?limit=200",
		"/api/history?limit=200",
		"/api/c/todo/" + id + "/history",
		"/api/c/todo/deleted",
		"/api/check",
		"/api/activity/commit/ledger/" + fullHash,
	}
	for _, who := range []string{viewerU, editorU, infraU, infraAuditU} {
		for _, p := range paths {
			code, body := e.raw(t, who, p)
			// A deleted record's "last" is the commit before its deletion: an opaque revision that
			// can be the anchor commit, as it can be any other state commit. The hash is no leak
			// of what the commit says; the subject, the identity and the diff are checked.
			hashLeak := strings.Contains(body, fullHash) && p != "/api/c/todo/deleted"
			if strings.Contains(body, "audit: anchor") || hashLeak || strings.Contains(body, anchor.Identity.ID) {
				t.Errorf("%s sees the anchor commit in %s: %s", who, p, body)
			}
			if p == "/api/activity/commit/ledger/"+fullHash && code != 404 {
				t.Errorf("%s: the anchor commit's diff is %d, not 404", who, code)
			}
		}
		if code, _ := e.get(t, who, "/api/audit/status"); code != 403 {
			t.Errorf("%s: the audit status is %d", who, code)
		}
	}
	for _, who := range []string{adminU, auditU, eveU} {
		code, d := e.get(t, who, "/api/activity/commit/ledger/"+fullHash)
		if code != 200 || len(arr(t, d["files"])) != 1 || arr(t, d["files"])[0].(map[string]any)["path"] != audit.AnchorsPath {
			t.Errorf("%s: %d %v", who, code, d)
		}
		if _, out := e.get(t, who, "/api/activity?limit=200"); find(items(t, out), "subject", subject) == nil {
			t.Errorf("%s must see the anchor commit", who)
		}
	}
	// an anchor problem is an audit problem: the same banner and status as any other, for
	// administrators and auditors
}

func TestAnchorProblemsShowInTheStatusAndTheBanner(t *testing.T) {
	e := newActEnv(t, actOpts{})
	e.log.Record(audit.Event{Event: "login", Identity: "x"})
	e.log.Record(audit.Event{Event: "login", Identity: "x"})
	bad := audit.Anchor{Day: "2026-11-19", Seq: 2, Hash: "sha256:" + strings.Repeat("0", 64), At: "2026-11-19T10:00:00Z"}
	if _, err := e.log.CheckAnchors(bad.Line()); err != nil {
		t.Fatal(err)
	}
	code, st := e.get(t, adminU, "/api/audit/status")
	probs := arr(t, st["problems"])
	if code != 200 || st["ok"] != false || len(probs) != 1 {
		t.Fatalf("%d %v", code, st)
	}
	p := probs[0].(map[string]any)
	if p["kind"] != "anchor_mismatch" || p["seq"] != float64(2) || !strings.Contains(p["detail"].(string), "2026-11-19") {
		t.Fatalf("%v", p)
	}
	if _, m := e.get(t, auditU, "/api/meta"); m["auditAlert"] == nil {
		t.Fatalf("the banner: %v", m)
	}
	if _, m := e.get(t, viewerU, "/api/meta"); m["auditAlert"] != nil {
		t.Fatalf("viewers get no banner: %v", m)
	}
	// acknowledging it works as for any chain problem, and is for administrators
	if code, _, _ := e.do(t, "POST", "/api/audit/ack", map[string]any{"through": p["recordedAt"]}, map[string]string{"X-User": adminU}); code != 200 {
		t.Fatalf("ack: %d", code)
	}
	if _, st = e.get(t, adminU, "/api/audit/status"); st["ok"] != true {
		t.Fatalf("%v", st)
	}
}
