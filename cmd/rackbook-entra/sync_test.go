package main

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFirstRunCreatesThenIsIdempotent(t *testing.T) {
	e := newEnv(t)
	e.graph.throttle = 1
	res := e.run(false)
	if res.Created != 4 || res.Updated != 0 || res.Revoked != 0 || res.Failed != 0 {
		t.Fatalf("first run = %+v", res)
	}
	if !reflect.DeepEqual(e.sleeps, []time.Duration{2 * time.Second}) {
		t.Errorf("sleeps = %v", e.sleeps)
	}
	if len(e.rb.records) != 4 {
		t.Fatalf("records = %d", len(e.rb.records))
	}
	// excluded app, undated credential and superseded credential have no record
	for _, k := range []string{kx, k3, k5} {
		for n := range e.rb.records {
			if strings.HasSuffix(n, k[:8]) {
				t.Errorf("unexpected record %s", n)
			}
		}
	}
	// cert beats password for k2
	r2 := e.rb.get(name("billing-service", k2))
	if r2["kind"] != "client_cert" || r2["self_signed"] != true {
		t.Errorf("k2 = %v", r2)
	}
	r1 := e.rb.get(name("billing-service", k1))
	if r1 == nil {
		t.Fatalf("missing k1 record: %v", e.rb.records)
	}
	want := map[string]any{
		"name": name("billing-service", k1), "source": "entra", "kind": "api_token",
		"purpose":    `Entra application "Billing Service!": client secret "prod"`,
		"expires":    "2027-03-01",
		"not_before": "2026-03-01",
		"kid":        k1,
		"ids":        []any{"entra_app_id=" + appA, "entra_tenant_id=" + testTenant},
		"owner":      "ops", "used_by": []any{"all"},
	}
	if !reflect.DeepEqual(norm(r1), norm(want)) {
		t.Errorf("k1 = %v\nwant %v", r1, want)
	}
	if _, ok := r1["revoked"]; ok {
		t.Error("live record has revoked")
	}
	if r6 := e.rb.get(name("daemon", k6)); r6 == nil || !strings.Contains(r6["purpose"].(string), "client secret") {
		t.Errorf("k6 = %v", r6)
	}
	if r4 := e.rb.get(name("legacy", k4)); r4 == nil {
		t.Error("missing k4")
	}

	w := e.rb.writeCount()
	res = e.run(false)
	if res.writes() != 0 || e.rb.writeCount() != w {
		t.Fatalf("second run wrote: %+v", res)
	}
	if e.tok.hits != 1 {
		t.Errorf("token requests = %d, want 1 (cached)", e.tok.hits)
	}
}

func TestExpiryChangeUpdatesOnlyOwnedFields(t *testing.T) {
	e := newEnv(t)
	e.run(false)
	n := name("billing-service", k1)
	e.rb.setField(n, "owner", "alice")
	e.graph.pages[0][0].PasswordCredentials[0].End = tm("2028-03-01T10:00:00Z")
	e.graph.sps[0].PasswordCredentials[0].End = tm("2028-03-01T10:00:00Z")
	res := e.run(false)
	if res.Updated != 1 || res.writes() != 1 {
		t.Fatalf("res = %+v", res)
	}
	r := e.rb.get(n)
	if r["expires"] != "2028-03-01" || r["owner"] != "alice" {
		t.Errorf("record = %v", r)
	}
	if res = e.run(false); res.writes() != 0 {
		t.Errorf("not idempotent: %+v", res)
	}
}

func TestVanishedCredentialIsRevokedNotDeleted(t *testing.T) {
	e := newEnv(t)
	e.run(false)
	e.graph.sps[1].PasswordCredentials = nil
	res := e.run(false)
	if res.Revoked != 1 || res.writes() != 1 {
		t.Fatalf("res = %+v", res)
	}
	r := e.rb.get(name("daemon", k6))
	if r == nil || r["revoked"] != "2026-11-18" {
		t.Fatalf("record = %v", r)
	}
	if res = e.run(false); res.writes() != 0 {
		t.Errorf("revoked again: %+v", res)
	}
}

func TestSupersededCredentialIsRevoked(t *testing.T) {
	e := newEnv(t)
	n := name("legacy", k3)
	e.rb.seed(n, map[string]any{"source": "entra", "kid": k3, "kind": "api_token", "expires": "2026-01-01", "owner": "ops"})
	res := e.run(false)
	if res.Revoked != 1 {
		t.Fatalf("res = %+v", res)
	}
	if e.rb.get(n)["revoked"] != "2026-11-18" {
		t.Errorf("record = %v", e.rb.get(n))
	}
}

func TestExpiredWithoutSuccessorStaysLive(t *testing.T) {
	e := newEnv(t)
	e.graph.pages[1][1].PasswordCredentials = e.graph.pages[1][1].PasswordCredentials[:1]
	res := e.run(false)
	if res.Created != 4 {
		t.Fatalf("res = %+v", res)
	}
	if r := e.rb.get(name("legacy", k3)); r == nil || r["expires"] != "2026-01-01" {
		t.Errorf("record = %v", r)
	}
}

func TestManualRecordsAreNeverTouched(t *testing.T) {
	e := newEnv(t)
	e.rb.seed("manual-one", map[string]any{"kind": "api_token", "kid": "unrelated", "expires": "2020-01-01"})
	e.rb.seed("manual-two", map[string]any{"kind": "api_token", "source": "manual", "expires": "2021-01-01"})
	before1, before2 := hashOf(e.rb.get("manual-one")), hashOf(e.rb.get("manual-two"))
	e.run(false)
	e.graph.sps[1].PasswordCredentials = nil
	e.run(false)
	if hashOf(e.rb.get("manual-one")) != before1 || hashOf(e.rb.get("manual-two")) != before2 {
		t.Error("manual record changed")
	}
}

func TestManualCoverageSkipsCreate(t *testing.T) {
	e := newEnv(t)
	e.rb.seed("by-kid", map[string]any{"kind": "api_token", "kid": strings.ToUpper(k6)})
	e.rb.seed("by-ids", map[string]any{"kind": "api_token", "ids": []any{"entra_app_id=" + appC}, "expires": "2027-09-01"})
	e.rb.seed("other-expiry", map[string]any{"kind": "api_token", "ids": []any{"entra_app_id=" + appA}, "expires": "2030-01-01"})
	res := e.run(false)
	if res.Created != 2 {
		t.Fatalf("res = %+v (k1 and k2 expected)", res)
	}
	if e.rb.get(name("daemon", k6)) != nil || e.rb.get(name("legacy", k4)) != nil {
		t.Error("covered credential was created")
	}
	if res = e.run(false); res.writes() != 0 {
		t.Errorf("second run wrote: %+v", res)
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	e := newEnv(t)
	e.rb.seed(name("daemon", k6), map[string]any{"source": "entra", "kid": k6, "kind": "api_token", "expires": "2020-01-01", "ids": []any{}})
	e.rb.seed(name("gone", "deadbeef-0"), map[string]any{"source": "entra", "kid": "deadbeef-0", "kind": "api_token"})
	w := e.rb.writeCount()
	res := e.run(true)
	if res.writes() != 0 || e.rb.writeCount() != w {
		t.Fatalf("dry run wrote: %+v", res)
	}
	out := e.out.String()
	for _, want := range []string{"create " + name("billing-service", k1), "update " + name("daemon", k6) + ": expires, ids, purpose", "revoke " + name("gone", "deadbeef-0")} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %q:\n%s", want, out)
		}
	}
}

func TestForeignNextLinkFails(t *testing.T) {
	e := newEnv(t)
	e.graph.nextHost = "http://evil.example.test/v1.0"
	_, err := e.a.syncOnce(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "nextLink") {
		t.Fatalf("err = %v", err)
	}
	if e.rb.writeCount() != 0 {
		t.Error("wrote after a failed read")
	}
}

func TestThrottleGivesUpAfterFiveAttempts(t *testing.T) {
	e := newEnv(t)
	e.graph.always = 503
	_, err := e.a.syncOnce(context.Background(), false)
	if err == nil {
		t.Fatal("want error")
	}
	if e.graph.hits != 5 || len(e.sleeps) != 4 {
		t.Errorf("hits=%d sleeps=%v", e.graph.hits, e.sleeps)
	}
}

func TestWriteRefusedAndConflictDoNotFail(t *testing.T) {
	e := newEnv(t)
	e.rb.denyAll = true
	res := e.run(false)
	if res.Denied != 4 || res.Failed != 0 {
		t.Errorf("denied run = %+v", res)
	}
	e.rb.denyAll = false
	e.rb.conflict = true
	res = e.run(false)
	if res.Conflicts != 4 || res.Failed != 0 {
		t.Errorf("conflict run = %+v", res)
	}
}

func TestOtherWriteErrorsFail(t *testing.T) {
	e := newEnv(t)
	e.rb.srv.Close()
	if _, err := e.a.syncOnce(context.Background(), false); err == nil {
		t.Fatal("want error when Rackbook is unreachable")
	}
}

func TestSlugAndFamily(t *testing.T) {
	cases := map[string]string{
		"Billing Service!": "billing-service", "  --A__b  ": "a-b", "日本語": "app", "": "app",
		strings.Repeat("a", 39) + " bcd": strings.Repeat("a", 39),
	}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
	if family("secret [2025] ") != "secret" || family("[x]") != "" || family("a [b] c") != "a [b] c" {
		t.Error("family")
	}
}
