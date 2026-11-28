package api_test

import (
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/ansiblerepo"
	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/auth"
)

const (
	claimRole  = "Rackbook.InfraAdmin"
	claimGroup = "7d1c0b52-0000-4000-8000-000000000002"
	claimUser  = "claim@kazuha.org"
)

// newClaimEnv is an infra deployment whose administrators are one identity and one app role,
// and whose auditors are one group.
func newClaimEnv(t *testing.T) *wEnv {
	t.Helper()
	return newWEnv(t, func(o *api.Options, io *api.InfraOptions) {
		ia, err := auth.NewInfraAdmins([]string{"me@kazuha.org", "app-role:" + claimRole})
		if err != nil {
			t.Fatal(err)
		}
		au, err := auth.NewInfraAuditors([]string{"group:" + claimGroup})
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range []*auth.InfraAdmins{ia, au} {
			if err := l.Pin(testIssuer, testClient, "", testTenant, 12*time.Hour); err != nil {
				t.Fatal(err)
			}
		}
		io.Admins, io.Auditors = ia, au
	})
}

func claimAs(kv ...string) map[string]string {
	h := map[string]string{"X-User": claimUser}
	for i := 0; i+1 < len(kv); i += 2 {
		h[kv[i]] = kv[i+1]
	}
	return h
}

func TestInfraAdminByAppRoleSeesAndEdits(t *testing.T) {
	t.Parallel()
	e := newClaimEnv(t)
	admin := claimAs("X-App-Roles", claimRole)
	_, m, _ := e.do(t, "GET", "/api/meta", nil, admin)
	if u := m["user"].(map[string]any); u["canInfra"] != true || u["canInfraWrite"] != true || u["infraAuditor"] != nil {
		t.Fatalf("%v", u)
	}
	path := "/api/infra/hosts/alpha/vars"
	base := e.base(t, path) // as the identity administrator
	body := map[string]any{"base": base, "content": wAlpha + "x: 1\n", "preview": true}
	if code, out, _ := e.do(t, "POST", path, body, admin); code != 200 {
		t.Fatalf("a fresh administrator by app role: %d %v", code, out)
	}
	// the sign-in is older than the write age (12 hours) but inside claims_absolute: the read stays, the write asks to sign in again
	old := claimAs("X-App-Roles", claimRole, "X-Signed-In-Age", "50000")
	if code, _, _ := e.do(t, "GET", "/api/infra/hosts", nil, old); code != 200 {
		t.Fatalf("read at 14 hours: %d", code)
	}
	if code, out, _ := e.do(t, "POST", path, body, old); code != 403 || out["error"] != "reauth_required" {
		t.Fatalf("the write age applies on top: %d %v", code, out)
	}
}

// Past claims_absolute the claim no longer counts: the ledger session may go on, the infra
// capability does not, and a listed identity is not touched.
func TestInfraClaimLapsesButTheIdentityDoesNot(t *testing.T) {
	t.Parallel()
	e := newClaimEnv(t)
	for _, c := range []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"app role, 23 hours in", claimAs("X-App-Roles", claimRole, "X-Signed-In-Age", "82800"), 200},
		{"app role, 25 hours in", claimAs("X-App-Roles", claimRole, "X-Signed-In-Age", "90000"), 403},
		{"app role, 100 hours in", claimAs("X-App-Roles", claimRole, "X-Signed-In-Age", "360000"), 403},
		{"auditor group, 25 hours in", claimAs("X-Groups", claimGroup, "X-Signed-In-Age", "90000"), 403},
		{"auditor group, 23 hours in", claimAs("X-Groups", claimGroup, "X-Signed-In-Age", "82800"), 200},
		{"listed identity, 100 hours in", map[string]string{"X-User": "me@kazuha.org", "X-Signed-In-Age": "360000"}, 200},
	} {
		if code, out, _ := e.do(t, "GET", "/api/infra/hosts", nil, c.hdr); code != c.want {
			t.Errorf("%s: %d %v, want %d", c.name, code, out, c.want)
		}
	}
	// the clock moves on: the same session, replayed later, loses it
	hdr := claimAs("X-App-Roles", claimRole)
	if code, _, _ := e.do(t, "GET", "/api/infra/hosts", nil, hdr); code != 200 {
		t.Fatalf("before: %d", code)
	}
	e.now = e.now.Add(25 * time.Hour)
	if code, _, _ := e.do(t, "GET", "/api/infra/hosts", nil, map[string]string{"X-User": claimUser, "X-App-Roles": claimRole, "X-Signed-In-Age": "90060"}); code != 403 {
		t.Fatalf("replayed after claims_absolute: %d", code)
	}
}

func TestInfraAuditorByGroupIsReadOnly(t *testing.T) {
	t.Parallel()
	e := newClaimEnv(t)
	aud := claimAs("X-Groups", claimGroup)
	_, m, _ := e.do(t, "GET", "/api/meta", nil, aud)
	if u := m["user"].(map[string]any); u["canInfra"] != true || u["infraAuditor"] != true || u["canInfraWrite"] != nil {
		t.Fatalf("%v", u)
	}
	if code, _, _ := e.do(t, "GET", "/api/infra/hosts", nil, aud); code != 200 {
		t.Fatalf("%d", code)
	}
	path := "/api/infra/hosts/alpha/vars"
	body := map[string]any{"base": e.base(t, path), "content": wAlpha + "x: 1\n", "preview": true}
	if code, out, _ := e.do(t, "POST", path, body, aud); code != 403 || out["error"] != "forbidden" {
		t.Fatalf("%d %v", code, out)
	}
}

// What an infra administrator does is recorded with how they are one.
func TestInfraAuditRecordsHowTheAdministratorIsOne(t *testing.T) {
	t.Parallel()
	e := newClaimEnv(t)
	path := "/api/infra/hosts/alpha/vars"
	base := e.base(t, path)
	edit := map[string]any{"base": base, "content": wAlpha + "x: 1\n"}
	// a refusal for a stale sign-in, by app role, and by identity
	e.do(t, "POST", path, edit, claimAs("X-App-Roles", claimRole, "X-Signed-In-Age", "50000"))
	e.do(t, "POST", path, edit, map[string]string{"X-User": "me@kazuha.org", "X-Signed-In-Age": "50000"})
	// and a person who is not an administrator
	e.do(t, "POST", path, edit, claimAs("X-Groups", claimGroup))
	e.audit.mu.Lock()
	entries := append([]ansiblerepo.AuditEntry(nil), e.audit.e...)
	e.audit.mu.Unlock()
	if len(entries) != 3 {
		t.Fatalf("%v", entries)
	}
	for i, want := range []struct{ who, outcome, via string }{
		{claimUser, "reauth_required", auth.InfraViaAppRole},
		{"me@kazuha.org", "reauth_required", auth.InfraViaIdentity},
		{claimUser, "forbidden", ""},
	} {
		got := entries[i]
		if got.Who != want.who || got.Outcome != want.outcome || got.Via != want.via {
			t.Errorf("entry %d: %+v, want %+v", i, got, want)
		}
	}
	// an edit the checks refuse is recorded by the repository, with the same field
	e.do(t, "POST", path, map[string]any{"base": base, "content": "tailscale_ip: [\n"}, claimAs("X-App-Roles", claimRole))
	e.audit.mu.Lock()
	entries = append([]ansiblerepo.AuditEntry(nil), e.audit.e...)
	e.audit.mu.Unlock()
	if last := entries[len(entries)-1]; len(entries) != 4 || last.Who != claimUser || last.Via != auth.InfraViaAppRole {
		t.Fatalf("%+v", entries)
	}
}
