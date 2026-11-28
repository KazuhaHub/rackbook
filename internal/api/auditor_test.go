package api_test

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/mcpserver"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

// The auditor capability (docs/design-audit.md, 3.4): a separate list, not a
// role. These tests walk the people the design names: viewer, editor, admin,
// auditor (no role), auditor with the editor role.

func TestAuditorMetaShowsTheCapabilityApartFromTheRole(t *testing.T) {
	t.Parallel()
	e := newActEnv(t, actOpts{})
	for _, c := range []struct {
		who               string
		role              string
		auditor           bool
		canEdit, canAdmin bool
	}{
		{viewerU, "viewer", false, false, false},
		{editorU, "editor", false, true, false},
		{adminU, "admin", false, true, true}, // an admin is not an auditor
		{auditU, "viewer", true, false, false},
		{eveU, "editor", true, true, false},
	} {
		code, m := e.get(t, c.who, "/api/meta")
		if code != 200 {
			t.Fatalf("%s: %d %v", c.who, code, m)
		}
		u := m["user"].(map[string]any)
		if u["role"] != c.role || (u["auditor"] == true) != c.auditor || u["canEdit"] != c.canEdit || u["canAdmin"] != c.canAdmin {
			t.Errorf("%s: %v", c.who, u)
		}
	}
	// infra: the two flags are separate lists and read-only for the auditors
	for _, c := range []struct {
		who                     string
		canInfra, auditor, edit bool
	}{
		{infraU, true, false, false}, // writes are not switched on in this fixture
		{infraAuditU, true, true, false},
		{auditU, false, false, false},
		{adminU, false, false, false},
	} {
		_, m := e.get(t, c.who, "/api/meta")
		u := m["user"].(map[string]any)
		if (u["canInfra"] == true) != c.canInfra || (u["infraAuditor"] == true) != c.auditor || (u["canInfraWrite"] == true) != c.edit {
			t.Errorf("%s: %v", c.who, u)
		}
	}
}

// Every visibility class of canSee for every kind of caller.
func TestAuditorEveryVisibilityClass(t *testing.T) {
	t.Parallel()
	e := newActEnv(t, actOpts{})
	e.laptopCommit(t, "2026-03-01T10:00:00Z", "state only", map[string]string{".rackbook/x.yml": "a: 1\n"})
	e.laptopCommit(t, "2026-03-02T10:00:00Z", "ledger edit", map[string]string{"notes.txt": "hi\n"})
	e.log.Record(audit.Event{Event: "login", Identity: editorU, Method: "oidc", Role: "editor", Addr: "203.0.113.0", Time: time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)})
	e.log.Record(audit.Event{Event: "secret_revealed", Area: "infra", Identity: infraU, Host: "alpha", Time: time.Date(2026, 3, 2, 9, 5, 0, 0, time.UTC)})
	sh(t, e.infraSeed, "commit", "--allow-empty", "-qm", "infra change")
	sh(t, e.infraSeed, "push", "-q", "origin", "HEAD:refs/heads/main")
	if err := e.infra.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, out := e.get(t, adminU, "/api/activity?limit=200")
	stateHash := find(items(t, out), "subject", "state only")["hash"].(string)

	for _, c := range []struct {
		who                                                      string
		seeLedger, seeState, seeAudit, seeExport, seeInfra, addr bool
	}{
		{viewerU, true, false, false, false, false, false},
		{editorU, true, false, false, false, false, false},
		{adminU, true, true, true, true, false, true},
		{auditU, true, true, true, true, false, true},
		{eveU, true, true, true, true, false, true},
		{infraU, true, false, false, false, true, false},
		{infraAuditU, true, false, false, false, true, false},
	} {
		_, out := e.get(t, c.who, "/api/activity?limit=200")
		its := items(t, out)
		if (find(its, "subject", "ledger edit") != nil) != c.seeLedger {
			t.Errorf("%s: ledger", c.who)
		}
		state := find(its, "subject", "state only")
		if (state != nil) != c.seeState || (state != nil && state["state"] != "only") {
			t.Errorf("%s: state %v", c.who, state)
		}
		login := find(its, "kind", "login")
		if (login != nil) != c.seeAudit || (login != nil && (login["addr"] != nil) != c.addr) {
			t.Errorf("%s: audit %v", c.who, login)
		}
		if (find(its, "kind", "secret_revealed") != nil) != c.seeInfra || (find(its, "subject", "infra change") != nil) != c.seeInfra {
			t.Errorf("%s: infra", c.who)
		}
		req, _ := http.NewRequest("GET", e.ts.URL+"/api/activity?format=jsonl", nil)
		req.Header.Set("X-User", c.who)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if (resp.StatusCode == 200) != c.seeExport {
			t.Errorf("%s: export %d", c.who, resp.StatusCode)
		}
		// the diff of a .rackbook/ commit follows seeState
		code, _ := e.get(t, c.who, "/api/activity/commit/ledger/"+stateHash)
		if (code == 200) != c.seeState {
			t.Errorf("%s: state diff %d", c.who, code)
		}
		// the status follows seeAudit
		code, _ = e.get(t, c.who, "/api/audit/status")
		if (code == 200) != c.seeAudit {
			t.Errorf("%s: status %d", c.who, code)
		}
		// nobody but an administrator acknowledges
		code, body, _ := e.do(t, "POST", "/api/audit/ack", map[string]any{"through": 1}, map[string]string{"X-User": c.who})
		if (c.who == adminU) != (code != 403) || (c.who != adminU && body["error"] != "forbidden") {
			t.Errorf("%s: ack %d %v", c.who, code, body)
		}
	}
	// the client address of an audit event is an audit-class value: an auditor's export carries it
	req, _ := http.NewRequest("GET", e.ts.URL+"/api/activity?format=jsonl&area=audit", nil)
	req.Header.Set("X-User", auditU)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b := make([]byte, 1<<16)
	n, _ := resp.Body.Read(b)
	if !strings.Contains(string(b[:n]), "203.0.113.0") {
		t.Errorf("the auditor's export has no addr: %s", b[:n])
	}
}

// Auditors may not take any step an admin takes beyond reading, and may not
// write anywhere. The routes come from the mux itself, so a route added later is
// walked too.
func TestAuditorNeverGets2xxOnAWriteRoute(t *testing.T) {
	t.Parallel()
	e := newActEnv(t, actOpts{})
	pats := api.RoutePatterns(e.opts)
	if len(pats) < 30 {
		t.Fatalf("only %d patterns: the walk is not seeing the mux", len(pats))
	}
	head := sh(t, e.infraSeed, "rev-parse", "HEAD")
	fill := strings.NewReplacer("{collection}", "todo", "{id}", "no-such-id", "{name}", "alpha", "{hash}", head, "{commit}", head, "{feature}", "beszel-agent", "{area}", "ledger")
	// writes that every signed-in person may make to their own state
	selfService := map[string]bool{"PUT /api/account/preferences": true}
	// one API token exists, made by the administrator: the auditors must not be able to touch it
	if code, body, _ := e.do(t, "POST", "/api/admin/tokens", map[string]any{"name": "ci", "scope": "read"}, map[string]string{"X-User": adminU}); code != 201 {
		t.Fatalf("create token: %d %v", code, body)
	}
	serverHead := sh(t, e.dir, "rev-parse", "HEAD")
	infraHead := sh(t, e.infraSeed, "rev-parse", "HEAD")
	walked := 0
	for _, who := range []string{auditU, infraAuditU} { // the ledger auditor and the infra auditor, both with the viewer floor
		for _, pat := range pats {
			method, path, ok := strings.Cut(pat, " ")
			if !ok || method == http.MethodGet || method == http.MethodHead || selfService[pat] {
				continue
			}
			walked++
			code, body, _ := e.do(t, method, fill.Replace(path), map[string]any{}, map[string]string{"X-User": who})
			if code != http.StatusForbidden {
				t.Errorf("%s as %s: %d %v (want 403)", pat, who, code, body)
			}
		}
		// the routes without a method of their own answer every method
		for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
			for _, p := range []string{"/api/c/todo", "/api/nothing", "/api/infra/groups"} {
				if code, body, _ := e.do(t, m, p, map[string]any{}, map[string]string{"X-User": who}); code >= 200 && code < 300 {
					t.Errorf("%s %s as %s: %d %v", m, p, who, code, body)
				}
			}
		}
	}
	if walked < 20 {
		t.Fatalf("walked %d write routes", walked)
	}
	if got := sh(t, e.dir, "rev-parse", "HEAD"); got != serverHead {
		t.Fatal("an auditor's request committed to the ledger")
	}
	if got := sh(t, e.infraSeed, "rev-parse", "HEAD"); got != infraHead {
		t.Fatal("an auditor's request committed to the infra repository")
	}
	// the token is still there, and an auditor who is also an editor is refused every admin-only write route
	if _, list, _ := e.do(t, "GET", "/api/admin/tokens", nil, map[string]string{"X-User": adminU}); len(list["tokens"].([]any)) != 1 {
		t.Fatalf("the token list changed: %v", list)
	}
	for _, pat := range pats {
		method, path, _ := strings.Cut(pat, " ")
		if method == http.MethodGet || !(strings.HasPrefix(path, "/api/admin/") || strings.HasPrefix(path, "/api/types") || strings.HasPrefix(path, "/api/modules/") || path == "/api/audit/ack") {
			continue
		}
		if code, body, _ := e.do(t, method, fill.Replace(path), map[string]any{}, map[string]string{"X-User": eveU}); code != http.StatusForbidden {
			t.Errorf("%s as an auditor+editor: %d %v (want 403)", pat, code, body)
		}
	}
	// the one write an auditor may make is to their own preferences
	if code, _, _ := e.do(t, "PUT", "/api/account/preferences", map[string]any{"locale": "en-US"}, map[string]string{"X-User": auditU}); code != 200 {
		t.Fatalf("preferences: %d", code)
	}
	// an auditor with the editor role keeps writing (the capability takes nothing away)
	code, body, _ := e.do(t, "POST", "/api/c/todo", map[string]any{"data": map[string]any{"item": "eve's", "status": "待办"}}, map[string]string{"X-User": eveU})
	if code != 201 {
		t.Fatalf("auditor+editor: %d %v", code, body)
	}
	// ... but not the admin-only ones
	if code, _, _ := e.do(t, "POST", "/api/audit/ack", map[string]any{"through": 1}, map[string]string{"X-User": eveU}); code != 403 {
		t.Fatalf("auditor+editor ack: %d", code)
	}
	if code, _, _ := e.do(t, "POST", "/api/admin/tokens", map[string]any{"name": "x", "scope": "read"}, map[string]string{"X-User": eveU}); code == 201 {
		t.Fatal("auditor+editor created a token")
	}
	// Restore is a write: an auditor without the editor role is refused, and the
	// console is told (user.canEdit is false) so it never shows the button.
	_, m := e.get(t, auditU, "/api/meta")
	if m["user"].(map[string]any)["canEdit"] != false {
		t.Fatalf("%v", m["user"])
	}
}

// infraRouteClass says what each /api/infra route is. A route that is not here
// fails TestInfraRouteClasses until it is classified.
//
//	read    infra administrators and infra auditors
//	secret  infra administrators (secrets, and the raw host_vars file)
//	write   infra administrators (edits, groups, reverts)
var infraRouteClass = map[string]string{
	"GET /api/infra/hosts":                            "read",
	"GET /api/infra/hosts/{name}":                     "read",
	"GET /api/infra/certs":                            "read",
	"GET /api/infra/iplists":                          "read",
	"GET /api/infra/commits":                          "read",
	"GET /api/infra/write":                            "read",
	"GET /api/infra/features":                         "read",
	"GET /api/infra/groups":                           "read",
	"GET /api/infra/hosts/{name}/vars":                "secret",
	"GET /api/infra/hosts/{name}/secrets":             "secret",
	"POST /api/infra/hosts/{name}/secrets/reveal":     "secret",
	"POST /api/infra/hosts/{name}/secrets/set":        "secret",
	"POST /api/infra/hosts/{name}/secrets/unset":      "secret",
	"POST /api/infra/hosts/{name}/secrets/reencrypt":  "secret",
	"POST /api/infra/hosts/{name}/vars":               "write",
	"POST /api/infra/hosts/{name}/features/{feature}": "write",
	"POST /api/infra/groups":                          "write",
	"POST /api/infra/commits/{hash}/revert":           "write",
}

func TestInfraRouteClasses(t *testing.T) {
	t.Parallel()
	const auditorU, neitherU, claimU = "aud@kazuha.org", "editor@kazuha.org", "claim@kazuha.org"
	const adminRole, auditGroup = "Rackbook.InfraAdmin", "7d1c0b52-0000-4000-8000-000000000001"
	var opts api.Options
	s := newSEnv(t, func(o *api.Options, io *api.InfraOptions) {
		// an administrator by identity and one by app role; an auditor by identity and one by group
		admins, err := auth.NewInfraAdmins([]string{"me@kazuha.org", "app-role:" + adminRole})
		if err != nil {
			t.Fatal(err)
		}
		if err := admins.Pin(testIssuer, testClient, "", testTenant, 12*time.Hour); err != nil {
			t.Fatal(err)
		}
		io.Admins = admins
		ia, err := auth.NewInfraAuditors([]string{auditorU, "group:" + auditGroup})
		if err != nil {
			t.Fatal(err)
		}
		if err := ia.Pin(testIssuer, testClient, "", testTenant, 12*time.Hour); err != nil {
			t.Fatal(err)
		}
		io.Auditors = ia
		o.Infra = io
		opts = *o
	}, nil)

	// every infra route is classified, and every class names a real route
	got := map[string]bool{}
	for _, p := range api.RoutePatterns(opts) {
		if strings.Contains(p, "/api/infra/") {
			got[p] = true
			if infraRouteClass[p] == "" {
				t.Errorf("%s is not classified as read, secret or write", p)
			}
		}
	}
	for p := range infraRouteClass {
		if !got[p] {
			t.Errorf("%s is classified but is not a route", p)
		}
	}
	if t.Failed() {
		return
	}

	head := s.remote(t, "%H")
	base := s.base(t, "alpha")
	fill := strings.NewReplacer("{name}", "alpha", "{feature}", "demo", "{hash}", head)
	bodies := map[string]map[string]any{
		"reveal": {"key": "cloudflare_dns_token"}, "set": {"base": base, "key": "k", "value": sNewValue},
		"unset": {"base": base, "key": "cloudflare_dns_token"}, "reencrypt": {"base": base},
	}
	people := []struct {
		name string
		hdr  map[string]string
	}{
		{"infra admin", me},
		{"infra admin by app role", map[string]string{"X-User": claimU, "X-App-Roles": "x," + adminRole}},
		{"infra auditor", map[string]string{"X-User": auditorU}},
		{"infra auditor by group", map[string]string{"X-User": claimU, "X-Groups": "g," + auditGroup}},
		{"admin app role, but sent as a group", map[string]string{"X-User": claimU, "X-Groups": adminRole}},
		{"admin app role past claims_absolute", map[string]string{"X-User": claimU, "X-App-Roles": adminRole, "X-Signed-In-Age": "90000"}},
		{"auditor group past claims_absolute", map[string]string{"X-User": claimU, "X-Groups": auditGroup, "X-Signed-In-Age": "90000"}},
		{"admin app role, other tenant", map[string]string{"X-User": claimU, "X-App-Roles": adminRole, "X-Tenant": "tenant-2"}},
		{"admin app role, other client", map[string]string{"X-User": claimU, "X-App-Roles": adminRole, "X-Client": "other-app"}},
		{"admin app role by passkey", map[string]string{"X-User": claimU, "X-App-Roles": adminRole, "X-Method": auth.MethodPasskey}},
		{"claims cut at the cap (the value is past it, so capping removes it)", map[string]string{"X-User": claimU, "X-Cap": "1", "X-Groups": fillers(40, "g") + "," + auditGroup, "X-App-Roles": fillers(40, "r") + "," + adminRole}},
		{"claims dropped by an overage", map[string]string{"X-User": claimU}},
		{"API token with the claim values", map[string]string{"Authorization": "Bearer token", "X-Groups": auditGroup, "X-App-Roles": adminRole}},
		{"OAuth grant with the claim values", map[string]string{"Authorization": "Bearer oauth", "X-Groups": auditGroup, "X-App-Roles": adminRole}},
		{"MCPHub with the claim values", map[string]string{"Authorization": "Bearer mcphub", "X-Groups": auditGroup, "X-App-Roles": adminRole}},
		{"neither", map[string]string{"X-User": neitherU}},
		{"infra auditor by passkey", map[string]string{"X-User": auditorU, "X-Method": auth.MethodPasskey}},
		{"infra auditor, other issuer", map[string]string{"X-User": auditorU, "X-Issuer": "https://evil.test"}},
		{"infra auditor, other client", map[string]string{"X-User": auditorU, "X-Client": "other-app"}},
		{"infra auditor, other tenant", map[string]string{"X-User": auditorU, "X-Tenant": "tenant-2"}},
		{"API token", map[string]string{"Authorization": "Bearer token"}},
	}
	keys := make([]string, 0, len(infraRouteClass))
	for p := range infraRouteClass {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	for _, pat := range keys {
		class := infraRouteClass[pat]
		method, path, _ := strings.Cut(pat, " ")
		var body map[string]any
		if method == "POST" {
			body = map[string]any{"base": base}
			if i := strings.LastIndex(path, "/"); strings.HasPrefix(path[i+1:], "re") || path[i+1:] == "set" || path[i+1:] == "unset" {
				body = bodies[path[i+1:]]
			}
		}
		for _, p := range people {
			if (p.name == "infra admin" || p.name == "infra admin by app role") && method != "GET" {
				continue // what an administrator's writes do is covered by the editor tests; here nothing may change
			}
			code, out, _ := s.do(t, method, fill.Replace(path), body, p.hdr)
			gate := code == http.StatusForbidden && out["error"] == "forbidden"
			var wantGate bool // the route's own gate refuses this person
			admin := p.name == "infra admin" || p.name == "infra admin by app role"
			auditor := p.name == "infra auditor" || p.name == "infra auditor by group"
			switch {
			case admin:
				wantGate = false
			case auditor:
				wantGate = class != "read"
			default: // neither, passkey, wrong provider, wrong tenant, token, a claim that does not count
				wantGate = true
			}
			if (admin || auditor) && class == "read" && code != 200 {
				t.Errorf("%s as %s: %d %v", pat, p.name, code, out)
			}
			if gate != wantGate {
				t.Errorf("%s (%s) as %s: %d %v, want the gate's 403 = %v", pat, class, p.name, code, out, wantGate)
			}
			// an auditor never gets a success from a secret or write route
			if !admin && class != "read" && code >= 200 && code < 300 {
				t.Errorf("%s as %s: %d", pat, p.name, code)
			}
		}
	}
	// refused requests changed nothing and revealed nothing
	if got := s.remote(t, "%H"); got != head {
		t.Fatalf("a request committed something (%s)", s.remote(t, "%s"))
	}
	for _, o := range s.audit.outcomes() {
		if o == "revealed" {
			t.Fatalf("a secret was revealed: %v", s.audit.outcomes())
		}
	}
}

// The infra auditor reads, and the rest of the page's data is the same for
// them; the editor state says so (the console hides every edit control).
func TestInfraAuditorSeesReadOnlyState(t *testing.T) {
	t.Parallel()
	s := newSEnv(t, func(o *api.Options, io *api.InfraOptions) {
		ia, _ := auth.NewInfraAuditors([]string{"aud@kazuha.org"})
		if err := ia.Pin(testIssuer, testClient, "", testTenant, 12*time.Hour); err != nil {
			t.Fatal(err)
		}
		io.Auditors = ia
	}, nil)
	aud := map[string]string{"X-User": "aud@kazuha.org"}
	code, w, _ := s.do(t, "GET", "/api/infra/write", nil, aud)
	if code != 200 || w["enabled"] != false || w["secrets"] != false || w["auditor"] != true {
		t.Fatalf("%d %v", code, w)
	}
	if code, w, _ = s.do(t, "GET", "/api/infra/write", nil, me); code != 200 || w["enabled"] != true || w["secrets"] != true {
		t.Fatalf("the administrator is unchanged: %d %v", code, w)
	}
	if _, c, _ := s.do(t, "GET", "/api/infra/commits", nil, aud); c["canRevert"] != false {
		t.Fatalf("%v", c)
	}
	if _, c, _ := s.do(t, "GET", "/api/infra/commits", nil, me); c["canRevert"] != true {
		t.Fatalf("%v", c)
	}
	_, m, _ := s.do(t, "GET", "/api/meta", nil, aud)
	u := m["user"].(map[string]any)
	if u["canInfra"] != true || u["infraAuditor"] != true || u["canInfraWrite"] != nil {
		t.Fatalf("%v", u)
	}
	// the values stay with the administrators: nothing was decrypted for the auditor
	before := s.spy.decrypts.Load()
	if code, out, _ := s.reveal(t, "alpha", "cloudflare_dns_token", aud); code != 403 || out["error"] != "forbidden" {
		t.Fatalf("%d %v", code, out)
	}
	if s.spy.decrypts.Load() != before {
		t.Fatal("a refused reveal decrypted a file")
	}
}

// Reloading rackbook.yml changes who is an auditor at once, in the same way it
// changes roles ("reload on pull").
func TestAuditorListReloads(t *testing.T) {
	t.Parallel()
	dir := withRoles(t, testutil.CopyExample(t))
	var st *gitstore.Store
	f := newFixtureOpts(t, func(o *api.Options) {
		a, err := auth.New(t.Context(), auth.Config{Mode: auth.ModeOIDC, Sessions: testSessions{now: time.Now}, Config: o.Store.Config, Degraded: func() bool { return o.Store.ConfigProblem() != "" }})
		if err != nil {
			t.Fatal(err)
		}
		o.Auth = a
		o.MCP = mcpserver.Handler(mcpserver.New(o.Store.Ledger, "test"), false)
	}, dir, func(*gitstore.Options) {}, &st)
	meta := func(who string) (int, map[string]any) {
		code, m, _ := f.do(t, "GET", "/api/meta", nil, map[string]string{"X-User": who})
		return code, m
	}
	if code, m := meta("new@example.com"); code != 403 {
		t.Fatalf("not listed: %d %v", code, m)
	}
	cfg := filepath.Join(dir, "rackbook.yml")
	b, _ := os.ReadFile(cfg)
	if err := os.WriteFile(cfg, []byte(strings.Replace(string(b), "auditors: [", "auditors: [new@example.com, ", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	code, m := meta("new@example.com")
	if code != 200 || m["user"].(map[string]any)["auditor"] != true || m["user"].(map[string]any)["role"] != "viewer" {
		t.Fatalf("listed: %d %v", code, m)
	}
	if err := os.WriteFile(cfg, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, m = meta("new@example.com"); code != 403 {
		t.Fatalf("removed again: %d %v", code, m)
	}
}

// fillers is n comma-separated values that match nothing.
func fillers(n int, prefix string) string {
	v := make([]string, n)
	for i := range v {
		v[i] = fmt.Sprintf("%s%02d", prefix, i)
	}
	return strings.Join(v, ",")
}
