package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/testutil"
	"github.com/kazuhahub/rackbook/internal/tokens"
	"github.com/kazuhahub/rackbook/internal/validate"
)

// The role editor's API (docs/design-audit.md, section 4): who may use it, what a
// preview shows, what a save writes, and the changes it refuses.

const (
	groupU = "grp@example.com" // an administrator only through the group ops-guid
	opsGrp = "ops-guid"
)

// rolesYML is the access block of the file the role editor works on: comments
// everywhere, a block list and flow lists, the keys not in the usual order.
const rolesYML = `
# ---- access ----
auth:
  # who may do what
  roles:
    viewer: [guest@example.com]   # read only
    admin:
      - boss@example.com   # the owner
      - other-admin@example.com
      - "group:ops-guid"   # the ops group
    editor: ["*@team.example.com"]
  auditors: [audie@example.com, eve@team.example.com]   # read the audit log
`

type rolesEnv struct {
	*fixture
	root, bare, laptop, server string
	log                        *audit.Log
	store                      *gitstore.Store
	opts                       api.Options
	github                     *httptest.Server
	pulls                      chan map[string]string
}

type rolesOpts struct {
	pr       bool // write.mode: pr, with a GitHub that answers
	readOnly bool
	yml      string
	infra    *api.InfraOptions // the /infra lists, for the note of the Roles tab (its repository is not used)
}

func newRolesEnv(t *testing.T, o rolesOpts) *rolesEnv {
	t.Helper()
	e := &rolesEnv{root: t.TempDir(), pulls: make(chan map[string]string, 4)}
	e.bare, e.laptop, e.server = filepath.Join(e.root, "origin.git"), filepath.Join(e.root, "laptop"), filepath.Join(e.root, "server")
	seed := testutil.CopyExample(t)
	cfgPath := filepath.Join(seed, "rackbook.yml")
	b, _ := os.ReadFile(cfgPath)
	yml := o.yml
	if yml == "" {
		yml = rolesYML
	}
	text := string(b) + yml
	if o.pr {
		text = strings.Replace(text, "mode: push", "mode: pr", 1)
	}
	if err := os.WriteFile(cfgPath, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	sh(t, e.root, "init", "--bare", "-b", "main", e.bare)
	sh(t, seed, "init", "-b", "main")
	sh(t, seed, "add", ".")
	sh(t, seed, "commit", "-m", "seed")
	sh(t, seed, "remote", "add", "origin", e.bare)
	sh(t, seed, "push", "origin", "main")
	sh(t, e.root, "clone", e.bare, e.server)
	sh(t, e.root, "clone", e.bare, e.laptop)

	var err error
	if e.log, err = audit.Open(filepath.Join(e.root, "state", "audit"), audit.Options{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.log.Close)

	if o.pr {
		e.github = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var got map[string]string
			_ = json.NewDecoder(r.Body).Decode(&got)
			e.pulls <- got
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"html_url":"https://github.com/acme/ledger/pull/9"}`))
		}))
		t.Cleanup(e.github.Close)
	}
	now := time.Now()
	e.fixture = newFixtureOpts(t, func(op *api.Options) {
		a, err := auth.New(context.Background(), auth.Config{Mode: auth.ModeOIDC, Sessions: testSessions{now: func() time.Time { return now }}, Config: op.Store.Config})
		if err != nil {
			t.Fatal(err)
		}
		a.SetBearer(testBearer{})
		op.Auth, op.ReadOnly, op.Audit, op.Infra = a, o.readOnly, e.log, o.infra
		op.Tokens = &tokens.Registry{Store: op.Store}
		e.opts = *op
	}, e.server, func(so *gitstore.Options) {
		if o.pr {
			so.GitHubToken, so.GitHubRepo, so.GitHubAPI = "tok", "acme/ledger", e.github.URL
		}
		so.OnCommit = func(hash string, who *auth.Identity, record string) {
			ev := audit.Event{Event: "commit", Area: "ledger", Repo: "ledger", Hash: hash, Record: record}
			ev.By(who)
			e.log.Record(ev)
		}
	}, &e.store)
	return e
}

func as(who string, kv ...string) map[string]string {
	h := map[string]string{"X-User": who}
	for i := 0; i+1 < len(kv); i += 2 {
		h[kv[i]] = kv[i+1]
	}
	return h
}

// the version and the lists as GET shows them
func (e *rolesEnv) read(t *testing.T) (version string, lists map[string][]string) {
	t.Helper()
	code, m, _ := e.do(t, "GET", "/api/admin/roles", nil, as(adminU))
	if code != 200 {
		t.Fatalf("GET: %d %v", code, m)
	}
	lists = map[string][]string{}
	roles := m["roles"].(map[string]any)
	for _, n := range []string{"admin", "editor", "viewer"} {
		lists[n] = entryValues(roles[n])
	}
	lists["auditors"] = entryValues(m["auditors"])
	return m["version"].(string), lists
}

func entryValues(v any) []string {
	out := []string{}
	for _, e := range v.([]any) {
		out = append(out, e.(map[string]any)["value"].(string))
	}
	return out
}

func rolesBody(version string, l map[string][]string, extra ...any) map[string]any {
	b := map[string]any{"version": version, "roles": map[string]any{"admin": l["admin"], "editor": l["editor"], "viewer": l["viewer"]}, "auditors": l["auditors"]}
	for i := 0; i+1 < len(extra); i += 2 {
		b[extra[i].(string)] = extra[i+1]
	}
	return b
}

// with returns a copy of l with the list changed.
func with(l map[string][]string, name string, v ...string) map[string][]string {
	out := map[string][]string{}
	for k, x := range l {
		out[k] = slices.Clone(x)
	}
	out[name] = v
	if v == nil {
		out[name] = []string{}
	}
	return out
}

func (e *rolesEnv) serverFile(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.server, "rackbook.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The Roles tab shows the one group or app role each /infra flag names (administrators only).
func TestRolesGetShowsTheInfraClaimEntries(t *testing.T) {
	t.Parallel()
	ia, _ := auth.NewInfraAdmins([]string{"ops@example.com", "app-role:Rackbook.InfraAdmin"})
	au, _ := auth.NewInfraAuditors([]string{"group:" + opsGrp})
	for _, l := range []*auth.InfraAdmins{ia, au} {
		if err := l.Pin(testIssuer, testClient, "", testTenant, 0); err != nil {
			t.Fatal(err)
		}
	}
	e := newRolesEnv(t, rolesOpts{infra: &api.InfraOptions{Admins: ia, Auditors: au}})
	code, m, _ := e.do(t, "GET", "/api/admin/roles", nil, as(adminU))
	if code != 200 || m["infra"] != true {
		t.Fatalf("%d %v", code, m)
	}
	c, _ := m["infraClaims"].(map[string]any)
	if c["admins"] != "app-role:Rackbook.InfraAdmin" || c["auditors"] != "group:"+opsGrp || c["claimsAbsolute"] != float64(86400) || len(c) != 3 {
		t.Fatalf("%v", m["infraClaims"])
	}
	if code, _, _ := e.do(t, "GET", "/api/admin/roles", nil, as("guest@example.com")); code != 403 {
		t.Fatalf("not for a viewer: %d", code)
	}
	// identities only: no entry to show
	ia2, _ := auth.NewInfraAdmins([]string{"ops@example.com"})
	_ = ia2.Pin(testIssuer, testClient, "", testTenant, 0)
	e = newRolesEnv(t, rolesOpts{infra: &api.InfraOptions{Admins: ia2}})
	if _, m, _ := e.do(t, "GET", "/api/admin/roles", nil, as(adminU)); m["infra"] != true || m["infraClaims"] != nil {
		t.Fatalf("%v", m)
	}
}

func TestRolesGetShape(t *testing.T) {
	t.Parallel()
	e := newRolesEnv(t, rolesOpts{})
	code, m, _ := e.do(t, "GET", "/api/admin/roles", nil, as(adminU))
	if code != 200 {
		t.Fatalf("%d %v", code, m)
	}
	if m["loads"] != true || m["explicit"] != true || m["writeMode"] != "push" || m["readOnly"] != false || m["file"] != "rackbook.yml" || m["infra"] != false {
		t.Fatalf("%v", m)
	}
	if v, _ := m["version"].(string); len(v) != 16 {
		t.Fatalf("version: %v", m["version"])
	}
	roles := m["roles"].(map[string]any)
	want := map[string][]string{
		"admin": {"boss@example.com", "other-admin@example.com", "group:ops-guid"}, "editor": {"*@team.example.com"}, "viewer": {"guest@example.com"},
	}
	for n, w := range want {
		if got := entryValues(roles[n]); !slices.Equal(got, w) {
			t.Errorf("%s: %v", n, got)
		}
	}
	kind := func(list any, i int) string { return list.([]any)[i].(map[string]any)["kind"].(string) }
	if kind(roles["admin"], 0) != "identity" || kind(roles["admin"], 2) != "group" || kind(roles["editor"], 0) != "domain" {
		t.Fatalf("%v", roles)
	}
	// the group entry has a note: this deployment has no single sign-in, so it matches nobody
	notes := roles["admin"].([]any)[2].(map[string]any)["notes"].([]any)
	if len(notes) != 1 || notes[0].(map[string]any)["code"] != "no_sso" || notes[0].(map[string]any)["level"] != "warning" {
		t.Fatalf("%v", notes)
	}
	if got := entryValues(m["auditors"]); !slices.Equal(got, []string{"audie@example.com", "eve@team.example.com"}) {
		t.Fatalf("%v", got)
	}
	you := m["you"].(map[string]any)
	if you["role"] != "admin" || you["byIdentity"] != "admin" || you["auditor"] != false {
		t.Fatalf("%v", you)
	}
	// the version does not move for a change that leaves the lists alone
	v1, _ := e.read(t)
	e.laptopEdit(t, func(s string) string { return strings.Replace(s, "# read only", "# read only, by the way", 1) })
	if v2, _ := e.read(t); v1 != v2 {
		t.Fatalf("a comment changed the version: %s %s", v1, v2)
	}
}

// laptopEdit changes rackbook.yml from somebody else's clone and has the server take it in.
func (e *rolesEnv) laptopEdit(t *testing.T, f func(string) string) {
	t.Helper()
	sh(t, e.laptop, "pull", "--quiet")
	p := filepath.Join(e.laptop, "rackbook.yml")
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(p, []byte(f(string(b))), 0o644); err != nil {
		t.Fatal(err)
	}
	sh(t, e.laptop, "commit", "-qam", "edit by hand")
	sh(t, e.laptop, "push", "--quiet", "origin", "main")
	if err := e.store.Pull(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRolesPreviewKeepsCommentsAndLayout(t *testing.T) {
	t.Parallel()
	e := newRolesEnv(t, rolesOpts{})
	ver, l := e.read(t)
	next := with(with(with(l, "viewer", "guest@example.com", "new@example.com"), "editor"), "auditors", "audie@example.com", "eve@team.example.com", "ann@example.com")
	head := sh(t, e.server, "rev-parse", "HEAD")
	code, m, _ := e.do(t, "POST", "/api/admin/roles/preview", rolesBody(ver, next), as(adminU))
	if code != 200 {
		t.Fatalf("%d %v", code, m)
	}
	if m["changed"] != true || m["refusal"] != nil || m["file"] != "rackbook.yml" {
		t.Fatalf("%v", m)
	}
	diff := m["diff"].(string)
	for _, want := range []string{
		"--- a/rackbook.yml", "+++ b/rackbook.yml",
		"-    viewer: [guest@example.com]   # read only\n+    viewer: [guest@example.com, new@example.com]   # read only\n",
		"-    editor: [\"*@team.example.com\"]\n",
		"+    editor: []\n",
		"-  auditors: [audie@example.com, eve@team.example.com]   # read the audit log\n",
		"+  auditors: [audie@example.com, eve@team.example.com, ann@example.com]   # read the audit log\n",
	} {
		if !strings.Contains(diff, want) {
			t.Errorf("the diff lacks %q:\n%s", want, diff)
		}
	}
	// the lines that did not change are not in the diff as changes, and no comment is touched
	for _, bad := range []string{"-      - boss@example.com", "# the owner\n-", "-# ---- access ----", "-  # who may do what"} {
		if strings.Contains(diff, bad) {
			t.Errorf("the diff touches %q:\n%s", bad, diff)
		}
	}
	if !strings.HasPrefix(m["subject"].(string), "roles: ") || !strings.Contains(m["subject"].(string), "viewer +new@example.com") {
		t.Fatalf("%v", m["subject"])
	}
	// the caller after the change: still an administrator by name
	you := m["you"].(map[string]any)
	after := you["after"].(map[string]any)
	if you["now"].(map[string]any)["role"] != "admin" || after["role"] != "admin" || after["byIdentity"] != "admin" || after["roleFrom"].([]any)[0] != "identity" {
		t.Fatalf("%v", you)
	}
	// nothing was written
	if sh(t, e.server, "rev-parse", "HEAD") != head || strings.Contains(e.serverFile(t), "new@example.com") {
		t.Fatal("a preview changed the file")
	}
	// an unchanged draft has no diff
	code, m, _ = e.do(t, "POST", "/api/admin/roles/preview", rolesBody(ver, l), as(adminU))
	if code != 200 || m["changed"] != false || m["diff"] != "" || m["refusal"] != nil {
		t.Fatalf("%d %v", code, m)
	}
}

func TestRolesPreviewWarnsAboutEntriesNobodyMatches(t *testing.T) {
	t.Parallel()
	e := newRolesEnv(t, rolesOpts{})
	e.log.ObserveRole(audit.RoleObservation{Identity: "tom@team.example.com", Name: "Tom", Method: "oidc", Role: "editor", SignedIn: true, Cause: audit.CauseSignIn})
	ver, l := e.read(t)
	next := with(l, "viewer", "guest@example.com", "tom@team.example.com", "tomm@team.example.com", "*@nowhere.example.org", "*@team.example.com", "*", "app-role:Rackbook.Viewer")
	code, m, _ := e.do(t, "POST", "/api/admin/roles/preview", rolesBody(ver, next), as(adminU))
	if code != 200 || m["refusal"] != nil {
		t.Fatalf("%d %v", code, m)
	}
	got := map[string][]string{}
	for _, w := range m["warnings"].([]any) {
		w := w.(map[string]any)
		got[w["entry"].(string)] = append(got[w["entry"].(string)], w["note"].(map[string]any)["code"].(string))
	}
	want := map[string][]string{
		"tomm@team.example.com":    {"never_seen"},
		"*@nowhere.example.org":    {"never_seen"},
		"app-role:Rackbook.Viewer": {"no_sso"},
		"*@team.example.com":       {"also_in"}, // an editor entry already
	}
	for k, w := range want {
		if !slices.Equal(got[k], w) {
			t.Errorf("%s: %v (want %v)", k, got[k], w)
		}
	}
	for _, k := range []string{"tom@team.example.com", "*"} {
		if len(got[k]) != 0 {
			t.Errorf("%s: %v", k, got[k])
		}
	}
	// a wildcard in the admin list says so
	code, m, _ = e.do(t, "POST", "/api/admin/roles/preview", rolesBody(ver, with(l, "admin", "boss@example.com", "*@example.com")), as(adminU))
	if code != 200 {
		t.Fatalf("%d %v", code, m)
	}
	var found bool
	for _, w := range m["warnings"].([]any) {
		found = found || w.(map[string]any)["note"].(map[string]any)["code"] == "wildcard_admin"
	}
	if !found {
		t.Fatalf("%v", m["warnings"])
	}
}

func TestRolesSaveCommitsWithTrailersAndTheFileStillChecks(t *testing.T) {
	t.Parallel()
	e := newRolesEnv(t, rolesOpts{})
	ver, l := e.read(t)
	before := e.serverFile(t)
	next := with(with(l, "viewer", "guest@example.com", "new@example.com"), "editor", "*@team.example.com", "dev@example.com")
	code, m, _ := e.do(t, "POST", "/api/admin/roles", rolesBody(ver, next), as(adminU))
	if code != 200 || m["changed"] != true || m["pullRequest"] != false || m["commit"] == "" {
		t.Fatalf("%d %v", code, m)
	}
	// the answer carries the new version and lists
	if m["version"] == ver || !slices.Contains(entryValues(m["roles"].(map[string]any)["viewer"]), "new@example.com") {
		t.Fatalf("%v", m)
	}
	// one commit, pushed, with the usual trailers and a subject that says what changed
	msg := sh(t, e.server, "log", "-1", "--format=%B")
	for _, want := range []string{"roles: ", "viewer +new@example.com", "editor +dev@example.com", "Edited-by: " + adminU, "Edited-via: rackbook (oidc)"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the commit message lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "Claude") || strings.Contains(msg, "Co-Authored") {
		t.Fatalf("%s", msg)
	}
	if sh(t, e.server, "rev-parse", "HEAD") != sh(t, e.bare, "rev-parse", "main") {
		t.Fatal("the commit was not pushed")
	}
	if n := sh(t, e.server, "rev-list", "--count", "HEAD"); n != "2" {
		t.Fatalf("%s commits", n)
	}
	// the file: only the two lists changed, every comment is where it was
	after := e.serverFile(t)
	want := strings.Replace(strings.Replace(before,
		"viewer: [guest@example.com]   # read only", "viewer: [guest@example.com, new@example.com]   # read only", 1),
		`editor: ["*@team.example.com"]`, `editor: ["*@team.example.com", dev@example.com]`, 1)
	if after != want {
		t.Fatalf("the file:\n%s\nwant:\n%s", after, want)
	}
	// and it passes what rackbook check runs
	cfg, err := config.Load(filepath.Join(e.server, "rackbook.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, is := range validate.Run(ledger.Load(cfg, nil)) {
		if !is.Warning() {
			t.Fatalf("rackbook check: %+v", is)
		}
	}
	// the save is an ordinary commit: the audit log vouches for it, and Activity shows it to the administrator and the auditor
	for _, who := range []string{adminU, auditU} {
		_, out := (&actEnv{fixture: e.fixture}).get(t, who, "/api/activity?limit=50")
		it := find(items(t, out), "identity", adminU, "kind", "commit")
		if it == nil || !strings.HasPrefix(it["subject"].(string), "roles: ") || it["verified"] != true {
			t.Errorf("%s sees %v", who, it)
		}
	}
	// an unchanged save writes nothing
	ver2, l2 := e.read(t)
	code, m, _ = e.do(t, "POST", "/api/admin/roles", rolesBody(ver2, l2), as(adminU))
	if code != 200 || m["changed"] != false || sh(t, e.server, "rev-list", "--count", "HEAD") != "2" {
		t.Fatalf("%d %v", code, m)
	}
}

func TestRolesSaveMessageIsTheSubject(t *testing.T) {
	t.Parallel()
	e := newRolesEnv(t, rolesOpts{})
	ver, l := e.read(t)
	code, m, _ := e.do(t, "POST", "/api/admin/roles", rolesBody(ver, with(l, "viewer", "guest@example.com", "v@example.com"), "message", "roles: welcome\nthe new viewer\x00"), as(adminU))
	if code != 200 {
		t.Fatalf("%d %v", code, m)
	}
	if got := sh(t, e.server, "log", "-1", "--format=%s"); got != "roles: welcome the new viewer" {
		t.Fatalf("%q", got)
	}
}

func TestRolesRefusals(t *testing.T) {
	t.Parallel()
	e := newRolesEnv(t, rolesOpts{})
	ver, l := e.read(t)
	head := sh(t, e.server, "rev-parse", "HEAD")
	refused := func(name string, who map[string]string, body map[string]any, status int, code string) map[string]any {
		t.Helper()
		st, m, _ := e.do(t, "POST", "/api/admin/roles", body, who)
		if st != status || m["error"] != code {
			t.Fatalf("%s: %d %v (want %d %s)", name, st, m, status, code)
		}
		// a preview says the same, as a refusal inside a 200 (it can still show the diff)
		if status == 422 {
			st, pm, _ := e.do(t, "POST", "/api/admin/roles/preview", body, who)
			rf, _ := pm["refusal"].(map[string]any)
			if st != 200 || rf == nil || rf["code"] != code {
				t.Fatalf("%s preview: %d %v", name, st, pm)
			}
		}
		if sh(t, e.server, "rev-parse", "HEAD") != head {
			t.Fatalf("%s: a refused save committed", name)
		}
		return m
	}
	// the last admin
	refused("last admin", as(adminU), rolesBody(ver, with(l, "admin")), 422, "last_admin")
	// the caller's own admin entry, by name: another administrator remains
	m := refused("self by name", as(adminU), rolesBody(ver, with(l, "admin", "other-admin@example.com", "group:ops-guid")), 422, "self_lockout")
	if !strings.Contains(m["message"].(string), "no longer be an administrator") {
		t.Fatalf("%v", m)
	}
	// downgraded: moved from admin to editor
	refused("downgrade", as(adminU), rolesBody(ver, with(with(l, "admin", "other-admin@example.com", "group:ops-guid"), "editor", "*@team.example.com", "boss@example.com")), 422, "self_lockout")
	// the group keeps them admin, but only through the group
	refused("self by group", as(adminU, "X-Groups", opsGrp), rolesBody(ver, with(l, "admin", "other-admin@example.com", "group:ops-guid")), 422, "self_lockout_claims")
	// a group-only administrator: an edit that leaves them so is refused; the one that names them is not
	refused("group only", as(groupU, "X-Groups", opsGrp), rolesBody(ver, with(l, "viewer", "guest@example.com", "v@example.com")), 422, "self_lockout_claims")
	// invalid entries, with the parser's own words, and none of them saved
	m = refused("invalid", as(adminU), rolesBody(ver, with(l, "viewer", "guest@example.com", "a*b@example.com", "oauth:x", "group:", "app-role:A*", "")), 422, "invalid_entries")
	viewer := m["entries"].(map[string]any)["viewer"].([]any)
	if len(viewer) != 6 || viewer[0].(map[string]any)["notes"].([]any) == nil || len(viewer[1].(map[string]any)["notes"].([]any)) == 0 {
		t.Fatalf("%v", viewer)
	}
	if msg := viewer[1].(map[string]any)["notes"].([]any)[0].(map[string]any)["message"].(string); !strings.Contains(msg, "wildcards are only supported") {
		t.Fatalf("the message is the parser's: %q", msg)
	}
	refused("control chars", as(adminU), rolesBody(ver, with(l, "viewer", "a\nb@example.com")), 422, "invalid_entries")
	// a version that is not the current one
	m = refused("stale", as(adminU), rolesBody("0000000000000000", with(l, "viewer", "guest@example.com", "v@example.com")), 409, "conflict")
	cur := m["current"].(map[string]any)
	if cur["version"] != ver || len(cur["roles"].(map[string]any)["admin"].([]any)) != 3 {
		t.Fatalf("%v", cur)
	}
	st, pm, _ := e.do(t, "POST", "/api/admin/roles/preview", rolesBody("0000000000000000", l), as(adminU))
	if st != 409 || pm["error"] != "conflict" {
		t.Fatalf("%d %v", st, pm)
	}
	// a body that is not complete
	for _, b := range []map[string]any{
		{"version": ver, "roles": map[string]any{"admin": []string{"boss@example.com"}, "editor": []string{}}, "auditors": []string{}},
		{"version": ver, "roles": map[string]any{"admin": []string{"boss@example.com"}, "editor": []string{}, "viewer": []string{}}},
		{"roles": map[string]any{"admin": []string{"boss@example.com"}, "editor": []string{}, "viewer": []string{}}, "auditors": []string{}},
		{"version": ver, "roles": map[string]any{"admin": []string{"boss@example.com"}, "editor": []string{}, "viewer": []string{}, "owner": []string{}}, "auditors": []string{}},
		{"version": ver, "roles": map[string]any{"admin": []string{"boss@example.com"}, "editor": []string{}, "viewer": []string{}}, "auditors": []string{}, "extra": 1},
	} {
		if st, m, _ := e.do(t, "POST", "/api/admin/roles", b, as(adminU)); st != 400 || m["error"] != "bad_request" {
			t.Errorf("%v: %d %v", b, st, m)
		}
	}
	// the cases that are allowed: a domain entry is an identity entry, so naming the caller by domain keeps them; the name entry may then go
	e1 := rolesBody(ver, with(l, "admin", "boss@example.com", "other-admin@example.com", "group:ops-guid", "*@example.com"))
	if st, m, _ := e.do(t, "POST", "/api/admin/roles", e1, as(adminU)); st != 200 {
		t.Fatalf("add a domain: %d %v", st, m)
	}
	ver, l = e.read(t)
	if st, m, _ := e.do(t, "POST", "/api/admin/roles", rolesBody(ver, with(l, "admin", "other-admin@example.com", "group:ops-guid", "*@example.com")), as(adminU, "X-Groups", opsGrp)); st != 200 {
		t.Fatalf("drop the name, keep the domain: %d %v", st, m)
	}
	// ... and the domain entry was the last thing that named them
	ver, l = e.read(t)
	refused2 := func(body map[string]any, who map[string]string, code string) {
		t.Helper()
		if st, m, _ := e.do(t, "POST", "/api/admin/roles", body, who); st != 422 || m["error"] != code {
			t.Fatalf("%d %v (want %s)", st, m, code)
		}
	}
	refused2(rolesBody(ver, with(l, "admin", "other-admin@example.com", "group:ops-guid")), as(adminU), "self_lockout")
}

func TestRolesAGroupAdministratorNamesThemselves(t *testing.T) {
	t.Parallel()
	e := newRolesEnv(t, rolesOpts{})
	ver, l := e.read(t)
	grp := as(groupU, "X-Groups", opsGrp)
	// as an administrator only by group they can read, and the preview says why a save is refused
	if code, m, _ := e.do(t, "GET", "/api/admin/roles", nil, grp); code != 200 || m["you"].(map[string]any)["byIdentity"] != "none" {
		t.Fatalf("%d %v", code, m)
	}
	// naming themselves is the one edit they can make
	if st, m, _ := e.do(t, "POST", "/api/admin/roles", rolesBody(ver, with(l, "admin", "boss@example.com", "other-admin@example.com", "group:ops-guid", "grp@example.com")), grp); st != 200 {
		t.Fatalf("name oneself: %d %v", st, m)
	}
	// without the claims they are an administrator all the same
	if code, m, _ := e.do(t, "GET", "/api/admin/roles", nil, as(groupU)); code != 200 || m["you"].(map[string]any)["role"] != "admin" {
		t.Fatalf("%d %v", code, m)
	}
}

func TestRolesSaveReplaysOnAMovedRemote(t *testing.T) {
	t.Parallel()
	e := newRolesEnv(t, rolesOpts{})
	ver, l := e.read(t)
	// somebody changes another part of the file on the remote: the edit is made again on the new tip
	sh(t, e.laptop, "pull", "--quiet")
	p := filepath.Join(e.laptop, "rackbook.yml")
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), "# ---- access ----", "# ---- access (edited elsewhere) ----", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	sh(t, e.laptop, "commit", "-qam", "comment")
	sh(t, e.laptop, "push", "--quiet", "origin", "main")
	code, m, _ := e.do(t, "POST", "/api/admin/roles", rolesBody(ver, with(l, "viewer", "guest@example.com", "v@example.com")), as(adminU))
	if code != 200 || m["changed"] != true {
		t.Fatalf("%d %v", code, m)
	}
	if s := e.serverFile(t); !strings.Contains(s, "access (edited elsewhere)") || !strings.Contains(s, "v@example.com") {
		t.Fatalf("both edits must be in the file:\n%s", s)
	}
	// ... but when the remote changed the lists themselves, the version no longer matches
	ver, l = e.read(t)
	e.laptopEdit(t, func(s string) string {
		return strings.Replace(s, "viewer: [guest@example.com, v@example.com]", "viewer: [guest@example.com, v@example.com, theirs@example.com]", 1)
	})
	code, m, _ = e.do(t, "POST", "/api/admin/roles", rolesBody(ver, with(l, "viewer", "mine@example.com")), as(adminU))
	if code != 409 || m["error"] != "conflict" {
		t.Fatalf("%d %v", code, m)
	}
}

func TestRolesDegradedConfigRefusesEditing(t *testing.T) {
	t.Parallel()
	e := newRolesEnv(t, rolesOpts{})
	ver, l := e.read(t)
	// a file that does not load arrives with a pull
	sh(t, e.laptop, "pull", "--quiet")
	if err := os.WriteFile(filepath.Join(e.laptop, "rackbook.yml"), []byte("auth: [unclosed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sh(t, e.laptop, "commit", "-qam", "break it")
	sh(t, e.laptop, "push", "--quiet", "origin", "main")
	_ = e.store.Pull(context.Background()) // fails: the config does not load
	if e.store.ConfigProblem() == "" {
		t.Fatal("the store should be degraded")
	}
	code, m, _ := e.do(t, "GET", "/api/admin/roles", nil, as(adminU))
	if code != 200 || m["loads"] != false || m["problem"] == nil || m["version"] != ver {
		t.Fatalf("the lists of the last good file are shown, with the flag: %d %v", code, m)
	}
	for _, path := range []string{"/api/admin/roles", "/api/admin/roles/preview"} {
		code, m, _ = e.do(t, "POST", path, rolesBody(ver, with(l, "viewer", "x@example.com")), as(adminU))
		if code != 409 || m["error"] != "config_degraded" || !strings.Contains(m["message"].(string), "does not load") {
			t.Fatalf("%s: %d %v", path, code, m)
		}
	}
}

func TestRolesPRModeOpensAPullRequest(t *testing.T) {
	t.Parallel()
	e := newRolesEnv(t, rolesOpts{pr: true})
	ver, l := e.read(t)
	if _, m, _ := e.do(t, "GET", "/api/admin/roles", nil, as(adminU)); m["writeMode"] != "pr" {
		t.Fatalf("%v", m)
	}
	main := sh(t, e.bare, "rev-parse", "main")
	// the preview says it would be a pull request
	code, pm, _ := e.do(t, "POST", "/api/admin/roles/preview", rolesBody(ver, with(l, "viewer", "guest@example.com", "v@example.com")), as(adminU))
	if code != 200 || pm["pullRequest"] != true {
		t.Fatalf("%d %v", code, pm)
	}
	code, m, _ := e.do(t, "POST", "/api/admin/roles", rolesBody(ver, with(l, "viewer", "guest@example.com", "v@example.com")), as(adminU))
	if code != 200 || m["pullRequest"] != true || m["pullRequestUrl"] != "https://github.com/acme/ledger/pull/9" || m["commit"] != nil {
		t.Fatalf("%d %v", code, m)
	}
	pr := <-e.pulls
	if !strings.HasPrefix(pr["title"], "roles: ") || !strings.Contains(pr["title"], "viewer +v@example.com") || pr["base"] != "main" || !strings.HasPrefix(pr["head"], "rackbook/") {
		t.Fatalf("%v", pr)
	}
	if !strings.Contains(pr["body"], "Edited-by: "+adminU) {
		t.Fatalf("the pull request carries the trailers: %v", pr)
	}
	// main did not move, the server's lists are what they were, and the branch is on the remote
	if sh(t, e.bare, "rev-parse", "main") != main {
		t.Fatal("main moved in pr mode")
	}
	if v2, _ := e.read(t); v2 != ver {
		t.Fatal("the lists changed before the pull request was merged")
	}
	if !strings.Contains(sh(t, e.bare, "branch", "--list", "rackbook/*"), pr["head"]) {
		t.Fatal("the branch was not pushed")
	}
}

func TestRolesReadOnlyModeRefusesTheSave(t *testing.T) {
	t.Parallel()
	e := newRolesEnv(t, rolesOpts{readOnly: true})
	ver, l := e.read(t)
	code, m, _ := e.do(t, "POST", "/api/admin/roles", rolesBody(ver, with(l, "viewer", "x@example.com")), as(adminU))
	if code != 403 || m["error"] != "read_only" {
		t.Fatalf("%d %v", code, m)
	}
	// the page still reads, and a preview works: nothing is written
	if _, g, _ := e.do(t, "GET", "/api/admin/roles", nil, as(adminU)); g["readOnly"] != true {
		t.Fatalf("%v", g)
	}
	if code, pm, _ := e.do(t, "POST", "/api/admin/roles/preview", rolesBody(ver, with(l, "viewer", "x@example.com")), as(adminU)); code != 200 || pm["readOnly"] != true {
		t.Fatalf("%d %v", code, pm)
	}
	if sh(t, e.server, "rev-list", "--count", "HEAD") != "1" {
		t.Fatal("a commit was made")
	}
}

func TestRolesWhoMayUseTheEditor(t *testing.T) {
	t.Parallel()
	e := newRolesEnv(t, rolesOpts{})
	ver, l := e.read(t)
	head := sh(t, e.server, "rev-parse", "HEAD")
	body := rolesBody(ver, with(l, "viewer", "guest@example.com", "x@example.com"))
	// every route is in the table the auditor test walks
	pats := api.RoutePatterns(e.opts)
	for _, want := range []string{"GET /api/admin/roles", "POST /api/admin/roles", "POST /api/admin/roles/preview"} {
		if !slices.Contains(pats, want) {
			t.Fatalf("%s is not a route", want)
		}
	}
	people := map[string]map[string]string{
		"viewer":              as(viewerU),
		"editor":              as(editorU),
		"auditor":             as(auditU),
		"auditor and editor":  as(eveU),
		"nobody":              as("nobody@elsewhere.org"),
		"API token":           {"Authorization": "Bearer token"},
		"OAuth access token":  {"Authorization": "Bearer oauth"},
		"MCPHub access token": {"Authorization": "Bearer mcphub"},
	}
	for name, hdr := range people {
		for _, c := range []struct{ method, path string }{{"GET", "/api/admin/roles"}, {"POST", "/api/admin/roles/preview"}, {"POST", "/api/admin/roles"}} {
			var b any
			if c.method == "POST" {
				b = body
			}
			code, m, _ := e.do(t, c.method, c.path, b, hdr)
			if code != 403 {
				t.Errorf("%s %s %s: %d %v (want 403)", name, c.method, c.path, code, m)
			}
			if name != "nobody" && m["error"] != "forbidden" {
				t.Errorf("%s %s %s: %v", name, c.method, c.path, m)
			}
			// a person with no role at all is stopped by the sign-in layer (the test session's no_role answer), before the handler
			if name == "nobody" && strings.TrimSpace(fmt.Sprint(m["_body"])) != "no role" {
				t.Errorf("%s %s %s: %v", name, c.method, c.path, m)
			}
		}
	}
	if sh(t, e.server, "rev-parse", "HEAD") != head {
		t.Fatal("a refused request committed")
	}
}

func TestRolesCrossSiteRequestsAreRefused(t *testing.T) {
	t.Parallel()
	e := newRolesEnv(t, rolesOpts{})
	ver, l := e.read(t)
	head := sh(t, e.server, "rev-parse", "HEAD")
	body := rolesBody(ver, with(l, "viewer", "x@example.com"))
	for _, path := range []string{"/api/admin/roles", "/api/admin/roles/preview"} {
		for _, h := range []map[string]string{
			as(adminU, "Sec-Fetch-Site", "cross-site"),
			as(adminU, "Origin", "https://evil.example"),
		} {
			code, m, _ := e.do(t, "POST", path, body, h)
			if code != 403 || m["error"] != "cross_site" {
				t.Errorf("%s %v: %d %v", path, h, code, m)
			}
		}
		// the console's own origin passes
		if code, m, _ := e.do(t, "POST", path, rolesBody(ver, l), as(adminU, "Sec-Fetch-Site", "same-origin")); code != 200 {
			t.Errorf("%s same-origin: %d %v", path, code, m)
		}
	}
	// a body that is not JSON
	req, _ := http.NewRequest("POST", e.ts.URL+"/api/admin/roles", strings.NewReader("version=x"))
	req.Header.Set("X-User", adminU)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("%d", resp.StatusCode)
	}
	if sh(t, e.server, "rev-parse", "HEAD") != head {
		t.Fatal("a refused request committed")
	}
}

func TestRolesLayoutsTheConsoleCannotEditAreRefusedWithAReason(t *testing.T) {
	t.Parallel()
	yml := `
auth:
  roles:
    admin: [boss@example.com,
      other-admin@example.com]
    viewer: []
`
	e := newRolesEnv(t, rolesOpts{yml: yml})
	ver, l := e.read(t)
	// the viewer list is fine, the admin list over two lines in flow style is not
	if code, m, _ := e.do(t, "POST", "/api/admin/roles", rolesBody(ver, with(l, "viewer", "v@example.com")), as(adminU)); code != 200 {
		t.Fatalf("%d %v", code, m)
	}
	ver, l = e.read(t)
	code, m, _ := e.do(t, "POST", "/api/admin/roles", rolesBody(ver, with(l, "admin", "boss@example.com", "x@example.com")), as(adminU))
	if code != 422 || m["error"] != "unsupported" || !strings.Contains(m["message"].(string), "by hand") || !strings.Contains(m["message"].(string), "auth.roles.admin") {
		t.Fatalf("%d %v", code, m)
	}
	if strings.Contains(e.serverFile(t), "x@example.com") {
		t.Fatal("the file was changed")
	}
}

func TestRolesWithoutARolesBlock(t *testing.T) {
	t.Parallel()
	// no roles block: every signed-in person edits and nobody administers, so the editor is closed to all
	e := newRolesEnv(t, rolesOpts{yml: "\n# no auth block\n"})
	if code, m, _ := e.do(t, "GET", "/api/admin/roles", nil, as(adminU)); code != 403 {
		t.Fatalf("%d %v", code, m)
	}
}

// The three credentials the sign-in layer lets past as an administrator (the test bearer
// plays the token layer and returns an admin-role identity of each method) are refused by
// the handler itself: the same identity is an administrator everywhere else.
func TestRolesHandlerRefusesCredentialIdentitiesThatAreAdmins(t *testing.T) {
	t.Parallel()
	e := newRolesEnv(t, rolesOpts{})
	ver, l := e.read(t)
	head := sh(t, e.server, "rev-parse", "HEAD")
	for _, kind := range []string{"token", "oauth", "mcphub"} {
		hdr := map[string]string{"Authorization": "Bearer " + kind}
		code, m, _ := e.do(t, "GET", "/api/meta", nil, hdr)
		if code != 200 || m["user"].(map[string]any)["canAdmin"] != true {
			t.Fatalf("%s is not an administrator elsewhere: %d %v", kind, code, m)
		}
		for _, c := range []struct{ method, path string }{{"GET", "/api/admin/roles"}, {"POST", "/api/admin/roles/preview"}, {"POST", "/api/admin/roles"}} {
			var b any
			if c.method == "POST" {
				b = rolesBody(ver, with(l, "viewer", "x@example.com"))
			}
			code, m, _ := e.do(t, c.method, c.path, b, hdr)
			if code != 403 || m["error"] != "forbidden" || !strings.Contains(m["message"].(string), "signed in on the console") {
				t.Errorf("%s %s %s: %d %v", kind, c.method, c.path, code, m)
			}
		}
	}
	if sh(t, e.server, "rev-parse", "HEAD") != head {
		t.Fatal("a credential committed")
	}
}

func TestRolesViewCarriesAuthModeAndLegacyEditors(t *testing.T) {
	t.Parallel()
	// no Auth option: auth mode none, whoever reaches the console is let in as the fixed editor
	dir := testutil.CopyExample(t)
	p := filepath.Join(dir, "rackbook.yml")
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(p, append(b, []byte(rolesYML+"  editors: [old@example.com]\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	f := newFixtureWithConfigSource(t, "Boss <boss@example.com>", dir)
	code, m, _ := f.do(t, "GET", "/api/admin/roles", nil, nil)
	if code != 200 || m["authMode"] != "none" || len(m["editors"].([]any)) != 1 || m["editors"].([]any)[0] != "old@example.com" {
		t.Fatalf("%d %v", code, m)
	}
	// with sign-in the mode is not none, and an empty legacy list is an empty array
	e := newRolesEnv(t, rolesOpts{})
	_, m, _ = e.do(t, "GET", "/api/admin/roles", nil, as(adminU))
	if m["authMode"] != "oidc" || len(m["editors"].([]any)) != 0 {
		t.Fatalf("%v", m)
	}
}
