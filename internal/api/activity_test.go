package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kazuhahub/rackbook/internal/ansiblerepo"
	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

const (
	adminU  = "boss@example.com"
	editorU = "tom@team.example.com"
	viewerU = "guest@example.com"
	infraU  = "ia@team.example.com" // an editor in the ledger, and the infra administrator
)

type actEnv struct {
	*fixture
	root, bare, laptop string
	infraBare          string
	infraSeed          string
	log                *audit.Log
	auditDir           string
	store              *gitstore.Store
	infra              *ansiblerepo.Repo
}

type actOpts struct {
	noAudit  bool
	auditDir string // an audit log prepared by the test (it is opened here)
	readOnly bool
	auditOpt audit.Options
}

// newActEnv is a ledger with roles, git (a bare origin and a laptop clone for
// commits this server did not make), an infra repository, and a real audit log
// that the store's commit hook writes to, as `rackbook serve` wires it.
func newActEnv(t *testing.T, o actOpts) *actEnv {
	t.Helper()
	e := &actEnv{root: t.TempDir()}
	e.bare, e.laptop = filepath.Join(e.root, "origin.git"), filepath.Join(e.root, "laptop")
	seed := withRoles(t, testutil.CopyExample(t))
	sh(t, e.root, "init", "--bare", "-b", "main", e.bare)
	sh(t, seed, "init", "-b", "main")
	sh(t, seed, "add", ".")
	sh(t, seed, "commit", "-m", "seed")
	sh(t, seed, "remote", "add", "origin", e.bare)
	sh(t, seed, "push", "origin", "main")
	server := filepath.Join(e.root, "server")
	sh(t, e.root, "clone", e.bare, server)
	sh(t, e.root, "clone", e.bare, e.laptop)

	if !o.noAudit {
		e.auditDir = o.auditDir
		if e.auditDir == "" {
			e.auditDir = filepath.Join(e.root, "state", "audit")
		}
		var err error
		if e.log, err = audit.Open(e.auditDir, o.auditOpt); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(e.log.Close)
	}

	// the infra repository
	e.infraBare, e.infraSeed = filepath.Join(e.root, "infra.git"), filepath.Join(e.root, "infra-seed")
	work := filepath.Join(e.root, "infra-work")
	sh(t, e.root, "init", "--bare", "--initial-branch=main", e.infraBare)
	sh(t, e.root, "clone", e.infraBare, e.infraSeed)
	for rel, body := range map[string]string{"inventory/hosts.yml": infraInventory, "inventory/host_vars/alpha.yml": infraAlphaVars, "secrets/alpha.sops.yaml": "ENC[AES256_GCM,data:abc]\n"} {
		p := filepath.Join(e.infraSeed, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sh(t, e.infraSeed, "add", ".")
	sh(t, e.infraSeed, "commit", "-m", "add hosts")
	sh(t, e.infraSeed, "push", "origin", "HEAD:refs/heads/main")
	sh(t, e.root, "clone", "--branch", "main", e.infraBare, work)
	repo, err := ansiblerepo.New(ansiblerepo.Options{Dir: work, Branch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.infra = repo
	ia, err := auth.NewInfraAdmins([]string{infraU})
	if err != nil {
		t.Fatal(err)
	}
	if err := ia.Pin(testIssuer, testClient, "", testTenant, 0); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	e.fixture = newFixtureOpts(t, func(op *api.Options) {
		a, err := auth.New(context.Background(), auth.Config{Mode: auth.ModeOIDC, Sessions: testSessions{now: func() time.Time { return now }}, Config: op.Store.Config})
		if err != nil {
			t.Fatal(err)
		}
		a.SetBearer(testBearer{})
		op.Auth, op.ReadOnly = a, o.readOnly
		op.Infra = &api.InfraOptions{Repo: repo, Admins: ia}
		op.Audit = e.log
	}, server, func(so *gitstore.Options) {
		so.OnCommit = func(hash string, who *auth.Identity, record string) {
			ev := audit.Event{Event: "commit", Area: "ledger", Repo: "ledger", Hash: hash, Record: record}
			ev.By(who)
			e.log.Record(ev)
		}
	}, &e.store)
	return e
}

// newFixtureOpts is newFixture with a hook on the store options and access to the store.
func newFixtureOpts(t *testing.T, mut func(*api.Options), dir string, so func(*gitstore.Options), out **gitstore.Store) *fixture {
	t.Helper()
	opts := gitstore.Options{ConfigPath: filepath.Join(dir, "rackbook.yml"), Committer: gitstore.Identity{Name: "Rackbook", Email: "rackbook@example.org"}}
	so(&opts)
	st, err := gitstore.Open(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	*out = st
	o := api.Options{Store: st, Web: fstest.MapFS{"index.html": {Data: []byte("<html>console</html>")}}}
	mut(&o)
	ts := httptest.NewServer(api.New(o))
	t.Cleanup(ts.Close)
	return &fixture{dir: dir, ts: ts}
}

func (e *actEnv) get(t *testing.T, who, path string) (int, map[string]any) {
	t.Helper()
	code, out, _ := e.do(t, "GET", path, nil, map[string]string{"X-User": who})
	return code, out
}

// write adds a todo record as who: a commit this server makes and the log vouches for.
func (e *actEnv) write(t *testing.T, who, item string) {
	t.Helper()
	code, out, _ := e.do(t, "POST", "/api/c/todo", map[string]any{"data": map[string]any{"item": item, "status": "待办"}}, map[string]string{"X-User": who})
	if code != 201 {
		t.Fatalf("%d %v", code, out)
	}
}

// laptopCommit makes a commit nobody vouches for (somebody with push access) and has the server take it in.
func (e *actEnv) laptopCommit(t *testing.T, when, msg string, files map[string]string) {
	t.Helper()
	sh(t, e.laptop, "pull", "--quiet")
	for rel, body := range files {
		p := filepath.Join(e.laptop, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sh(t, e.laptop, "add", "-A")
	cmd := exec.Command("git", "-C", e.laptop, "commit", "-q", "-m", msg+"\n\nEdited-by: "+adminU+"\nEdited-via: rackbook (oidc)")
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Lap Top", "GIT_AUTHOR_EMAIL=lap@example.com", "GIT_COMMITTER_NAME=Lap Top", "GIT_COMMITTER_EMAIL=lap@example.com",
		"GIT_AUTHOR_DATE="+when, "GIT_COMMITTER_DATE="+when)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	sh(t, e.laptop, "push", "--quiet", "origin", "main")
	if err := e.store.Pull(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func items(t *testing.T, out map[string]any) []map[string]any {
	t.Helper()
	var r []map[string]any
	for _, v := range arr(t, out["items"]) {
		r = append(r, v.(map[string]any))
	}
	return r
}

func find(its []map[string]any, kv ...string) map[string]any {
	for _, it := range its {
		ok := true
		for i := 0; i+1 < len(kv); i += 2 {
			if it[kv[i]] != kv[i+1] {
				ok = false
			}
		}
		if ok {
			return it
		}
	}
	return nil
}

func TestActivityVerifiedFromARealAuditLogAndARealCommit(t *testing.T) {
	e := newActEnv(t, actOpts{})
	e.write(t, editorU, "made by the server")
	e.laptopCommit(t, "2026-03-01T10:00:00Z", "edit by hand", map[string]string{"notes.txt": "x\n"})

	code, out := e.get(t, viewerU, "/api/activity")
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	its := items(t, out)
	mine := find(its, "subject", "ledger(todo): add made by the server")
	if mine == nil || mine["verified"] != true || mine["identity"] != editorU || mine["area"] != "ledger" || mine["kind"] != "commit" ||
		len(mine["hash"].(string)) != 40 || mine["short"] != mine["commit"] || len(mine["records"].([]any)) != 1 {
		t.Fatalf("%v", its)
	}
	hand := find(its, "subject", "edit by hand")
	if hand == nil || hand["verified"] != false || hand["name"] != "Lap Top" || hand["identity"] != adminU || hand["via"] != "rackbook (oidc)" {
		t.Fatalf("a commit the log does not know shows its git author, marked unverified: %v", hand)
	}
	if out["audit"] != true {
		t.Fatalf("%v", out)
	}

	// the identity filter matches what the log vouches for, and nothing a commit merely claims
	_, out = e.get(t, viewerU, "/api/activity?identity="+editorU)
	its = items(t, out)
	if len(its) != 1 || its[0]["hash"] != mine["hash"] {
		t.Fatalf("%v", its)
	}
	_, out = e.get(t, viewerU, "/api/activity?identity="+adminU)
	if its = items(t, out); len(its) != 0 {
		t.Fatalf("the trailer of an unverified commit names an admin, the filter must not match it: %v", its)
	}

	// deleting the cache changes nothing
	if err := os.Remove(filepath.Join(e.auditDir, "index.json")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	_, out = e.get(t, viewerU, "/api/activity")
	if m := find(items(t, out), "hash", mine["hash"].(string)); m == nil || m["verified"] != true {
		t.Fatal("verified after the index was deleted")
	}
	if _, err := os.Stat(filepath.Join(e.auditDir, "index.json")); err != nil {
		t.Fatalf("rebuilt: %v", err)
	}
	// a commit made with an API token names the token
	e.laptopCommit(t, "2026-03-02T10:00:00Z", "by token", map[string]string{"t.txt": "t\n"})
	_, out = e.get(t, viewerU, "/api/activity?limit=200")
	tokHash := find(items(t, out), "subject", "by token")["hash"].(string)
	ev := audit.Event{Event: "commit", Area: "ledger", Repo: "ledger", Hash: tokHash, Identity: editorU, Method: "token"}
	ev.By(&auth.Identity{ID: editorU, Method: auth.MethodToken, Token: "ci"})
	e.log.Record(ev)
	_, out = e.get(t, viewerU, "/api/activity?limit=200")
	if tk := find(items(t, out), "hash", tokHash); tk == nil || tk["token"] != "ci" || tk["verified"] != true || tk["identity"] != editorU {
		t.Fatalf("%v", tk)
	}
}

func TestActivityWithoutAnAuditLogShowsEveryCommitUnverified(t *testing.T) {
	e := newActEnv(t, actOpts{noAudit: true})
	code, _, _ := e.do(t, "POST", "/api/c/todo", map[string]any{"data": map[string]any{"item": "x", "status": "待办"}}, map[string]string{"X-User": editorU})
	_ = code
	code, out := e.get(t, viewerU, "/api/activity")
	if code != 200 || out["audit"] != false {
		t.Fatalf("%d %v", code, out)
	}
	for _, it := range items(t, out) {
		if it["verified"] != false {
			t.Fatalf("%v", it)
		}
	}
	if len(items(t, out)) < 2 {
		t.Fatalf("%v", out)
	}
	_, out = e.get(t, viewerU, "/api/activity?identity="+editorU)
	if len(items(t, out)) != 0 {
		t.Fatal("nothing is verified, so nothing matches")
	}
	code, st := e.get(t, adminU, "/api/audit/status")
	if code != 200 || st["enabled"] != false || st["ok"] != true {
		t.Fatalf("%d %v", code, st)
	}
	code, out, _ = e.do(t, "POST", "/api/audit/ack", map[string]any{"through": 1}, map[string]string{"X-User": adminU})
	if code != 409 || out["error"] != "no_audit_log" {
		t.Fatalf("%d %v", code, out)
	}
	if code, m := e.get(t, adminU, "/api/meta"); code != 200 || m["auditAlert"] != nil {
		t.Fatalf("%d %v", code, m["auditAlert"])
	}
}

func TestActivityPermissionTable(t *testing.T) {
	e := newActEnv(t, actOpts{})
	// a state commit, a sign-in, an infra audit event and an infra commit
	e.laptopCommit(t, "2026-03-01T10:00:00Z", "state only", map[string]string{".rackbook/x.yml": "a: 1\n"})
	e.log.Record(audit.Event{Event: "login", Identity: editorU, Method: "oidc", Role: "editor", Addr: "203.0.113.0", Time: time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)})
	e.log.Record(audit.Event{Event: "secret_revealed", Area: "infra", Identity: infraU, Host: "alpha", Time: time.Date(2026, 3, 2, 9, 5, 0, 0, time.UTC)})
	if err := os.WriteFile(filepath.Join(e.infraSeed, "inventory/hosts.yml"), []byte(infraInventory+"# x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sh(t, e.infraSeed, "commit", "-qam", "infra change")
	sh(t, e.infraSeed, "push", "-q", "origin", "HEAD:refs/heads/main")
	if err := e.infra.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	areasOf := func(who string) map[string]int {
		_, out := e.get(t, who, "/api/activity?limit=200")
		n := map[string]int{}
		for _, it := range items(t, out) {
			n[it["area"].(string)]++
		}
		return n
	}
	has := func(who, subject string) bool {
		_, out := e.get(t, who, "/api/activity?limit=200")
		return find(items(t, out), "subject", subject) != nil
	}
	for _, c := range []struct {
		who                                  string
		areas                                []string
		state, signin, infraEvent, infraRepo bool
		addr                                 bool
	}{
		{viewerU, []string{"ledger"}, false, false, false, false, false},
		{editorU, []string{"ledger"}, false, false, false, false, false},
		{adminU, []string{"ledger", "audit"}, true, true, false, false, true},
		{infraU, []string{"ledger", "infra"}, false, false, true, true, false},
	} {
		code, out := e.get(t, c.who, "/api/activity")
		if code != 200 {
			t.Fatalf("%s: %d %v", c.who, code, out)
		}
		got := []string{}
		for _, a := range arr(t, out["areas"]) {
			got = append(got, a.(string))
		}
		if strings.Join(got, ",") != strings.Join(c.areas, ",") {
			t.Errorf("%s: areas %v, want %v", c.who, got, c.areas)
		}
		n := areasOf(c.who)
		if (n["audit"] > 0) != c.signin || (n["infra"] > 0) != (c.infraEvent || c.infraRepo) {
			t.Errorf("%s: %v", c.who, n)
		}
		if has(c.who, "state only") != c.state {
			t.Errorf("%s: state commit visible = %v", c.who, !c.state)
		}
		if has(c.who, "infra change") != c.infraRepo {
			t.Errorf("%s: infra commit visible = %v", c.who, !c.infraRepo)
		}
		_, out = e.get(t, c.who, "/api/activity?limit=200")
		if lg := find(items(t, out), "kind", "login"); (lg != nil) != c.signin || (lg != nil && (lg["addr"] != nil) != c.addr) {
			t.Errorf("%s: login %v", c.who, lg)
		}
		if ev := find(items(t, out), "kind", "secret_revealed"); (ev != nil) != c.infraEvent {
			t.Errorf("%s: infra event %v", c.who, ev)
		}
	}
	// an area the caller may not see is a 403, not an empty list
	for who, bad := range map[string][]string{viewerU: {"audit", "infra"}, editorU: {"audit", "infra"}, adminU: {"infra"}, infraU: {"audit"}} {
		for _, a := range bad {
			if code, out := e.get(t, who, "/api/activity?area="+a); code != 403 || out["error"] != "forbidden" {
				t.Errorf("%s area=%s: %d %v", who, a, code, out)
			}
		}
	}
	if code, out := e.get(t, adminU, "/api/activity?area=ledger&area=audit"); code != 200 || len(arr(t, out["areas"])) != 2 {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := e.get(t, adminU, "/api/activity?area=ledger,audit"); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	_, out := e.get(t, adminU, "/api/activity?area=audit&limit=200")
	for _, it := range items(t, out) {
		if it["area"] != "audit" || it["kind"] == "commit" {
			t.Fatalf("a commit audit line is no item of its own: %v", it)
		}
	}
	if code, _ := e.get(t, adminU, "/api/activity?area=nope"); code != 400 {
		t.Fatal(code)
	}
	// the state commit is flagged for administrators
	_, out = e.get(t, adminU, "/api/activity?limit=200")
	if it := find(items(t, out), "subject", "state only"); it == nil || it["state"] != "only" {
		t.Fatalf("%v", it)
	}
	// no sign-in: nothing
	if code, _, _ := e.do(t, "GET", "/api/activity", nil, nil); code != 401 {
		t.Fatalf("%d", code)
	}
}

func TestActivityCommitDiffVisibility(t *testing.T) {
	e := newActEnv(t, actOpts{})
	e.laptopCommit(t, "2026-03-01T10:00:00Z", "state only", map[string]string{".rackbook/x.yml": "a: 1\n"})
	e.laptopCommit(t, "2026-03-02T10:00:00Z", "mixed", map[string]string{".rackbook/x.yml": "a: 2\n", "notes.txt": "hello\n"})
	_, out := e.get(t, adminU, "/api/activity?limit=200")
	stateHash := find(items(t, out), "subject", "state only")["hash"].(string)
	mixedHash := find(items(t, out), "subject", "mixed")["hash"].(string)

	paths := func(out map[string]any) string {
		var p []string
		for _, f := range arr(t, out["files"]) {
			p = append(p, f.(map[string]any)["path"].(string))
		}
		return strings.Join(p, ",")
	}
	code, d := e.get(t, adminU, "/api/activity/commit/ledger/"+mixedHash)
	if code != 200 || paths(d) != ".rackbook/x.yml,notes.txt" || d["hash"] != mixedHash {
		t.Fatalf("%d %v", code, d)
	}
	for _, who := range []string{editorU, viewerU} {
		code, d = e.get(t, who, "/api/activity/commit/ledger/"+mixedHash)
		if code != 200 || paths(d) != "notes.txt" || !strings.Contains(arr(t, d["files"])[0].(map[string]any)["patch"].(string), "+hello") {
			t.Fatalf("%s: %d %v", who, code, d)
		}
		if code, d = e.get(t, who, "/api/activity/commit/ledger/"+stateHash); code != 404 || d["error"] != "not_found" {
			t.Fatalf("%s: %d %v", who, code, d)
		}
	}
	if code, _ = e.get(t, adminU, "/api/activity/commit/ledger/"+stateHash); code != 200 {
		t.Fatal(code)
	}
	for _, bad := range []string{"abc", "zzzzzzzz", "0000000000000000000000000000000000000000"} {
		if code, _ = e.get(t, adminU, "/api/activity/commit/ledger/"+bad); code != 404 {
			t.Errorf("%s: %d", bad, code)
		}
	}
	if code, _ = e.get(t, adminU, "/api/activity/commit/nowhere/"+mixedHash); code != 404 {
		t.Fatal(code)
	}

	// infra: only for the infra administrators, and secret files show no patch
	head := sh(t, e.infraSeed, "rev-parse", "HEAD")
	for _, who := range []string{adminU, editorU, viewerU} {
		if code, _ = e.get(t, who, "/api/activity/commit/infra/"+head); code != 403 {
			t.Errorf("%s: %d", who, code)
		}
	}
	code, d = e.get(t, infraU, "/api/activity/commit/infra/"+head)
	if code != 200 {
		t.Fatalf("%d %v", code, d)
	}
	var sawSecret, sawVars bool
	for _, f := range arr(t, d["files"]) {
		fm := f.(map[string]any)
		switch fm["path"] {
		case "secrets/alpha.sops.yaml":
			sawSecret = fm["hidden"] == true && fm["patch"] == nil && fm["status"] == "A"
		case "inventory/host_vars/alpha.yml":
			p, _ := fm["patch"].(string)
			sawVars = strings.Contains(p, "tailscale_ip") && !strings.Contains(p, "nope")
		}
	}
	if !sawSecret || !sawVars {
		t.Fatalf("secret file listed without its patch, other files with secret-looking values hidden: %v", d)
	}
}

func TestActivityPagesHaveNoDuplicatesOrGapsAcrossEqualTimes(t *testing.T) {
	e := newActEnv(t, actOpts{})
	same := "2026-03-01T10:00:00Z"
	// history with committer dates that never go back, as Rackbook's own commits are
	e.laptopCommit(t, "2026-03-01T09:00:00Z", "earlier", map[string]string{"z.txt": "z\n"})
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		e.laptopCommit(t, same, "same second "+n, map[string]string{n + ".txt": n + "\n"})
	}
	at := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	e.log.Record(audit.Event{Event: "logout", Identity: adminU, Time: at.Add(-time.Hour)}) // in time order: the audit log is read by seq
	for i := 0; i < 4; i++ {                                                               // the same second as the commits, in the audit log
		e.log.Record(audit.Event{Event: "login", Identity: adminU, Time: at.Add(time.Duration(i) * 100 * time.Millisecond)})
	}

	_, full := e.get(t, adminU, "/api/activity?limit=200&since=2026-03-01&until=2026-03-01")
	all := items(t, full)
	if len(all) != 11 || full["cursor"] != nil {
		t.Fatalf("%d items, cursor %v", len(all), full["cursor"])
	}
	keyOf := func(it map[string]any) string {
		if it["kind"] == "commit" {
			return it["hash"].(string)
		}
		return "audit:" + it["time"].(string) + ":" + it["kind"].(string) + ":" + jsonNum(it["seq"])
	}
	var want []string
	for _, it := range all {
		want = append(want, keyOf(it))
	}
	for _, limit := range []string{"1", "2", "3", "4", "5", "10"} {
		var got []string
		cursor := ""
		for pages := 0; ; pages++ {
			if pages > 30 {
				t.Fatalf("limit %s: does not end", limit)
			}
			path := "/api/activity?since=2026-03-01&until=2026-03-01&limit=" + limit
			if cursor != "" {
				path += "&cursor=" + cursor
			}
			code, out := e.get(t, adminU, path)
			if code != 200 {
				t.Fatalf("%d %v", code, out)
			}
			for _, it := range items(t, out) {
				got = append(got, keyOf(it))
			}
			c, _ := out["cursor"].(string)
			if c == "" {
				break
			}
			cursor = c
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("limit %s:\ngot  %v\nwant %v", limit, got, want)
		}
	}
	// the order is by time, newest first
	for i := 1; i < len(all); i++ {
		if all[i-1]["time"].(string) < all[i]["time"].(string) {
			t.Fatalf("%v before %v", all[i-1]["time"], all[i]["time"])
		}
	}
	if code, _ := e.get(t, adminU, "/api/activity?cursor=!!!"); code != 400 {
		t.Fatal(code)
	}
	if code, _ := e.get(t, adminU, "/api/activity?since=yesterday"); code != 400 {
		t.Fatal(code)
	}
	// a date alone is the whole day: until includes it
	_, out := e.get(t, adminU, "/api/activity?limit=200&until=2026-03-01")
	if len(items(t, out)) != 11 {
		t.Fatalf("%d", len(items(t, out)))
	}
	_, out = e.get(t, adminU, "/api/activity?limit=200&since=2026-03-02&until=2026-03-02")
	if len(items(t, out)) != 0 {
		t.Fatalf("%v", items(t, out))
	}
}

func jsonNum(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestActivityFiltersCollectionAndRecord(t *testing.T) {
	e := newActEnv(t, actOpts{})
	e.write(t, editorU, "first item")
	e.write(t, editorU, "second item")
	_, out := e.get(t, viewerU, "/api/activity?collection=todo&id="+"first%20item")
	its := items(t, out)
	if len(its) != 1 || its[0]["subject"] != "ledger(todo): add first item" {
		t.Fatalf("%v", its)
	}
	_, out = e.get(t, viewerU, "/api/activity?collection=todo")
	if n := len(items(t, out)); n != 3 { // the seed added the file
		t.Fatalf("%d", n)
	}
	for _, q := range []string{"collection=nope", "id=x"} {
		if code, _ := e.get(t, viewerU, "/api/activity?"+q); code != 400 {
			t.Errorf("%s: %d", q, code)
		}
	}
}

func TestActivityJSONLExport(t *testing.T) {
	e := newActEnv(t, actOpts{})
	e.write(t, editorU, "one")
	e.log.Record(audit.Event{Event: "login", Identity: editorU, Role: "editor"})
	req, _ := http.NewRequest("GET", e.ts.URL+"/api/activity?format=jsonl&limit=1", nil)
	req.Header.Set("X-User", adminU)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-ndjson" ||
		!strings.HasPrefix(resp.Header.Get("Content-Disposition"), "attachment; filename=rackbook-activity-") || !strings.HasSuffix(resp.Header.Get("Content-Disposition"), ".jsonl") {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	_, page := e.get(t, adminU, "/api/activity?limit=200")
	want := items(t, page)
	if len(lines) != len(want) || len(lines) < 3 {
		t.Fatalf("%d lines, %d items (limit is ignored: the export has every item)\n%s", len(lines), len(want), body)
	}
	for i, l := range lines {
		var it map[string]any
		if err := json.Unmarshal([]byte(l), &it); err != nil || it["time"] != want[i]["time"] || it["kind"] != want[i]["kind"] {
			t.Fatalf("line %d: %v %s", i, err, l)
		}
	}
	// the export is for administrators (design 3.1); piece 4 adds the auditors in canSee
	for _, who := range []string{viewerU, editorU, infraU} {
		req.Header.Set("X-User", who)
		resp2, _ := http.DefaultClient.Do(req)
		resp2.Body.Close()
		if resp2.StatusCode != 403 {
			t.Fatalf("%s: %d", who, resp2.StatusCode)
		}
	}
	// the hard cap ends the file with a marker
	old := api.SetMaxExportItems(2)
	defer api.SetMaxExportItems(old)
	req.Header.Set("X-User", adminU)
	resp3, _ := http.DefaultClient.Do(req)
	b3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	ls := strings.Split(strings.TrimSpace(string(b3)), "\n")
	if len(ls) != 3 || ls[2] != `{"truncated":true}` {
		t.Fatalf("%s", b3)
	}
	// a format that is not jsonl is refused
	if code, _ := e.get(t, adminU, "/api/activity?format=csv"); code != 400 {
		t.Fatal(code)
	}
}

func TestAuditStatusAndAcknowledgement(t *testing.T) {
	// an audit log with a recorded problem: a line cut from the end, found at start
	auditDir := filepath.Join(t.TempDir(), "audit")
	clk := time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC)
	l, err := audit.Open(auditDir, audit.Options{Now: func() time.Time { return clk }})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []time.Month{1, 2} {
		for d := 1; d <= 2; d++ {
			l.Record(audit.Event{Event: "login", Identity: "x", Time: time.Date(2026, m, d, 12, 0, 0, 0, time.UTC)})
		}
	}
	l.Close()
	feb := filepath.Join(auditDir, "audit-2026-02.jsonl")
	b, _ := os.ReadFile(feb)
	if err := os.WriteFile(feb, []byte(strings.SplitAfter(string(b), "\n")[0]), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	e := newActEnv(t, actOpts{auditDir: auditDir, auditOpt: audit.Options{Now: func() time.Time { return now }}})
	now = time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC) // later events go into a newer month

	code, st := e.get(t, adminU, "/api/audit/status")
	probs := st["problems"].([]any)
	if code != 200 || st["enabled"] != true || st["ok"] != false || len(probs) != 1 || probs[0].(map[string]any)["kind"] != "cut_from_end" {
		t.Fatalf("%d %v", code, st)
	}
	through := probs[0].(map[string]any)["recordedAt"]
	if _, m := e.get(t, adminU, "/api/meta"); m["auditAlert"] == nil {
		t.Fatalf("the banner for administrators: %v", m)
	}
	if _, m := e.get(t, editorU, "/api/meta"); m["auditAlert"] != nil {
		t.Fatalf("only administrators: %v", m["auditAlert"])
	}
	for _, who := range []string{editorU, viewerU, infraU} {
		if code, _ := e.get(t, who, "/api/audit/status"); code != 403 {
			t.Errorf("%s: %d", who, code)
		}
		if code, _, _ := e.do(t, "POST", "/api/audit/ack", map[string]any{"through": through}, map[string]string{"X-User": who}); code != 403 {
			t.Errorf("%s ack: %d", who, code)
		}
	}
	// a token cannot acknowledge; the origin guard applies as for every write
	if code, _, _ := e.do(t, "POST", "/api/audit/ack", map[string]any{"through": through}, map[string]string{"Authorization": "Bearer token"}); code != 403 {
		t.Fatalf("token: %d", code)
	}
	if code, _, _ := e.do(t, "POST", "/api/audit/ack", map[string]any{"through": through}, map[string]string{"X-User": adminU, "Sec-Fetch-Site": "cross-site"}); code != 403 {
		t.Fatalf("cross-site: %d", code)
	}
	if code, _, _ := e.do(t, "POST", "/api/audit/ack", "x", map[string]string{"X-User": adminU}); code != 400 {
		t.Fatalf("body: %d", code)
	}
	if code, out, _ := e.do(t, "POST", "/api/audit/ack", map[string]any{"through": 9999}, map[string]string{"X-User": adminU}); code != 400 {
		t.Fatalf("%d %v", code, out)
	}
	if code, out, _ := e.do(t, "POST", "/api/audit/ack", map[string]any{"through": 1}, map[string]string{"X-User": adminU}); code != 409 || out["error"] != "nothing_to_ack" {
		t.Fatalf("%d %v", code, out)
	}
	code, st, _ = e.do(t, "POST", "/api/audit/ack", map[string]any{"through": through}, map[string]string{"X-User": adminU})
	if code != 200 || st["ok"] != true || len(st["problems"].([]any)) != 0 {
		t.Fatalf("%d %v", code, st)
	}
	if _, m := e.get(t, adminU, "/api/meta"); m["auditAlert"] != nil {
		t.Fatalf("%v", m["auditAlert"])
	}
	// the acknowledgement is an item of the activity view, by who made it
	_, out := e.get(t, adminU, "/api/activity?area=audit&limit=200")
	ack := find(items(t, out), "kind", "chain_problem_ack")
	if ack == nil || ack["identity"] != adminU || find(items(t, out), "kind", "chain_problem") == nil {
		t.Fatalf("%v", items(t, out))
	}
	// and retention no longer keeps the month that holds the problem
	e.log.Close()
	l2, err := audit.Open(auditDir, audit.Options{RetentionMonths: 1, Now: func() time.Time { return time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	ents, _ := os.ReadDir(auditDir)
	for _, en := range ents {
		if strings.HasPrefix(en.Name(), "audit-2026-01") || strings.HasPrefix(en.Name(), "audit-2026-02") || strings.HasPrefix(en.Name(), "audit-2026-03") {
			t.Fatalf("%s is still there after the acknowledgement", en.Name())
		}
	}
}

func TestAckNeedsAWritableServer(t *testing.T) {
	e := newActEnv(t, actOpts{readOnly: true})
	if code, out, _ := e.do(t, "POST", "/api/audit/ack", map[string]any{"through": 1}, map[string]string{"X-User": adminU}); code != 403 || out["error"] != "read_only" {
		t.Fatalf("%d %v", code, out)
	}
}

// A parent with a newer committer date than its child used to be lost when the
// next page asked for "until the last date seen". Paging is by position in the
// walk now: every commit appears exactly once.
func TestActivityPagingUnderClockSkewLosesNothing(t *testing.T) {
	e := newActEnv(t, actOpts{})
	for i, d := range []string{"09:00", "12:00", "10:00", "10:30"} {
		e.laptopCommit(t, "2026-03-01T"+d+":00Z", "at "+d, map[string]string{"f" + string(rune('a'+i)) + ".txt": d + "\n"})
	}
	_, out := e.get(t, viewerU, "/api/activity?limit=200")
	want := map[string]bool{}
	for _, it := range items(t, out) {
		want[it["hash"].(string)] = true
	}
	if len(want) != 5 {
		t.Fatalf("%v", want)
	}
	for _, n := range []string{"1", "2"} {
		seen := map[string]int{}
		cursor := ""
		for page := 0; ; page++ {
			if page > 20 {
				t.Fatal("does not end")
			}
			path := "/api/activity?limit=" + n
			if cursor != "" {
				path += "&cursor=" + cursor
			}
			_, out := e.get(t, viewerU, path)
			for _, it := range items(t, out) {
				seen[it["hash"].(string)]++
			}
			if page == 0 {
				// a commit lands between two requests: the cursor keeps its walk
				e.laptopCommit(t, "2026-03-02T10:00:00Z", "landed "+n, map[string]string{"late" + n + ".txt": "x\n"})
			}
			c, _ := out["cursor"].(string)
			if c == "" {
				break
			}
			cursor = c
		}
		if len(seen) != len(want) {
			t.Fatalf("n=%s: %v", n, seen)
		}
		for h, c := range seen {
			if !want[h] || c != 1 {
				t.Fatalf("n=%s: %s seen %d times", n, h, c)
			}
		}
		_, out = e.get(t, viewerU, "/api/activity?limit=200")
		want = map[string]bool{}
		for _, it := range items(t, out) {
			want[it["hash"].(string)] = true
		}
	}
}

// Audit lines are read within a budget; running out of it is a position to
// resume from, not the end of the log.
func TestActivityAuditPagingResumesAfterTheScanBudget(t *testing.T) {
	e := newActEnv(t, actOpts{})
	for i := 1; i <= 60; i++ {
		who := adminU
		if i%25 == 0 {
			who = "rare@example.com"
		}
		e.log.Record(audit.Event{Event: "login", Identity: who, Time: time.Date(2026, 3, 1, 10, 0, i, 0, time.UTC)})
	}
	defer api.SetAuditBudget(api.SetAuditBudget(8))
	defer api.SetActivityChunk(api.SetActivityChunk(3))
	got := map[string]bool{}
	cursor := ""
	for page := 0; ; page++ {
		if page > 100 {
			t.Fatal("does not end")
		}
		path := "/api/activity?area=audit&identity=rare@example.com"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		code, out := e.get(t, adminU, path)
		if code != 200 {
			t.Fatalf("%d %v", code, out)
		}
		for _, it := range items(t, out) {
			got[it["time"].(string)] = true
		}
		c, _ := out["cursor"].(string)
		if c == "" {
			break
		}
		cursor = c
	}
	if len(got) != 2 {
		t.Fatalf("older audit events disappeared: %v", got)
	}
	// the export carries on across the resumes, and says when it ran out of work
	req, _ := http.NewRequest("GET", e.ts.URL+"/api/activity?format=jsonl&area=audit&identity=rare@example.com", nil)
	req.Header.Set("X-User", adminU)
	resp, _ := http.DefaultClient.Do(req)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if n := strings.Count(string(b), `"kind":"login"`); n != 2 || strings.Contains(string(b), "truncated") {
		t.Fatalf("%s", b)
	}
	defer api.SetExportWorkBudget(api.SetExportWorkBudget(5))
	resp, _ = http.DefaultClient.Do(req)
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasSuffix(strings.TrimSpace(string(b)), `{"truncated":true}`) {
		t.Fatalf("the export ran out of work and did not say so: %s", b)
	}
}
