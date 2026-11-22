package api_test

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func (e *actEnv) as(who string) map[string]string { return map[string]string{"X-User": who} }

func (e *actEnv) getAs(t *testing.T, who, path string) (int, map[string]any) {
	t.Helper()
	code, out, _ := e.do(t, "GET", path, nil, e.as(who))
	return code, out
}

func (e *actEnv) post(t *testing.T, who, path string, body map[string]any) (int, map[string]any) {
	t.Helper()
	code, out, _ := e.do(t, "POST", path, body, e.as(who))
	return code, out
}

// laptopEdit changes a file of the data repository as somebody with push access
// does: nothing vouches for the commit. msg is the whole commit message.
func (e *actEnv) laptopEdit(t *testing.T, when, msg, rel string, mutate func(string) string) string {
	t.Helper()
	sh(t, e.laptop, "pull", "--quiet")
	p := filepath.Join(e.laptop, rel)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	nb := mutate(string(b))
	if nb == string(b) {
		t.Fatalf("the edit of %s changed nothing:\n%s", rel, b)
	}
	if err := os.WriteFile(p, []byte(nb), 0o644); err != nil {
		t.Fatal(err)
	}
	sh(t, e.laptop, "add", "-A")
	cmd := exec.Command("git", "-C", e.laptop, "commit", "-q", "-m", msg)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Lap Top", "GIT_AUTHOR_EMAIL=lap@example.com", "GIT_COMMITTER_NAME=Lap Top", "GIT_COMMITTER_EMAIL=lap@example.com",
		"GIT_AUTHOR_DATE="+when, "GIT_COMMITTER_DATE="+when)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	sh(t, e.laptop, "push", "--quiet", "origin", "main")
	if err := e.store.Pull(context.Background()); err != nil {
		t.Fatal(err)
	}
	return sh(t, e.laptop, "rev-parse", "HEAD")
}

func (e *actEnv) head(t *testing.T) string {
	return sh(t, filepath.Join(e.root, "server"), "rev-parse", "HEAD")
}

func todo(item, scope, status string) map[string]any {
	d := map[string]any{"item": item, "status": status}
	if scope != "" {
		d["scope"] = scope
	}
	return d
}

func (e *actEnv) addTodo(t *testing.T, who string, d map[string]any) {
	t.Helper()
	if code, out := e.post(t, who, "/api/c/todo", map[string]any{"data": d}); code != 201 {
		t.Fatalf("%d %v", code, out)
	}
}

func (e *actEnv) putTodo(t *testing.T, who, id string, d map[string]any) {
	t.Helper()
	_, cur := e.getAs(t, who, "/api/c/todo/"+url.PathEscape(id))
	code, out, _ := e.do(t, "PUT", "/api/c/todo/"+url.PathEscape(id), map[string]any{"hash": cur["hash"], "data": d}, e.as(who))
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
}

func versionsOf(t *testing.T, out map[string]any) []map[string]any {
	t.Helper()
	var r []map[string]any
	for _, v := range arr(t, out["versions"]) {
		r = append(r, v.(map[string]any))
	}
	return r
}

func changeAt(v map[string]any, path string) map[string]any {
	for _, c := range v["changes"].([]any) {
		if c.(map[string]any)["path"] == path {
			return c.(map[string]any)
		}
	}
	return nil
}

func TestRecordHistoryShowsVersionsWithWhoAndFieldDiffs(t *testing.T) {
	e := newActEnv(t, actOpts{})
	e.addTodo(t, editorU, todo("History item", "", "待办"))
	e.putTodo(t, editorU, "History item", todo("History item", "gw", "待办"))
	// somebody with push access changes it by hand, and names the record
	e.laptopEdit(t, "2026-03-01T10:00:00Z", "tidy up\n\nRecord: todo/History item", "docs/ledger/todo.yml", func(s string) string {
		return strings.Replace(s, "{item: History item, status: 待办, scope: gw}", "{item: History item, status: 完成, scope: gw}", 1)
	})
	if _, out := e.getAs(t, viewerU, "/api/c/todo/History%20item"); out["data"].(map[string]any)["status"] != "完成" {
		t.Fatalf("%v", out)
	}

	code, out := e.getAs(t, viewerU, "/api/c/todo/History%20item/history")
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	vs := versionsOf(t, out)
	if len(vs) != 3 || out["id"] != "History item" || out["audit"] != true || out["cursor"] != nil {
		t.Fatalf("%v", out)
	}
	hand, edited, created := vs[0], vs[1], vs[2]
	if hand["verified"] != false || hand["name"] != "Lap Top" || hand["subject"] != "tidy up" || hand["change"] != "changed" {
		t.Fatalf("a commit nobody vouches for is unverified: %v", hand)
	}
	if c := changeAt(hand, "status"); c == nil || c["op"] != "changed" || c["old"] != "待办" || c["new"] != "完成" || len(hand["changes"].([]any)) != 1 {
		t.Fatalf("%v", hand["changes"])
	}
	if edited["verified"] != true || edited["identity"] != editorU || edited["change"] != "changed" || changeAt(edited, "scope")["op"] != "added" {
		t.Fatalf("%v", edited)
	}
	if created["change"] != "created" || created["verified"] != true || len(created["hash"].(string)) != 40 || created["recordHash"] == "" || created["recordHash"] == edited["recordHash"] {
		t.Fatalf("%v", created)
	}
	// a viewer reads it, an unknown collection or a bad limit is refused
	if code, _ := e.getAs(t, viewerU, "/api/c/nope/x/history"); code != 404 {
		t.Fatal(code)
	}
	if code, _ := e.getAs(t, viewerU, "/api/c/todo/History%20item/history?limit=0"); code != 400 {
		t.Fatal(code)
	}

	// paging: the cursor is for this record and this person
	code, p1 := e.getAs(t, viewerU, "/api/c/todo/History%20item/history?limit=2")
	cur, _ := p1["cursor"].(string)
	if code != 200 || len(versionsOf(t, p1)) != 2 || cur == "" {
		t.Fatalf("%d %v", code, p1)
	}
	if _, p2 := e.getAs(t, viewerU, "/api/c/todo/History%20item/history?limit=2&cursor="+url.QueryEscape(cur)); len(versionsOf(t, p2)) != 1 || p2["cursor"] != nil || versionsOf(t, p2)[0]["hash"] != created["hash"] {
		t.Fatalf("%v", p2)
	}
	if code, _ := e.getAs(t, viewerU, "/api/c/todo/Other/history?cursor="+url.QueryEscape(cur)); code != 400 {
		t.Fatalf("a cursor of another record: %d", code)
	}
	if code, _ := e.getAs(t, adminU, "/api/c/todo/History%20item/history?cursor="+url.QueryEscape(cur)); code != 400 {
		t.Fatalf("a cursor of another person: %d", code)
	}
	if code, _ := e.getAs(t, viewerU, "/api/c/todo/History%20item/history?cursor=x.y"); code != 400 {
		t.Fatalf("%d", code)
	}

	// one version, with what restoring it would change
	code, one := e.getAs(t, viewerU, "/api/c/todo/History%20item/history/"+created["hash"].(string))
	if code != 200 || one["exists"] != true || one["current"] != false || one["data"].(map[string]any)["status"] != "待办" ||
		changeAt(one, "status")["old"] != "完成" || changeAt(one, "status")["new"] != "待办" || one["commit"].(map[string]any)["verified"] != true {
		t.Fatalf("%d %v", code, one)
	}
	if code, _ := e.getAs(t, viewerU, "/api/c/todo/History%20item/history/"+strings.Repeat("0", 40)); code != 404 {
		t.Fatal(code)
	}
	if code, _ := e.getAs(t, viewerU, "/api/c/todo/Nothing/history/"+created["hash"].(string)); code != 404 {
		t.Fatal(code)
	}
}

func TestRestoreWritesOneOrdinaryEditWithTheRestoredFromTrailer(t *testing.T) {
	e := newActEnv(t, actOpts{})
	e.addTodo(t, editorU, todo("R1", "gw", "待办"))
	e.putTodo(t, editorU, "R1", todo("R1", "web", "完成"))
	_, h := e.getAs(t, viewerU, "/api/c/todo/R1/history")
	first := versionsOf(t, h)[1]["hash"].(string)
	_, cur := e.getAs(t, viewerU, "/api/c/todo/R1")
	before := e.head(t)

	code, out := e.post(t, editorU, "/api/c/todo/R1/restore", map[string]any{"commit": first[:12], "hash": cur["hash"]})
	if code != 200 || out["restoredFrom"] != first || out["data"].(map[string]any)["scope"] != "gw" || out["commit"] == "" {
		t.Fatalf("%d %v", code, out)
	}
	_, now := e.getAs(t, viewerU, "/api/c/todo/R1")
	if d := now["data"].(map[string]any); d["scope"] != "gw" || d["status"] != "待办" {
		t.Fatalf("%v", now)
	}
	if sh(t, filepath.Join(e.root, "server"), "rev-parse", "HEAD~1") != before {
		t.Fatal("one new commit")
	}
	msg := sh(t, e.bare, "log", "-1", "--format=%B", "main")
	for _, want := range []string{"ledger(todo): restore R1\n", "Edited-by: " + editorU, "Record: todo/R1", "Restored-from: " + first} {
		if !strings.Contains(msg, want) {
			t.Fatalf("%q is not in\n%s", want, msg)
		}
	}
	// the audit log vouches for it as for any commit of the server, and Activity shows where it came from
	_, act := e.getAs(t, viewerU, "/api/activity")
	r := find(items(t, act), "hash", e.head(t))
	if r == nil || r["verified"] != true || r["identity"] != editorU || r["restoredFrom"] != first {
		t.Fatalf("%v", r)
	}
	// and so does the record's own history
	_, h = e.getAs(t, viewerU, "/api/c/todo/R1/history")
	top := versionsOf(t, h)[0]
	if top["restoredFrom"] != first || top["verified"] != true || changeAt(top, "status")["new"] != "待办" {
		t.Fatalf("%v", top)
	}
	// the restored version is now the current one: there is nothing to restore
	_, now = e.getAs(t, viewerU, "/api/c/todo/R1")
	if code, out := e.post(t, editorU, "/api/c/todo/R1/restore", map[string]any{"commit": first, "hash": now["hash"]}); code != 409 || out["error"] != "already_current" {
		t.Fatalf("%d %v", code, out)
	}
}

func TestRestoreRefusals(t *testing.T) {
	e := newActEnv(t, actOpts{})
	e.addTodo(t, editorU, todo("R2", "gw", "待办"))
	_, h := e.getAs(t, viewerU, "/api/c/todo/R2/history")
	first := versionsOf(t, h)[0]["hash"].(string)
	// a commit before the record existed: the seed
	other := sh(t, filepath.Join(e.root, "server"), "rev-list", "--max-parents=0", "HEAD")
	e.putTodo(t, editorU, "R2", todo("R2", "web", "完成"))
	_, cur := e.getAs(t, viewerU, "/api/c/todo/R2")
	body := map[string]any{"commit": first, "hash": cur["hash"]}
	head := e.head(t)

	// a stale hash is the usual conflict, and shows the current record
	if code, out := e.post(t, editorU, "/api/c/todo/R2/restore", map[string]any{"commit": first, "hash": "0000000000000000"}); code != 409 || out["error"] != "conflict" || out["current"] == nil {
		t.Fatalf("%d %v", code, out)
	}
	// the hash is required for a record that exists
	if code, out := e.post(t, editorU, "/api/c/todo/R2/restore", map[string]any{"commit": first}); code != 400 {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := e.post(t, editorU, "/api/c/todo/R2/restore", map[string]any{"hash": cur["hash"]}); code != 400 {
		t.Fatalf("%d", code)
	}
	// a commit of another record, an unknown or unreachable one, and nonsense
	for _, c := range []string{other, strings.Repeat("0", 40), "nothex", "HEAD", "--all", head[:10] + "zz"} {
		if code, out := e.post(t, editorU, "/api/c/todo/R2/restore", map[string]any{"commit": c, "hash": cur["hash"]}); code < 400 || code >= 500 {
			t.Fatalf("%q: %d %v", c, code, out)
		}
	}
	if code, out := e.post(t, editorU, "/api/c/todo/R2/restore", map[string]any{"commit": other, "hash": cur["hash"]}); code != 404 {
		t.Fatalf("a commit in which the record did not exist: %d %v", code, out)
	}
	// who may: a viewer may not, nor a cross-site page, and an unknown collection is a 404
	if code, out := e.post(t, viewerU, "/api/c/todo/R2/restore", body); code != 403 || out["error"] != "forbidden" {
		t.Fatalf("%d %v", code, out)
	}
	code, out, _ := e.do(t, "POST", "/api/c/todo/R2/restore", body, map[string]string{"X-User": editorU, "Sec-Fetch-Site": "cross-site"})
	if code != 403 || out["error"] != "cross_site" {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := e.post(t, editorU, "/api/c/nope/R2/restore", body); code != 404 {
		t.Fatal(code)
	}
	if e.head(t) != head {
		t.Fatal("a refused restore wrote something")
	}
}

func TestRestoreIsRefusedOnAReadOnlyServer(t *testing.T) {
	e := newActEnv(t, actOpts{readOnly: true})
	_, h := e.getAs(t, adminU, "/api/c/todo/"+url.PathEscape("评估关闭路由器 WAN 上的 Web 后台")+"/history")
	// reading the history works; restoring does not
	if code, out := e.post(t, adminU, "/api/c/todo/x/restore", map[string]any{"commit": strings.Repeat("a", 40), "hash": "x"}); code != 403 || out["error"] != "read_only" {
		t.Fatalf("%d %v %v", code, out, h)
	}
}

func TestRestoreThatNoLongerFitsTheSchemaOpensInTheEditor(t *testing.T) {
	e := newActEnv(t, actOpts{})
	e.addTodo(t, editorU, todo("R3", "", "待办")) // no scope
	_, h := e.getAs(t, viewerU, "/api/c/todo/R3/history")
	first := versionsOf(t, h)[0]["hash"].(string)
	e.putTodo(t, editorU, "R3", todo("R3", "web", "完成"))
	// the type now requires a scope
	e.laptopEdit(t, "2026-03-01T10:00:00Z", "require scope", "schemas/todo.json", func(s string) string {
		return strings.Replace(s, `"required": ["item", "status"]`, `"required": ["item", "status", "scope"]`, 1)
	})
	_, cur := e.getAs(t, viewerU, "/api/c/todo/R3")
	head := e.head(t)
	code, out := e.post(t, editorU, "/api/c/todo/R3/restore", map[string]any{"commit": first, "hash": cur["hash"]})
	if code != 409 || out["error"] != "restore_needs_edit" || out["commit"] != first || out["data"].(map[string]any)["status"] != "待办" || out["errors"] == nil {
		t.Fatalf("%d %v", code, out)
	}
	if _, has := out["data"].(map[string]any)["scope"]; has {
		t.Fatalf("the old content comes back as it was: %v", out["data"])
	}
	if e.head(t) != head {
		t.Fatal("nothing is written")
	}
	// the editor then saves it as an ordinary edit
	d := out["data"].(map[string]any)
	d["scope"] = "fixed"
	e.putTodo(t, editorU, "R3", d)
}

func TestRestoreOfADifferentKeyIsAnEdit(t *testing.T) {
	e := newActEnv(t, actOpts{})
	e.addTodo(t, editorU, todo("R4", "gw", "待办"))
	_, h := e.getAs(t, viewerU, "/api/c/todo/R4/history")
	first := versionsOf(t, h)[0]["hash"].(string)
	_, cur := e.getAs(t, viewerU, "/api/c/todo/R4")
	e.putTodo(t, editorU, "R4", todo("R4", "web", "完成"))
	_, cur2 := e.getAs(t, viewerU, "/api/c/todo/R4")
	_ = cur
	// the key of the collection changes: the id of R4 is now "R4/web"
	e.laptopEdit(t, "2026-03-01T10:00:00Z", "key is item and scope", "rackbook.yml", func(s string) string {
		return strings.Replace(s, "    key: [item]\n", "    key: [item, scope]\n", 1)
	})
	// the old version has no scope-keyed id "R4/web" at that time, so it is not found
	code, _ := e.post(t, editorU, "/api/c/todo/"+url.PathEscape("R4/web")+"/restore", map[string]any{"commit": first, "hash": cur2["hash"]})
	if code != 404 && code != 409 {
		t.Fatalf("%d", code)
	}
	// delete it, and restore it by its old id: the old key fields give "R4/gw" under today's key
	_, now := e.getAs(t, editorU, "/api/c/todo/"+url.PathEscape("R4/web"))
	hash, _ := now["hash"].(string)
	if hash == "" {
		t.Fatalf("%v", now)
	}
	if code, out, _ := e.do(t, "DELETE", "/api/c/todo/"+url.PathEscape("R4/web")+"?hash="+hash, nil, e.as(editorU)); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	head := e.head(t)
	code, out := e.post(t, editorU, "/api/c/todo/R4/restore", map[string]any{"commit": first, "hash": ""})
	if code != 409 || out["error"] != "restore_needs_edit" || out["data"].(map[string]any)["scope"] != "gw" {
		t.Fatalf("%d %v", code, out)
	}
	if e.head(t) != head {
		t.Fatal("nothing is written")
	}
}

func TestDeletedRecordsListAndRestore(t *testing.T) {
	e := newActEnv(t, actOpts{})
	e.addTodo(t, editorU, todo("D1", "gw", "待办"))
	e.addTodo(t, editorU, todo("D2", "web", "完成"))
	e.addTodo(t, editorU, todo("D3", "", "待办"))
	del := func(id string) {
		t.Helper()
		_, now := e.getAs(t, editorU, "/api/c/todo/"+id)
		if code, out, _ := e.do(t, "DELETE", "/api/c/todo/"+id+"?hash="+now["hash"].(string), nil, e.as(editorU)); code != 200 {
			t.Fatalf("%d %v", code, out)
		}
	}
	del("D1")
	del("D2")
	e.addTodo(t, editorU, todo("D2", "again", "待办")) // deleted and added again

	code, out := e.getAs(t, viewerU, "/api/c/todo/deleted")
	if code != 200 || out["complete"] != true || out["audit"] != true {
		t.Fatalf("%d %v", code, out)
	}
	recs := arr(t, out["records"])
	if len(recs) != 1 {
		t.Fatalf("%v", recs)
	}
	d := recs[0].(map[string]any)
	if d["id"] != "D1" || d["verified"] != true || d["identity"] != editorU || d["subject"] != "ledger(todo): delete D1" || d["deletedAt"] == "" || len(d["last"].(string)) != 40 || len(d["hash"].(string)) != 40 {
		t.Fatalf("%v", d)
	}
	sum := d["summary"].([]any)
	if len(sum) == 0 || sum[0].(map[string]any)["field"] != "item" || sum[0].(map[string]any)["value"] != "D1" {
		t.Fatalf("%v", sum)
	}
	// its last version, expandable
	code, one := e.getAs(t, viewerU, "/api/c/todo/D1/history/"+d["last"].(string))
	if code != 200 || one["exists"] != false || one["data"].(map[string]any)["scope"] != "gw" {
		t.Fatalf("%d %v", code, one)
	}

	// restore: an empty hash, for a record that is not there
	if code, out := e.post(t, viewerU, "/api/c/todo/D1/restore", map[string]any{"commit": d["last"], "hash": ""}); code != 403 {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := e.post(t, editorU, "/api/c/todo/D1/restore", map[string]any{"commit": d["last"], "hash": "abcdabcdabcdabcd"}); code != 409 || out["error"] != "conflict" {
		t.Fatalf("a hash for a record that does not exist: %d %v", code, out)
	}
	code, out = e.post(t, editorU, "/api/c/todo/D1/restore", map[string]any{"commit": d["last"], "hash": ""})
	if code != 201 || out["data"].(map[string]any)["scope"] != "gw" || out["restoredFrom"] != d["last"] {
		t.Fatalf("%d %v", code, out)
	}
	if code, now := e.getAs(t, viewerU, "/api/c/todo/D1"); code != 200 || now["data"].(map[string]any)["status"] != "待办" {
		t.Fatalf("%d %v", code, now)
	}
	msg := sh(t, e.bare, "log", "-1", "--format=%B", "main")
	if !strings.Contains(msg, "ledger(todo): restore D1") || !strings.Contains(msg, "Restored-from: "+d["last"].(string)) {
		t.Fatal(msg)
	}
	// it is not deleted any more; and a record that exists needs its hash
	if _, out := e.getAs(t, viewerU, "/api/c/todo/deleted"); len(arr(t, out["records"])) != 0 {
		t.Fatalf("%v", out)
	}
	if code, out := e.post(t, editorU, "/api/c/todo/D1/restore", map[string]any{"commit": d["last"], "hash": ""}); code != 400 {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := e.getAs(t, viewerU, "/api/c/nope/deleted"); code != 404 {
		t.Fatal(code)
	}
}

func TestRestoreAsksForTheSecretScanConfirmationAgain(t *testing.T) {
	e := newActEnv(t, actOpts{})
	e.addTodo(t, editorU, todo("S1", "clean", "待办"))
	// by hand, somebody puts something in that the scan would ask about
	hand := e.laptopEdit(t, "2026-03-01T10:00:00Z", "hand edit", "docs/ledger/todo.yml", func(s string) string {
		return strings.Replace(s, "{item: S1, scope: clean, status: 待办}", `{item: S1, scope: "password: hunter2hunter2", status: 待办}`, 1)
	})
	e.putTodo(t, editorU, "S1", todo("S1", "clean again", "待办"))
	_, cur := e.getAs(t, viewerU, "/api/c/todo/S1")
	head := e.head(t)

	// the history does not show the value
	_, h := e.getAs(t, viewerU, "/api/c/todo/S1/history")
	if raw := strings.Contains(strings.ReplaceAll(toJSON(h), " ", ""), "hunter2"); raw {
		t.Fatalf("the history leaks it: %v", h)
	}
	_, one := e.getAs(t, viewerU, "/api/c/todo/S1/history/"+hand)
	if strings.Contains(toJSON(one), "hunter2") || one["hidden"] != float64(1) {
		t.Fatalf("%v", one)
	}
	code, out := e.post(t, editorU, "/api/c/todo/S1/restore", map[string]any{"commit": hand, "hash": cur["hash"]})
	if code != 422 || out["error"] != "secret_suspected" || strings.Contains(toJSON(out), "hunter2") {
		t.Fatalf("%d %v", code, out)
	}
	if e.head(t) != head {
		t.Fatal("nothing is written before it is confirmed")
	}
	// a viewer cannot confirm; the editor does, as for any write
	code, out = e.post(t, editorU, "/api/c/todo/S1/restore", map[string]any{"commit": hand, "hash": cur["hash"], "confirm_not_secret": true})
	if code != 200 || out["restoredFrom"] != hand {
		t.Fatalf("%d %v", code, out)
	}
	msg := sh(t, e.bare, "log", "-1", "--format=%B", "main")
	if !strings.Contains(msg, "Restored-from: "+hand) || !strings.Contains(msg, "Secret-scan: confirmed-not-secret by "+editorU) {
		t.Fatal(msg)
	}
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
