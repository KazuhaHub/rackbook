package mcpauth_test

import (
	"encoding/base64"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kazuhahub/rackbook/internal/auth/oauth/oauthtest"
	"github.com/kazuhahub/rackbook/internal/gitstore"
)

// obj, arr and field read nested parts of a decoded tool result.
func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }
func arr(v any) []any          { a, _ := v.([]any); return a }

func todo(item string) map[string]any {
	return map[string]any{"item": item, "scope": "x", "status": "待办"}
}

func toolNames(t *testing.T, cs *mcp.ClientSession) map[string]bool {
	t.Helper()
	res, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}
	return names
}

func TestRecordsWriteToolsOpenPullRequests(t *testing.T) {
	h := newHarness(t, hopts{git: true})
	cs := h.mcpSession(h.jwt(oauthtest.Options{Subject: "Alice", Scope: "rackbook:write", ClientID: "cursor"}))

	// dry_run shows the change and opens nothing.
	out, isErr := call(t, cs, "records_create", map[string]any{"collection": "todo", "data": todo("dry"), "dry_run": true})
	d := obj(out["dry_run"])
	if isErr || out["change"] != nil || d["valid"] != true || d["changed"] != true || d["would_be"] != "pull_request" || len(arr(d["files"])) != 1 {
		t.Fatalf("%v", out)
	}
	f := obj(arr(d["files"])[0])
	if f["path"] != "docs/ledger/todo.yml" || f["status"] != "modified" || !strings.Contains(f["diff"].(string), "+- {item: dry,") || obj(out["record"])["hash"] == "" {
		t.Fatalf("%v", f)
	}
	if h.gh.count() != 0 || git(t, h.bare, "rev-list", "--count", "main") != "1" {
		t.Fatal("a dry run must write nothing")
	}
	// A dry run of an invalid write reports the problems and is not an error.
	out, isErr = call(t, cs, "records_create", map[string]any{"collection": "todo", "data": map[string]any{"status": "待办"}, "dry_run": true})
	d = obj(out["dry_run"])
	if isErr || d["valid"] != false || obj(arr(d["problems"])[0])["error"] != "invalid" || h.gh.count() != 0 {
		t.Fatalf("%v", out)
	}

	// The real create is a pull request: {change, record}.
	out, isErr = call(t, cs, "records_create", map[string]any{"collection": "todo", "data": todo("via mcp")})
	ch := obj(out["change"])
	if isErr || ch["kind"] != "pull_request" || ch["id"] != "1" || ch["url"] != "https://github.com/acme/ledger/pull/1" || obj(out["record"])["hash"] == "" || obj(out["record"])["id"] != "via mcp" {
		t.Fatalf("%v", out)
	}
	if h.gh.count() != 1 || !strings.HasPrefix(h.gh.prs[0]["head"], "rackbook/mcp/alice/") {
		t.Fatalf("%+v", h.gh.prs)
	}
	// Invalid data: structured error with details.errors, nothing opened.
	out, isErr = call(t, cs, "records_create", map[string]any{"collection": "todo", "data": map[string]any{"status": "待办"}})
	if !isErr || out["error"] != "invalid" || obj(out["details"])["errors"] == nil || h.gh.count() != 1 {
		t.Fatalf("%v", out)
	}

	// Update: expected_hash is required, a stale one conflicts with the current record.
	rec := "所有服务器 SSH 改到 10511"
	hash := todoRecord(t, cs, rec)
	upd := func(extra map[string]any) map[string]any {
		args := map[string]any{"collection": "todo", "id": rec, "expected_hash": hash,
			"data": map[string]any{"item": rec, "scope": "所有服务器", "status": "完成（2026-11-02）"}}
		for k, v := range extra {
			args[k] = v
		}
		out, _ := call(t, cs, "records_update", args)
		return out
	}
	if out = upd(map[string]any{"expected_hash": ""}); out["error"] != "invalid" {
		t.Fatalf("%v", out)
	}
	if out = upd(map[string]any{"expected_hash": "deadbeef"}); out["error"] != "conflict" || obj(out["details"])["current"] == nil {
		t.Fatalf("%v", out)
	}
	if out = upd(map[string]any{"dry_run": true}); obj(out["dry_run"])["valid"] != true || h.gh.count() != 1 {
		t.Fatalf("%v", out)
	}
	if out = upd(nil); obj(out["change"])["kind"] != "pull_request" || h.gh.count() != 2 {
		t.Fatalf("%v", out)
	}

	// Delete: a stale hash conflicts; a referenced record is a conflict with the references;
	// clear_references shows what it would clear; deletes are always pull requests.
	const dev = "web-hostco-ashburn-va-us-dc"
	devHash, _ := call(t, cs, "records_get", map[string]any{"collection": "devices", "id": dev})
	dh := devHash["hash"].(string)
	if out, isErr = call(t, cs, "records_delete", map[string]any{"collection": "devices", "id": dev}); !isErr || out["error"] != "invalid" {
		t.Fatalf("%v", out)
	}
	out, isErr = call(t, cs, "records_delete", map[string]any{"collection": "devices", "id": dev, "expected_hash": dh})
	if !isErr || out["error"] != "conflict" || len(arr(obj(out["details"])["references"])) == 0 {
		t.Fatalf("%v", out)
	}
	// clear_references removes the pointers from the services and addresses that hold
	// them; here that would leave them without their required device, so the dry run
	// reports the validation problem instead of opening anything.
	out, isErr = call(t, cs, "records_delete", map[string]any{"collection": "devices", "id": dev, "expected_hash": dh, "clear_references": true, "dry_run": true})
	d = obj(out["dry_run"])
	if isErr || d["valid"] != false || obj(arr(d["problems"])[0])["error"] != "invalid" || h.gh.count() != 2 {
		t.Fatalf("%v", out)
	}
	// A dry run of a delete that is fine says it would be a pull request.
	out, isErr = call(t, cs, "records_delete", map[string]any{"collection": "todo", "id": rec, "expected_hash": hash, "dry_run": true})
	d = obj(out["dry_run"])
	if isErr || d["valid"] != true || d["would_be"] != "pull_request" || out["record"] != nil || len(arr(d["files"])) != 1 || h.gh.count() != 2 {
		t.Fatalf("%v", out)
	}
	if out, isErr = call(t, cs, "records_delete", map[string]any{"collection": "todo", "id": "via mcp", "expected_hash": "x"}); !isErr || out["error"] != "not_found" && out["error"] != "conflict" {
		t.Fatalf("%v", out)
	}
	if git(t, h.bare, "rev-list", "--count", "main") != "1" {
		t.Fatal("main must not move")
	}
}

func TestRecordsWriteIdempotencyKey(t *testing.T) {
	h := newHarness(t, hopts{git: true})
	cs := h.mcpSession(h.jwt(oauthtest.Options{Subject: "alice", Scope: "rackbook:write"}))
	args := func(item, key string) map[string]any {
		return map[string]any{"collection": "todo", "data": todo(item), "idempotency_key": key}
	}
	first, isErr := call(t, cs, "records_create", args("once", "k1"))
	if isErr || first["replayed"] != nil || h.gh.count() != 1 {
		t.Fatalf("%v", first)
	}
	// The same key and arguments: the first result, no second pull request.
	again, isErr := call(t, cs, "records_create", args("once", "k1"))
	if isErr || again["replayed"] != true || obj(again["change"])["url"] != obj(first["change"])["url"] || h.gh.count() != 1 {
		t.Fatalf("%v", again)
	}
	// The same key with other arguments is refused, and nothing is written.
	out, isErr := call(t, cs, "records_create", args("other", "k1"))
	if !isErr || out["error"] != "conflict" || h.gh.count() != 1 {
		t.Fatalf("%v", out)
	}
	// Another key is another change; a dry run never takes a key.
	if out, isErr = call(t, cs, "records_create", args("two", "k2")); isErr || h.gh.count() != 2 {
		t.Fatalf("%v", out)
	}
	dry := args("three", "k3")
	dry["dry_run"] = true
	call(t, cs, "records_create", dry)
	if out, isErr = call(t, cs, "records_create", args("three", "k3")); isErr || out["replayed"] != nil || h.gh.count() != 3 {
		t.Fatalf("%v", out)
	}
	// A failed write is not remembered: the retry runs again.
	bad := args("", "k4")
	bad["data"] = map[string]any{"status": "待办"}
	if _, isErr = call(t, cs, "records_create", bad); !isErr {
		t.Fatal("must fail")
	}
	if out, isErr = call(t, cs, "records_create", args("four", "k4")); isErr || out["replayed"] != nil {
		t.Fatalf("%v", out)
	}
	// Keys are per identity.
	ed := h.mcpSession(h.jwt(oauthtest.Options{Subject: "ed", Scope: "rackbook:write"}))
	if out, isErr = call(t, ed, "records_create", args("once", "k1")); isErr || out["replayed"] != nil {
		t.Fatalf("%v", out)
	}
}

func TestRecordsWriteIsGatedLikeTheOldTools(t *testing.T) {
	h := newHarness(t, hopts{git: true, mcpYAML: "    direct_push:\n      - {users: [\"mcphub:alice\"], collections: [todo]}\n"})
	writes := []struct {
		tool string
		args map[string]any
	}{
		{"records_create", map[string]any{"collection": "todo", "data": todo("x")}},
		{"records_update", map[string]any{"collection": "todo", "id": "x", "expected_hash": "h", "data": todo("x")}},
		{"records_delete", map[string]any{"collection": "todo", "id": "x", "expected_hash": "h"}},
	}
	// No write scope: insufficient_scope. A viewer: forbidden, scope or not. Also with dry_run.
	for _, c := range []struct {
		who   oauthtest.Options
		code  string
		write bool
	}{
		{oauthtest.Options{Subject: "alice", Scope: "other"}, "insufficient_scope", false},
		{oauthtest.Options{Subject: "vic", Scope: "rackbook:write"}, "forbidden", false},
	} {
		cs := h.mcpSession(h.jwt(c.who))
		for _, w := range writes {
			for _, dry := range []bool{false, true} {
				args := map[string]any{"dry_run": dry}
				for k, v := range w.args {
					args[k] = v
				}
				if out, isErr := call(t, cs, w.tool, args); !isErr || out["error"] != c.code {
					t.Errorf("%s as %s dry_run=%v: %v", w.tool, c.who.Subject, dry, out)
				}
			}
		}
		names := toolNames(t, cs)
		if names["records_create"] || names["records_delete"] || names["create_record"] || names["delete_record"] || !names["records_query"] || !names["list_records"] {
			t.Errorf("%s must see read tools only: %v", c.who.Subject, names)
		}
		info, _ := call(t, cs, "ledger_info", nil)
		if obj(info["caller"])["can_write"] != false || obj(info["caller"])["authenticated"] != true {
			t.Errorf("%v", info["caller"])
		}
		for _, f := range arr(info["families"]) {
			for _, tl := range arr(obj(f)["tools"]) {
				if strings.HasPrefix(tl.(string), "records_") && tl != "records_query" && tl != "records_get" {
					t.Errorf("ledger_info lists %v to a caller that cannot write", tl)
				}
			}
		}
	}
	if h.gh.count() != 0 {
		t.Fatal("nothing may be opened")
	}

	// An editor sees the write tools, and a listed user's create goes straight to main.
	alice := h.mcpSession(h.jwt(oauthtest.Options{Subject: "alice", Scope: "rackbook:write"}))
	names := toolNames(t, alice)
	for _, n := range []string{"records_create", "records_update", "records_delete", "create_record", "update_record", "delete_record", "history_list", "history_diff", "record_history"} {
		if !names[n] {
			t.Errorf("an editor must see %s", n)
		}
	}
	info, _ := call(t, alice, "ledger_info", nil)
	if c := obj(info["caller"]); c["can_write"] != true || c["role"] != "editor" {
		t.Fatalf("%v", c)
	}
	out, isErr := call(t, alice, "records_create", map[string]any{"collection": "todo", "data": todo("direct"), "dry_run": true})
	if isErr || obj(out["dry_run"])["would_be"] != "direct_push" {
		t.Fatalf("%v", out)
	}
	out, isErr = call(t, alice, "records_create", map[string]any{"collection": "todo", "data": todo("direct")})
	ch := obj(out["change"])
	if isErr || ch["kind"] != "commit" || ch["id"] == "" || ch["url"] != nil || h.gh.count() != 0 || git(t, h.bare, "rev-list", "--count", "main") != "2" {
		t.Fatalf("%v", out)
	}
	// ... but a delete is a pull request anyway, in a dry run too.
	hash := todoRecord(t, alice, "direct")
	out, _ = call(t, alice, "records_delete", map[string]any{"collection": "todo", "id": "direct", "expected_hash": hash, "dry_run": true})
	if obj(out["dry_run"])["would_be"] != "pull_request" {
		t.Fatalf("%v", out)
	}
	out, isErr = call(t, alice, "records_delete", map[string]any{"collection": "todo", "id": "direct", "expected_hash": hash})
	if isErr || obj(out["change"])["kind"] != "pull_request" || h.gh.count() != 1 || git(t, h.bare, "rev-list", "--count", "main") != "2" {
		t.Fatalf("%v", out)
	}
}

func TestOldWriteNamesKeepTheirArgumentsAndResultShape(t *testing.T) {
	h := newHarness(t, hopts{git: true})
	cs := h.mcpSession(h.jwt(oauthtest.Options{Subject: "alice", Scope: "rackbook:write"}))
	// create_record: {id, hash, data, url, pullRequest, message}, no {change, record}.
	out, isErr := call(t, cs, "create_record", map[string]any{"collection": "todo", "data": todo("old")})
	if isErr || out["pullRequest"] != true || out["url"] == nil || out["hash"] == nil || out["change"] != nil || out["record"] != nil || out["message"] == nil {
		t.Fatalf("%v", out)
	}
	// update_record takes "hash", and has no dry_run.
	rec := "所有服务器 SSH 改到 10511"
	hash := todoRecord(t, cs, rec)
	data := map[string]any{"item": rec, "scope": "所有服务器", "status": "完成（2026-11-02）"}
	if out, isErr = call(t, cs, "update_record", map[string]any{"collection": "todo", "id": rec, "hash": hash, "data": data}); isErr || out["id"] != rec || out["change"] != nil || out["pullRequest"] != true {
		t.Fatalf("%v", out)
	}
	if res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "update_record", Arguments: map[string]any{"collection": "todo", "id": rec, "hash": hash, "data": data, "dry_run": true}}); err == nil && !res.IsError {
		t.Fatal("the old tool must not take the new arguments")
	}
	// delete_record keeps its flat error shape.
	if out, isErr = call(t, cs, "delete_record", map[string]any{"collection": "todo", "id": rec, "hash": "nope"}); !isErr || out["error"] != "conflict" || out["status"] != float64(409) {
		t.Fatalf("%v", out)
	}
	// And each says it is deprecated.
	res, _ := cs.ListTools(t.Context(), nil)
	for _, tool := range res.Tools {
		want := map[string]string{"create_record": "records_create", "update_record": "records_update", "delete_record": "records_delete", "record_history": "history_list"}[tool.Name]
		if want != "" && !strings.HasPrefix(tool.Description, "Deprecated: use "+want+"; removed in v0.7.0. ") {
			t.Errorf("%s: %q", tool.Name, tool.Description)
		}
	}
}

func TestHistoryToolsPageAndDiff(t *testing.T) {
	h := newHarness(t, hopts{git: true, mcpYAML: "    direct_push:\n      - {users: [\"mcphub:alice\"], collections: [todo]}\n"})
	cs := h.mcpSession(h.jwt(oauthtest.Options{Subject: "alice", Scope: "rackbook:write"}))
	// Three direct commits to one record: create, then two updates.
	out, _ := call(t, cs, "records_create", map[string]any{"collection": "todo", "data": todo("hist")})
	created := obj(out["change"])["id"].(string)
	hash := obj(out["record"])["hash"].(string)
	for _, status := range []string{"进行中", "完成"} {
		out, _ = call(t, cs, "records_update", map[string]any{"collection": "todo", "id": "hist", "expected_hash": hash,
			"data": map[string]any{"item": "hist", "scope": "x", "status": status}})
		hash = obj(out["record"])["hash"].(string)
	}
	last := obj(out["change"])["id"].(string)

	list, isErr := call(t, cs, "history_list", map[string]any{"collection": "todo", "id": "hist"})
	commits := arr(list["items"])
	if isErr || len(commits) != 3 || list["next_cursor"] != "" || obj(commits[0])["hash"] != last || obj(commits[2])["hash"] != created {
		t.Fatalf("%v", list)
	}
	// Paging: one commit per page, newest first, all three reached once.
	var got []string
	cursor := ""
	for pages := 0; pages < 6; pages++ {
		args := map[string]any{"collection": "todo", "id": "hist", "limit": 1}
		if cursor != "" {
			args["cursor"] = cursor
		}
		p, _ := call(t, cs, "history_list", args)
		for _, c := range arr(p["items"]) {
			got = append(got, obj(c)["hash"].(string))
		}
		if cursor, _ = p["next_cursor"].(string); cursor == "" {
			break
		}
	}
	if strings.Join(got, ",") != last+","+obj(commits[1])["hash"].(string)+","+created {
		t.Fatalf("%v", got)
	}
	// A collection's history includes the seed commit; a limit above 100 is capped.
	if all, _ := call(t, cs, "history_list", map[string]any{"collection": "todo", "limit": 100000}); len(arr(all["items"])) != 4 {
		t.Fatalf("%v", all)
	}
	if out, isErr = call(t, cs, "history_list", map[string]any{"collection": "nope"}); !isErr || out["error"] != "not_found" {
		t.Fatalf("%v", out)
	}
	if out, isErr = call(t, cs, "history_list", map[string]any{"collection": "todo", "cursor": "!"}); !isErr || out["error"] != "invalid" {
		t.Fatalf("%v", out)
	}

	// history_diff: field-level before and after.
	diff, isErr := call(t, cs, "history_diff", map[string]any{"commit": last})
	chg := arr(diff["changes"])
	if isErr || len(chg) != 1 || diff["total"] != float64(1) || diff["truncated"] != false || obj(diff["commit"])["hash"] != last {
		t.Fatalf("%v", diff)
	}
	c := obj(chg[0])
	f := obj(arr(c["fields"])[0])
	if c["collection"] != "todo" || c["id"] != "hist" || c["change"] != "updated" || len(arr(c["fields"])) != 1 || f["field"] != "status" || f["before"] != "进行中" || f["after"] != "完成" {
		t.Fatalf("%v", c)
	}
	diff, _ = call(t, cs, "history_diff", map[string]any{"commit": created, "collection": "todo", "id": "hist"})
	if c = obj(arr(diff["changes"])[0]); c["change"] != "added" || len(arr(c["fields"])) != 3 || obj(arr(c["fields"])[0])["before"] != nil {
		t.Fatalf("%v", diff)
	}
	// The seed commit added every record; filters narrow it, and an unrelated filter finds nothing.
	seed := git(t, h.bare, "rev-list", "--max-parents=0", "main")[:7]
	all, _ := call(t, cs, "history_diff", map[string]any{"commit": seed})
	if all["total"].(float64) < 20 {
		t.Fatalf("the seed commit adds the whole ledger: %v", all["total"])
	}
	if only, _ := call(t, cs, "history_diff", map[string]any{"commit": seed, "collection": "ports"}); only["total"].(float64) < 1 || only["total"].(float64) >= all["total"].(float64) {
		t.Fatalf("%v", only["total"])
	}
	if none, _ := call(t, cs, "history_diff", map[string]any{"commit": last, "collection": "ports"}); none["total"] != float64(0) {
		t.Fatalf("%v", none)
	}
	for name, args := range map[string]map[string]any{
		"unknown commit":    {"commit": "abcdef1"},
		"not a hash":        {"commit": "--output=x"},
		"id needs a collec": {"commit": last, "id": "hist"},
		"unknown coll":      {"commit": last, "collection": "nope"},
	} {
		out, isErr := call(t, cs, "history_diff", args)
		if !isErr || (out["error"] != "not_found" && out["error"] != "invalid") {
			t.Errorf("%s: %v", name, out)
		}
	}
	// The old name still lists commits under "commits".
	if out, isErr := call(t, cs, "record_history", map[string]any{"collection": "todo", "id": "hist"}); isErr || len(arr(out["commits"])) != 3 {
		t.Fatalf("%v", out)
	}
}

func TestHistoryDiffOnlyReadsCommitsOfTheTrackedBranch(t *testing.T) {
	h := newHarness(t, hopts{git: true})
	cs := h.mcpSession(h.jwt(oauthtest.Options{Subject: "vic"})) // a viewer
	editor := h.mcpSession(h.jwt(oauthtest.Options{Subject: "alice", Scope: "rackbook:write"}))
	if out, isErr := call(t, editor, "records_create", map[string]any{"collection": "todo", "data": todo("unmerged")}); isErr || h.gh.count() != 1 {
		t.Fatalf("%v", out)
	}
	// The pull request's commit exists in the remote (and was in the clone for a moment),
	// but is not on the tracked branch: it must read as a commit that does not exist.
	pr := git(t, h.bare, "rev-parse", h.gh.prs[0]["head"])
	_, missing := call(t, cs, "history_diff", map[string]any{"commit": "abcdef1234"})
	want, _ := call(t, cs, "history_diff", map[string]any{"commit": "abcdef1234"})
	for _, rev := range []string{pr, pr[:7], pr[:12]} {
		out, isErr := call(t, cs, "history_diff", map[string]any{"commit": rev})
		if !missing || !isErr || out["error"] != "not_found" || strings.Replace(out["message"].(string), rev, "X", 1) != strings.Replace(want["message"].(string), "abcdef1234", "X", 1) {
			t.Errorf("%s: %v (nonexistent: %v)", rev, out, want)
		}
	}
	// A commit of the tracked branch still works, by full and by abbreviated hash.
	seed := git(t, h.bare, "rev-parse", "main")
	for _, rev := range []string{seed, seed[:7]} {
		if out, isErr := call(t, cs, "history_diff", map[string]any{"commit": rev}); isErr || out["total"].(float64) < 20 {
			t.Errorf("%s: %v", rev, out)
		}
	}

	// A commit that only touched Rackbook's state files is not ledger history either:
	// the log would answer with the previous ledger commit, which must not pass for it.
	other := t.TempDir()
	git(t, other, "clone", "-q", h.bare, "w")
	w := other + "/w"
	if err := os.MkdirAll(w+"/.rackbook", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w+"/.rackbook/state.txt", []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, w, "add", ".")
	git(t, w, "commit", "-q", "-m", "state only")
	git(t, w, "push", "-q", "origin", "main")
	stateOnly := git(t, w, "rev-parse", "HEAD")
	if err := h.store.Pull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if out, isErr := call(t, cs, "history_diff", map[string]any{"commit": stateOnly}); !isErr || out["error"] != "not_found" {
		t.Fatalf("a state-only commit: %v", out)
	}
}

func TestIdempotencyKeysAreNotSharedBetweenCredentials(t *testing.T) {
	h := newHarness(t, hopts{git: true})
	// Two API tokens, one creator: the same identity ID, different credentials.
	a, _ := h.createToken(map[string]any{"name": "tok-a", "scope": "write"})
	b, _ := h.createToken(map[string]any{"name": "tok-b", "scope": "write"})
	args := map[string]any{"collection": "todo", "data": todo("shared key"), "idempotency_key": "k"}
	first, isErr := call(t, h.mcpSession(a), "records_create", args)
	if isErr || h.gh.count() != 1 {
		t.Fatalf("%v", first)
	}
	// The other credential must neither replay the first result nor be told the key is taken.
	second, isErr := call(t, h.mcpSession(b), "records_create", args)
	if isErr || second["replayed"] != nil || h.gh.count() != 2 {
		t.Fatalf("%v", second)
	}
	// The same credential does replay.
	if again, _ := call(t, h.mcpSession(a), "records_create", args); again["replayed"] != true || h.gh.count() != 2 {
		t.Fatalf("%v", again)
	}
	// And an OAuth session of the same user name is a third credential.
	oauth := h.mcpSession(h.jwt(oauthtest.Options{Subject: "alice", Scope: "rackbook:write"}))
	if out, isErr := call(t, oauth, "records_create", args); isErr || out["replayed"] != nil || h.gh.count() != 3 {
		t.Fatalf("%v", out)
	}
}

func TestHistoryListSaysWhenItsScanCapIsHit(t *testing.T) {
	old := gitstore.MaxHistoryScan
	gitstore.MaxHistoryScan = 3
	t.Cleanup(func() { gitstore.MaxHistoryScan = old })
	h := newHarness(t, hopts{git: true, mcpYAML: "    direct_push:\n      - {users: [\"mcphub:alice\"], collections: [todo]}\n"})
	cs := h.mcpSession(h.jwt(oauthtest.Options{Subject: "alice", Scope: "rackbook:write"}))
	for _, item := range []string{"one", "two", "three"} {
		if out, isErr := call(t, cs, "records_create", map[string]any{"collection": "todo", "data": todo(item)}); isErr {
			t.Fatalf("%v", out)
		}
	}
	// Four commits touch todo; the scan reads three.
	page := func(args map[string]any) map[string]any {
		t.Helper()
		args["collection"] = "todo"
		out, isErr := call(t, cs, "history_list", args)
		if isErr {
			t.Fatalf("%v", out)
		}
		return out
	}
	// A page that lies fully inside the scan is returned, with a next page.
	p1 := page(map[string]any{"limit": 2})
	if len(arr(p1["items"])) != 2 || p1["next_cursor"] == "" || p1["scan_limit_reached"] != false {
		t.Fatalf("%v", p1)
	}
	// A page that was fully read and ends exactly at the cap is returned whole, not refused;
	// only the next page is unreachable, which is said with the flag and no cursor.
	p := page(map[string]any{"limit": 2, "cursor": encodeOffset(1)})
	if len(arr(p["items"])) != 2 || p["next_cursor"] != "" || p["scan_limit_reached"] != true {
		t.Fatalf("%v", p)
	}
	// A page that is partly beyond the cap returns what was read.
	p = page(map[string]any{"limit": 2, "cursor": p1["next_cursor"]})
	if len(arr(p["items"])) != 1 || p["next_cursor"] != "" || p["scan_limit_reached"] != true {
		t.Fatalf("%v", p)
	}
	// One entirely beyond it is empty, and says why.
	p = page(map[string]any{"limit": 2, "cursor": encodeOffset(5)})
	if len(arr(p["items"])) != 0 || p["next_cursor"] != "" || p["scan_limit_reached"] != true {
		t.Fatalf("%v", p)
	}
	// A history shorter than the cap really ends.
	if out, isErr := call(t, cs, "history_list", map[string]any{"collection": "todo", "id": "one", "limit": 2}); isErr || out["next_cursor"] != "" || out["scan_limit_reached"] != false {
		t.Fatalf("%v", out)
	}
}

func encodeOffset(n int) string { return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(n))) }

// A commit left at the server clone's HEAD (a crash or a failed reset during a pull
// request) is not on the tracked branch: history lists and diffs never show it.
func TestHistoryIgnoresACommitLeftAtHEAD(t *testing.T) {
	h := newHarness(t, hopts{git: true})
	cs := h.mcpSession(h.jwt(oauthtest.Options{Subject: "vic"}))
	p := h.dir + "/docs/ledger/todo.yml"
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(p, append(b, []byte("- {item: leftover, scope: x, status: 待办}\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, h.dir, "commit", "-q", "-am", "leftover pr commit")
	head := git(t, h.dir, "rev-parse", "HEAD")
	if out, isErr := call(t, cs, "history_diff", map[string]any{"commit": head}); !isErr || out["error"] != "not_found" {
		t.Fatalf("%v", out)
	}
	list, _ := call(t, cs, "history_list", map[string]any{"collection": "todo"})
	for _, c := range arr(list["items"]) {
		if strings.HasPrefix(head, obj(c)["hash"].(string)) {
			t.Fatalf("listed: %v", list)
		}
	}
	// The record's own history does not show it either.
	if out, _ := call(t, cs, "history_list", map[string]any{"collection": "todo", "id": "leftover"}); strings.Contains(strings.Join(func() (s []string) {
		for _, c := range arr(out["items"]) {
			s = append(s, obj(c)["subject"].(string))
		}
		return
	}(), "|"), "leftover") {
		t.Fatalf("%v", out)
	}
}

func TestDryRunRefusesWhatARealWriteWouldRefuse(t *testing.T) {
	// No repository: a pull request cannot be opened.
	h := newHarness(t, hopts{})
	cs := h.mcpSession(h.jwt(oauthtest.Options{Subject: "alice", Scope: "rackbook:write"}))
	out, isErr := call(t, cs, "records_create", map[string]any{"collection": "todo", "data": todo("x"), "dry_run": true})
	if !isErr || out["error"] != "pull_request_unavailable" {
		t.Fatalf("%v", out)
	}
	// A rewritten remote history pauses writes, and so it does a dry run.
	g := newHarness(t, hopts{git: true})
	other := t.TempDir()
	git(t, other, "clone", "-q", g.bare, "w")
	w := other + "/w"
	git(t, w, "commit", "-q", "--allow-empty", "-m", "extra")
	git(t, w, "push", "-q", "origin", "main")
	g.store.Pull(t.Context())
	git(t, g.bare, "update-ref", "refs/heads/main", git(t, g.bare, "commit-tree", "-m", "rewritten", "main^{tree}"))
	g.store.Pull(t.Context())
	cs = g.mcpSession(g.jwt(oauthtest.Options{Subject: "alice", Scope: "rackbook:write"}))
	for _, dry := range []bool{false, true} {
		out, isErr = call(t, cs, "records_create", map[string]any{"collection": "todo", "data": todo("x"), "dry_run": dry})
		if !isErr || out["error"] != "history_rewritten" || obj(out["details"])["lastGood"] == nil {
			t.Fatalf("dry_run=%v: %v", dry, out)
		}
	}
	// A dirty clone refuses both too.
	d := newHarness(t, hopts{git: true})
	if err := os.WriteFile(d.dir+"/stray.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cs = d.mcpSession(d.jwt(oauthtest.Options{Subject: "alice", Scope: "rackbook:write"}))
	for _, dry := range []bool{false, true} {
		out, isErr = call(t, cs, "records_create", map[string]any{"collection": "todo", "data": todo("x"), "dry_run": dry})
		if !isErr || out["error"] != "repo_dirty" {
			t.Fatalf("dry_run=%v: %v", dry, out)
		}
	}
}

func TestToolsListHonoursATokensActionsAndCollections(t *testing.T) {
	h := newHarness(t, hopts{git: true})
	tests := []struct {
		name        string
		body        map[string]any
		create      bool
		update      bool
		del         bool
		wantWrite   bool
		wantDeleter bool
	}{
		{"create only", map[string]any{"name": "c", "scope": "write", "actions": []string{"create"}}, true, false, false, true, false},
		{"delete only", map[string]any{"name": "d", "scope": "write", "actions": []string{"delete"}}, false, false, true, false, true},
		{"update and delete on todo", map[string]any{"name": "ud", "scope": "write", "collections": []string{"todo"}, "actions": []string{"update", "delete"}}, false, true, true, true, true},
		{"all actions", map[string]any{"name": "all", "scope": "write"}, true, true, true, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, _ := h.createToken(tt.body)
			cs := h.mcpSession(secret)
			names := toolNames(t, cs)
			for tool, want := range map[string]bool{"records_create": tt.create, "create_record": tt.create, "records_update": tt.update, "update_record": tt.update,
				"records_delete": tt.del, "delete_record": tt.del, "records_query": true} {
				if names[tool] != want {
					t.Errorf("%s listed=%v, want %v", tool, names[tool], want)
				}
			}
			info, _ := call(t, cs, "ledger_info", nil)
			c := obj(info["caller"])
			if c["can_write"] != tt.wantWrite || c["can_delete"] != tt.wantDeleter {
				t.Errorf("caller %v", c)
			}
		})
	}
}
