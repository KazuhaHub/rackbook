package mcpauth_test

import (
	"net/url"
	"strings"
	"testing"
)

const modulesYAML = `modules:
  bot:
    token: bot-token
    collection: todo
    fields: [status]
    direct_push: true
  pr-bot:
    token: pr-token
    collection: todo
    fields: [status]
`

const manualItem = "评估关闭路由器 WAN 上的 Web 后台"

func todoBody(item, status, source string) map[string]any {
	d := map[string]any{"item": item, "scope": "x", "status": status}
	if source != "" {
		d["source"] = source
	}
	return map[string]any{"data": d}
}

func TestModuleTokenWrites(t *testing.T) {
	t.Parallel()
	h := newHarness(t, hopts{git: true, modules: modulesYAML})
	bot, _ := h.createToken(map[string]any{"name": "bot-token", "scope": "write", "actions": []string{"create", "update", "delete"}})
	prBot, _ := h.createToken(map[string]any{"name": "pr-token", "scope": "write"})
	plain, _ := h.createToken(map[string]any{"name": "plain", "scope": "write"})
	todo := func(item string) string { return "/api/c/todo/" + url.PathEscape(item) }

	// direct_push: a create goes straight to the branch, tagged with the trailer.
	code, r, _ := h.do("POST", "/api/c/todo", bot, todoBody("rotate", "待办", "bot"))
	if code != 201 || r["pullRequest"] != nil || h.gh.count() != 0 {
		t.Fatalf("%d %v", code, r)
	}
	msg := git(t, h.bare, "log", "-1", "--format=%B", "main")
	if !strings.Contains(msg, "\nSource: bot") || !strings.Contains(msg, "Edited-via: rackbook (token:bot-token)") {
		t.Fatalf("trailers:\n%s", msg)
	}
	hash := r["hash"].(string)

	// The source is enforced on create.
	for _, src := range []string{"", "manual", "pr-bot"} {
		if code, r, _ := h.do("POST", "/api/c/todo", bot, todoBody("other", "待办", src)); code != 403 || r["error"] != "forbidden" {
			t.Fatalf("source %q: %d %v", src, code, r)
		}
	}
	// Its own field may change (direct push); a foreign field may not.
	code, r, _ = h.do("PUT", todo("rotate"), bot, map[string]any{"hash": hash, "data": todoBody("rotate", "完成", "bot")["data"]})
	if code != 200 || r["pullRequest"] != nil {
		t.Fatalf("%d %v", code, r)
	}
	hash = r["hash"].(string)
	d := todoBody("rotate", "完成", "bot")["data"].(map[string]any)
	d["scope"] = "changed"
	if code, r, _ := h.do("PUT", todo("rotate"), bot, map[string]any{"hash": hash, "data": d}); code != 403 || r["error"] != "forbidden" || !strings.Contains(r["message"].(string), "scope") {
		t.Fatalf("%d %v", code, r)
	}
	// Manual records are out of reach: no source on them.
	before := git(t, h.bare, "rev-parse", "main")
	_, got, _ := h.do("GET", todo(manualItem), bot, nil)
	manualData := got["data"].(map[string]any)
	manualData["status"] = "完成"
	manualData["source"] = "bot"
	if code, r, _ := h.do("PUT", todo(manualItem), bot, map[string]any{"hash": got["hash"], "data": manualData}); code != 403 {
		t.Fatalf("%d %v", code, r)
	}
	// Deletes are refused, also with a delete-capable token and a valid hash.
	if code, r, _ := h.do("DELETE", todo("rotate")+"?hash="+hash, bot, nil); code != 403 || r["error"] != "forbidden" {
		t.Fatalf("%d %v", code, r)
	}
	// Another collection is refused even though the token may write anywhere.
	if code, r, _ := h.do("POST", "/api/c/sites", bot, map[string]any{"data": map[string]any{"code": "x", "name": "x"}}); code != 403 || !strings.Contains(r["message"].(string), "only write to todo") {
		t.Fatalf("%d %v", code, r)
	}
	if h.gh.count() != 0 || git(t, h.bare, "rev-parse", "main") != before {
		t.Fatal("a refused write reached the repository")
	}

	// Without direct_push the module's write is a pull request.
	code, r, _ = h.do("POST", "/api/c/todo", prBot, todoBody("pr item", "待办", "pr-bot"))
	if code != 201 || r["pullRequest"] != true || h.gh.count() != 1 {
		t.Fatalf("%d %v", code, r)
	}
	// A token that is not listed is not a module: it writes records without a source.
	if code, r, _ := h.do("POST", "/api/c/todo", plain, todoBody("by hand", "待办", "")); code != 201 || r["pullRequest"] != true {
		t.Fatalf("%d %v", code, r)
	}

	// /api/meta lists the modules without token names.
	_, meta, _ := h.do("GET", "/api/meta", bot, nil)
	mods := meta["modules"].([]any)
	if len(mods) != 2 {
		t.Fatalf("%v", mods)
	}
	m0 := mods[0].(map[string]any)
	if m0["name"] != "bot" || m0["collection"] != "todo" || m0["directPush"] != true || m0["fields"].([]any)[0] != "status" {
		t.Fatalf("%v", m0)
	}
}

func TestModuleTokenOverMCP(t *testing.T) {
	t.Parallel()
	h := newHarness(t, hopts{git: true, modules: modulesYAML})
	bot, _ := h.createToken(map[string]any{"name": "bot-token", "scope": "write", "actions": []string{"create", "update", "delete"}})
	cs := h.mcpSession(bot)

	out, isErr := call(t, cs, "create_record", map[string]any{"collection": "todo", "data": map[string]any{"item": "via mcp", "scope": "x", "status": "待办", "source": "bot"}})
	if isErr || out["pullRequest"] != false {
		t.Fatalf("%v", out)
	}
	if msg := git(t, h.bare, "log", "-1", "--format=%B", "main"); !strings.Contains(msg, "\nSource: bot") {
		t.Fatalf("trailers:\n%s", msg)
	}
	hash := out["hash"].(string)
	if out, isErr := call(t, cs, "create_record", map[string]any{"collection": "todo", "data": map[string]any{"item": "nosrc", "scope": "x", "status": "待办"}}); !isErr || out["error"] != "forbidden" {
		t.Fatalf("%v", out)
	}
	if out, isErr := call(t, cs, "update_record", map[string]any{"collection": "todo", "id": "via mcp", "hash": hash, "data": map[string]any{"item": "via mcp", "scope": "y", "status": "待办", "source": "bot"}}); !isErr || out["error"] != "forbidden" {
		t.Fatalf("%v", out)
	}
	if out, isErr := call(t, cs, "update_record", map[string]any{"collection": "todo", "id": "via mcp", "hash": hash, "data": map[string]any{"item": "via mcp", "scope": "x", "status": "完成", "source": "bot"}}); isErr || out["pullRequest"] != false {
		t.Fatalf("%v", out)
	}
	if out, isErr := call(t, cs, "delete_record", map[string]any{"collection": "todo", "id": "via mcp", "hash": hash}); !isErr || out["error"] != "forbidden" {
		t.Fatalf("%v", out)
	}
	if out, isErr := call(t, cs, "create_record", map[string]any{"collection": "sites", "data": map[string]any{"code": "x"}}); !isErr || out["error"] != "forbidden" {
		t.Fatalf("%v", out)
	}
	if h.gh.count() != 0 {
		t.Fatal("no pull request expected")
	}
}
