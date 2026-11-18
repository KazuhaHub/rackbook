package mcpauth_test

import (
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/auth/oauth/oauthtest"
)

// Assembled at run time: this file holds no string a scanner would flag.
var slackName = "xox" + "b-1234567890-abcdefghij"
var leak = "gh" + "p_" + strings.Repeat("a1B2", 9)

func TestMCPWriteToolsRefuseSecretsAndTokenNamesToo(t *testing.T) {
	h := newHarness(t, hopts{git: true})
	cs := h.mcpSession(h.jwt(oauthtest.Options{Subject: "alice", Scope: "rackbook:write"}))
	headBefore := git(t, h.bare, "rev-parse", "main")

	out, isErr := call(t, cs, "create_record", map[string]any{"collection": "todo", "data": map[string]any{"item": "new " + leak, "status": "待办"}})
	if !isErr || out["error"] != "secret_detected" || out["status"] != float64(422) {
		t.Fatalf("%v", out)
	}
	f := out["findings"].([]any)[0].(map[string]any)
	if f["rule"] != "github-token" || f["path"] != "/item" || strings.Contains(f["excerpt"].(string), leak[:8]) {
		t.Fatalf("%v", f)
	}

	hash := todoRecord(t, cs, "评估关闭路由器 WAN 上的 Web 后台")
	out, isErr = call(t, cs, "update_record", map[string]any{"collection": "todo", "id": "评估关闭路由器 WAN 上的 Web 后台", "hash": hash,
		"data": map[string]any{"item": "评估关闭路由器 WAN 上的 Web 后台", "scope": "password: hunter2hunter2", "status": "待决定"}})
	if !isErr || out["error"] != "secret_suspected" { // a keyword assignment is the heuristic tier
		t.Fatalf("%v", out)
	}
	if h.gh.count() != 0 || git(t, h.bare, "rev-parse", "main") != headBefore {
		t.Fatal("a refused MCP write reached Git or GitHub")
	}

	// A token whose name is a secret is refused with the same error, nothing committed.
	code, m, _ := h.do("POST", "/api/admin/tokens", "", map[string]any{"name": slackName, "scope": "read"})
	if code != 422 || m["error"] != "secret_detected" {
		t.Fatalf("%d %v", code, m)
	}
	if git(t, h.bare, "rev-parse", "main") != headBefore {
		t.Fatal("token name was committed")
	}
	// A normal name still works, and the hash and prefix it stores are not scanned.
	h.createToken(map[string]any{"name": "ci", "scope": "read"})
}

func TestConfirmNotSecretOverAPIAndMCP(t *testing.T) {
	h := newHarness(t, hopts{git: true})
	suspect := map[string]any{"item": "root密码：Hunter2Hunter2", "status": "待办"}
	create := func(body map[string]any, bearer string) (int, map[string]any) {
		code, m, _ := h.do("POST", "/api/c/todo", bearer, body)
		return code, m
	}

	// an editor session: held as secret_suspected, then accepted with the confirmation
	code, m := create(map[string]any{"data": suspect}, "")
	if code != 422 || m["error"] != "secret_suspected" || m["findings"].([]any)[0].(map[string]any)["tier"] != "confirm" {
		t.Fatalf("%d %v", code, m)
	}
	headBefore := git(t, h.bare, "rev-parse", "main")
	code, m = create(map[string]any{"data": suspect, "confirm_not_secret": true}, "")
	if code != 201 {
		t.Fatalf("%d %v", code, m)
	}
	msg := git(t, h.bare, "log", "-1", "--format=%B", "main")
	if !strings.Contains(msg, "Secret-scan: confirmed-not-secret by boss@example.com (secret-assignment)") || git(t, h.bare, "rev-parse", "main") == headBefore {
		t.Fatalf("%s", msg)
	}
	// check does not warn about a record whose last commit confirmed it
	if _, c, _ := h.do("GET", "/api/check", "", nil); c["ok"] != true || len(c["warnings"].([]any)) != 0 {
		t.Fatalf("%v", c)
	}

	// block tier ignores the confirmation
	code, m = create(map[string]any{"data": map[string]any{"item": "x " + leak, "status": "待办"}, "confirm_not_secret": true}, "")
	if code != 422 || m["error"] != "secret_detected" {
		t.Fatalf("%d %v", code, m)
	}

	// a token write becomes a pull request: its confirmation is never accepted
	secret, _ := h.createToken(map[string]any{"name": "ci", "scope": "write", "collections": []string{"todo"}})
	code, m = create(map[string]any{"data": suspect, "confirm_not_secret": true}, secret)
	if code != 422 || m["error"] != "secret_suspected" || h.gh.count() != 0 {
		t.Fatalf("token: %d %v", code, m)
	}
	cs := h.mcpSession(secret)
	out, isErr := call(t, cs, "create_record", map[string]any{"collection": "todo", "data": suspect, "confirm_not_secret": true})
	if !isErr || out["error"] != "secret_suspected" {
		t.Fatalf("mcp token: %v", out)
	}

	suspect2 := map[string]any{"item": "alice 口令是 Hunter2Hunter2", "status": "待办"}
	// an OAuth/MCP identity with write rights may confirm, even though its write is a pull request
	cs = h.mcpSession(h.jwt(oauthtest.Options{Subject: "alice", Scope: "rackbook:write"}))
	out, isErr = call(t, cs, "create_record", map[string]any{"collection": "todo", "data": suspect2})
	if !isErr || out["error"] != "secret_suspected" {
		t.Fatalf("mcp unconfirmed: %v", out)
	}
	out, isErr = call(t, cs, "create_record", map[string]any{"collection": "todo", "data": suspect2, "confirm_not_secret": true})
	if isErr || out["pullRequest"] != true || h.gh.count() != 1 {
		t.Fatalf("mcp confirmed: %v", out)
	}
	if body := git(t, h.bare, "log", "-1", "--format=%B", h.gh.prs[0]["head"]); !strings.Contains(body, "Secret-scan: confirmed-not-secret by alice (secret-assignment)") {
		t.Fatal(body)
	}
}
