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
	if !isErr || out["error"] != "secret_detected" {
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
