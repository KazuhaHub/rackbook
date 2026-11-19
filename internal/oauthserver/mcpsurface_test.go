package oauthserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (e *env) session(token string) *mcp.ClientSession {
	e.t.Helper()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil).Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: e.ts.URL + "/mcp", HTTPClient: &http.Client{Transport: bearerTransport{token}}}, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { cs.Close() })
	return cs
}

func (e *env) callTool(cs *mcp.ClientSession, name string, args map[string]any) (map[string]any, bool) {
	e.t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		e.t.Fatal(err)
	}
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(sb.String()), &out); err != nil {
		e.t.Fatalf("%s: not JSON: %q", name, sb.String())
	}
	return out, res.IsError
}

func (e *env) toolSet(cs *mcp.ClientSession) map[string]bool {
	e.t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		e.t.Fatal(err)
	}
	m := map[string]bool{}
	for _, tl := range res.Tools {
		m[tl.Name] = true
	}
	return m
}

// A viewer's built-in token sees no write tools; an admin token creates a
// record through the new MCP surface and the commit names the client.
func TestBuiltinTokenOnTheMCPSurface(t *testing.T) {
	e := newEnv(t, opts{git: true, mcpYAML: "    direct_push:\n      - {roles: [admin], collections: [\"*\"]}\n"})
	git := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = e.repo
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return string(out)
	}

	_, vtok := e.login("vic@example.com", "Viewer Client")
	vs := e.session(vtok.access)
	names := e.toolSet(vs)
	for _, w := range []string{"records_create", "records_update", "records_delete", "create_record", "update_record", "delete_record"} {
		if names[w] {
			t.Errorf("viewer sees %s", w)
		}
	}
	if !names["records_query"] || !names["ledger_info"] {
		t.Fatalf("viewer tools: %v", names)
	}
	info, _ := e.callTool(vs, "ledger_info", nil)
	if c, _ := info["caller"].(map[string]any); c["can_write"] != false {
		t.Fatalf("viewer caller: %v", info["caller"])
	}

	_, etok := e.login(boss, "Editor Client")
	es := e.session(etok.access)
	if names := e.toolSet(es); !names["records_create"] || !names["create_record"] {
		t.Fatalf("editor tools: %v", names)
	}
	data := map[string]any{"item": "oauth-mcp-check", "scope": "all", "status": "待办"}
	out, isErr := e.callTool(es, "records_create", map[string]any{"collection": "todo", "data": data, "dry_run": true})
	d, _ := out["dry_run"].(map[string]any)
	if isErr || d["valid"] != true {
		t.Fatalf("dry run: %v", out)
	}
	before := git("rev-list", "--count", "HEAD")
	out, isErr = e.callTool(es, "records_create", map[string]any{"collection": "todo", "data": data})
	ch, _ := out["change"].(map[string]any)
	if isErr || ch["kind"] != "commit" {
		t.Fatalf("create: %v", out)
	}
	if after := git("rev-list", "--count", "HEAD"); after == before {
		t.Fatal("no commit: " + git("log", "--oneline", "-3") + git("status", "--short"))
	}
	msg := git("log", "-1", "--format=%B")
	if !strings.Contains(msg, "Edited-by: boss@example.com") || !strings.Contains(msg, "Edited-via: mcp (rackbook, client Editor Client)") {
		t.Fatalf("commit message:\n%s", msg)
	}
}
