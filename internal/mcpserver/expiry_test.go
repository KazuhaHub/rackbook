package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

func expiryClient(t *testing.T, n int) *mcp.ClientSession {
	t.Helper()
	dir := testutil.CopyExample(t)
	testutil.Replace(t, dir, "schemas/todo.json", `"status":`, `"due": {"type": ["string", "null"], "x-rackbook": {"expires": true}}, "status":`)
	rows := "- {item: tbd, status: 待办, due: 待补}\n- {item: none, status: 待办}\n"
	for i := 0; i < n; i++ {
		rows += fmt.Sprintf("- {item: i%03d, status: 待办, due: %s}\n", i, time.Now().UTC().AddDate(0, 0, i%20-3).Format("2006-01-02"))
	}
	p := filepath.Join(dir, "docs/ledger/todo.yml")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append(b, rows...), 0o644)
	l := ledger.Load(testutil.LoadConfig(t, dir), nil)
	srv := New(func() *ledger.Ledger { return l }, "test")
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func callStructured(t *testing.T, cs *mcp.ClientSession, args map[string]any) (map[string]any, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "expiry_list", Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("structured content: %s", raw)
	}
	return out, res.IsError
}

func TestExpiryListTool(t *testing.T) {
	cs := expiryClient(t, 40)
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range tools.Tools {
		if tool.Name != "expiry_list" {
			continue
		}
		found = true
		if tool.OutputSchema == nil || tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
			t.Fatalf("schema or annotations: %+v", tool)
		}
	}
	if !found {
		t.Fatal("expiry_list is not registered")
	}

	// Default window of 30 days: every dated record (40 of them: -3..16 twice) is within it.
	out, isErr := callStructured(t, cs, map[string]any{})
	items := out["items"].([]any)
	if isErr || out["days"] != float64(30) || out["today"] != time.Now().UTC().Format("2006-01-02") || len(items) != 40 || out["next_cursor"] != "" {
		t.Fatalf("%v %v", isErr, out)
	}
	if first := items[0].(map[string]any); first["status"] != "expired" || first["daysLeft"] != float64(-3) || first["collection"] != "todo" {
		t.Fatalf("%v", first)
	}

	// Paging with a small limit visits every item once, in order, without repeats.
	var ids []string
	cursor := ""
	for pages := 0; ; pages++ {
		args := map[string]any{"limit": 15, "include_unknown": true}
		if cursor != "" {
			args["cursor"] = cursor
		}
		out, isErr := callStructured(t, cs, args)
		if isErr || pages > 5 {
			t.Fatalf("%v", out)
		}
		for _, it := range out["items"].([]any) {
			ids = append(ids, it.(map[string]any)["id"].(string))
		}
		cursor, _ = out["next_cursor"].(string)
		if cursor == "" {
			break
		}
	}
	if len(ids) != 41 || ids[40] != "tbd" {
		t.Fatalf("%d ids, last %q", len(ids), ids[len(ids)-1])
	}

	// Window, collection filter and the limit cap.
	if out, _ := callStructured(t, cs, map[string]any{"days": 0, "collections": []string{"todo"}}); len(out["items"].([]any)) != 8 {
		t.Fatalf("days=0: %v", out["items"])
	}
	if out, _ := callStructured(t, cs, map[string]any{"limit": 100000}); len(out["items"].([]any)) != 40 {
		t.Fatal("a huge limit must still work")
	}
	if out, _ := callStructured(t, cs, map[string]any{"cursor": "MTAwMA"}); len(out["items"].([]any)) != 0 {
		t.Fatalf("a cursor past the end gives an empty page: %v", out)
	}

	// Errors are results with a structured body.
	out, isErr = callStructured(t, cs, map[string]any{"collections": []string{"nope"}})
	if !isErr || out["error"] != "not_found" || out["message"] == "" {
		t.Fatalf("%v %v", isErr, out)
	}
	out, isErr = callStructured(t, cs, map[string]any{"cursor": "!!"})
	if !isErr || out["error"] != "invalid" {
		t.Fatalf("%v %v", isErr, out)
	}
}
