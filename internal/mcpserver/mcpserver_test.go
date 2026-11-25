package mcpserver

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	l := ledger.Load(testutil.LoadConfig(t, testutil.CopyExample(t)), nil)
	srv := New(func() *ledger.Ledger { return l }, "test")
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String(), res.IsError
}

func TestToolsList(t *testing.T) {
	t.Parallel()
	cs := connect(t)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tool := range res.Tools {
		got[tool.Name] = true
		if tool.Description == "" {
			t.Errorf("%s has no description", tool.Name)
		}
	}
	for _, n := range []string{"list_collections", "list_records", "get_record", "search", "get_schema", "check", "export_markdown"} {
		if !got[n] {
			t.Errorf("missing tool %s", n)
		}
	}
}

func TestListRecordsWhere(t *testing.T) {
	t.Parallel()
	cs := connect(t)
	out, isErr := call(t, cs, "list_records", map[string]any{"collection": "services", "where": map[string]any{"device": "web-hostco-ashburn-va-us-dc"}})
	if isErr {
		t.Fatal(out)
	}
	var r listRecordsOut
	if err := json.Unmarshal([]byte(out), &r); err != nil || r.Count != 3 {
		t.Fatalf("%v %s", err, out)
	}
	out, _ = call(t, cs, "list_records", map[string]any{"collection": "devices", "where": map[string]any{"managed": true}})
	json.Unmarshal([]byte(out), &r)
	if r.Count != 2 {
		t.Fatalf("managed: %s", out)
	}
	if out, isErr = call(t, cs, "list_records", map[string]any{"collection": "nope"}); !isErr || !strings.Contains(out, "available: devices") {
		t.Fatalf("%v %s", isErr, out)
	}
}

func TestGetRecordBackrefsSearchSchemaCheck(t *testing.T) {
	t.Parallel()
	cs := connect(t)
	out, isErr := call(t, cs, "get_record", map[string]any{"collection": "devices", "id": "web-hostco-ashburn-va-us-dc"})
	if isErr {
		t.Fatal(out)
	}
	var g getRecordOut
	json.Unmarshal([]byte(out), &g)
	if len(g.Backrefs["services"]) != 4 || len(g.Backrefs["addresses"]) != 2 {
		t.Fatalf("backrefs: %s", out)
	}
	if _, isErr = call(t, cs, "get_record", map[string]any{"collection": "devices", "id": "zzz"}); !isErr {
		t.Fatal("expected error for a missing record")
	}

	out, _ = call(t, cs, "search", map[string]any{"query": "10511"})
	var s searchOut
	json.Unmarshal([]byte(out), &s)
	if s.Count < 5 {
		t.Fatalf("search: %s", out)
	}
	out, _ = call(t, cs, "search", map[string]any{"query": "TAILSCALE", "collection": "ports"})
	json.Unmarshal([]byte(out), &s)
	if s.Count != 1 || s.Matches[0].Fields[0] != "service" {
		t.Fatalf("%s", out)
	}

	_, isErr = call(t, cs, "get_schema", map[string]any{"collection": "device"})
	if !isErr {
		t.Fatal("unknown collection must be an error")
	}
	out, isErr = call(t, cs, "get_schema", map[string]any{"collection": "devices"})
	if isErr || !strings.Contains(out, `"设备名"`) {
		t.Fatalf("%s", out)
	}
	out, _ = call(t, cs, "check", nil)
	if !strings.Contains(out, `"ok":true`) {
		t.Fatalf("%s", out)
	}
	out, _ = call(t, cs, "export_markdown", nil)
	if !strings.HasPrefix(out, "# 示例网络台账") {
		t.Fatalf("%s", out)
	}
	out, _ = call(t, cs, "list_collections", nil)
	if !strings.Contains(out, `"referencedBy"`) || !strings.Contains(out, `"records":5`) {
		t.Fatalf("%s", out)
	}
}

func TestHTTPHandler(t *testing.T) {
	t.Parallel()
	l := ledger.Load(testutil.LoadConfig(t, testutil.CopyExample(t)), nil)
	ts := httptest.NewServer(Handler(New(func() *ledger.Ledger { return l }, "test"), false))
	defer ts.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil).Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: ts.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	if out, isErr := call(t, cs, "check", nil); isErr || !strings.Contains(out, `"ok":true`) {
		t.Fatalf("%s", out)
	}
}
