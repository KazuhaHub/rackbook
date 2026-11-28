package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

func TestDescribeCollectionListsCodesWithLabels(t *testing.T) {
	t.Parallel()
	l := ledger.Load(testutil.LoadConfig(t, testutil.CopyFixture(t, "labels")), nil)
	srv := New(func() *ledger.Ledger { return l }, "test")
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	d, isErr := structured(t, cs, "collections_describe", map[string]any{"collection": "devices"})
	if isErr {
		t.Fatal(d)
	}
	fields := map[string]map[string]any{}
	for _, f := range d["fields"].([]any) {
		m := f.(map[string]any)
		fields[m["name"].(string)] = m
	}
	vals := func(name string) string {
		b, _ := json.Marshal(fields[name]["values"])
		return string(b)
	}
	// default language (zh-CN) label from the oneOf title, others from x-rackbook-i18n,
	// a language without a translation falls back to the default label
	if got, want := vals("ipv4_type"), `[{"code":"static","labels":{"en-US":"Static","zh-CN":"静态","zh-TW":"靜態"}},{"code":"dynamic","labels":{"en-US":"Dynamic","zh-CN":"动态","zh-TW":"動態"}},{"code":"nat","labels":{"en-US":"NAT","zh-CN":"NAT","zh-TW":"NAT"}}]`; got != want {
		t.Fatalf("ipv4_type values:\n%s\n%s", got, want)
	}
	// a plain enum has codes only
	if got, want := vals("status"), `[{"code":"up"},{"code":"down"}]`; got != want {
		t.Fatalf("status values: %s", got)
	}
	// an array of enum-like items
	if got, want := vals("tags"), `[{"code":"core","labels":{"en-US":"Core","zh-CN":"核心","zh-TW":"核心"}},{"code":"edge","labels":{"en-US":"Edge","zh-CN":"边缘","zh-TW":"边缘"}}]`; got != want {
		t.Fatalf("tags values: %s", got)
	}
	// enum-like properties inside row objects (items.properties)
	rows, _ := json.Marshal(fields["ports"]["row"])
	if string(rows) != `[{"name":"proto","values":[{"code":"tcp","labels":{"en-US":"TCP","zh-CN":"TCP","zh-TW":"傳輸控制"}},{"code":"udp","labels":{"en-US":"UDP","zh-CN":"UDP","zh-TW":"UDP"}}]}]` {
		t.Fatalf("row values: %s", rows)
	}
	if fields["name"]["values"] != nil || fields["country"]["values"] != nil {
		t.Fatalf("only enum-like fields list values: %v", fields["name"])
	}
	// translated titles only where the schema has them
	b, _ := json.Marshal(fields["ipv4_type"]["titles"])
	if string(b) != `{"en-US":"IPv4 type","zh-CN":"IPv4 类型","zh-TW":"IPv4 類型"}` {
		t.Fatalf("titles: %s", b)
	}
	if fields["status"]["titles"] != nil {
		t.Fatalf("status has no translated title: %v", fields["status"])
	}
	// the stored record values stay codes
	recs, _ := structured(t, cs, "records_query", map[string]any{"collection": "devices"})
	if got := items(recs)[0]["data"].(map[string]any)["ipv4_type"]; got != "static" {
		t.Fatalf("record value is %v", got)
	}
}
