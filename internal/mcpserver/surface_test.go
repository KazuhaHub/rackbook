package mcpserver

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

var update = flag.Bool("update", false, "rewrite testdata/surface.golden.json")

// structured calls a tool and returns its structuredContent and isError.
func structured(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: structured content %s", name, raw)
	}
	if res.IsError && out["error"] == nil {
		t.Fatalf("%s: an error result must carry {error, message}: %s", name, raw)
	}
	return out, res.IsError
}

func items(out map[string]any) []map[string]any {
	var res []map[string]any
	for _, x := range out["items"].([]any) {
		res = append(res, x.(map[string]any))
	}
	return res
}

func ids(out map[string]any) []string {
	var res []string
	for _, it := range items(out) {
		res = append(res, it["id"].(string))
	}
	return res
}

func TestSurfaceListsNewToolsAndDeprecatedAliases(t *testing.T) {
	t.Parallel()
	cs := connect(t)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*mcp.Tool{}
	for _, tool := range res.Tools {
		got[tool.Name] = tool
		if tool.Annotations == nil || tool.Annotations.DestructiveHint == nil || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
			t.Errorf("%s: destructiveHint and openWorldHint must be set, openWorldHint false: %+v", tool.Name, tool.Annotations)
		}
		if !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s: a read-only server has only read tools", tool.Name)
		}
	}
	for _, n := range []string{"ledger_info", "ledger_search", "ledger_check", "ledger_export", "collections_list", "collections_describe", "records_query", "records_get", "expiry_list"} {
		tool := got[n]
		if tool == nil {
			t.Errorf("missing tool %s", n)
			continue
		}
		if tool.OutputSchema == nil {
			t.Errorf("%s has no outputSchema", n)
		}
		if strings.HasPrefix(tool.Description, "Deprecated") {
			t.Errorf("%s must not be deprecated", n)
		}
	}
	aliases := map[string]string{"list_collections": "collections_list", "get_schema": "collections_describe", "list_records": "records_query", "get_record": "records_get",
		"search": "ledger_search", "check": "ledger_check", "list_problems": "ledger_check", "export_markdown": "ledger_export"}
	for old, repl := range aliases {
		tool := got[old]
		if tool == nil {
			t.Errorf("alias %s is gone", old)
			continue
		}
		if want := "Deprecated: use " + repl + "; removed in v0.8.0. "; !strings.HasPrefix(tool.Description, want) {
			t.Errorf("%s: description %q must start with %q", old, tool.Description, want)
		}
	}
	for _, n := range []string{"records_create", "records_update", "records_delete", "history_list", "history_diff", "create_record", "record_history"} {
		if got[n] != nil {
			t.Errorf("%s needs a Backend (and writes)", n)
		}
	}
}

func TestLedgerInfo(t *testing.T) {
	t.Parallel()
	cs := connect(t)
	out, isErr := structured(t, cs, "ledger_info", nil)
	if isErr {
		t.Fatal(out)
	}
	if out["server"].(map[string]any)["version"] != "test" || out["protocol_version"] == "" {
		t.Fatalf("%v", out)
	}
	fams := map[string]float64{}
	for _, f := range out["families"].([]any) {
		m := f.(map[string]any)
		fams[m["name"].(string)] = m["version"].(float64)
	}
	if len(fams) != 4 || fams["ledger"] != 1 || fams["collections"] != 1 || fams["records"] != 1 || fams["expiry"] != 1 {
		t.Fatalf("families of a read-only server: %v", fams)
	}
	limits := out["limits"].(map[string]any)
	if limits["default_limit"] != float64(50) || limits["max_limit"] != float64(500) || limits["max_history_limit"] != float64(100) || limits["max_result_bytes"] != float64(1<<20) {
		t.Fatalf("%v", limits)
	}
	if out["caller"].(map[string]any)["authenticated"] != false {
		t.Fatalf("%v", out["caller"])
	}
	dep := map[string]string{}
	for _, d := range out["deprecated"].([]any) {
		m := d.(map[string]any)
		dep[m["tool"].(string)] = m["replacement"].(string) + "@" + m["removed_in"].(string)
	}
	if dep["list_records"] != "records_query@v0.8.0" || dep["list_problems"] != "ledger_check@v0.8.0" || len(dep) != 8 {
		t.Fatalf("%v", dep)
	}
}

func TestCollectionsListAndDescribe(t *testing.T) {
	t.Parallel()
	cs := connect(t)
	out, isErr := structured(t, cs, "collections_list", nil)
	if isErr || len(out["collections"].([]any)) < 5 {
		t.Fatal(out)
	}
	var dev map[string]any
	for _, c := range out["collections"].([]any) {
		if m := c.(map[string]any); m["name"] == "devices" {
			dev = m
		}
	}
	if dev == nil || dev["records"] != float64(5) || dev["referenced_by"] == nil || dev["key"] == nil {
		t.Fatalf("%v", dev)
	}

	d, isErr := structured(t, cs, "collections_describe", map[string]any{"collection": "devices"})
	if isErr {
		t.Fatal(d)
	}
	schema := d["schema"].(map[string]any)
	if schema["properties"] == nil || d["documents"] != false || d["records"] != float64(5) || d["references"] == nil || d["facets"] == nil || d["notes"] == nil || d["fields"] == nil {
		t.Fatalf("%v", d)
	}
	if !strings.Contains(fmt.Sprint(d["fields"]), "设备名") {
		t.Fatalf("%v", d["fields"])
	}
	e, isErr := structured(t, cs, "collections_describe", map[string]any{"collection": "nope"})
	if !isErr || e["error"] != "not_found" || e["details"].(map[string]any)["available"] == nil {
		t.Fatalf("%v", e)
	}
	// The old name still returns the bare schema text.
	if out, isErr := call(t, cs, "get_schema", map[string]any{"collection": "devices"}); isErr || !strings.Contains(out, `"设备名"`) {
		t.Fatalf("%s", out)
	}
}

func TestRecordsQuery(t *testing.T) {
	t.Parallel()
	cs := connect(t)
	const web = "web-hostco-ashburn-va-us-dc"
	tests := []struct {
		name string
		args map[string]any
		want int // total, -1 for an error
		code string
	}{
		{"all", map[string]any{"collection": "services"}, 9, ""},
		{"exact", map[string]any{"collection": "services", "where": map[string]any{"device": web}}, 3, ""},
		{"exact bool", map[string]any{"collection": "devices", "where": map[string]any{"managed": true}}, 2, ""},
		{"exact eq object", map[string]any{"collection": "services", "where": map[string]any{"device": map[string]any{"eq": web}}}, 3, ""},
		{"prefix", map[string]any{"collection": "devices", "where": map[string]any{"name": map[string]any{"prefix": "web-"}}}, -2, ""},
		{"contains", map[string]any{"collection": "devices", "where": map[string]any{"name": map[string]any{"contains": "hostco"}}}, -2, ""},
		{"search", map[string]any{"collection": "ports", "search": "TAILSCALE"}, 1, ""},
		{"unknown field", map[string]any{"collection": "services", "where": map[string]any{"nope": "x"}}, -1, "invalid"},
		{"bad operator", map[string]any{"collection": "services", "where": map[string]any{"device": map[string]any{"regex": "x"}}}, -1, "invalid"},
		{"bad where value", map[string]any{"collection": "services", "where": map[string]any{"device": []any{"a"}}}, -1, "invalid"},
		{"unknown fields", map[string]any{"collection": "services", "fields": []string{"nope"}}, -1, "invalid"},
		{"unknown order", map[string]any{"collection": "services", "order_by": "nope"}, -1, "invalid"},
		{"bad cursor", map[string]any{"collection": "services", "cursor": "!!"}, -1, "invalid"},
		{"unknown collection", map[string]any{"collection": "nope"}, -1, "not_found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, isErr := structured(t, cs, "records_query", tt.args)
			if tt.want == -1 {
				if !isErr || out["error"] != tt.code {
					t.Fatalf("%v", out)
				}
				return
			}
			if isErr {
				t.Fatal(out)
			}
			if tt.want >= 0 && out["total"] != float64(tt.want) {
				t.Fatalf("total %v, want %d: %v", out["total"], tt.want, out)
			}
			if tt.want == -2 && out["total"].(float64) < 1 {
				t.Fatalf("expected matches: %v", out)
			}
		})
	}

	// Items carry id, hash and data; fields projects data only.
	out, _ := structured(t, cs, "records_query", map[string]any{"collection": "devices", "fields": []string{"name"}, "limit": 1})
	it := items(out)[0]
	if it["hash"] == "" || len(it["data"].(map[string]any)) != 1 || out["next_cursor"] == "" {
		t.Fatalf("%v", out)
	}
}

func TestRecordsQueryOrderAndPaging(t *testing.T) {
	t.Parallel()
	cs := connect(t)
	all, _ := structured(t, cs, "records_query", map[string]any{"collection": "services"})
	want := ids(all)
	if len(want) != 9 || all["next_cursor"] != "" {
		t.Fatalf("%v", all)
	}
	var got []string
	cursor, pages := "", 0
	for {
		args := map[string]any{"collection": "services", "limit": 3}
		if cursor != "" {
			args["cursor"] = cursor
		}
		out, isErr := structured(t, cs, "records_query", args)
		if isErr || pages > 5 {
			t.Fatal(out)
		}
		pages++
		got = append(got, ids(out)...)
		if cursor, _ = out["next_cursor"].(string); cursor == "" {
			break
		}
	}
	if pages != 3 || !slices.Equal(got, want) {
		t.Fatalf("pages %d: %v != %v", pages, got, want)
	}
	// A huge limit is capped, a cursor past the end is an empty page.
	if out, _ := structured(t, cs, "records_query", map[string]any{"collection": "services", "limit": 100000}); len(items(out)) != 9 {
		t.Fatal("a huge limit must work")
	}
	if out, _ := structured(t, cs, "records_query", map[string]any{"collection": "services", "cursor": "MTAwMA"}); len(items(out)) != 0 {
		t.Fatalf("%v", out)
	}
	// order_by sorts, a leading - reverses.
	asc, _ := structured(t, cs, "records_query", map[string]any{"collection": "ports", "order_by": "port"})
	desc, _ := structured(t, cs, "records_query", map[string]any{"collection": "ports", "order_by": "-port"})
	a, d := ids(asc), ids(desc)
	slices.Reverse(d)
	if len(a) < 3 || !slices.Equal(a, d) {
		t.Fatalf("%v vs %v", a, d)
	}
	var ports []string
	for _, it := range items(asc) {
		ports = append(ports, it["data"].(map[string]any)["port"].(string))
	}
	if !sort.StringsAreSorted(ports) {
		t.Fatalf("ports must be in order: %v", ports)
	}
	// Numbers sort as numbers, not as text.
	if !lessValue(float64(9), float64(10)) || lessValue("9", "10a") {
		t.Fatal("lessValue")
	}
}

func TestRecordsGetInclude(t *testing.T) {
	t.Parallel()
	cs := connect(t)
	const web = "web-hostco-ashburn-va-us-dc"
	out, isErr := structured(t, cs, "records_get", map[string]any{"collection": "devices", "id": web})
	if isErr || out["backrefs"] != nil || out["hash"] == "" || out["data"] == nil {
		t.Fatalf("backrefs are opt-in: %v", out)
	}
	out, isErr = structured(t, cs, "records_get", map[string]any{"collection": "devices", "id": web, "include": []string{"backrefs", "doc", "history"}})
	br := out["backrefs"].(map[string]any)
	if isErr || len(br["services"].([]any)) != 4 || len(br["addresses"].([]any)) != 2 {
		t.Fatalf("%v", out)
	}
	if out, isErr = structured(t, cs, "records_get", map[string]any{"collection": "devices", "id": "zzz"}); !isErr || out["error"] != "not_found" {
		t.Fatalf("%v", out)
	}
	if out, isErr = structured(t, cs, "records_get", map[string]any{"collection": "devices", "id": web, "include": []string{"x"}}); !isErr || out["error"] != "invalid" {
		t.Fatalf("%v", out)
	}
	// The old name keeps backrefs always on, with the old result shape.
	text, isErr := call(t, cs, "get_record", map[string]any{"collection": "devices", "id": web})
	var old getRecordOut
	if err := json.Unmarshal([]byte(text), &old); isErr || err != nil || len(old.Backrefs["services"]) != 4 {
		t.Fatalf("%v %s", err, text)
	}
}

func TestLedgerSearch(t *testing.T) {
	t.Parallel()
	cs := connect(t)
	out, isErr := structured(t, cs, "ledger_search", map[string]any{"query": "10511"})
	if isErr || out["total"].(float64) < 5 {
		t.Fatalf("%v", out)
	}
	hits := items(out)
	for i := 1; i < len(hits); i++ {
		if hits[i]["score"].(float64) > hits[i-1]["score"].(float64) {
			t.Fatalf("hits must be ranked: %v", hits)
		}
	}
	if hits[0]["matched_fields"] == nil || hits[0]["data"] == nil {
		t.Fatalf("%v", hits[0])
	}
	// Restricted to collections.
	out, _ = structured(t, cs, "ledger_search", map[string]any{"query": "TAILSCALE", "collections": []string{"ports"}})
	if h := items(out); len(h) != 1 || h[0]["matched_fields"].([]any)[0] != "service" || h[0]["collection"] != "ports" {
		t.Fatalf("%v", out)
	}
	if out, isErr = structured(t, cs, "ledger_search", map[string]any{"query": "TAILSCALE", "collections": []string{"nope"}}); !isErr || out["error"] != "not_found" {
		t.Fatalf("%v", out)
	}
	if out, isErr = structured(t, cs, "ledger_search", map[string]any{"query": " "}); !isErr || out["error"] != "invalid" {
		t.Fatalf("%v", out)
	}
	// An exact value outranks a partial one: "ssh" fully equals a field of its best hit.
	// Paging visits every hit once.
	total := int(structuredTotal(t, cs, "10511"))
	var seen []string
	cursor := ""
	for pages := 0; pages < 20; pages++ {
		args := map[string]any{"query": "10511", "limit": 2}
		if cursor != "" {
			args["cursor"] = cursor
		}
		p, _ := structured(t, cs, "ledger_search", args)
		for _, it := range items(p) {
			seen = append(seen, it["collection"].(string)+"/"+it["id"].(string))
		}
		if cursor, _ = p["next_cursor"].(string); cursor == "" {
			break
		}
	}
	if len(seen) != total {
		t.Fatalf("%d hits over pages, total %d", len(seen), total)
	}
	// The old search keeps its shape.
	text, _ := call(t, cs, "search", map[string]any{"query": "TAILSCALE", "collection": "ports"})
	var old searchOut
	if err := json.Unmarshal([]byte(text), &old); err != nil || old.Count != 1 || old.Matches[0].Fields[0] != "service" {
		t.Fatalf("%v %s", err, text)
	}
}

func structuredTotal(t *testing.T, cs *mcp.ClientSession, q string) float64 {
	out, _ := structured(t, cs, "ledger_search", map[string]any{"query": q})
	return out["total"].(float64)
}

func TestLedgerCheckMergesProblemsAndFilters(t *testing.T) {
	t.Parallel()
	dir := testutil.CopyExample(t)
	testutil.Replace(t, dir, "docs/ledger/todo.yml", "{item: 评估关闭路由器 WAN 上的 Web 后台, ", "{")
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

	out, isErr := structured(t, cs, "ledger_check", nil)
	errs := out["errors"].([]any)
	if isErr || out["ok"] != false || len(errs) < 1 || out["store"] == nil || out["total"] != float64(len(errs)+len(out["warnings"].([]any))) {
		t.Fatalf("%v", out)
	}
	tests := []struct {
		name string
		args map[string]any
		want int
		code string
	}{
		{"collection", map[string]any{"collection": "todo"}, len(errs), ""},
		{"other collection", map[string]any{"collection": "devices"}, 0, ""},
		{"rule", map[string]any{"rule": "schema"}, len(errs), ""},
		{"other rule", map[string]any{"rule": "unique"}, 0, ""},
		{"unknown collection", map[string]any{"collection": "nope"}, 0, "not_found"},
		{"bad cursor", map[string]any{"cursor": "x!"}, 0, "invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o, isErr := structured(t, cs, "ledger_check", tt.args)
			if tt.code != "" {
				if !isErr || o["error"] != tt.code {
					t.Fatalf("%v", o)
				}
				return
			}
			if len(o["errors"].([]any)) != tt.want || (tt.want == 0) != (o["ok"] == true) {
				t.Fatalf("%v", o)
			}
		})
	}
	// Paging: one problem per page.
	if len(errs) > 1 {
		o, _ := structured(t, cs, "ledger_check", map[string]any{"limit": 1})
		if len(o["errors"].([]any)) != 1 || o["next_cursor"] == "" {
			t.Fatalf("%v", o)
		}
	}
	// Both old names still answer with their old shapes.
	text, _ := call(t, cs, "check", nil)
	var c checkOut
	if err := json.Unmarshal([]byte(text), &c); err != nil || c.OK || len(c.Errors) != len(errs) {
		t.Fatalf("%v %s", err, text)
	}
	text, _ = call(t, cs, "list_problems", nil)
	var p problemsOut
	if err := json.Unmarshal([]byte(text), &p); err != nil || p.OK || len(p.Errors) != len(errs) || p.Store == nil {
		t.Fatalf("%v %s", err, text)
	}
}

func TestLedgerExport(t *testing.T) {
	t.Parallel()
	cs := connect(t)
	md, isErr := structured(t, cs, "ledger_export", nil)
	if isErr || md["format"] != "markdown" || !strings.HasPrefix(md["content"].(string), "# 示例网络台账") || md["bytes"] != float64(len(md["content"].(string))) {
		t.Fatalf("%v", md)
	}
	one, _ := structured(t, cs, "ledger_export", map[string]any{"collection": "ports"})
	if c := one["content"].(string); !strings.Contains(c, "Tailscale") || len(c) >= len(md["content"].(string)) || strings.Contains(c, "设备名") {
		t.Fatalf("%v", one)
	}
	js, isErr := structured(t, cs, "ledger_export", map[string]any{"format": "json"})
	var doc map[string]any
	if isErr || json.Unmarshal([]byte(js["content"].(string)), &doc) != nil || doc["collections"] == nil {
		t.Fatalf("%v", js)
	}
	jone, _ := structured(t, cs, "ledger_export", map[string]any{"format": "json", "collection": "ports"})
	json.Unmarshal([]byte(jone["content"].(string)), &doc)
	if len(doc["collections"].(map[string]any)) != 1 {
		t.Fatalf("%v", doc["collections"])
	}
	if out, isErr := structured(t, cs, "ledger_export", map[string]any{"format": "xml"}); !isErr || out["error"] != "invalid" {
		t.Fatalf("%v", out)
	}
	if out, isErr := structured(t, cs, "ledger_export", map[string]any{"collection": "nope"}); !isErr || out["error"] != "not_found" {
		t.Fatalf("%v", out)
	}
	// The old export_markdown returns the Markdown text itself.
	if text, _ := call(t, cs, "export_markdown", nil); !strings.HasPrefix(text, "# 示例网络台账") {
		t.Fatal(text)
	}
}

// bigClient serves a ledger whose services collection is far over 1 MiB.
func bigClient(t *testing.T) *mcp.ClientSession {
	t.Helper()
	dir := testutil.CopyExample(t)
	var rows strings.Builder
	for i := 0; i < 800; i++ {
		fmt.Fprintf(&rows, "- {device: web-hostco-ashburn-va-us-dc, service: bigrow%04d, port: TCP 1, notes: \"%s\"}\n", i, strings.Repeat("n", 3000))
	}
	// One record that alone is over the cap.
	fmt.Fprintf(&rows, "- {device: web-hostco-ashburn-va-us-dc, service: hugerow, port: TCP 2, notes: \"%s\"}\n", strings.Repeat("h", maxResultBytes+1000))
	p := filepath.Join(dir, "docs/ledger/services.yml")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append(b, rows.String()...), 0o644)
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

// TestSuggestedLimitAlwaysMakesProgress follows the too_large advice the way an
// agent would: it must end, whatever limit was asked for, even one above the
// server's maximum of 500 (which the tool already capped).
func TestSuggestedLimitAlwaysMakesProgress(t *testing.T) {
	t.Parallel()
	cs := bigClient(t)
	for _, tool := range []struct {
		name string
		args map[string]any
	}{
		{"records_query", map[string]any{"collection": "services", "where": map[string]any{"service": map[string]any{"prefix": "bigrow"}}}},
		{"ledger_search", map[string]any{"query": "bigrow"}},
	} {
		for _, asked := range []int{1000, 500, 400, 100000} {
			t.Run(fmt.Sprintf("%s limit=%d", tool.name, asked), func(t *testing.T) {
				t.Parallel()
				args := map[string]any{"limit": asked}
				for k, v := range tool.args {
					args[k] = v
				}
				var tried []float64
				for step := 0; ; step++ {
					out, isErr := structured(t, cs, tool.name, args)
					if !isErr {
						break
					}
					if out["error"] != "too_large" {
						t.Fatalf("%s limit=%d: %.300v", tool.name, asked, out)
					}
					d := out["details"].(map[string]any)
					if d["suggested_limit"] == nil {
						t.Fatalf("%s limit=%d: %v", tool.name, asked, d)
					}
					n, sug := d["returned"].(float64), d["suggested_limit"].(float64)
					if out["error"] != "too_large" || step > 6 || sug < 1 || sug >= n {
						t.Fatalf("%s limit=%d step %d: suggested %v for %v returned (tried %v)", tool.name, asked, step, sug, n, tried)
					}
					tried = append(tried, sug)
					args["limit"] = sug
				}
				if len(tried) == 0 {
					t.Fatalf("%s limit=%d was meant to be too large", tool.name, asked)
				}
			})
		}
	}
	// A single record that alone is over the cap: no limit helps, the resource does.
	out, isErr := structured(t, cs, "records_query", map[string]any{"collection": "services", "where": map[string]any{"service": "hugerow"}, "limit": 1})
	d, _ := out["details"].(map[string]any)
	if !isErr || out["error"] != "too_large" || d["suggested_limit"] != nil || d["resource"] != "rackbook://records/services/web-hostco-ashburn-va-us-dc%2Fhugerow" {
		t.Fatalf("%v", out)
	}
	r, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: d["resource"].(string)})
	if err != nil || len(r.Contents) != 1 {
		t.Fatalf("the named resource must be readable: %v", err)
	}
}

func TestEveryResultIsCappedAt1MiB(t *testing.T) {
	t.Parallel()
	cs := bigClient(t)
	const web = "web-hostco-ashburn-va-us-dc"
	tests := []struct {
		name     string
		tool     string
		args     map[string]any
		resource string // details.resource, when the content exists as a resource
		paged    bool   // details carry cursor and suggested_limit
	}{
		{"records_get backrefs", "records_get", map[string]any{"collection": "devices", "id": web, "include": []string{"backrefs"}}, "rackbook://records/devices/" + web, false},
		{"records_query", "records_query", map[string]any{"collection": "services", "limit": 500}, "", true},
		{"ledger_search", "ledger_search", map[string]any{"query": "bigrow", "limit": 500}, "", true},
		{"ledger_export", "ledger_export", map[string]any{}, "rackbook://export/markdown", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, isErr := structured(t, cs, tt.tool, tt.args)
			if !isErr || out["error"] != "too_large" {
				t.Fatalf("%.300v", out)
			}
			d := out["details"].(map[string]any)
			if d["limit_bytes"] != float64(maxResultBytes) || d["resource"] != nil && d["resource"] != tt.resource || (tt.resource != "" && d["resource"] != tt.resource) {
				t.Fatalf("%v", d)
			}
			if tt.paged {
				n := d["suggested_limit"].(float64)
				if n < 1 || n >= 500 {
					t.Fatalf("suggested_limit %v", n)
				}
				args := map[string]any{}
				for k, v := range tt.args {
					args[k] = v
				}
				args["limit"] = n
				if o, isErr := structured(t, cs, tt.tool, args); isErr {
					t.Fatalf("the suggested limit must fit: %.200v", o)
				}
			}
		})
	}
	// What is under the cap still works, and the resource carries the content.
	if _, isErr := structured(t, cs, "records_get", map[string]any{"collection": "devices", "id": web}); isErr {
		t.Fatal("records_get without include is small")
	}
	r, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "rackbook://records/devices/" + web})
	if err != nil || len(r.Contents) != 1 {
		t.Fatalf("%v", err)
	}
	// The deprecated names keep their v0.2 behaviour: no cap.
	if text, isErr := call(t, cs, "get_record", map[string]any{"collection": "devices", "id": web}); isErr || len(text) < maxResultBytes {
		t.Fatalf("get_record: %v %d", isErr, len(text))
	}
}

func TestResourcesAndPrompts(t *testing.T) {
	t.Parallel()
	cs := connect(t)
	ctx := context.Background()
	res, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var uris []string
	for _, r := range res.Resources {
		uris = append(uris, r.URI)
	}
	sort.Strings(uris)
	if want := []string{"rackbook://collections", "rackbook://export/markdown", "rackbook://info", "rackbook://llms.txt"}; !slices.Equal(uris, want) {
		t.Fatalf("%v", uris)
	}
	tpl, err := cs.ListResourceTemplates(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var tpls []string
	for _, r := range tpl.ResourceTemplates {
		tpls = append(tpls, r.URITemplate)
	}
	sort.Strings(tpls)
	if want := []string{"rackbook://collections/{collection}", "rackbook://records/{collection}/{id}"}; !slices.Equal(tpls, want) {
		t.Fatalf("%v", tpls)
	}

	read := func(uri string) (string, error) {
		r, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
		if err != nil {
			return "", err
		}
		return r.Contents[0].Text, nil
	}
	tests := []struct {
		uri      string
		contains string
		fail     bool
	}{
		{"rackbook://info", `"families"`, false},
		{"rackbook://collections", `"referenced_by"`, false},
		{"rackbook://collections/devices", `"设备名"`, false},
		{"rackbook://collections/nope", "", true},
		{"rackbook://records/devices/web-hostco-ashburn-va-us-dc", `"hash"`, false},
		{"rackbook://records/services/all%2FTailscale", `"Tailscale"`, false},
		{"rackbook://records/devices/zzz", "", true},
		{"rackbook://export/markdown", "# 示例网络台账", false},
		{"rackbook://llms.txt", "# ", false},
	}
	for _, tt := range tests {
		got, err := read(tt.uri)
		if tt.fail != (err != nil) || !strings.Contains(got, tt.contains) {
			t.Errorf("%s: %v %.200s", tt.uri, err, got)
		}
	}

	pr, err := cs.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range pr.Prompts {
		names = append(names, p.Name)
	}
	sort.Strings(names)
	if want := []string{"audit_record", "explain_collection", "prepare_change"}; !slices.Equal(names, want) {
		t.Fatalf("%v", names)
	}
	prompt := func(name string, args map[string]string) (string, error) {
		r, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: name, Arguments: args})
		if err != nil {
			return "", err
		}
		return r.Messages[0].Content.(*mcp.TextContent).Text, nil
	}
	if txt, err := prompt("audit_record", map[string]string{"collection": "devices", "id": "web-hostco-ashburn-va-us-dc"}); err != nil || !strings.Contains(txt, "web-hostco-ashburn-va-us-dc") || !strings.Contains(txt, "history_diff") {
		t.Fatalf("%v %s", err, txt)
	}
	if _, err := prompt("audit_record", map[string]string{"collection": "devices", "id": "zzz"}); err == nil {
		t.Fatal("an unknown record is an error")
	}
	if txt, err := prompt("prepare_change", map[string]string{"goal": "move SSH to 10511"}); err != nil || !strings.Contains(txt, "dry_run=true") || !strings.Contains(txt, "move SSH to 10511") {
		t.Fatalf("%v %s", err, txt)
	}
	if _, err := prompt("prepare_change", map[string]string{"goal": " "}); err == nil {
		t.Fatal("an empty goal is an error")
	}
	if txt, err := prompt("explain_collection", map[string]string{"collection": "ports"}); err != nil || !strings.Contains(txt, `"ports"`) {
		t.Fatalf("%v %s", err, txt)
	}
}

// TestSurfaceGolden compares the live surface with testdata/surface.golden.json:
// every tool with its input and output schema and annotations, resource
// templates and prompts. A change to the surface shows up in the golden file;
// regenerate it with `go test ./internal/mcpserver -run SurfaceGolden -update`.
func TestSurfaceGolden(t *testing.T) {
	l := ledger.Load(testutil.LoadConfig(t, testutil.CopyExample(t)), nil)
	srv := NewWithOptions(Options{Source: func() *ledger.Ledger { return l }, Version: "test", Backend: &gitstore.Store{}})
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(tools.Tools, func(a, b *mcp.Tool) int { return strings.Compare(a.Name, b.Name) })
	rt, err := cs.ListResourceTemplates(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(rt.ResourceTemplates, func(a, b *mcp.ResourceTemplate) int { return strings.Compare(a.URITemplate, b.URITemplate) })
	rs, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(rs.Resources, func(a, b *mcp.Resource) int { return strings.Compare(a.URI, b.URI) })
	ps, err := cs.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(ps.Prompts, func(a, b *mcp.Prompt) int { return strings.Compare(a.Name, b.Name) })
	got, err := json.MarshalIndent(map[string]any{"tools": tools.Tools, "resources": rs.Resources, "resourceTemplates": rt.ResourceTemplates, "prompts": ps.Prompts}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "surface.golden.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if string(want) != string(got) {
		t.Fatalf("the MCP surface changed; if that is intended, run `go test ./internal/mcpserver -run SurfaceGolden -update` and review the diff of testdata/surface.golden.json")
	}
	// Every deprecated alias in the golden surface names a tool that exists.
	names := map[string]bool{}
	for _, tool := range tools.Tools {
		names[tool.Name] = true
	}
	for _, tool := range tools.Tools {
		if repl, ok := replacements[tool.Name]; ok {
			if !names[repl] || !strings.HasPrefix(tool.Description, "Deprecated: use "+repl+"; removed in "+removedIn) {
				t.Errorf("%s: its replacement %s must exist and the description must say so", tool.Name, repl)
			}
		}
	}
}
