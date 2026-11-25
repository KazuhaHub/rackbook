package api_test

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/testutil"
)

func adminFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWithConfigSource(t, "Boss <boss@example.com>", withRoles(t, testutil.CopyExample(t)))
}

func typeOf(t *testing.T, f *fixture, name string) map[string]any {
	t.Helper()
	code, r, _ := f.do(t, "GET", "/api/types/"+name, nil, nil)
	if code != 200 {
		t.Fatalf("GET type %s: %d %v", name, code, r)
	}
	return r["type"].(map[string]any)
}

func TestTypesAreForAdministratorsOnly(t *testing.T) {
	t.Parallel()
	dir := withRoles(t, testutil.CopyExample(t))
	for _, who := range []string{"Tom <tom@team.example.com>", "Guest <guest@example.com>"} {
		f := newFixtureWithConfigSource(t, who, dir)
		ty := map[string]any{"type": map[string]any{"name": "x", "title": "x"}}
		for _, c := range []struct{ m, p string }{{"GET", "/api/types"}, {"GET", "/api/types/todo"}, {"POST", "/api/types/todo/plan"}, {"POST", "/api/types"}, {"PUT", "/api/types/todo"}, {"DELETE", "/api/types/todo"}} {
			body := any(nil)
			if c.m == "POST" || c.m == "PUT" {
				body = ty
			}
			if code, r, _ := f.do(t, c.m, c.p, body, nil); code != 403 || r["error"] != "forbidden" {
				t.Fatalf("%s %s %s: %d %v", who, c.m, c.p, code, r)
			}
		}
	}
	f := newFixtureWithConfigSource(t, "Boss <boss@example.com>", dir)
	if code, r, _ := f.do(t, "GET", "/api/types", nil, nil); code != 200 || len(arr(t, r["types"])) != 9 {
		t.Fatalf("%d %v", code, r)
	}
}

func TestPlanThenSaveATypeChange(t *testing.T) {
	t.Parallel()
	f := adminFixture(t)
	ty := typeOf(t, f, "services")
	fields := arr(t, ty["fields"])
	ty["fields"] = append(fields, map[string]any{"name": "owner", "title": "负责人", "type": "text", "required": true, "default": "ops"})
	body := map[string]any{"type": ty}

	code, plan, _ := f.do(t, "POST", "/api/types/services/plan", body, nil)
	if code != 200 || plan["clean"] != false || len(arr(t, plan["invalid"])) == 0 || len(arr(t, plan["migrations"])) != 1 {
		t.Fatalf("%d %v", code, plan)
	}
	before, _ := os.ReadFile(filepath.Join(f.dir, "schemas/service.json"))
	// saving without the migration is refused and writes nothing
	code, r, _ := f.do(t, "PUT", "/api/types/services", body, nil)
	if code != 422 || r["error"] != "refused" || r["plan"].(map[string]any)["clean"] != false {
		t.Fatalf("%d %v", code, r)
	}
	if after, _ := os.ReadFile(filepath.Join(f.dir, "schemas/service.json")); string(after) != string(before) {
		t.Fatal("a refused change wrote")
	}
	body["migrations"] = []any{map[string]any{"kind": "fill-default", "field": "owner"}}
	if _, plan, _ = f.do(t, "POST", "/api/types/services/plan", body, nil); plan["clean"] != true || len(arr(t, plan["files"])) != 2 {
		t.Fatalf("%v", plan)
	}
	code, r, _ = f.do(t, "PUT", "/api/types/services", body, nil)
	if code != 200 || r["changed"] != true || len(arr(t, r["files"])) != 2 {
		t.Fatalf("%d %v", code, r)
	}
	// the console sees the change at once
	_, m, _ := f.do(t, "GET", "/api/meta", nil, nil)
	var props map[string]any
	for _, c := range arr(t, m["collections"]) {
		if c.(map[string]any)["name"] == "services" {
			props = c.(map[string]any)["schema"].(map[string]any)["properties"].(map[string]any)
		}
	}
	if props["owner"] == nil {
		t.Fatalf("owner missing in meta: %v", props)
	}
	_, l, _ := f.do(t, "GET", "/api/c/services", nil, nil)
	for _, rec := range arr(t, l["records"]) {
		if rec.(map[string]any)["data"].(map[string]any)["owner"] != "ops" {
			t.Fatalf("%v", rec)
		}
	}
	if code, c, _ := f.do(t, "GET", "/api/check", nil, nil); code != 200 || c["ok"] != true {
		t.Fatalf("%v", c)
	}
}

func TestCreateAndDeleteAType(t *testing.T) {
	t.Parallel()
	f := adminFixture(t)
	ty := map[string]any{"name": "contacts", "title": "联系人", "icon": "users", "key": []string{"name"}, "fields": []any{
		map[string]any{"name": "name", "type": "text", "required": true},
		map[string]any{"name": "device", "type": "ref", "ref": map[string]any{"to": "devices", "toField": "name"}},
	}}
	// planning a name that does not exist plans a creation
	code, plan, _ := f.do(t, "POST", "/api/types/contacts/plan", map[string]any{"type": ty}, nil)
	if code != 200 || plan["op"] != "create" || plan["clean"] != true || len(arr(t, plan["files"])) != 3 {
		t.Fatalf("%d %v", code, plan)
	}
	if code, r, _ := f.do(t, "POST", "/api/types", map[string]any{"type": ty}, nil); code != 201 || len(arr(t, r["files"])) != 3 {
		t.Fatalf("%d %v", code, r)
	}
	if code, r, _ := f.do(t, "POST", "/api/types", map[string]any{"type": ty}, nil); code != 422 || r["error"] != "refused" {
		t.Fatalf("a second create must be refused: %d %v", code, r)
	}
	_, m, _ := f.do(t, "GET", "/api/meta", nil, nil)
	var found map[string]any
	for _, c := range arr(t, m["collections"]) {
		if c.(map[string]any)["name"] == "contacts" {
			found = c.(map[string]any)
		}
	}
	if found == nil || found["icon"] != "users" || found["file"] != "docs/ledger/contacts.yml" {
		t.Fatalf("%v", found)
	}
	for _, c := range arr(t, m["collections"]) {
		if c.(map[string]any)["name"] == "devices" {
			bs := arr(t, c.(map[string]any)["backrefs"])
			if len(bs) != 3 { // services, addresses and the new contacts
				t.Fatalf("%v", bs)
			}
		}
	}
	// the first record goes in through the normal path
	if code, r, _ := f.do(t, "POST", "/api/c/contacts", map[string]any{"data": map[string]any{"name": "ann", "device": "laptop-me-pc"}}, nil); code != 201 {
		t.Fatalf("%d %v", code, r)
	}
	if code, r, _ := f.do(t, "DELETE", "/api/types/contacts?version="+typeOf(t, f, "contacts")["version"].(string), nil, nil); code != 422 || len(arr(t, r["plan"].(map[string]any)["refusals"])) == 0 {
		t.Fatalf("a type with records stays: %d %v", code, r)
	}
	// the reference guard: laptop-me-pc is referenced by a record of the new type and by an address
	_, g, _ := f.do(t, "GET", "/api/c/contacts/ann", nil, nil)
	if code, r, _ := f.do(t, "DELETE", "/api/c/contacts/ann?hash="+g["hash"].(string), nil, nil); code != 200 {
		t.Fatalf("%d %v", code, r)
	}
	if code, r, _ := f.do(t, "DELETE", "/api/types/contacts?version="+typeOf(t, f, "contacts")["version"].(string), nil, nil); code != 200 {
		t.Fatalf("%d %v", code, r)
	}
	if code, _, _ := f.do(t, "GET", "/api/c/contacts", nil, nil); code != 404 {
		t.Fatal("the collection must be gone")
	}
	if _, err := os.Stat(filepath.Join(f.dir, "docs/ledger/contacts.yml")); err != nil {
		t.Fatal("the data file stays in place")
	}
	if _, err := os.Stat(filepath.Join(f.dir, "schemas/contacts.json")); err == nil {
		t.Fatal("the schema goes")
	}
}

func TestRecordDeleteGuardListsReferences(t *testing.T) {
	t.Parallel()
	f := adminFixture(t)
	id := "laptop-me-pc"
	_, g, _ := f.do(t, "GET", "/api/c/devices/"+url.PathEscape(id), nil, nil)
	code, r, _ := f.do(t, "DELETE", "/api/c/devices/"+id+"?hash="+g["hash"].(string), nil, nil)
	refs, _ := r["references"].([]any)
	if code != 409 || r["error"] != "referenced" || len(refs) == 0 || refs[0].(map[string]any)["collection"] == "" || !strings.Contains(r["message"].(string), id) {
		t.Fatalf("%d %v", code, r)
	}
	// clearing a required reference would leave records invalid
	code, r, _ = f.do(t, "DELETE", "/api/c/devices/"+id+"?clearReferences=true&hash="+g["hash"].(string), nil, nil)
	if code != 422 || r["error"] != "invalid" {
		t.Fatalf("%d %v", code, r)
	}
}

func TestTypeChangesCarryTheBaseVersion(t *testing.T) {
	t.Parallel()
	f := adminFixture(t)
	ty := typeOf(t, f, "todo")
	v, _ := ty["version"].(string)
	if v == "" {
		t.Fatal("GET must return the type's version")
	}
	// No version: refused.
	noVer := map[string]any{"title": "x"}
	for k, val := range ty {
		noVer[k] = val
	}
	delete(noVer, "version")
	noVer["title"] = "Tasks"
	if code, _, _ := f.do(t, "PUT", "/api/types/todo", map[string]any{"type": noVer}, nil); code != 400 {
		t.Fatalf("a change without a version: %d", code)
	}
	if code, _, _ := f.do(t, "DELETE", "/api/types/todo", nil, nil); code != 400 {
		t.Fatalf("a delete without a version: %d", code)
	}
	// Somebody else changes the title first.
	other := map[string]any{}
	for k, val := range ty {
		other[k] = val
	}
	other["title"] = "Other title"
	if code, r, _ := f.do(t, "PUT", "/api/types/todo", map[string]any{"type": other}, nil); code != 200 {
		t.Fatalf("first change: %d %v", code, r)
	}
	// Our change, still based on the old version: 409 with the current type.
	mine := map[string]any{}
	for k, val := range ty {
		mine[k] = val
	}
	mine["title"] = "My title"
	code, r, _ := f.do(t, "PUT", "/api/types/todo", map[string]any{"type": mine}, nil)
	cur, _ := r["current"].(map[string]any)
	if code != 409 || r["error"] != "conflict" || cur["title"] != "Other title" || cur["version"] == v {
		t.Fatalf("stale change: %d %v", code, r)
	}
	if code, _, _ := f.do(t, "DELETE", "/api/types/todo?version="+v, nil, nil); code != 409 {
		t.Fatalf("stale delete: %d", code)
	}
}
