package edit_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

// moduleSetup is the example ledger with a source field on todo and one record
// the module "bot" maintains next to the manual ones.
func moduleSetup(t *testing.T) (dir string, apply func(edit.Op) (*edit.Result, error)) {
	t.Helper()
	dir = testutil.CopyExample(t)
	testutil.Replace(t, dir, "schemas/todo.json", `"status":`, `"source": {"type": "string"}, "status":`)
	cfg := testutil.LoadConfig(t, dir)
	rule := &edit.ModuleRule{Name: "bot", Fields: []string{"status"}}
	if _, err := edit.Apply(cfg, edit.Op{Kind: edit.Add, Collection: "todo", Module: rule, Data: map[string]any{"item": "rotate", "scope": "x", "status": "待办", "source": "bot"}}); err != nil {
		t.Fatal(err)
	}
	return dir, func(op edit.Op) (*edit.Result, error) { return edit.Apply(cfg, op) }
}

func wantModuleError(t *testing.T, err error, contains string) {
	t.Helper()
	var me *edit.ModuleError
	if !errors.As(err, &me) || !strings.Contains(me.Error(), contains) {
		t.Fatalf("want a module error containing %q, got %v", contains, err)
	}
}

func TestModuleRules(t *testing.T) {
	t.Parallel()
	rule := &edit.ModuleRule{Name: "bot", Fields: []string{"status"}}
	dir, apply := moduleSetup(t)
	botID := "rotate"
	botHash := hashOf(t, dir, "todo", botID)
	data := func(kv ...string) map[string]any {
		m := map[string]any{"item": "rotate", "scope": "x", "status": "待办", "source": "bot"}
		for i := 0; i+1 < len(kv); i += 2 {
			if kv[i+1] == "-" {
				delete(m, kv[i])
			} else {
				m[kv[i]] = kv[i+1]
			}
		}
		return m
	}
	op := func(kind edit.Kind, id, hash string, d map[string]any) edit.Op {
		return edit.Op{Kind: kind, Collection: "todo", ID: id, Hash: hash, Data: d, Module: rule}
	}

	// Create: source must be the module's.
	for _, d := range []map[string]any{data("source", "-"), data("source", "manual"), data("source", "other")} {
		_, err := apply(op(edit.Add, "", "", d))
		wantModuleError(t, err, `only create records with source "bot"`)
	}
	res, err := apply(op(edit.Add, "", "", data("item", "second")))
	if err != nil || len(res.Trailers) != 1 || res.Trailers[0] != "Source: bot" {
		t.Fatalf("%v %+v", err, res)
	}

	// Update: its own field may change.
	res, err = apply(op(edit.Edit, botID, botHash, data("status", "完成")))
	if err != nil || res.Data["status"] != "完成" {
		t.Fatalf("%v %+v", err, res)
	}
	hash := res.Hash
	// A foreign field changed, added or removed is refused.
	for name, d := range map[string]map[string]any{
		"changed": data("item", "renamed"),
		"removed": data("scope", "-"),
		"added":   data("extra", "1"),
	} {
		_, err := apply(op(edit.Edit, botID, hash, d))
		wantModuleError(t, err, "may not change")
		if name == "removed" && !strings.Contains(err.Error(), "scope") {
			t.Fatal(err)
		}
	}
	// source must stay.
	_, err = apply(op(edit.Edit, botID, hash, data("source", "manual")))
	wantModuleError(t, err, "keep source")
	_, err = apply(op(edit.Edit, botID, hash, data("source", "-")))
	wantModuleError(t, err, "keep source")

	// Manual records (no source) and another module's records are untouched.
	manual := "评估关闭路由器 WAN 上的 Web 后台"
	before := read(t, dir, "docs/ledger/todo.yml")
	_, err = apply(op(edit.Edit, manual, hashOf(t, dir, "todo", manual), map[string]any{"item": manual, "scope": "gw", "status": "完成", "source": "bot"}))
	wantModuleError(t, err, "only update records with source")
	_, err = apply(edit.Op{Kind: edit.Edit, Collection: "todo", ID: botID, Hash: hash, Module: &edit.ModuleRule{Name: "other", Fields: []string{"status"}},
		Data: data("source", "other")})
	wantModuleError(t, err, "only update records with source")
	if read(t, dir, "docs/ledger/todo.yml") != before {
		t.Fatal("a refused write changed the file")
	}

	// Delete is refused, whatever the record.
	_, err = apply(op(edit.Delete, botID, "", nil))
	wantModuleError(t, err, "may not delete")

	// Without a module rule the same edits are plain edits (people may do them).
	if _, err := apply(edit.Op{Kind: edit.Edit, Collection: "todo", ID: botID, Hash: hash, Data: data("item", "renamed by a person")}); err != nil {
		t.Fatal(err)
	}
}

func TestModuleUnchangedForeignFieldsMayBeResent(t *testing.T) {
	t.Parallel()
	// Normalization: numbers and nulls compare equal to what the file holds.
	rule := &edit.ModuleRule{Name: "bot", Fields: []string{"status"}}
	dir, apply := moduleSetup(t)
	hash := hashOf(t, dir, "todo", "rotate")
	res, err := apply(edit.Op{Kind: edit.Edit, Collection: "todo", ID: "rotate", Hash: hash, Module: rule,
		Data: map[string]any{"item": "rotate", "scope": "x", "status": "待办", "source": "bot"}})
	if err != nil || res.Changed() {
		t.Fatalf("%v %+v", err, res)
	}
}
