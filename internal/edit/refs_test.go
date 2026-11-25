package edit_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/testutil"
	"github.com/kazuhahub/rackbook/internal/validate"
)

// a small ledger: people, and tasks that point at people (one optional, one many)
func refLedger(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	w := func(rel, s string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("rackbook.yml", `collections:
  people:
    file: data/people.yml
    schema: schemas/people.json
    key: [name]
  tasks:
    file: data/tasks.yml
    schema: schemas/tasks.json
    key: [title]
rules:
  - ref: {from: tasks.owner, to: people.name}
  - ref: {from: tasks.watchers, to: people.name, many: true}
  - ref: {from: tasks.reviewer, to: people.name}
`)
	w("schemas/people.json", `{"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}}`)
	w("schemas/tasks.json", `{"type": "object", "required": ["title", "reviewer"], "properties": {"title": {"type": "string"}, "owner": {"type": "string"}, "watchers": {"type": "array", "items": {"type": "string"}}, "reviewer": {"type": "string"}}}`)
	w("data/people.yml", "- {name: ann}\n- {name: bob}\n- {name: cy}\n")
	w("data/tasks.yml", "# tasks\n- {title: t1, owner: ann, reviewer: cy}\n- {title: t2, owner: bob, watchers: [ann, bob, cy], reviewer: cy}\n- {title: t3, reviewer: cy}\n")
	return dir
}

func TestDeleteOfAReferencedRecordIsRefusedWithTheReferences(t *testing.T) {
	t.Parallel()
	dir := refLedger(t)
	cfg := testutil.LoadConfig(t, dir)
	before := read(t, dir, "data/people.yml")
	_, err := edit.Apply(cfg, edit.Op{Kind: edit.Delete, Collection: "people", ID: "ann"})
	var re *edit.ReferencedError
	if !errors.As(err, &re) {
		t.Fatalf("want *ReferencedError, got %v", err)
	}
	if len(re.Refs) != 2 || re.Refs[0].Collection != "tasks" || re.Refs[0].ID != "t1" || re.Refs[0].Field != "owner" || re.Refs[1].ID != "t2" || re.Refs[1].Field != "watchers" {
		t.Fatalf("%+v", re.Refs)
	}
	if read(t, dir, "data/people.yml") != before {
		t.Fatal("a refused delete must not write")
	}
	// an unreferenced record deletes as before
	if _, err := edit.Apply(cfg, edit.Op{Kind: edit.Delete, Collection: "people", ID: "bob"}); err == nil {
		t.Fatal("bob is referenced by t2")
	}
}

func TestDeleteClearingReferencesIsOneChange(t *testing.T) {
	t.Parallel()
	dir := refLedger(t)
	cfg := testutil.LoadConfig(t, dir)
	res, err := edit.Apply(cfg, edit.Op{Kind: edit.Delete, Collection: "people", ID: "ann", ClearReferences: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Files, ",") != "data/people.yml,data/tasks.yml" || len(res.Cleared) != 2 {
		t.Fatalf("%+v", res)
	}
	tasks := read(t, dir, "data/tasks.yml")
	if strings.Contains(tasks, "ann") || !strings.Contains(tasks, "watchers: [bob, cy]") || !strings.Contains(tasks, "# tasks") {
		t.Fatalf("%s", tasks)
	}
	if strings.Contains(read(t, dir, "data/people.yml"), "ann") {
		t.Fatal("ann still there")
	}
	l := ledger.Load(testutil.LoadConfig(t, dir), nil)
	if issues := validate.Run(l); len(issues) != 0 {
		t.Fatalf("%v", issues)
	}
	// clearing a required reference would leave records invalid: refused, nothing written
	before := read(t, dir, "data/tasks.yml")
	_, err = edit.Apply(testutil.LoadConfig(t, dir), edit.Op{Kind: edit.Delete, Collection: "people", ID: "cy", ClearReferences: true})
	var ie *edit.InvalidError
	if !errors.As(err, &ie) || read(t, dir, "data/tasks.yml") != before {
		t.Fatalf("%v", err)
	}
}
