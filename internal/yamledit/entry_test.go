package yamledit

import (
	"strings"
	"testing"
)

const cfgSample = `# Rackbook config
title: demo

collections:
  # devices come first
  devices:
    title: 设备            # the title
    file: docs/devices.yml
    schema: schemas/device.json
    key: [name]
    list: [name, category]

  # ---- services
  services:
    title: 服务
    description: |
      line one
      line two
    file: docs/services.yml
    schema: schemas/service.json
    facets:
      - device
      - {field: exposure, match: contains, values: [a, b]}
  todo:
    title: 待办
    file: docs/todo.yml
    schema: schemas/todo.json

# the notes
notes: []

rules:
  # the device rule
  - ref: {from: services.device, to: devices.name, allow: [all]}
  - unique: {collection: devices, fields: [name]}
`

func mustEntry(t *testing.T, out []byte, err error) string {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestSetEntryReplacesOnlyChangedKeys(t *testing.T) {
	out, err := SetEntry([]byte(cfgSample), "collections", "devices", []EntryChange{
		{Key: "list", Value: []any{"name", "site"}},
		{Key: "icon", Value: "server"},
		{Key: "title", Value: "设备"}, // unchanged: bytes stay
	}, []string{"title", "description", "group", "icon", "file", "path", "schema", "key", "label", "list", "facets"})
	got := mustEntry(t, out, err)
	want := strings.Replace(cfgSample, "    list: [name, category]\n", "    list: [name, site]\n", 1)
	want = strings.Replace(want, "    title: 设备            # the title\n", "    title: 设备            # the title\n    icon: server\n", 1)
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestSetEntryRemoveAndMultilineScalar(t *testing.T) {
	out, err := SetEntry([]byte(cfgSample), "collections", "services", []EntryChange{
		{Key: "description", Remove: true},
		{Key: "facets", Value: []any{"device"}},
	}, nil)
	got := mustEntry(t, out, err)
	if strings.Contains(got, "line one") || strings.Contains(got, "exposure") {
		t.Fatalf("not removed:\n%s", got)
	}
	if !strings.Contains(got, "    facets: [device]\n  todo:\n") {
		t.Fatalf("facets not rewritten in place:\n%s", got)
	}
	if !strings.Contains(got, "  # ---- services\n  services:") || !strings.Contains(got, "# the notes\nnotes: []") {
		t.Fatalf("comments lost:\n%s", got)
	}
}

func TestSetEntryAddsFacetListWithMaps(t *testing.T) {
	out, err := SetEntry([]byte(cfgSample), "collections", "todo", []EntryChange{
		{Key: "facets", Value: []any{"status", Flow{Keys: []string{"field", "match", "values"}, Values: map[string]any{"field": "pri", "match": "prefix", "values": []any{"P0"}}}}},
		{Key: "group", Value: "杂项"},
	}, []string{"title", "description", "group", "file", "schema", "facets"})
	got := mustEntry(t, out, err)
	if !strings.Contains(got, "    title: 待办\n    group: 杂项\n    file:") {
		t.Fatalf("group placed wrong:\n%s", got)
	}
	if !strings.Contains(got, "    facets:\n      - status\n      - {field: pri, match: prefix, values: [P0]}\n\n# the notes") {
		t.Fatalf("facets block wrong:\n%s", got)
	}
}

func TestAddAndRemoveEntry(t *testing.T) {
	fields := []EntryChange{
		{Key: "title", Value: "新"}, {Key: "file", Value: "docs/new.yml"}, {Key: "schema", Value: "schemas/new.json"},
		{Key: "key", Value: []any{"name"}},
	}
	out, err := AddEntry([]byte(cfgSample), "collections", "fresh", fields)
	got := mustEntry(t, out, err)
	want := strings.Replace(cfgSample, "    schema: schemas/todo.json\n", "    schema: schemas/todo.json\n  fresh:\n    title: 新\n    file: docs/new.yml\n    schema: schemas/new.json\n    key: [name]\n", 1)
	if got != want {
		t.Fatalf("got:\n%s", got)
	}
	back, err := RemoveEntry(out, "collections", "fresh")
	if s := mustEntry(t, back, err); s != cfgSample {
		t.Fatalf("remove did not restore the file:\n%s", s)
	}
	// removing a middle entry keeps the neighbours and the separating comment
	mid, err := RemoveEntry([]byte(cfgSample), "collections", "services")
	s := mustEntry(t, mid, err)
	if strings.Contains(s, "services.yml") || !strings.Contains(s, "  devices:") || !strings.Contains(s, "  todo:") {
		t.Fatalf("bad removal:\n%s", s)
	}
}

func TestAddEntryKeepsBlankSeparator(t *testing.T) {
	src := "collections:\n  a:\n    title: A\n\n  b:\n    title: B\n\nrules: []\n"
	out, err := AddEntry([]byte(src), "collections", "c", []EntryChange{{Key: "title", Value: "C"}})
	got := mustEntry(t, out, err)
	if got != "collections:\n  a:\n    title: A\n\n  b:\n    title: B\n\n  c:\n    title: C\n\nrules: []\n" {
		t.Fatalf("got:\n%s", got)
	}
}

func TestAddAndRemoveItem(t *testing.T) {
	item := Flow{Keys: []string{"from", "to", "allow"}, Values: map[string]any{"from": "todo.owner", "to": "devices.name", "allow": []any{"all"}}}
	text := "ref: " + item.String()
	out, err := AddItem([]byte(cfgSample), "rules", text, map[string]any{"ref": item})
	got := mustEntry(t, out, err)
	if !strings.HasSuffix(got, "  - unique: {collection: devices, fields: [name]}\n  - ref: {from: todo.owner, to: devices.name, allow: [all]}\n") {
		t.Fatalf("got:\n%s", got)
	}
	back, err := RemoveItem(out, "rules", 2)
	if s := mustEntry(t, back, err); s != cfgSample {
		t.Fatalf("not restored:\n%s", s)
	}
	first, err := RemoveItem([]byte(cfgSample), "rules", 0)
	s := mustEntry(t, first, err)
	if !strings.Contains(s, "rules:\n  # the device rule\n  - unique:") {
		t.Fatalf("got:\n%s", s)
	}
}

func TestAddItemCreatesMissingList(t *testing.T) {
	src := "title: x\ncollections:\n  a:\n    title: A\n"
	out, err := AddItem([]byte(src), "rules", "unique: {collection: a, fields: [x]}", map[string]any{"unique": map[string]any{"collection": "a", "fields": []any{"x"}}})
	got := mustEntry(t, out, err)
	if got != src+"\nrules:\n  - unique: {collection: a, fields: [x]}\n" {
		t.Fatalf("got:\n%s", got)
	}
}

func TestEntryCRLFAndFlowRefusal(t *testing.T) {
	crlf := strings.ReplaceAll("collections:\n  a:\n    title: A\n    list: [x]\n  b:\n    title: B\n", "\n", "\r\n")
	out, err := SetEntry([]byte(crlf), "collections", "a", []EntryChange{{Key: "list", Value: []any{"yy"}}}, nil)
	got := mustEntry(t, out, err)
	if got != strings.ReplaceAll("collections:\n  a:\n    title: A\n    list: [yy]\n  b:\n    title: B\n", "\n", "\r\n") {
		t.Fatalf("crlf broken: %q", got)
	}
	_, err = SetEntry([]byte("collections:\n  a: {title: A}\n"), "collections", "a", []EntryChange{{Key: "title", Value: "B"}}, nil)
	if err == nil {
		t.Fatal("flow entry must be refused")
	}
	if _, err = RemoveEntry([]byte(cfgSample), "collections", "nope"); err == nil {
		t.Fatal("missing entry must error")
	}
}

func TestRemoveLastItemDropsTheKey(t *testing.T) {
	src := "title: x\n\nrules:\n  - unique: {collection: a, fields: [x]}\n\nnotes: []\n"
	out, err := RemoveItem([]byte(src), "rules", 0)
	if got := mustEntry(t, out, err); got != "title: x\n\nnotes: []\n" {
		t.Fatalf("got %q", got)
	}
}
