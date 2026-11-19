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
)

func setup(t *testing.T) (dir string, apply func(edit.Op) (*edit.Result, error)) {
	dir = testutil.CopyExample(t)
	cfg := testutil.LoadConfig(t, dir)
	return dir, func(op edit.Op) (*edit.Result, error) { return edit.Apply(cfg, op) }
}

func read(t *testing.T, dir, rel string) string {
	b, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func hashOf(t *testing.T, dir, coll, id string) string {
	t.Helper()
	l := ledger.Load(testutil.LoadConfig(t, dir), nil)
	r := l.Collection(coll).Get(id)
	if r == nil {
		t.Fatalf("%s/%s missing", coll, id)
	}
	return r.Hash
}

func TestEditAddDelete(t *testing.T) {
	dir, apply := setup(t)
	id := "web-hostco-ashburn-va-us-dc/SSH"
	res, err := apply(edit.Op{Kind: edit.Edit, Collection: "services", ID: id, Hash: hashOf(t, dir, "services", id),
		Data: map[string]any{"device": "web-hostco-ashburn-va-us-dc", "service": "SSH", "port": "TCP 22", "exposure": "公网 + Tailscale", "notes": "仅密钥"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.ID != id || !res.Changed() || res.Data["port"] != "TCP 22" || res.Subject() != "ledger(services): edit "+id {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(read(t, dir, "docs/ledger/services.yml"), "service: SSH, port: TCP 22, exposure: 公网 + Tailscale, notes: 仅密钥}") {
		t.Fatal(read(t, dir, "docs/ledger/services.yml"))
	}

	// Add lands after the other rows of the same device.
	res, err = apply(edit.Op{Kind: edit.Add, Collection: "services", Data: map[string]any{"device": "web-hostco-ashburn-va-us-dc", "service": "nginx", "port": "TCP 80"}})
	if err != nil || res.ID != "web-hostco-ashburn-va-us-dc/nginx" {
		t.Fatalf("%v %+v", err, res)
	}
	s := read(t, dir, "docs/ledger/services.yml")
	if strings.Index(s, "service: nginx") < strings.Index(s, "Rackbook") || strings.Index(s, "service: nginx") > strings.Index(s, "# --- standby") {
		t.Fatal(s)
	}

	// Delete.
	if _, err = apply(edit.Op{Kind: edit.Delete, Collection: "services", ID: res.ID, Hash: res.Hash}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(read(t, dir, "docs/ledger/services.yml"), "service: nginx") {
		t.Fatal("not deleted")
	}
}

func TestRenameAndConflicts(t *testing.T) {
	dir, apply := setup(t)
	id := "laptop-me-pc"
	h := hashOf(t, dir, "devices", id)
	var ce *edit.ConflictError
	// stale hash
	_, err := apply(edit.Op{Kind: edit.Edit, Collection: "devices", ID: id, Hash: "0000000000000000", Data: map[string]any{"name": id, "category": "x"}})
	if !errors.As(err, &ce) || ce.Current == nil || ce.Current.ID != id {
		t.Fatalf("stale: %v", err)
	}
	// duplicate on add
	_, err = apply(edit.Op{Kind: edit.Add, Collection: "devices", Data: map[string]any{"name": id, "category": "x"}})
	if !errors.As(err, &ce) || ce.Current == nil {
		t.Fatalf("dup add: %v", err)
	}
	// rename onto an existing id
	_, err = apply(edit.Op{Kind: edit.Edit, Collection: "devices", ID: id, Hash: h, Data: map[string]any{"name": "nas-example-springfield-or-us-home", "category": "x"}})
	if !errors.As(err, &ce) {
		t.Fatalf("rename onto existing: %v", err)
	}
	// vanished record
	_, err = apply(edit.Op{Kind: edit.Delete, Collection: "devices", ID: "nope", Hash: h})
	if !errors.As(err, &ce) || ce.Current != nil {
		t.Fatalf("missing: %v", err)
	}
	// a real rename works (on a device nothing references)
	if _, err = apply(edit.Op{Kind: edit.Add, Collection: "devices", Data: map[string]any{"name": "tmp-dev", "category": "x"}}); err != nil {
		t.Fatal(err)
	}
	h = hashOf(t, dir, "devices", "tmp-dev")
	res, err := apply(edit.Op{Kind: edit.Edit, Collection: "devices", ID: "tmp-dev", Hash: h, Data: map[string]any{"name": "tmp-dev2", "category": "x"}})
	if err != nil || res.ID != "tmp-dev2" {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestInvalidWritesAreRejectedAndNothingIsWritten(t *testing.T) {
	dir, apply := setup(t)
	before := read(t, dir, "docs/ledger/services.yml")
	var ie *edit.InvalidError
	_, err := apply(edit.Op{Kind: edit.Add, Collection: "services", Data: map[string]any{"device": "ghost", "service": "x", "port": "TCP 1"}})
	if !errors.As(err, &ie) || ie.Issues[0].Rule != "ref" {
		t.Fatalf("ref: %v", err)
	}
	_, err = apply(edit.Op{Kind: edit.Add, Collection: "services", Data: map[string]any{"device": "all", "service": "x"}})
	if !errors.As(err, &ie) || ie.Issues[0].Rule != "schema" {
		t.Fatalf("schema: %v", err)
	}
	// Renaming a device referenced elsewhere is introduced breakage.
	id := "nas-example-springfield-or-us-home"
	_, err = apply(edit.Op{Kind: edit.Edit, Collection: "devices", ID: id, Hash: hashOf(t, dir, "devices", id), Data: map[string]any{"name": "nas2", "category": "家里服务"}})
	if !errors.As(err, &ie) {
		t.Fatalf("rename: %v", err)
	}
	if read(t, dir, "docs/ledger/services.yml") != before {
		t.Fatal("file was modified")
	}
}

func TestPreexistingErrorsDoNotBlockUnrelatedWrites(t *testing.T) {
	dir, apply := setup(t)
	testutil.Replace(t, dir, "docs/ledger/addresses.yml", "{device: laptop-me-pc, network", "{device: ghost, network")
	if _, err := apply(edit.Op{Kind: edit.Add, Collection: "todo", Data: map[string]any{"item": "new", "status": "待办"}}); err != nil {
		t.Fatalf("unrelated write blocked: %v", err)
	}
}

func TestNestedAndKeylessAndNoop(t *testing.T) {
	dir, apply := setup(t)
	if _, err := apply(edit.Op{Kind: edit.Add, Collection: "docker_ranges", Data: map[string]any{"range": "172.20.0.0/16", "purpose": "new"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, dir, "docs/ledger/networks.yml"), "    - {range: 172.20.0.0/16, purpose: new}\n") {
		t.Fatal(read(t, dir, "docs/ledger/networks.yml"))
	}
	// A no-op edit writes nothing.
	id := "SSH"
	res, err := apply(edit.Op{Kind: edit.Edit, Collection: "ports", ID: id, Data: map[string]any{"service": "SSH", "port": "TCP 10511", "scope": "所有服务器和路由器", "notes": "统一端口，只允许密钥登录"}})
	if err != nil || res.Changed() {
		t.Fatalf("%v %+v", err, res)
	}
	if _, err := apply(edit.Op{Kind: edit.Add, Collection: "nope", Data: map[string]any{"a": 1}}); !errors.Is(err, edit.ErrUnknownCollection) {
		t.Fatalf("%v", err)
	}
	if _, err := apply(edit.Op{Kind: edit.Add, Collection: "todo"}); !errors.Is(err, edit.ErrBadRequest) {
		t.Fatalf("%v", err)
	}
}

func TestDeleteNotBlockedByPreexistingErrorInKeylessCollection(t *testing.T) {
	dir, apply := setup(t)
	testutil.Replace(t, dir, "rackbook.yml", "  todo:\n    title: 待办\n    file: docs/ledger/todo.yml\n    schema: schemas/todo.json\n    key: [item]\n", "  todo:\n    title: 待办\n    file: docs/ledger/todo.yml\n    schema: schemas/todo.json\n")
	// Break the last record; ids are positions, so deleting an earlier one shifts it.
	testutil.Replace(t, dir, "docs/ledger/todo.yml", "{item: 所有服务器 SSH 改到 10511, scope: 所有服务器, status: 完成（2026-11-01）}", "{item: 所有服务器 SSH 改到 10511, scope: 所有服务器}")
	cfg := testutil.LoadConfig(t, dir)
	l := ledger.Load(cfg, nil)
	r := l.Collection("todo").Records[0]
	if _, err := edit.Apply(cfg, edit.Op{Kind: edit.Delete, Collection: "todo", ID: r.ID, Hash: r.Hash}); err != nil {
		t.Fatalf("pre-existing error blocked an unrelated delete: %v", err)
	}
	_ = apply
}

func TestSubjectIsSanitizedAndMultilineKeysRejected(t *testing.T) {
	r := &edit.Result{Kind: edit.Add, Collection: "todo", ID: "a\nEdited-by: x@y.z\r\n" + strings.Repeat("x", 300)}
	subj := r.Subject()
	if strings.ContainsAny(subj, "\r\n") || len([]rune(subj)) > 160 || !strings.HasPrefix(subj, "ledger(todo): add a Edited-by: x@y.z") {
		t.Fatalf("%q", subj)
	}
	_, apply := setup(t)
	var ie *edit.InvalidError
	_, err := apply(edit.Op{Kind: edit.Add, Collection: "todo", Data: map[string]any{"item": "a\nb", "status": "待办"}})
	if !errors.As(err, &ie) || !strings.Contains(ie.Error(), "control characters") {
		t.Fatalf("%v", err)
	}
}

func TestApplyDryRunChecksEverythingAndWritesNothing(t *testing.T) {
	dir, apply := setup(t)
	before := read(t, dir, "docs/ledger/services.yml")
	id := "web-hostco-ashburn-va-us-dc/SSH"
	edited := map[string]any{"device": "web-hostco-ashburn-va-us-dc", "service": "SSH", "port": "TCP 22", "exposure": "公网 + Tailscale", "notes": "仅密钥"}
	h := hashOf(t, dir, "services", id)
	tests := []struct {
		name string
		op   edit.Op
		err  any // a pointer of the error type the real write would return, nil for success
	}{
		{"edit", edit.Op{Kind: edit.Edit, Collection: "services", ID: id, Hash: h, Data: edited}, nil},
		{"add", edit.Op{Kind: edit.Add, Collection: "services", Data: map[string]any{"device": "web-hostco-ashburn-va-us-dc", "service": "nginx", "port": "TCP 80"}}, nil},
		{"stale hash", edit.Op{Kind: edit.Edit, Collection: "services", ID: id, Hash: "deadbeef", Data: edited}, new(*edit.ConflictError)},
		{"invalid", edit.Op{Kind: edit.Add, Collection: "services", Data: map[string]any{"service": "x"}}, new(*edit.InvalidError)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dry := tt.op
			dry.DryRun = true
			res, err := apply(dry)
			if read(t, dir, "docs/ledger/services.yml") != before {
				t.Fatal("a dry run must not write")
			}
			if tt.err != nil {
				if err == nil || !errors.As(err, tt.err) {
					t.Fatalf("%T %v", err, err)
				}
				return
			}
			if err != nil || !res.Changed() || res.Hash == "" {
				t.Fatalf("%v %+v", err, res)
			}
			f := res.Files[0]
			if string(res.Before[f]) != before || string(res.After[f]) == before {
				t.Fatalf("before and after of %s", f)
			}
			// The same op for real writes exactly what the dry run showed.
			real, err := apply(tt.op)
			if err != nil || real.Hash != res.Hash || read(t, dir, "docs/ledger/services.yml") != string(res.After[f]) {
				t.Fatalf("%v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "docs/ledger/services.yml"), []byte(before), 0o644); err != nil {
				t.Fatal(err)
			}
		})
	}
}
