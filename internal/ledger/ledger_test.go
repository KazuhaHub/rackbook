package ledger_test

import (
	"testing"

	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

func load(t *testing.T) *ledger.Ledger {
	t.Helper()
	l := ledger.Load(testutil.LoadConfig(t, testutil.CopyExample(t)), nil)
	if len(l.Issues) != 0 {
		t.Fatalf("load issues: %v", l.Issues)
	}
	return l
}

func TestLoadExample(t *testing.T) {
	l := load(t)
	want := map[string]int{"devices": 5, "addresses": 8, "services": 9, "ports": 5, "tailscale_ranges": 5, "lan_ranges": 1, "docker_ranges": 2, "sites": 2, "todo": 4}
	for name, n := range want {
		if got := len(l.Collection(name).Records); got != n {
			t.Errorf("%s: %d records, want %d", name, got, n)
		}
	}
	if len(l.Notes) != 2 || l.Notes[0].Text == "" {
		t.Fatalf("notes: %+v", l.Notes)
	}
	svc := l.Collection("services")
	r := svc.Get("web-hostco-ashburn-va-us-dc/SSH")
	if r == nil || len(r.Hash) != 16 || r.Data["port"] != "TCP 10511" {
		t.Fatalf("record: %+v", r)
	}
	if props := svc.Schema.Props; props[0].Name != "device" || props[0].Title != "设备" || props[2].Type != "string" {
		t.Fatalf("schema props: %+v", props)
	}
}

func TestIDEscapingAndHash(t *testing.T) {
	l := load(t)
	c := l.Collection("services").Collection
	id := ledger.ID(c, 0, map[string]any{"device": "a/b", "service": "50%"})
	if id != "a%2Fb/50%25" {
		t.Fatalf("id: %s", id)
	}
	a := ledger.Hash(map[string]any{"b": 1, "a": "x"})
	b := ledger.Hash(map[string]any{"a": "x", "b": 1})
	if a != b || ledger.Hash(map[string]any{"a": "y"}) == a {
		t.Fatal("hash must be order independent and content sensitive")
	}
	todo := l.Collection("todo")
	if todo.Records[1].ID != "NAS 纳入配置仓库，纳入后 managed 改为 true" {
		t.Fatalf("%q", todo.Records[1].ID)
	}
}

func TestBackrefs(t *testing.T) {
	l := load(t)
	dev := l.Collection("devices").Get("web-hostco-ashburn-va-us-dc")
	br := l.Backrefs("devices", dev)
	if len(br["addresses"]) != 2 {
		t.Fatalf("addresses: %d", len(br["addresses"]))
	}
	// 3 own services (SSH, 主站, Rackbook) plus the "all" row.
	if len(br["services"]) != 4 {
		t.Fatalf("services: %d", len(br["services"]))
	}
	if refs := l.Refs("services"); len(refs) != 1 || refs[0].To != "devices" || refs[0].Allow[0] != "all" {
		t.Fatalf("refs: %+v", refs)
	}
	if b := l.BackRefs("devices"); len(b) != 2 {
		t.Fatalf("backrefs: %+v", b)
	}
}

func TestOverlay(t *testing.T) {
	dir := testutil.CopyExample(t)
	cfg := testutil.LoadConfig(t, dir)
	l := ledger.Load(cfg, map[string][]byte{"docs/ledger/todo.yml": []byte("- {item: only, status: 待办}\n")})
	if n := len(l.Collection("todo").Records); n != 1 {
		t.Fatalf("overlay ignored: %d", n)
	}
}
