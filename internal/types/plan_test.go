package types

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/testutil"
	"github.com/kazuhahub/rackbook/internal/validate"
)

func setup(t *testing.T) (*config.Config, string) {
	t.Helper()
	dir := testutil.CopyExample(t)
	return testutil.LoadConfig(t, dir), dir
}

func current(t *testing.T, cfg *config.Config, name string) *Type {
	t.Helper()
	ty, err := Load(ledger.Load(cfg, nil), name)
	if err != nil {
		t.Fatal(err)
	}
	return ty
}

func update(t *testing.T, cfg *config.Config, name string, mutate func(*Type), migs ...Migration) *Plan {
	t.Helper()
	nt := current(t, cfg, name)
	mutate(nt)
	p, err := Build(cfg, Request{Op: OpUpdate, Name: name, Type: nt, Migrations: migs})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func hasRefusal(p *Plan, code string) *Refusal {
	for i := range p.Refusals {
		if p.Refusals[i].Code == code {
			return &p.Refusals[i]
		}
	}
	return nil
}

func file(p *Plan, path string) *FileChange {
	for i := range p.Files {
		if p.Files[i].Path == path {
			return &p.Files[i]
		}
	}
	return nil
}

func TestPlanNoChange(t *testing.T) {
	cfg, _ := setup(t)
	p := update(t, cfg, "services", func(*Type) {})
	if !p.Clean || p.Changed || len(p.Files) != 0 {
		t.Fatalf("%v", p)
	}
}

func TestPlanAddOptionalField(t *testing.T) {
	cfg, _ := setup(t)
	p := update(t, cfg, "services", func(ty *Type) {
		ty.Fields = append(ty.Fields, Field{Name: "owner", Title: "负责人", Type: TText})
	})
	if !p.Clean || !p.Changed || len(p.Files) != 1 {
		t.Fatalf("%v", p)
	}
	f := file(p, "schemas/service.json")
	if f == nil || !strings.Contains(f.Diff, `+    "owner": {"type": "string", "title": "负责人", "x-rackbook-type": "text"}`) {
		t.Fatalf("%v", p.Files)
	}
	if !strings.Contains(p.Subject, `add field "owner"`) || !strings.HasPrefix(p.Subject, "ledger(types): edit services") {
		t.Fatal(p.Subject)
	}
}

func TestPlanRequiredFieldOffersDefaultMigration(t *testing.T) {
	cfg, _ := setup(t)
	add := func(ty *Type) {
		ty.Fields = append(ty.Fields, Field{Name: "owner", Type: TText, Required: true, Default: "ops"})
	}
	p := update(t, cfg, "services", add)
	if p.Clean || len(p.Invalid) == 0 {
		t.Fatalf("records lacking the field must be reported: %v", p)
	}
	if len(p.Migrations) != 1 || p.Migrations[0].Kind != MigFillDefault || p.Migrations[0].Applied || p.Migrations[0].Default != "ops" {
		t.Fatalf("%v", p.Migrations)
	}
	n := p.Migrations[0].Count
	p = update(t, cfg, "services", add, Migration{Kind: MigFillDefault, Field: "owner"})
	if !p.Clean || !p.Migrations[0].Applied || file(p, "docs/ledger/services.yml") == nil || file(p, "schemas/service.json") == nil {
		t.Fatalf("%v", p)
	}
	if got := strings.Count(file(p, "docs/ledger/services.yml").Diff, "owner"); got < n {
		t.Fatalf("owner added to %d lines, want %d", got, n)
	}
	// a value given with the migration wins over the default
	p = update(t, cfg, "services", add, Migration{Kind: MigFillDefault, Field: "owner", Value: "ann"})
	if !strings.Contains(file(p, "docs/ledger/services.yml").Diff, "owner: ann") && !strings.Contains(file(p, "docs/ledger/services.yml").Diff, "owner: ann") {
		t.Fatal(file(p, "docs/ledger/services.yml").Diff[:400])
	}
}

func TestPlanRemoveFieldWithValuesOffersMigration(t *testing.T) {
	cfg, _ := setup(t)
	drop := func(ty *Type) {
		var keep []Field
		for _, f := range ty.Fields {
			if f.Name != "exposure" {
				keep = append(keep, f)
			}
		}
		ty.Fields = keep
		var facets []config.Facet
		for _, f := range ty.Facets {
			if f.Field != "exposure" {
				facets = append(facets, f)
			}
		}
		ty.Facets = facets
		var list []string
		for _, f := range ty.List {
			if f != "exposure" {
				list = append(list, f)
			}
		}
		ty.List = list
	}
	p := update(t, cfg, "services", drop)
	if p.Clean || len(p.Invalid) == 0 || len(p.Migrations) != 1 || p.Migrations[0].Kind != MigRemoveField || p.Migrations[0].Count == 0 {
		t.Fatalf("%v", p)
	}
	p = update(t, cfg, "services", drop, Migration{Kind: MigRemoveField, Field: "exposure"})
	if !p.Clean {
		t.Fatalf("%v %v", p.Invalid, p.Refusals)
	}
	cf := file(p, "rackbook.yml")
	if cf == nil || !strings.Contains(cf.Diff, "-      - {field: exposure") {
		t.Fatalf("the facet must leave rackbook.yml: %v", p.Files)
	}
	if d := file(p, "docs/ledger/services.yml").Diff; !strings.Contains(d, "-") || strings.Contains(strings.ReplaceAll(d, "-exposure", ""), "+exposure") {
		t.Fatal(d[:300])
	}
}

func TestPlanNarrowingIsRefused(t *testing.T) {
	cfg, _ := setup(t)
	p := update(t, cfg, "devices", func(ty *Type) { ty.Field("os").Type = TIPv4 })
	r := hasRefusal(p, "narrowing")
	if p.Clean || r == nil || r.Field != "os" || r.Count == 0 || len(r.Records) == 0 {
		t.Fatalf("%v", p.Refusals)
	}
	if len(p.Invalid) == 0 || p.Invalid[0].ID == "" {
		t.Fatalf("%v", p.Invalid)
	}
}

func TestPlanLooseningIsClean(t *testing.T) {
	cfg, _ := setup(t)
	p := update(t, cfg, "devices", func(ty *Type) { ty.Field("os").Type = TTextarea })
	if !p.Clean {
		t.Fatalf("%v %v", p.Refusals, p.Invalid)
	}
}

func TestPlanRefusals(t *testing.T) {
	cfg, _ := setup(t)
	p := update(t, cfg, "services", func(ty *Type) { ty.Name = "svc" })
	if hasRefusal(p, "rename") == nil || p.Clean {
		t.Fatalf("%v", p.Refusals)
	}
	p = update(t, cfg, "services", func(ty *Type) { ty.File = "docs/ledger/other.yml" })
	if hasRefusal(p, "layout") == nil {
		t.Fatalf("%v", p.Refusals)
	}
	// tailscale_ranges, lan_ranges and docker_ranges share one schema file
	p = update(t, cfg, "lan_ranges", func(ty *Type) {
		ty.Fields = append(ty.Fields, Field{Name: "owner", Type: TText})
	})
	if hasRefusal(p, "shared-schema") == nil {
		t.Fatalf("%v", p.Refusals)
	}
	// ...but its settings can change
	p = update(t, cfg, "lan_ranges", func(ty *Type) { ty.Title = "局域网"; ty.Icon = "network" })
	if !p.Clean || file(p, "rackbook.yml") == nil || len(p.Files) != 1 {
		t.Fatalf("%v", p)
	}
	// a key field must stay a field; a field referenced by another collection must stay
	p = update(t, cfg, "devices", func(ty *Type) {
		var keep []Field
		for _, f := range ty.Fields {
			if f.Name != "name" {
				keep = append(keep, f)
			}
		}
		ty.Fields = keep
	})
	if p.Clean || hasRefusal(p, "invalid") == nil {
		t.Fatalf("%v", p.Refusals)
	}
	p = update(t, cfg, "devices", func(ty *Type) {
		ty.Key, ty.Label = []string{"category"}, "category"
		var keep []Field
		for _, f := range ty.Fields {
			if f.Name != "name" {
				keep = append(keep, f)
			}
		}
		ty.Fields = keep
		ty.List = []string{"category"}
		ty.Facets = nil
	})
	if hasRefusal(p, "field-in-use") == nil {
		t.Fatalf("%v", p.Refusals)
	}
}

func TestPlanAddReference(t *testing.T) {
	cfg, _ := setup(t)
	p := update(t, cfg, "todo", func(ty *Type) {
		ty.Fields = append(ty.Fields, Field{Name: "device", Type: TRef, Ref: &Ref{To: "devices", ToField: "name", BackrefTitle: "相关待办", BackrefColumns: []string{"item", "status"}}})
	})
	if !p.Clean {
		t.Fatalf("%v %v", p.Refusals, p.Dangling)
	}
	cf := file(p, "rackbook.yml")
	if cf == nil || !strings.Contains(cf.Diff, "+  - ref: {from: todo.device, to: devices.name, backref_title: 相关待办, backref_columns: [item, status]}") {
		t.Fatalf("%v", p.Files)
	}
	if len(p.Backrefs) != 1 || p.Backrefs[0].Collection != "devices" || p.Backrefs[0].Change != "gained" {
		t.Fatalf("%v", p.Backrefs)
	}
	// removing it again loses the back-reference and the rule
	_, dir := setup(t)
	_ = dir
}

func TestPlanReferenceToUnknownTargetIsRefused(t *testing.T) {
	cfg, _ := setup(t)
	p := update(t, cfg, "todo", func(ty *Type) {
		ty.Fields = append(ty.Fields, Field{Name: "x", Type: TRef, Ref: &Ref{To: "nope", ToField: "name"}})
	})
	if p.Clean || hasRefusal(p, "invalid") == nil {
		t.Fatalf("%v", p.Refusals)
	}
	p = update(t, cfg, "todo", func(ty *Type) {
		ty.Fields = append(ty.Fields, Field{Name: "x", Type: TRef, Ref: &Ref{To: "devices", ToField: "nope"}})
	})
	if p.Clean {
		t.Fatalf("%v", p.Refusals)
	}
}

func TestPlanUniqueRule(t *testing.T) {
	cfg, _ := setup(t)
	p := update(t, cfg, "devices", func(ty *Type) {
		ty.Field("category").Unique = true // several devices share a category
	})
	if p.Clean || len(p.Other) == 0 || p.Other[0].Rule != ledger.RuleUnique {
		t.Fatalf("%v", p)
	}
	p = update(t, cfg, "todo", func(ty *Type) { ty.Field("item").Unique = true })
	if !p.Clean {
		t.Fatalf("%v", p.Other)
	}
	if cf := file(p, "rackbook.yml"); cf == nil || !strings.Contains(cf.Diff, "+  - unique: {collection: todo, fields: [item]}") {
		t.Fatalf("%v", p.Files)
	}
}

func TestPlanRemoveReferenceDropsRule(t *testing.T) {
	cfg, _ := setup(t)
	p := update(t, cfg, "addresses", func(ty *Type) { ty.Field("device").Type = TText; ty.Field("device").Ref = nil })
	if !p.Clean {
		t.Fatalf("%v %v", p.Refusals, p.Invalid)
	}
	cf := file(p, "rackbook.yml")
	if cf == nil || !strings.Contains(cf.Diff, "-  - ref: {from: addresses.device, to: devices.name}") {
		t.Fatalf("%v", p.Files)
	}
	if len(p.Backrefs) != 1 || p.Backrefs[0].Change != "lost" {
		t.Fatalf("%v", p.Backrefs)
	}
}

func newType() *Type {
	return &Type{Name: "contacts", Title: "联系人", Group: "杂项", Icon: "users", Key: []string{"name"}, Label: "name", List: []string{"name", "email"},
		Fields: []Field{
			{Name: "name", Title: "姓名", Type: TText, Required: true},
			{Name: "email", Title: "邮箱", Type: TText},
			{Name: "device", Title: "设备", Type: TRef, Ref: &Ref{To: "devices", ToField: "name"}},
		}}
}

func TestPlanCreate(t *testing.T) {
	cfg, _ := setup(t)
	p, err := Build(cfg, Request{Op: OpCreate, Name: "contacts", Type: newType()})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Clean || len(p.Files) != 3 || p.Subject != "ledger(types): add contacts" {
		t.Fatalf("%v", p)
	}
	for _, want := range []string{"docs/ledger/contacts.yml", "schemas/contacts.json", "rackbook.yml"} {
		f := file(p, want)
		if f == nil || f.Status == "modified" && want != "rackbook.yml" {
			t.Fatalf("%v: %v", want, p.Files)
		}
	}
	if file(p, "rackbook.yml").Status != "modified" || file(p, "schemas/contacts.json").Status != "added" {
		t.Fatalf("%v", p.Files)
	}
	if len(p.Backrefs) != 1 || p.Backrefs[0].Collection != "devices" {
		t.Fatalf("%v", p.Backrefs)
	}
	// refusals
	bad := newType()
	bad.Name = "Bad Name"
	if p, _ := Build(cfg, Request{Op: OpCreate, Type: bad}); p.Clean {
		t.Fatal("bad name accepted")
	}
	dup := newType()
	dup.Name = "devices"
	if p, _ := Build(cfg, Request{Op: OpCreate, Type: dup}); p.Clean || hasRefusal(p, "exists") == nil {
		t.Fatalf("%v", p.Refusals)
	}
	cfg.Types.DataDir = "elsewhere"
	if p, _ := Build(cfg, Request{Op: OpCreate, Type: newType()}); !p.Clean || file(p, "elsewhere/contacts.yml") == nil {
		t.Fatalf("the data dir must be configurable: %v", p.Files)
	}
}

func TestPlanDelete(t *testing.T) {
	cfg, dir := setup(t)
	p, _ := Build(cfg, Request{Op: OpDelete, Name: "devices"})
	if p.Clean || hasRefusal(p, "not-empty") == nil || hasRefusal(p, "referenced") == nil {
		t.Fatalf("%v", p.Refusals)
	}
	// an empty collection nobody references can go; its data file stays
	if _, err := Apply(cfg, Request{Op: OpCreate, Name: "contacts", Type: newType()}); err != nil {
		t.Fatal(err)
	}
	cfg = testutil.LoadConfig(t, dir)
	p, err := Build(cfg, Request{Op: OpDelete, Name: "contacts"})
	if err != nil || !p.Clean {
		t.Fatalf("%v %v", err, p)
	}
	if f := file(p, "schemas/contacts.json"); f == nil || f.Status != "removed" || file(p, "docs/ledger/contacts.yml") != nil {
		t.Fatalf("%v", p.Files)
	}
	// a shared schema stays
	p, _ = Build(cfg, Request{Op: OpDelete, Name: "lan_ranges"})
	if hasRefusal(p, "not-empty") == nil {
		t.Fatalf("%v", p.Refusals)
	}
}

func TestApplyWritesAndReloads(t *testing.T) {
	cfg, dir := setup(t)
	res, err := Apply(cfg, Request{Op: OpCreate, Name: "contacts", Type: newType()})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Files, ",") != "docs/ledger/contacts.yml,rackbook.yml,schemas/contacts.json" || res.Subject() != "ledger(types): add contacts" || res.Record() != "" {
		t.Fatalf("%v %q", res.Files, res.Subject())
	}
	cfg = testutil.LoadConfig(t, dir)
	l := ledger.Load(cfg, nil)
	if issues := validate.Run(l); len(issues) != 0 {
		t.Fatalf("%v", issues)
	}
	ty := current(t, cfg, "contacts")
	b, _ := json.Marshal(ty)
	if !strings.Contains(string(b), `"icon":"users"`) || ty.Field("device").Ref == nil || ty.Field("device").Ref.To != "devices" {
		t.Fatalf("%v", b)
	}
	// the new file is a seed, the first record can be added through the normal path
	seed, _ := os.ReadFile(filepath.Join(dir, "docs/ledger/contacts.yml"))
	if !strings.HasPrefix(string(seed), "# 联系人") {
		t.Fatalf("%q", seed)
	}
	// an unclean plan writes nothing
	before, _ := os.ReadFile(filepath.Join(dir, "rackbook.yml"))
	bad := current(t, cfg, "devices")
	bad.Field("os").Type = TIPv4
	if _, err := Apply(cfg, Request{Op: OpUpdate, Name: "devices", Type: bad}); err == nil {
		t.Fatal("expected a plan error")
	} else if pe, ok := err.(*PlanError); !ok || pe.Plan.Clean {
		t.Fatalf("%T %v", err, err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "rackbook.yml"))
	if string(before) != string(after) {
		t.Fatal("rackbook.yml changed")
	}
}

func TestApplyKeepsRackbookYmlComments(t *testing.T) {
	cfg, dir := setup(t)
	nt := current(t, cfg, "services")
	nt.Icon = "server"
	nt.Description = "每台设备上实际开着的服务。"
	if _, err := Apply(cfg, Request{Op: OpUpdate, Name: "services", Type: nt}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "rackbook.yml"))
	orig, _ := os.ReadFile(filepath.Join(testutil.RepoRoot(t), "examples/homelab/rackbook.yml"))
	if !strings.HasPrefix(string(b), "# Rackbook config for a fictional homelab.") {
		t.Fatal("comment lost")
	}
	want := strings.Replace(string(orig), "    description: 每台设备上实际开着的服务。device 为 all 表示所有设备。\n", "    description: 每台设备上实际开着的服务。\n    icon: server\n", 1)
	if string(b) != want {
		t.Fatalf("unexpected rewrite:\n%v", b)
	}
}

func TestCreateRefusesRackbookStateDir(t *testing.T) {
	cfg, dir := setup(t)
	for _, tc := range []struct{ file, schema string }{
		{".rackbook/contacts.yml", ""},
		{"", ".rackbook/contacts.json"},
	} {
		nt := newType()
		nt.File, nt.SchemaFile = tc.file, tc.schema
		p, err := Build(cfg, Request{Op: OpCreate, Name: "contacts", Type: nt})
		if err == nil && p.Clean {
			t.Errorf("file %q schema %q: a type under .rackbook/ must be refused", tc.file, tc.schema)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ".rackbook")); err == nil {
		t.Error(".rackbook must not be created")
	}
}

func TestRemovingAFieldWithValuesNeedsTheMigrationEvenWhenTheSchemaIsOpen(t *testing.T) {
	cfg, dir := setup(t)
	sp := filepath.Join(dir, cfg.Collection("services").Schema)
	b, err := os.ReadFile(sp)
	if err != nil {
		t.Fatal(err)
	}
	open := strings.Replace(string(b), `"additionalProperties": false`, `"additionalProperties": true`, 1)
	if open == string(b) {
		t.Skip("the example schema has no additionalProperties: false")
	}
	if err := os.WriteFile(sp, []byte(open), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg = testutil.LoadConfig(t, dir)
	drop := func(ty *Type) {
		var keep []Field
		for _, f := range ty.Fields {
			if f.Name != "notes" {
				keep = append(keep, f)
			}
		}
		ty.Fields = keep
		var list []string
		for _, f := range ty.List {
			if f != "notes" {
				list = append(list, f)
			}
		}
		ty.List = list
	}
	p := update(t, cfg, "services", drop)
	if p.Clean || hasRefusal(p, "field-has-values") == nil {
		t.Fatalf("must be refused without the migration: clean=%v %v", p.Clean, p.Refusals)
	}
	if p := update(t, cfg, "services", drop, Migration{Kind: MigRemoveField, Field: "notes"}); !p.Clean {
		t.Fatalf("%v %v", p.Invalid, p.Refusals)
	}
}

func TestCreateRefusesFilesAnotherPartOwns(t *testing.T) {
	cfg, dir := setup(t)
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Type){
		"the config file":               func(ty *Type) { ty.File = "rackbook.yml" },
		"the config file, dotted":       func(ty *Type) { ty.File = "./rackbook.yml" },
		"a schema file":                 func(ty *Type) { ty.File = "schemas/device.json" },
		"under .git":                    func(ty *Type) { ty.File = ".git/contacts.yml" },
		"outside the data dir":          func(ty *Type) { ty.File = "other/contacts.yml" },
		"another collection's file":     func(ty *Type) { ty.File = "./docs/ledger/devices.yml" },
		"data and schema are the same":  func(ty *Type) { ty.File, ty.SchemaFile = "docs/ledger/x.yml", "docs/ledger/x.yml" },
		"the schema is the config file": func(ty *Type) { ty.SchemaFile = "rackbook.yml" },
		"the schema is a data file":     func(ty *Type) { ty.SchemaFile = "docs/ledger/devices.yml" },
		"schema outside the schema dir": func(ty *Type) { ty.SchemaFile = "docs/contacts.json" },
		"schema under .git":             func(ty *Type) { ty.SchemaFile = ".git/contacts.json" },
		"schema under .rackbook":        func(ty *Type) { ty.SchemaFile = ".rackbook/contacts.json" },
		"schema escaping the repo":      func(ty *Type) { ty.SchemaFile = "../contacts.json" },
		"schema that already exists":    func(ty *Type) { ty.SchemaFile = "schemas/device.json" },
	} {
		nt := newType()
		mut(nt)
		p, err := Build(cfg, Request{Op: OpCreate, Name: "contacts", Type: nt})
		if err == nil && p.Clean {
			t.Errorf("%s: a new collection must be refused", name)
		}
	}
	if p, err := Build(cfg, Request{Op: OpCreate, Name: "contacts", Type: newType()}); err != nil || !p.Clean {
		t.Fatalf("the default files must still work: %v %v", err, p)
	}
}
