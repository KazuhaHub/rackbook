package types

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/secretscan"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

func labelSetup(t *testing.T) (*config.Config, string) {
	t.Helper()
	dir := testutil.CopyFixture(t, "labels")
	return testutil.LoadConfig(t, dir), dir
}

func readFile(t *testing.T, dir, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func field(ty *Type, name string) *Field { return ty.Field(name) }

func TestReadEnumForms(t *testing.T) {
	t.Parallel()
	cfg, _ := labelSetup(t)
	ty := current(t, cfg, "devices")
	if ty.Title != "设备" || ty.I18n["en-US"]["title"] != "Devices" || ty.I18n["en-US"]["group"] != "Network" || ty.I18n["zh-TW"]["title"] != "設備" {
		t.Fatalf("type i18n: %+v", ty.I18n)
	}
	f := field(ty, "ipv4_type")
	if f.Type != TEnum || f.Advanced || len(f.Extras) != 0 {
		t.Fatalf("oneOf form must be an enum the console edits: %+v", f)
	}
	if f.Title != "IPv4 类型" || f.I18n["en-US"]["title"] != "IPv4 type" || f.I18n["zh-TW"]["title"] != "IPv4 類型" {
		t.Fatalf("field i18n: %+v", f)
	}
	want := []EnumItem{
		{Value: "static", Color: "green", Icon: "pin", Label: "静态", Labels: map[string]string{"en-US": "Static", "zh-TW": "靜態"}},
		{Value: "dynamic", Icon: "refresh-cw", Label: "动态", Labels: map[string]string{"en-US": "Dynamic", "zh-TW": "動態"}},
		{Value: "nat", Label: "NAT", Labels: map[string]string{"en-US": "NAT"}},
	}
	got, _ := json.Marshal(f.Enum)
	exp, _ := json.Marshal(want)
	if string(got) != string(exp) {
		t.Fatalf("items:\n%s\n%s", got, exp)
	}
	st := field(ty, "status")
	if st.Type != TEnum || len(st.Enum) != 2 || st.Enum[0].Label != "" || st.Enum[0].Labels != nil || st.Advanced {
		t.Fatalf("legacy enum: %+v", st)
	}
	// the translations of a property the console does not edit are still read
	if tg := field(ty, "tags"); tg.Type != TAdvanced {
		t.Fatalf("tags: %+v", tg)
	}
	if c := field(ty, "country"); c.Type != TCountry || c.Advanced {
		t.Fatalf("country: %+v", c)
	}
}

func TestEnumAndOneOfTogetherStayAdvanced(t *testing.T) {
	t.Parallel()
	prop := `{"type":"string","enum":["a"],"oneOf":[{"const":"a"}]}`
	v, _ := parseOrdered([]byte(prop))
	f := fieldFromProp("x", v, nil)
	if f.Type != TAdvanced {
		t.Fatalf("%+v", f)
	}
	for _, p := range []string{
		`{"type":"string","oneOf":[{"const":"a","description":"x"}]}`, // another key
		`{"type":"string","oneOf":[{"const":1}]}`,                     // not a string
		`{"type":"string","oneOf":[{"type":"string"}]}`,               // no const
		`{"type":"string","oneOf":[]}`,
	} {
		v, _ := parseOrdered([]byte(p))
		if f := fieldFromProp("x", v, nil); f.Type == TEnum {
			t.Errorf("%s must not be an enum", p)
		}
	}
}

func TestNoChangeIsByteForByte(t *testing.T) {
	t.Parallel()
	cfg, dir := labelSetup(t)
	before := readFile(t, dir, "schemas/device.json")
	cfgBefore := readFile(t, dir, "rackbook.yml")
	p := update(t, cfg, "devices", func(*Type) {})
	if !p.Clean || p.Changed || len(p.Files) != 0 {
		t.Fatalf("%v", p)
	}
	if _, err := Apply(cfg, Request{Op: OpUpdate, Name: "devices", Type: current(t, cfg, "devices")}); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, dir, "schemas/device.json")) != string(before) || string(readFile(t, dir, "rackbook.yml")) != string(cfgBefore) {
		t.Fatal("files changed although nothing did")
	}
}

func TestEditLabelsKeepsOtherKeys(t *testing.T) {
	t.Parallel()
	_, dir := labelSetup(t)
	// an unknown key in a locale object, an unsupported language, and unknown keys on the property
	testutil.Replace(t, dir, "schemas/device.json", `"zh-TW": {"title": "IPv4 類型", "enum"`, `"fr-FR": {"title": "Type IPv4"}, "zh-TW": {"note": "keep me", "title": "IPv4 類型", "enum"`)
	testutil.Replace(t, dir, "schemas/device.json", `"x-rackbook-type": "enum"
    },
    "status"`, `"x-rackbook-type": "enum", "x-extra": {"a": 1}
    },
    "status"`)
	cfg := testutil.LoadConfig(t, dir)
	p := update(t, cfg, "devices", func(ty *Type) {
		f := field(ty, "ipv4_type")
		f.Enum[0].Labels["en-US"] = "Fixed"
		f.Enum[2].Labels["zh-TW"] = "網路位址轉換"
		f.I18n["en-US"]["description"] = "How the address is set"
	})
	if !p.Clean || !p.Changed {
		t.Fatalf("%v", p)
	}
	var doc map[string]any
	if err := json.Unmarshal(p.files["schemas/device.json"], &doc); err != nil {
		t.Fatal(err)
	}
	prop := doc["properties"].(map[string]any)["ipv4_type"].(map[string]any)
	i18n := prop["x-rackbook-i18n"].(map[string]any)
	if i18n["fr-FR"].(map[string]any)["title"] != "Type IPv4" {
		t.Fatalf("unsupported language lost: %v", i18n)
	}
	tw := i18n["zh-TW"].(map[string]any)
	if tw["note"] != "keep me" || tw["enum"].(map[string]any)["nat"] != "網路位址轉換" || tw["enum"].(map[string]any)["static"] != "靜態" {
		t.Fatalf("zh-TW: %v", tw)
	}
	en := i18n["en-US"].(map[string]any)
	if en["enum"].(map[string]any)["static"] != "Fixed" || en["description"] != "How the address is set" || en["title"] != "IPv4 type" {
		t.Fatalf("en-US: %v", en)
	}
	if prop["x-extra"] == nil || prop["x-rackbook-enum-icons"] == nil || prop["x-rackbook-enum-colors"] == nil {
		t.Fatalf("keys lost: %v", prop)
	}
	// the other properties are untouched
	diff := file(p, "schemas/device.json").Diff
	if strings.Contains(diff, "-    \"status\"") || strings.Contains(diff, "-    \"name\"") {
		t.Fatalf("unrelated properties rewritten:\n%s", diff)
	}
}

// Adding labels to a legacy enum writes the oneOf form; removing them again
// returns to the plain enum, in the same place in the property.
func TestSwitchBetweenEnumAndOneOf(t *testing.T) {
	t.Parallel()
	cfg, dir := labelSetup(t)
	orig := readFile(t, dir, "schemas/device.json")
	set := func(mutate func(*Field)) {
		t.Helper()
		nt := current(t, cfg, "devices")
		mutate(field(nt, "status"))
		if _, err := Apply(cfg, Request{Op: OpUpdate, Name: "devices", Type: nt}); err != nil {
			t.Fatal(err)
		}
		cfg = testutil.LoadConfig(t, dir)
	}
	prop := func() map[string]any {
		var doc map[string]any
		if err := json.Unmarshal(readFile(t, dir, "schemas/device.json"), &doc); err != nil {
			t.Fatal(err)
		}
		return doc["properties"].(map[string]any)["status"].(map[string]any)
	}
	// only a language label, no default label: oneOf without titles
	set(func(f *Field) { f.Enum[0].Labels = map[string]string{"en-US": "Up", "zh-TW": "運作中"} })
	p := prop()
	if _, has := p["enum"]; has {
		t.Fatalf("enum must go when oneOf is written: %v", p)
	}
	one := p["oneOf"].([]any)
	if len(one) != 2 || one[0].(map[string]any)["const"] != "up" || one[0].(map[string]any)["title"] != nil || one[1].(map[string]any)["const"] != "down" {
		t.Fatalf("oneOf: %v", one)
	}
	if p["x-rackbook-i18n"].(map[string]any)["en-US"].(map[string]any)["enum"].(map[string]any)["up"] != "Up" {
		t.Fatalf("%v", p)
	}
	// mixed: one item with a default label, one without
	set(func(f *Field) { f.Enum[1].Label = "停止" })
	one = prop()["oneOf"].([]any)
	if one[0].(map[string]any)["title"] != nil || one[1].(map[string]any)["title"] != "停止" {
		t.Fatalf("mixed: %v", one)
	}
	ty := current(t, cfg, "devices")
	if f := field(ty, "status"); f.Type != TEnum || f.Enum[0].Labels["zh-TW"] != "運作中" || f.Enum[1].Label != "停止" || f.Enum[0].Label != "" {
		t.Fatalf("read back: %+v", f)
	}
	// every label removed: back to the plain enum
	set(func(f *Field) {
		for i := range f.Enum {
			f.Enum[i].Label, f.Enum[i].Labels = "", nil
		}
	})
	p = prop()
	if _, has := p["oneOf"]; has {
		t.Fatalf("oneOf must go: %v", p)
	}
	if _, has := p["x-rackbook-i18n"]; has {
		t.Fatalf("empty x-rackbook-i18n must go: %v", p)
	}
	if e, _ := p["enum"].([]any); len(e) != 2 || e[0] != "up" {
		t.Fatalf("%v", p)
	}
	if !sameSchema(orig, readFile(t, dir, "schemas/device.json")) {
		t.Fatalf("a round trip must give the schema back, key order included:\n%s", readFile(t, dir, "schemas/device.json"))
	}
}

func TestIconsAreWrittenAndSwitchedOff(t *testing.T) {
	t.Parallel()
	cfg, _ := labelSetup(t)
	p := update(t, cfg, "devices", func(ty *Type) {
		f := field(ty, "status")
		f.Enum[0].Icon, f.Enum[1].Icon = "circle-check", "circle-x"
	})
	if !p.Clean || !strings.Contains(file(p, "schemas/device.json").Diff, `"x-rackbook-enum-icons": {"up": "circle-check", "down": "circle-x"}`) {
		t.Fatalf("%v", p)
	}
	// icons and labels go when the field stops being an enum
	p = update(t, cfg, "devices", func(ty *Type) {
		f := field(ty, "ipv4_type")
		f.Type, f.Enum = TText, nil
	})
	var doc map[string]any
	_ = json.Unmarshal(p.files["schemas/device.json"], &doc)
	prop := doc["properties"].(map[string]any)["ipv4_type"].(map[string]any)
	for _, k := range []string{"oneOf", "enum", "x-rackbook-enum-icons", "x-rackbook-enum-colors"} {
		if _, has := prop[k]; has {
			t.Errorf("%s must go with the enum type: %v", k, prop)
		}
	}
	tr := prop["x-rackbook-i18n"].(map[string]any)["en-US"].(map[string]any)
	if _, has := tr["enum"]; has || tr["title"] != "IPv4 type" {
		t.Fatalf("title translation stays, enum labels go: %v", tr)
	}
}

func TestPlanRefusesBadTranslations(t *testing.T) {
	t.Parallel()
	cfg, _ := labelSetup(t)
	cases := []struct {
		name   string
		mutate func(*Type)
		want   string
	}{
		{"field language", func(ty *Type) { field(ty, "name").I18n = map[string]map[string]string{"fr-FR": {"title": "Nom"}} }, `"fr-FR" is not a supported language`},
		{"field key", func(ty *Type) { field(ty, "name").I18n = map[string]map[string]string{"en-US": {"group": "x"}} }, `no "group" text`},
		{"enum labels outside the items", func(ty *Type) {
			field(ty, "status").I18n = map[string]map[string]string{"en-US": {"enum": "Up"}}
		}, "give enum labels on the enum items"},
		{"type language", func(ty *Type) { ty.I18n["de-DE"] = map[string]string{"title": "Geräte"} }, `"de-DE" is not a supported language`},
		{"type key", func(ty *Type) { ty.I18n["en-US"]["icon"] = "x" }, `no "icon" text`},
		{"label language", func(ty *Type) { field(ty, "status").Enum[0].Labels = map[string]string{"ja-JP": "稼働"} }, `"ja-JP", which is not a supported language`},
		{"icon shape", func(ty *Type) { field(ty, "status").Enum[0].Icon = "Circle Check" }, "is not an icon name"},
		{"icon underscore", func(ty *Type) { field(ty, "status").Enum[0].Icon = "circle_check" }, "is not an icon name"},
		{"empty code", func(ty *Type) {
			field(ty, "status").Enum = append(field(ty, "status").Enum, EnumItem{Value: "", Labels: map[string]string{"en-US": "Nothing"}})
		}, "non-empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := update(t, cfg, "devices", c.mutate)
			if p.Clean || len(p.Refusals) == 0 {
				t.Fatalf("must be refused: %v", p)
			}
			found := false
			for _, r := range p.Refusals {
				found = found || strings.Contains(r.Message, c.want)
			}
			if !found {
				t.Fatalf("want %q in %v", c.want, p.Refusals)
			}
		})
	}
	// empty strings are not translations: they are dropped, not refused
	p := update(t, cfg, "devices", func(ty *Type) {
		field(ty, "name").I18n = map[string]map[string]string{"en-US": {"title": ""}, "fr-FR": {"title": " "}}
	})
	if !p.Clean {
		t.Fatalf("%v", p)
	}
}

func TestTypeTranslationsInRackbookYml(t *testing.T) {
	t.Parallel()
	cfg, dir := labelSetup(t)
	p := update(t, cfg, "devices", func(ty *Type) {
		ty.I18n["en-US"]["title"] = "Machines"
		ty.I18n["zh-TW"]["group"] = "網路"
	})
	if !p.Clean {
		t.Fatalf("%v", p)
	}
	d := file(p, "rackbook.yml").Diff
	if !strings.Contains(d, "+      en-US: {title: Machines, description: All devices, group: Network}") && !strings.Contains(d, "+    i18n: {") {
		t.Fatalf("%s", d)
	}
	if _, err := Apply(cfg, Request{Op: OpUpdate, Name: "devices", Type: func() *Type {
		ty := current(t, cfg, "devices")
		ty.I18n["en-US"]["title"] = "Machines"
		ty.I18n["zh-TW"]["group"] = "網路"
		return ty
	}()}); err != nil {
		t.Fatal(err)
	}
	cfg2 := testutil.LoadConfig(t, dir)
	c := cfg2.Collection("devices")
	if c.I18n["en-US"]["title"] != "Machines" || c.I18n["zh-TW"]["group"] != "網路" || c.Title != "设备" {
		t.Fatalf("%+v", c.I18n)
	}
	// removing every translation removes the key
	p = update(t, cfg2, "devices", func(ty *Type) { ty.I18n = map[string]map[string]string{} })
	if !p.Clean || strings.Contains(string(p.files["rackbook.yml"]), "Machines") || strings.Count(string(p.files["rackbook.yml"]), "i18n:") != 3 {
		t.Fatalf("%s", p.files["rackbook.yml"])
	}
	// the version covers the translations
	a, b := current(t, cfg, "devices"), current(t, cfg2, "devices")
	if a.Version == b.Version {
		t.Fatal("the version must change with the translations")
	}
}

func TestNewTypeWithTranslations(t *testing.T) {
	t.Parallel()
	cfg, dir := labelSetup(t)
	nt := &Type{Name: "sites", Title: "站点", I18n: map[string]map[string]string{"en-US": {"title": "Sites", "group": "Places"}},
		Fields: []Field{
			{Name: "code", Type: TText, Title: "代码", I18n: map[string]map[string]string{"en-US": {"title": "Code"}}, Required: true},
			{Name: "country", Type: TCountry},
			{Name: "region", Type: TSubdivision},
			{Name: "kind", Type: TEnum, Enum: []EnumItem{{Value: "dc", Label: "机房", Labels: map[string]string{"en-US": "Data centre"}, Icon: "server"}, {Value: "home", Label: "家"}}},
		}, Key: []string{"code"}}
	if _, err := Apply(cfg, Request{Op: OpCreate, Name: "sites", Type: nt}); err != nil {
		t.Fatal(err)
	}
	cfg2 := testutil.LoadConfig(t, dir)
	if got := cfg2.Collection("sites"); got.I18n["en-US"]["title"] != "Sites" || got.I18n["en-US"]["group"] != "Places" {
		t.Fatalf("%+v", got)
	}
	raw := string(readFile(t, dir, "schemas/sites.json"))
	for _, want := range []string{`"format": "country"`, `"format": "subdivision"`, `"x-rackbook-type": "country"`, `"x-rackbook-type": "subdivision"`, `"oneOf"`, `"x-rackbook-enum-icons": {"dc": "server"}`, `"x-rackbook-i18n": {"en-US": {"title": "Code"}}`} {
		if !strings.Contains(raw, want) {
			t.Errorf("schema lacks %s:\n%s", want, raw)
		}
	}
	back := current(t, cfg2, "sites")
	if f := field(back, "country"); f.Type != TCountry || f.Advanced {
		t.Fatalf("%+v", f)
	}
	if f := field(back, "region"); f.Type != TSubdivision {
		t.Fatalf("%+v", f)
	}
	if f := field(back, "kind"); f.Type != TEnum || f.Enum[0].Labels["en-US"] != "Data centre" || f.Enum[1].Label != "家" {
		t.Fatalf("%+v", f)
	}
	if ft := FieldTypes; ft[10] != THostname || ft[11] != TCountry || ft[12] != TSubdivision {
		t.Fatalf("country and subdivision go after hostname: %v", ft)
	}
}

func TestSecretInTranslationIsRefused(t *testing.T) {
	t.Parallel()
	cfg, _ := labelSetup(t)
	const secret = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
	for name, mutate := range map[string]func(*Type){
		"field title":  func(ty *Type) { field(ty, "name").I18n = map[string]map[string]string{"en-US": {"title": secret}} },
		"enum label":   func(ty *Type) { field(ty, "status").Enum[0].Labels = map[string]string{"en-US": secret} },
		"type title":   func(ty *Type) { ty.I18n["en-US"]["title"] = secret },
		"type comment": func(ty *Type) { ty.I18n["zh-TW"]["description"] = "token " + secret },
	} {
		nt := current(t, cfg, "devices")
		mutate(nt)
		_, err := Apply(cfg, Request{Op: OpUpdate, Name: "devices", Type: nt})
		var se *secretscan.Error
		if err == nil || !errors.As(err, &se) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A reference rule's translations survive a type edit that does not mention
// them, and can be changed through Ref.I18n.
func TestRefRuleTranslations(t *testing.T) {
	t.Parallel()
	cfg, dir := labelSetup(t)
	ty := current(t, cfg, "devices")
	owner := field(ty, "owner")
	if owner.Type != TRef || owner.Ref.I18n["en-US"]["message"] != "Unknown owner" || owner.Ref.I18n["en-US"]["backref_title"] != "Devices owned" {
		t.Fatalf("%+v", owner.Ref)
	}
	// a request that leaves ref.i18n out (an older client) keeps the rule as it is
	p := update(t, cfg, "devices", func(ty *Type) {
		field(ty, "owner").Ref.I18n = nil
		field(ty, "owner").Title = "负责人"
	})
	if !p.Clean || file(p, "rackbook.yml") != nil {
		t.Fatalf("the rule must be untouched: %v", p)
	}
	p = update(t, cfg, "devices", func(ty *Type) {
		field(ty, "owner").Ref.I18n["zh-TW"] = map[string]string{"message": "負責人不存在"}
	})
	d := file(p, "rackbook.yml").Diff
	if !p.Clean || !strings.Contains(d, "i18n: {zh-TW: {message: 負責人不存在}, en-US: {message: Unknown owner, backref_title: Devices owned}}") {
		t.Fatalf("%v\n%s", p, d)
	}
	if _, err := Apply(cfg, Request{Op: OpUpdate, Name: "devices", Type: func() *Type {
		ty := current(t, cfg, "devices")
		field(ty, "owner").Ref.I18n["zh-TW"] = map[string]string{"message": "負責人不存在"}
		return ty
	}()}); err != nil {
		t.Fatal(err)
	}
	r := testutil.LoadConfig(t, dir).Rules[0].Ref
	if r.I18n["zh-TW"]["message"] != "負責人不存在" || r.I18n["en-US"]["backref_title"] != "Devices owned" {
		t.Fatalf("%+v", r.I18n)
	}
	// an explicit empty value removes the translations
	p = update(t, cfg, "devices", func(ty *Type) { field(ty, "owner").Ref.I18n = map[string]map[string]string{} })
	if !p.Clean || strings.Contains(file(p, "rackbook.yml").Diff, "+  - ref: {from: devices.owner, to: people.name, backref_title: 名下设备, message: 负责人不存在, i18n") {
		t.Fatalf("%s", file(p, "rackbook.yml").Diff)
	}
}

// An existing x-rackbook-i18n the console cannot read is kept, and a request
// that would write translations next to it is refused, not silently dropped.
func TestMalformedI18nRefusesNewTranslations(t *testing.T) {
	t.Parallel()
	_, dir := labelSetup(t)
	testutil.Replace(t, dir, "schemas/device.json", `"x-rackbook-i18n": {"en-US": {"title": "Name"}}`, `"x-rackbook-i18n": {"en-US": {"title": 5}}`)
	cfg := testutil.LoadConfig(t, dir)
	if f := field(current(t, cfg, "devices"), "name"); !hasExtra(f.Extras, kwI18n) || f.I18n != nil {
		t.Fatalf("%+v", f)
	}
	p := update(t, cfg, "devices", func(*Type) {})
	if !p.Clean || p.Changed {
		t.Fatalf("untouched stays untouched: %v", p)
	}
	p = update(t, cfg, "devices", func(ty *Type) {
		field(ty, "name").I18n = map[string]map[string]string{"en-US": {"title": "Nom"}}
	})
	if p.Clean || hasRefusal(p, "invalid") == nil || !strings.Contains(p.Refusals[0].Message, "x-rackbook-i18n on name is not in the expected shape; fix it in the schema file or remove it") {
		t.Fatalf("%v", p)
	}
	// other edits of that field are fine and keep the odd value as written
	p = update(t, cfg, "devices", func(ty *Type) { field(ty, "name").Title = "名字" })
	if !p.Clean || !strings.Contains(string(p.files["schemas/device.json"]), `"title": 5`) {
		t.Fatalf("%v", p)
	}
	// enum labels on a field whose i18n is malformed are refused too
	testutil.Replace(t, dir, "schemas/device.json", `"zh-TW": {"title": "IPv4 類型", "enum": {"static": "靜態", "dynamic": "動態"}}`, `"zh-TW": 7`)
	cfg = testutil.LoadConfig(t, dir)
	p = update(t, cfg, "devices", func(ty *Type) { field(ty, "ipv4_type").Enum[0].Labels = map[string]string{"zh-TW": "靜態"} })
	if p.Clean {
		t.Fatalf("%v", p)
	}
}

// x-rackbook-i18n keys the editor does not manage for a field type are never deleted.
func TestHandWrittenEnumLabelsOnOtherTypesSurvive(t *testing.T) {
	t.Parallel()
	_, dir := labelSetup(t)
	testutil.Replace(t, dir, "schemas/device.json", `"owner": {"type": "string"}`, `"owner": {"type": "string"},
    "legacy": {"type": "string", "oneOf": [{"const": "a", "description": "x"}], "x-rackbook-i18n": {"en-US": {"enum": {"a": "A"}, "title": "Old"}}}`)
	cfg := testutil.LoadConfig(t, dir)
	p := update(t, cfg, "devices", func(ty *Type) {
		f := field(ty, "legacy")
		f.Title = "旧"
		f.I18n = map[string]map[string]string{"en-US": {"title": "Legacy"}}
	})
	if !p.Clean || !p.Changed {
		t.Fatalf("%v", p)
	}
	var doc map[string]any
	_ = json.Unmarshal(p.files["schemas/device.json"], &doc)
	en := doc["properties"].(map[string]any)["legacy"].(map[string]any)["x-rackbook-i18n"].(map[string]any)["en-US"].(map[string]any)
	if en["enum"].(map[string]any)["a"] != "A" || en["title"] != "Legacy" {
		t.Fatalf("%v", en)
	}
}

// Translations left out of a request are kept; an empty object clears them.
func TestOmittedTranslationsAreKept(t *testing.T) {
	t.Parallel()
	cfg, _ := labelSetup(t)
	p := update(t, cfg, "devices", func(ty *Type) {
		ty.I18n = nil
		field(ty, "name").I18n = nil
		field(ty, "ipv4_type").I18n = nil
		ty.Description = "改"
	})
	if !p.Clean {
		t.Fatalf("%v", p)
	}
	for _, line := range strings.Split(file(p, "rackbook.yml").Diff, "\n") {
		if strings.HasPrefix(line, "-") && strings.Contains(line, "i18n") && !strings.HasPrefix(line, "---") {
			t.Fatalf("collection i18n lost:\n%s", file(p, "rackbook.yml").Diff)
		}
	}
	if file(p, "schemas/device.json") != nil {
		t.Fatalf("field translations lost:\n%s", file(p, "schemas/device.json").Diff)
	}
	if got := p.Type.I18n["en-US"]["title"]; got != "Devices" {
		t.Fatalf("%v", p.Type.I18n)
	}
	p = update(t, cfg, "devices", func(ty *Type) {
		ty.I18n = map[string]map[string]string{}
		field(ty, "name").I18n = map[string]map[string]string{}
	})
	if !p.Clean || !p.Changed || strings.Contains(string(p.files["rackbook.yml"]), "title: Devices,") || strings.Contains(string(p.files["schemas/device.json"]), `"title": "Name"`) {
		t.Fatalf("an empty object must clear:\n%v", p.Files)
	}
}

func TestPlanRefusesLabelClashesAndLongIcons(t *testing.T) {
	t.Parallel()
	cfg, _ := labelSetup(t)
	cases := []struct {
		name   string
		mutate func(*Field)
		want   string
	}{
		{"same default label", func(f *Field) { f.Enum[0].Label, f.Enum[1].Label = "X", "X" }, `used for both`},
		{"same label in a language", func(f *Field) {
			f.Enum[0].Labels = map[string]string{"en-US": "Same"}
			f.Enum[1].Labels = map[string]string{"en-US": "Same"}
		}, `used for both`},
		{"label is another code", func(f *Field) { f.Enum[0].Label = "down" }, "code of another value"},
		{"icon too long", func(f *Field) { f.Enum[0].Icon = strings.Repeat("a", 65) }, "is not an icon name"},
	}
	for _, c := range cases {
		p := update(t, cfg, "devices", func(ty *Type) { c.mutate(field(ty, "status")) })
		if p.Clean || !strings.Contains(p.String(), c.want) {
			t.Errorf("%s: %v", c.name, p.Refusals)
		}
	}
	// the same label in different languages is fine, and a label equal to its own code too
	p := update(t, cfg, "devices", func(ty *Type) {
		f := field(ty, "status")
		f.Enum[0].Label, f.Enum[0].Labels = "up", map[string]string{"en-US": "Up"}
		f.Enum[1].Labels = map[string]string{"zh-TW": "Up"}
	})
	if !p.Clean {
		t.Fatalf("%v", p.Refusals)
	}
	if p := update(t, cfg, "devices", func(ty *Type) { field(ty, "status").Enum[0].Icon = strings.Repeat("a", 64) }); !p.Clean {
		t.Fatalf("64 characters are allowed: %v", p.Refusals)
	}
}

// A malformed x-rackbook-i18n on one field blocks only changes of that field's
// translations, not other edits of the type, and the oneOf titles never count.
func TestMalformedI18nDoesNotBlockOtherEdits(t *testing.T) {
	t.Parallel()
	_, dir := labelSetup(t)
	testutil.Replace(t, dir, "schemas/device.json", `"zh-TW": {"title": "IPv4 類型", "enum": {"static": "靜態", "dynamic": "動態"}}`, `"zh-TW": 7`)
	cfg := testutil.LoadConfig(t, dir)
	// the malformed field has oneOf titles; renaming another field, and editing that field's title, are fine
	p := update(t, cfg, "devices", func(ty *Type) {
		field(ty, "name").Title = "名字"
		field(ty, "ipv4_type").Title = "类型"
		field(ty, "ipv4_type").Enum[2].Label = "地址转换"
	})
	if !p.Clean || !p.Changed {
		t.Fatalf("%v", p.Refusals)
	}
	// changing its translations is refused
	p = update(t, cfg, "devices", func(ty *Type) { field(ty, "ipv4_type").I18n = map[string]map[string]string{"en-US": {"title": "x"}} })
	if p.Clean {
		t.Fatal("must be refused")
	}
}

// Label clashes are checked for fields whose choices changed, not for every field.
func TestLabelClashesOnlyForChangedFields(t *testing.T) {
	t.Parallel()
	_, dir := labelSetup(t)
	testutil.Replace(t, dir, "schemas/device.json", `{"const": "dynamic", "title": "动态"}`, `{"const": "dynamic", "title": "静态"}`)
	cfg := testutil.LoadConfig(t, dir)
	p := update(t, cfg, "devices", func(ty *Type) { field(ty, "name").Title = "名字" })
	if !p.Clean || !p.Changed {
		t.Fatalf("an unrelated edit must not be blocked: %v", p.Refusals)
	}
	p = update(t, cfg, "devices", func(ty *Type) { field(ty, "ipv4_type").Enum[2].Label = "别的" })
	if p.Clean {
		t.Fatal("touching the clashing field's choices is checked")
	}
}
