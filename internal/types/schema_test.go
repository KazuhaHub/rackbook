package types

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/config"
)

func ip(i int) *int            { return &i }
func fp(f float64) *float64    { return &f }
func num(s string) json.Number { return json.Number(s) }

// one field of every console type, with the options the type has
func allFields() []Field {
	return []Field{
		{Name: "name", Title: "名称", Type: TText, Required: true, MinLength: ip(1), MaxLength: ip(40), Pattern: "^[a-z]+$", Examples: []string{"a", "b"}},
		{Name: "notes", Title: "备注", Type: TTextarea},
		{Name: "count", Title: "数量", Type: TInteger, Min: fp(0), Max: fp(100), Default: num("5")},
		{Name: "ratio", Type: TNumber, Min: fp(0.5), Max: fp(9.5)},
		{Name: "addr", Type: TIP, Description: "地址"},
		{Name: "v4", Type: TIPv4},
		{Name: "v6", Type: TIPv6},
		{Name: "net", Type: TCIDR},
		{Name: "port", Type: TPort},
		{Name: "listen", Type: TPortSpec},
		{Name: "host", Type: THostname},
		{Name: "link", Type: TURL},
		{Name: "status", Type: TEnum, Enum: []EnumItem{{Value: "up", Color: "green"}, {Value: "down"}}, Default: "up"},
		{Name: "managed", Type: TBool, Default: false},
		{Name: "since", Type: TDate},
		{Name: "owner", Type: TRef, Ref: &Ref{To: "people", ToField: "name", Allow: []string{"all"}, BackrefTitle: "拥有的"}},
		{Name: "tags", Type: TRef, Ref: &Ref{To: "people", ToField: "name", Many: true, BackrefColumns: []string{"name"}}},
	}
}

func roundTripType() *Type {
	return &Type{Name: "things", Title: "东西", Description: "d", Group: "g", Icon: "box", File: "docs/things.yml", SchemaFile: "schemas/things.json",
		Key: []string{"name"}, Label: "name", List: []string{"name", "status"}, Facets: []config.Facet{{Field: "status", Match: "exact"}},
		Fields: allFields(), Unique: [][]string{}}
}

func TestSchemaRoundTripEveryFieldType(t *testing.T) {
	t.Parallel()
	want := roundTripType()
	want.Fields[0].Unique = true
	raw, err := applySchema(nil, nil, want)
	if err != nil {
		t.Fatal(err)
	}
	col := &config.Collection{Name: "things", Title: "东西", Description: "d", Group: "g", Icon: "box", File: "docs/things.yml", Schema: "schemas/things.json",
		Key: []string{"name"}, Label: "name", List: []string{"name", "status"}, Facets: []config.Facet{{Field: "status", Match: "exact"}}}
	got, err := ParseType(col, raw, want.Rules(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Fields) != len(want.Fields) {
		t.Fatalf("fields: %d != %d\n%s", len(got.Fields), len(want.Fields), raw)
	}
	for i := range want.Fields {
		if !reflect.DeepEqual(got.Fields[i], want.Fields[i]) {
			t.Errorf("field %s:\n got %+v\nwant %+v", want.Fields[i].Name, got.Fields[i], want.Fields[i])
		}
	}
	if !reflect.DeepEqual(got.Rules(), want.Rules()) {
		t.Errorf("rules differ: %+v vs %+v", got.Rules(), want.Rules())
	}
	// the JSON Schema itself carries the meaning
	s := string(raw)
	for _, frag := range []string{`"format": "ipv4"`, `"format": "cidr"`, `"format": "port-spec"`, `"format": "uri"`, `"format": "date"`, `"format": "textarea"`, `"minimum": 1, "maximum": 65535`, `"enum": ["up", "down"]`, `"x-rackbook-type": "port"`, `"type": "array"`} {
		if !strings.Contains(s, frag) {
			t.Errorf("schema lacks %s:\n%s", frag, s)
		}
	}
	// writing again is stable
	again, _ := applySchema(raw, got, got)
	if string(again) != string(raw) {
		t.Errorf("rewrite is not stable:\n%s\n%s", raw, again)
	}
}

func TestParseKeepsUnknownKeywordsAndMarksAdvanced(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "X",
  "type": "object",
  "x-custom": {"a": 1},
  "required": ["a"],
  "properties": {
    "a": {"type": "string", "title": "A", "format": "email", "x-flag": true},
    "b": {"type": ["string", "null"]},
    "c": {"type": "string", "minLength": 2, "contentMediaType": "text/plain"},
    "d": {"type": "object", "properties": {"z": {"type": "string"}}}
  }
}
`)
	col := &config.Collection{Name: "x", Title: "X", File: "f.yml", Schema: "s.json"}
	ty, err := ParseType(col, raw, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ty.Extras) != 1 || ty.Extras[0].Key != "x-custom" {
		t.Fatalf("top-level extras: %+v", ty.Extras)
	}
	a, b, c, d := ty.Fields[0], ty.Fields[1], ty.Fields[2], ty.Fields[3]
	if a.Type != TText || !a.Advanced || len(a.Extras) != 2 {
		t.Errorf("a: %+v", a)
	}
	if b.Type != TAdvanced || !b.Advanced {
		t.Errorf("b: %+v", b)
	}
	if c.Type != TText || c.MinLength == nil || len(c.Extras) != 1 || c.Extras[0].Key != "contentMediaType" {
		t.Errorf("c: %+v", c)
	}
	if d.Type != TAdvanced {
		t.Errorf("d: %+v", d)
	}
	// an edit keeps the keywords the console does not know, and untouched properties byte for byte
	nt := *ty
	nt.Fields = append([]Field(nil), ty.Fields...)
	nt.Fields[2].MinLength = ip(3)
	out, err := applySchema(raw, ty, &nt)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, frag := range []string{`"x-custom": {"a": 1}`, `"contentMediaType": "text/plain"`, `"minLength": 3`, `"b": {"type": ["string", "null"]}`, `"a": {"type": "string", "title": "A", "format": "email", "x-flag": true}`} {
		if !strings.Contains(s, frag) {
			t.Errorf("lost %s:\n%s", frag, s)
		}
	}
}

func TestSchemaTypeChangeDropsOldTypeKeywords(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"type": "object", "properties": {"a": {"type": "string", "pattern": "^x", "title": "A", "examples": ["x"]}}}` + "\n")
	col := &config.Collection{Name: "x", File: "f", Schema: "s"}
	ty, _ := ParseType(col, raw, nil, 0)
	nt := *ty
	nt.Fields = []Field{{Name: "a", Title: "A", Type: TIPv4}}
	out, err := applySchema(raw, ty, &nt)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "pattern") || strings.Contains(s, "examples") || !strings.Contains(s, `"format": "ipv4"`) {
		t.Fatalf("%s", s)
	}
}

func TestFormatSchemaStyle(t *testing.T) {
	t.Parallel()
	raw := []byte("{\n  \"$schema\": \"x\",\n  \"required\": [\"a\", \"b\"],\n  \"properties\": {\n    \"a\": {\"type\": \"string\", \"title\": \"设备\"},\n    \"b\": {\"type\": \"boolean\", \"default\": false}\n  }\n}\n")
	v, err := parseOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(formatSchema(v.(*omap))); got != string(raw) {
		t.Fatalf("got:\n%s\nwant:\n%s", got, raw)
	}
}

// The console renders arrays of enum values (tags) and arrays of pattern-checked
// strings (port lists) and reads `x-rackbook` options such as suggest. The type
// editor has no field type for them: they are advanced fields, kept as they are,
// and an edit of another field leaves them byte for byte.
func TestArrayFieldsAndConsoleOptionsSurviveATypeEdit(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "type": "object",
  "required": ["name"],
  "properties": {
    "name": {"type": "string", "title": "名称", "x-rackbook": {"suggest": false}},
    "exposure": {"type": "array", "title": "开放范围", "uniqueItems": true, "items": {"type": "string", "enum": ["公网", "Tailscale"]}},
    "ports": {"type": "array", "title": "端口", "items": {"type": "string", "pattern": "^[0-9]{1,5}(-[0-9]{1,5})?$"}}
  }
}
`)
	col := &config.Collection{Name: "x", File: "f", Schema: "s"}
	ty, err := ParseType(col, raw, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	name, exposure, ports := ty.Fields[0], ty.Fields[1], ty.Fields[2]
	if name.Type != TText || !name.Advanced || len(name.Extras) != 1 || name.Extras[0].Key != "x-rackbook" {
		t.Errorf("name: %+v", name)
	}
	if exposure.Type != TAdvanced || ports.Type != TAdvanced {
		t.Errorf("array fields should be advanced: %+v %+v", exposure, ports)
	}
	nt := *ty
	nt.Fields = append([]Field(nil), ty.Fields...)
	nt.Fields[0].Title = "名字"
	out, err := applySchema(raw, ty, &nt)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, frag := range []string{
		`"title": "名字"`,
		`"x-rackbook": {"suggest": false}`,
		`"exposure": {"type": "array", "title": "开放范围", "uniqueItems": true, "items": {"type": "string", "enum": ["公网", "Tailscale"]}}`,
		`"ports": {"type": "array", "title": "端口", "items": {"type": "string", "pattern": "^[0-9]{1,5}(-[0-9]{1,5})?$"}}`,
	} {
		if !strings.Contains(s, frag) {
			t.Errorf("lost %s:\n%s", frag, s)
		}
	}
}
