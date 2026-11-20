package labels

import (
	"encoding/json"
	"reflect"
	"testing"
)

func prop(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

const oneOf = `{"type":"string","title":"类型","description":"d",
 "oneOf":[{"const":"static","title":"静态"},{"const":"dynamic","title":"动态"},{"const":"nat"}],
 "x-rackbook-i18n":{"en-US":{"title":"Type","description":"about","enum":{"static":"Static","gone":"Removed"}},"zh-TW":{"enum":{"static":"靜態"}},"fr-FR":{"title":"Type","enum":{"static":"Statique"}}},
 "x-rackbook-enum-icons":{"static":"pin","nat":"network","gone":"x"}}`

func TestParseOneOfForm(t *testing.T) {
	e, ok := Parse(prop(t, oneOf))
	if !ok || !e.OneOf {
		t.Fatal("oneOf form must parse")
	}
	if !reflect.DeepEqual(e.Codes(), []string{"static", "dynamic", "nat"}) {
		t.Fatal(e.Codes())
	}
	for _, c := range []struct{ loc, code, want string }{
		{"zh-CN", "static", "静态"},     // the default-language label is the oneOf title
		{"en-US", "static", "Static"}, // the extension wins
		{"zh-TW", "static", "靜態"},
		{"zh-TW", "dynamic", "动态"}, // no zh-TW entry: the standard title
		{"en-US", "nat", "nat"},    // no title anywhere: the code
		{"fr-FR", "static", "静态"},  // an unsupported language is ignored
		{"en-US", "gone", "gone"},  // labels of codes outside the enum are ignored; unknown code is itself
	} {
		if got := e.Label(c.loc, c.code); got != c.want {
			t.Errorf("Label(%s,%s) = %q, want %q", c.loc, c.code, got, c.want)
		}
	}
	if it, _ := e.Item("static"); it.Icon != "pin" {
		t.Fatal(it)
	}
	if it, _ := e.Item("nat"); it.Icon != "network" {
		t.Fatal(it)
	}
	if _, ok := e.Item("gone"); ok {
		t.Fatal("icons of unknown codes are ignored")
	}
}

func TestParseLegacyEnumAndForms(t *testing.T) {
	e, ok := Parse(prop(t, `{"type":"string","enum":["a","b"]}`))
	if !ok || e.OneOf || e.Label("en-US", "a") != "a" {
		t.Fatal("legacy enum")
	}
	if _, ok := Parse(prop(t, `{"type":["string","null"],"enum":["a"]}`)); !ok {
		t.Fatal("string or null is enum-like")
	}
	for _, s := range []string{
		`{"type":"integer","enum":[1]}`, `{"type":"string","enum":["a",1]}`, `{"type":"string"}`, `{"enum":["a"]}`,
		`{"type":"string","oneOf":[{"const":"a","x":1}]}`, `{"type":"string","oneOf":[{"const":2}]}`, `{"type":"string","oneOf":[{"title":"t"}]}`,
		`{"type":"string","oneOf":[{"const":"a","title":3}]}`, `{"type":"string","oneOf":[]}`, `{"type":"string","oneOf":"x"}`,
		`{"type":["string","integer"],"enum":["a"]}`,
	} {
		if _, ok := Parse(prop(t, s)); ok {
			t.Errorf("%s must not be enum-like", s)
		}
	}
}

func TestMatchAndText(t *testing.T) {
	e, _ := Parse(prop(t, oneOf))
	for _, c := range []struct {
		in, code string
		exact    bool
		ok       bool
	}{
		{"static", "static", true, true}, {"静态", "static", false, true}, {"Static", "static", false, true}, {"靜態", "static", false, true},
		{"NAT", "nat", false, true}, {"DYNAMIC", "dynamic", false, true}, {"Statique", "", false, false}, {"xyz", "", false, false},
	} {
		code, exact, ok := e.Match(c.in)
		if code != c.code || exact != c.exact || ok != c.ok {
			t.Errorf("Match(%q) = %q %v %v", c.in, code, exact, ok)
		}
	}
	p := prop(t, oneOf)
	if Text(p, "en-US", "title") != "Type" || Text(p, "zh-TW", "title") != "类型" || Text(p, "zh-CN", "description") != "d" || Text(p, "en-US", "description") != "about" {
		t.Fatal("Text")
	}
	if Title(prop(t, `{"type":"string"}`), "en-US", "fallback") != "fallback" {
		t.Fatal("Title falls back to the name")
	}
	if tr := Translations(p); len(tr) != 1 || tr["en-US"]["title"] != "Type" {
		t.Fatalf("%v", tr)
	}
}

func TestPropertyFollowsItemsAndRows(t *testing.T) {
	schema := prop(t, `{"properties":{"tags":{"type":"array","items":{"type":"string","enum":["a"]}},
	 "rows":{"type":"array","items":{"type":"object","properties":{"k":{"type":"string","enum":["x"]}}}}}}`)
	if Property(schema, []string{"tags", "0"})["enum"] == nil || Property(schema, []string{"rows", "3", "k"})["enum"] == nil {
		t.Fatal("items and row properties")
	}
	if Property(schema, []string{"nope"}) != nil || Property(schema, []string{"tags", "x"}) != nil || Property(schema, nil) == nil {
		t.Fatal("unresolvable paths")
	}
	if !ValidIcon("circle-check") || !ValidIcon("clock") || !ValidIcon("a1") || ValidIcon("Circle") || ValidIcon("a_b") || ValidIcon("-a") || ValidIcon("a--b") || ValidIcon("") {
		t.Fatal("icon shape")
	}
}
