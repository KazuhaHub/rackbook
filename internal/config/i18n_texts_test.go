package config

import (
	"strings"
	"testing"
)

func TestI18nTexts(t *testing.T) {
	src := `
title: 台账
description: 说明
i18n:
  default: zh-CN
  en-US: {title: Ledger, description: About}
  zh-TW: {title: 台賬}
collections:
  devices:
    title: 设备
    group: 网段
    file: d.yml
    schema: d.json
    i18n:
      en-US: {title: Devices, description: Hosts, group: Networks}
notes:
  - title: 规则
    file: d.yml
    path: note
    i18n: {en-US: {title: Rule}}
rules:
  - ref: {from: devices.a, to: devices.b, message: 引用, backref_title: 反向, i18n: {en-US: {message: Reference, backref_title: Back}}}
  - same_set: {left: {collection: devices, field: a}, right: {file: d.yml, path: x}, message: 一致, i18n: {en-US: {message: Same}}}
`
	c, err := Parse([]byte(src), "/r/rackbook.yml")
	if err != nil {
		t.Fatal(err)
	}
	if c.DefaultLocale() != "zh-CN" {
		t.Fatal(c.DefaultLocale())
	}
	col := c.Collections[0]
	in := func(t Texts, loc, key, std string) string {
		if s := t[loc][key]; s != "" {
			return s
		}
		return std
	}
	for _, tc := range []struct{ got, want string }{
		{in(c.I18n.Texts, "en-US", "title", c.Title), "Ledger"}, {in(c.I18n.Texts, "zh-TW", "title", c.Title), "台賬"}, {in(c.I18n.Texts, "zh-CN", "title", c.Title), "台账"},
		{in(c.I18n.Texts, "en-US", "description", c.Description), "About"}, {in(c.I18n.Texts, "zh-TW", "description", c.Description), "说明"}, // falls back to the standard text
		{in(col.I18n, "en-US", "title", col.Title), "Devices"}, {in(col.I18n, "zh-TW", "title", col.Title), "设备"}, {in(col.I18n, "en-US", "group", col.Group), "Networks"},
		{in(col.I18n, "en-US", "description", col.Description), "Hosts"}, {in(col.I18n, "zh-TW", "group", col.Group), "网段"},
		{in(c.Notes[0].I18n, "en-US", "title", c.Notes[0].Title), "Rule"}, {in(c.Notes[0].I18n, "zh-TW", "title", c.Notes[0].Title), "规则"},
		{in(c.Rules[0].Ref.I18n, "en-US", "message", c.Rules[0].Ref.Message), "Reference"}, {in(c.Rules[0].Ref.I18n, "en-US", "backref_title", c.Rules[0].Ref.BackrefTitle), "Back"}, {in(c.Rules[0].Ref.I18n, "zh-TW", "message", c.Rules[0].Ref.Message), "引用"},
		{in(c.Rules[1].SameSet.I18n, "en-US", "message", c.Rules[1].SameSet.Message), "Same"}, {in(c.Rules[1].SameSet.I18n, "zh-CN", "message", c.Rules[1].SameSet.Message), "一致"},
	} {
		if tc.got != tc.want {
			t.Errorf("got %q, want %q", tc.got, tc.want)
		}
	}
}

func TestI18nTextsErrors(t *testing.T) {
	base := "collections:\n  a: {file: a.yml, schema: a.json%s}\n"
	for name, c := range map[string]struct{ yaml, want string }{
		"top-level language":  {"i18n: {fr-FR: {title: x}}\n" + strings.Replace(base, "%s", "", 1), "i18n.fr-FR"},
		"top-level key":       {"i18n: {en-US: {titel: x}}\n" + strings.Replace(base, "%s", "", 1), `unknown key "titel"`},
		"top-level not text":  {"i18n: {en-US: [x]}\n" + strings.Replace(base, "%s", "", 1), "i18n.en-US"},
		"collection language": {strings.Replace(base, "%s", ", i18n: {de-DE: {title: x}}", 1), "collections.a.i18n.de-DE"},
		"collection key":      {strings.Replace(base, "%s", ", i18n: {en-US: {icon: x}}", 1), `unknown key "icon"`},
		"note key":            {strings.Replace(base, "%s", "", 1) + "notes:\n  - {title: n, file: a.yml, path: p, i18n: {en-US: {text: x}}}\n", `unknown key "text"`},
		"ref key":             {strings.Replace(base, "%s", "", 1) + "rules:\n  - ref: {from: a.x, to: a.y, i18n: {en-US: {title: x}}}\n", `unknown key "title"`},
		"same_set key":        {strings.Replace(base, "%s", "", 1) + "rules:\n  - same_set: {left: {collection: a, field: x}, right: {file: a.yml, path: p}, i18n: {en-US: {backref_title: x}}}\n", `unknown key "backref_title"`},
	} {
		if _, err := Parse([]byte(c.yaml), "/r/rackbook.yml"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A file without any i18n text behaves as before.
	c, err := Parse([]byte(strings.Replace(base, "%s", "", 1)), "/r/rackbook.yml")
	if err != nil || c.Collections[0].I18n != nil {
		t.Fatalf("%v %v", err, c)
	}
}

func TestI18nShapeErrors(t *testing.T) {
	base := "collections:\n  a: {file: a.yml, schema: a.json}\n"
	for name, c := range map[string]struct{ yaml, want string }{
		"language is text":       {"i18n: {en-US: \"text\"}\n" + base, "i18n.en-US must be a mapping of text"},
		"language is a list":     {"i18n: {en-US: [a]}\n" + base, "not a list"},
		"value is a mapping":     {"i18n: {en-US: {title: {a: b}}}\n" + base, "i18n.en-US.title must be text, not a mapping"},
		"value is a list":        {"i18n: {en-US: {title: [a]}}\n" + base, "must be text, not a list"},
		"value is empty":         {"i18n: {en-US: {title: }}\n" + base, "must be text, not empty"},
		"block is text":          {"i18n: nope\n" + base, "i18n must be a mapping"},
		"default is a mapping":   {"i18n: {default: {a: b}}\n" + base, "i18n.default must be a language tag"},
		"duplicate language":     {"i18n:\n  en-US: {title: a}\n  en-US: {title: b}\n" + base, "given twice"},
		"duplicate key":          {"i18n:\n  en-US: {title: a, title: b}\n" + base, "given twice"},
		"merge key":              {"x: &m {title: a}\ni18n:\n  en-US: {<<: *m}\n" + base, "merge keys"},
		"merge of languages":     {"x: &m {en-US: {title: a}}\ni18n:\n  <<: *m\n" + base, "merge keys"},
		"collection not mapping": {"collections:\n  a: {file: a.yml, schema: a.json, i18n: \"x\"}\n", "collections.a.i18n must be a mapping"},
	} {
		_, err := Parse([]byte(c.yaml), "/r/rackbook.yml")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// an alias of a whole language entry is fine
	if _, err := Parse([]byte("x: &e {title: a}\ni18n: {en-US: *e, zh-TW: *e}\n"+base), "/r/rackbook.yml"); err != nil {
		t.Fatal(err)
	}
}

func TestI18nShapeErrorsSayWhere(t *testing.T) {
	base := "collections:\n  a: {file: a.yml, schema: a.json}\n"
	for name, c := range map[string]struct{ yaml, want string }{
		"collection": {"collections:\n  a: {file: a.yml, schema: a.json, i18n: {en-US: text}}\n", "collections.a.i18n.en-US must be a mapping of text"},
		"note":       {base + "notes:\n  - {title: x, file: a.yml, path: p}\n  - {title: n, file: a.yml, path: p, i18n: {en-US: {title: [x]}}}\n", "notes[1].i18n.en-US.title must be text"},
		"ref":        {base + "rules:\n  - unique: {collection: a, fields: [x]}\n  - ref: {from: a.x, to: a.y, i18n: {en-US: nope}}\n", "rules[1].ref.i18n.en-US must be a mapping"},
		"same_set":   {base + "rules:\n  - same_set: {left: {collection: a, field: x}, right: {file: a.yml, path: p}, i18n: [x]}\n", "rules[0].same_set.i18n must be a mapping"},
		"top level":  {"i18n: {en-US: text}\n" + base, "i18n.en-US must be a mapping of text"},
	} {
		_, err := Parse([]byte(c.yaml), "/r/rackbook.yml")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
