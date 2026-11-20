package api_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/testutil"
)

func TestMetaCarriesTranslationsAsRawMaps(t *testing.T) {
	f := newFixture(t, nil, testutil.CopyFixture(t, "labels"))
	_, m, _ := f.do(t, "GET", "/api/meta", nil, nil)
	j := func(v any) string { b, _ := json.Marshal(v); return string(b) }

	if got := j(m["i18n"]); got != `{"en-US":{"description":"Devices and services","title":"Home network ledger"},"zh-TW":{"title":"家庭網路台帳"}}` {
		t.Fatalf("top-level i18n: %s", got)
	}
	if m["title"] != "家庭网络台账" || m["defaultLocale"] != "zh-CN" {
		t.Fatalf("standard text stays: %v", m["title"])
	}
	var dev, people map[string]any
	for _, c := range arr(t, m["collections"]) {
		switch c.(map[string]any)["name"] {
		case "devices":
			dev = c.(map[string]any)
		case "people":
			people = c.(map[string]any)
		}
	}
	if got := j(dev["i18n"]); got != `{"en-US":{"description":"All devices","group":"Network","title":"Devices"},"zh-TW":{"title":"設備"}}` {
		t.Fatalf("collection i18n: %s", got)
	}
	if _, has := people["i18n"]; has {
		t.Fatalf("no translations, no key: %v", people)
	}
	notes := arr(t, dev["notes"])
	if len(notes) != 1 || j(notes[0].(map[string]any)["i18n"]) != `{"en-US":{"title":"Address pool rule"}}` || notes[0].(map[string]any)["title"] != "地址池规则" {
		t.Fatalf("notes: %v", notes)
	}
	back := arr(t, people["backrefs"])
	if len(back) != 1 || back[0].(map[string]any)["title"] != "名下设备" || j(back[0].(map[string]any)["i18n"]) != `{"en-US":{"title":"Devices owned"}}` {
		t.Fatalf("backrefs: %v", back)
	}
	// the schema stays the raw bytes, translations included
	if !strings.Contains(j(dev["schema"]), "x-rackbook-i18n") {
		t.Fatal("schema must stay raw")
	}
	// a ledger without translations sends no i18n key
	dir := testutil.CopyFixture(t, "labels")
	testutil.Replace(t, dir, "rackbook.yml", "  en-US: {title: Home network ledger, description: Devices and services}\n  zh-TW: {title: 家庭網路台帳}\n", "")
	_, m, _ = newFixture(t, nil, dir).do(t, "GET", "/api/meta", nil, nil)
	if _, has := m["i18n"]; has {
		t.Fatalf("i18n without translations: %v", m["i18n"])
	}
}

// The write path gives the same hint as `rackbook check`.
func TestWriteRefusalNamesTheCode(t *testing.T) {
	f := newFixture(t, nil, testutil.CopyFixture(t, "labels"))
	code, r, _ := f.do(t, "POST", "/api/c/devices", map[string]any{"data": map[string]any{"name": "x", "ipv4_type": "静态", "status": "UP"}}, nil)
	if code != 422 || r["error"] != "invalid" {
		t.Fatalf("%d %v", code, r)
	}
	var msgs []string
	for _, e := range arr(t, r["errors"]) {
		msgs = append(msgs, e.(map[string]any)["message"].(string))
	}
	got := strings.Join(msgs, "\n")
	if !strings.Contains(got, `"静态" is not allowed; use code "static"`) || !strings.Contains(got, `"UP" is not allowed; use code "up"`) || strings.Contains(got, "oneOf") {
		t.Fatalf("%s", got)
	}
}

// The data types list carries the same collection translations as /api/meta,
// so the types page can show titles and groups in the viewer's language.
func TestTypesListCarriesTranslations(t *testing.T) {
	f := newFixtureWithConfigSource(t, "Boss <boss@example.com>", withRoles(t, testutil.CopyFixture(t, "labels")))
	code, r, _ := f.do(t, "GET", "/api/types", nil, nil)
	if code != 200 {
		t.Fatalf("GET /api/types: %d", code)
	}
	j := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	for _, ty := range arr(t, r["types"]) {
		m := ty.(map[string]any)
		switch m["name"] {
		case "devices":
			if got := j(m["i18n"]); got != `{"en-US":{"description":"All devices","group":"Network","title":"Devices"},"zh-TW":{"title":"設備"}}` {
				t.Fatalf("devices i18n: %s", got)
			}
		case "people":
			if _, has := m["i18n"]; has {
				t.Fatalf("no translations, no key: %v", m)
			}
		}
	}
}
