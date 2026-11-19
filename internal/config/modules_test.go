package config

import (
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/modsettings"
)

const modCols = "collections:\n  creds: {file: c.yml, schema: s.json}\n"

func TestModuleSettingsAndTypes(t *testing.T) {
	c, err := Parse([]byte(modCols+`modules:
  entra:
    token: entra-sync
    collection: creds
    fields: [expires]
    settings:
      sync_at: ["03:00"]
      timezone: Asia/Shanghai
      exclude_app_ids: [11111111-2222-3333-4444-555555555555]
      service_principals: false
  notify:
    token: notify-read
    settings:
      thresholds: [7, 30]
      recipients: [ops@example.org]
      collections: [creds]
  custom:
    token: custom-token
    collection: creds
    fields: [expires]
`), "/r/rackbook.yml")
	if err != nil {
		t.Fatal(err)
	}
	e := c.Modules["entra"]
	if e.Type != "entra" || e.ReadOnly() {
		t.Fatalf("entra: %+v", e)
	}
	es := e.ParsedSettings().(*modsettings.Entra)
	if es.Timezone != "Asia/Shanghai" || es.ServicePrincipals == nil || *es.ServicePrincipals {
		t.Fatalf("%+v", es)
	}
	n := c.Modules["notify"]
	if n.Type != "notify" || !n.ReadOnly() {
		t.Fatalf("notify: %+v", n)
	}
	if ns := n.ParsedSettings().(*modsettings.Notify); len(ns.Thresholds) != 2 || ns.Thresholds[0] != 30 {
		t.Fatalf("%+v", ns)
	}
	if cm := c.Modules["custom"]; cm.Type != "" || cm.ParsedSettings() != nil {
		t.Fatalf("custom: %+v", cm)
	}
}

func TestModuleConfigErrors(t *testing.T) {
	bad := map[string]struct{ block, want string }{
		"unknown key":      {"  notify: {token: t, settings: {thresholdz: [1]}}\n", `unknown setting "thresholdz"`},
		"wrong type":       {"  notify: {token: t, settings: {thresholds: nope}}\n", "settings"},
		"unknown type":     {"  m: {token: t, type: sms}\n", `unknown module type "sms"`},
		"settings no type": {"  m: {token: t, settings: {paused: true}}\n", "needs modules.m.type"},
		"bad time":         {"  notify: {token: t, settings: {send_at: ['8am']}}\n", "send_at"},
		"bad zone":         {"  notify: {token: t, settings: {timezone: Mars/Base}}\n", "timezone"},
		"threshold range":  {"  notify: {token: t, settings: {thresholds: [4000]}}\n", "thresholds"},
		"bad email":        {"  notify: {token: t, settings: {recipients: ['Ops <ops@example.org>']}}\n", "recipients"},
		"unknown col":      {"  notify: {token: t, settings: {collections: [nope]}}\n", "not a collection"},
		"bad app id":       {"  entra: {token: t, collection: creds, fields: [a], settings: {exclude_app_ids: [abc]}}\n", "exclude_app_ids"},
		"entra read only":  {"  entra: {token: t}\n", "needs collection and fields"},
		"fields only":      {"  m: {token: t, fields: [a]}\n", "needs modules.m.collection"},
		"collection only":  {"  m: {token: t, collection: creds}\n", "must list the fields"},
	}
	for name, c := range bad {
		_, err := Parse([]byte(modCols+"modules:\n"+c.block), "/r/rackbook.yml")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}
