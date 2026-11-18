package expiry_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/expiry"
	"github.com/kazuhahub/rackbook/internal/ledger"
)

const cfgYAML = `
collections:
  credentials:
    file: credentials.yml
    schema: credentials.json
    key: [name]
    label: title
  plain:
    file: plain.yml
    schema: plain.json
    key: [name]
`

const credSchema = `{"type":"object","properties":{
 "name":{"type":"string"},"title":{"type":["string","null"]},
 "expires":{"type":["string","number","boolean","null"],"x-rackbook":{"expires":true}},
 "revoked":{"type":["string","boolean","null"],"x-rackbook":{"revoked":true}},
 "source":{"type":["string","null"]}}}`

const plainSchema = `{"type":"object","properties":{"name":{"type":"string"},"expires":{"type":"string"}}}`

func load(t *testing.T, data string) *ledger.Ledger {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"rackbook.yml": cfgYAML, "credentials.json": credSchema, "plain.json": plainSchema,
		"credentials.yml": data, "plain.yml": "- {name: p1, expires: 2020-01-01}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.Load(filepath.Join(dir, "rackbook.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return ledger.Load(cfg, nil)
}

var today = time.Date(2026, 11, 18, 23, 59, 0, 0, time.UTC)

func TestList(t *testing.T) {
	l := load(t, `
- {name: today, expires: 2026-11-18}
- {name: yesterday, expires: 2026-11-17}
- {name: edge, expires: 2026-12-18}
- {name: beyond, expires: 2026-12-19}
- {name: rfc, expires: "2026-11-20T23:30:00-05:00"}
- {name: never-null, expires: null}
- {name: never-empty, expires: ""}
- {name: never-missing}
- {name: tbd, expires: 待补, source: entra}
- {name: num, expires: 20261120}
- {name: flag, expires: true}
- {name: revoked-date, expires: 2026-11-01, revoked: 2026-11-02}
- {name: revoked-true, expires: 2026-11-01, revoked: true}
- {name: revoked-empty, expires: 2026-11-01, revoked: ""}
- {name: revoked-false, expires: 2026-11-02, revoked: false}
- {name: labelled, title: Main cert, expires: 2026-11-19, source: entra}
`)
	res, err := expiry.List(l, expiry.Options{Days: 30, Unknown: true, Today: today})
	if err != nil {
		t.Fatal(err)
	}
	if res.Today != "2026-11-18" || res.Days != 30 {
		t.Fatalf("header: %+v", res)
	}
	type row struct {
		id, label, expires, status, source string
		left                               int // -1000 = nil
	}
	want := []row{
		{"revoked-empty", "revoked-empty", "2026-11-01", "expired", "", -17},
		{"revoked-false", "revoked-false", "2026-11-02", "expired", "", -16},
		{"yesterday", "yesterday", "2026-11-17", "expired", "", -1},
		{"today", "today", "2026-11-18", "expiring", "", 0},
		{"labelled", "Main cert", "2026-11-19", "expiring", "entra", 1},
		{"rfc", "rfc", "2026-11-20T23:30:00-05:00", "expiring", "", 3},
		{"edge", "edge", "2026-12-18", "expiring", "", 30},
		{"flag", "flag", "true", "unknown", "", -1000},
		{"num", "num", "20261120", "unknown", "", -1000},
		{"tbd", "tbd", "待补", "unknown", "entra", -1000},
	}
	if len(res.Items) != len(want) {
		t.Fatalf("got %d items: %+v", len(res.Items), res.Items)
	}
	for i, w := range want {
		g := res.Items[i]
		if g.Collection != "credentials" || g.ID != w.id || g.Label != w.label || g.Expires != w.expires || g.Status != w.status || g.Source != w.source {
			t.Errorf("item %d: %+v, want %+v", i, g, w)
		}
		if w.left == -1000 {
			if g.DaysLeft != nil {
				t.Errorf("item %d: daysLeft %d, want nil", i, *g.DaysLeft)
			}
		} else if g.DaysLeft == nil || *g.DaysLeft != w.left {
			t.Errorf("item %d: daysLeft %v, want %d", i, g.DaysLeft, w.left)
		}
	}
}

func TestListOptions(t *testing.T) {
	l := load(t, "- {name: a, expires: 2026-11-30}\n- {name: b, expires: 待补}\n- {name: c, expires: 2026-11-10}\n")
	ids := func(o expiry.Options) []string {
		o.Today = today
		res, err := expiry.List(l, o)
		if err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for _, it := range res.Items {
			out = append(out, it.ID)
		}
		return out
	}
	eq := func(got []string, want ...string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("got %v, want %v", got, want)
			}
		}
	}
	eq(ids(expiry.Options{Days: 30}), "c", "a")
	eq(ids(expiry.Options{Days: 5}), "c")
	eq(ids(expiry.Options{Days: 0}), "c")
	eq(ids(expiry.Options{Days: -4}), "c")
	eq(ids(expiry.Options{Days: 30, Unknown: true}), "c", "a", "b")
	eq(ids(expiry.Options{Days: 30, Collections: []string{"credentials", "credentials"}}), "c", "a")
	eq(ids(expiry.Options{Days: 30, Collections: []string{"plain"}})) // no expires mark: never listed
	if res, _ := expiry.List(l, expiry.Options{Days: 99999, Today: today}); res.Days != expiry.MaxDays {
		t.Fatalf("days not clamped: %d", res.Days)
	}
	if res, _ := expiry.List(l, expiry.Options{Days: -1, Today: today}); res.Days != 0 {
		t.Fatalf("days not clamped: %d", res.Days)
	}
	if _, err := expiry.List(l, expiry.Options{Days: 30, Collections: []string{"nope"}}); !errors.Is(err, expiry.ErrUnknownCollection) {
		t.Fatalf("err: %v", err)
	}
}

func TestSortTies(t *testing.T) {
	l := load(t, "- {name: b, expires: 2026-11-20}\n- {name: a, expires: 2026-11-20}\n- {name: z, expires: 2026-11-19}\n")
	res, _ := expiry.List(l, expiry.Options{Days: 30, Today: today})
	if len(res.Items) != 3 || res.Items[0].ID != "z" || res.Items[1].ID != "a" || res.Items[2].ID != "b" {
		t.Fatalf("%+v", res.Items)
	}
}

func TestFields(t *testing.T) {
	l := load(t, "[]\n")
	if f := expiry.ExpiryField(l.Collection("credentials")); f != "expires" {
		t.Fatalf("expiry field %q", f)
	}
	if f := expiry.RevokedField(l.Collection("credentials")); f != "revoked" {
		t.Fatalf("revoked field %q", f)
	}
	if expiry.ExpiryField(l.Collection("plain")) != "" || expiry.RevokedField(l.Collection("plain")) != "" || expiry.ExpiryField(nil) != "" {
		t.Fatal("unmarked collection must have no fields")
	}
}
