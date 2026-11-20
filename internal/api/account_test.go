package api_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/prefs"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

const sameOrigin = "same-origin"

func putLocale(t *testing.T, f *fixture, body any, hdr map[string]string) (int, map[string]any) {
	t.Helper()
	if hdr == nil {
		hdr = map[string]string{}
	}
	hdr["Sec-Fetch-Site"] = sameOrigin
	code, out, _ := f.do(t, "PUT", "/api/account/preferences", body, hdr)
	return code, out
}

func metaOf(t *testing.T, f *fixture, hdr map[string]string) map[string]any {
	t.Helper()
	_, m, h := f.do(t, "GET", "/api/meta", nil, hdr)
	if !strings.Contains(h.Get("Vary"), "Accept-Language") || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("headers: Vary=%q Cache-Control=%q", h.Get("Vary"), h.Get("Cache-Control"))
	}
	return m
}

// identified is a server whose callers are the named person (--auth none with --editor).
func identified(t *testing.T, dir, who string, mut func(*api.Options)) *fixture {
	t.Helper()
	return newFixture(t, func(o *api.Options) {
		a, err := auth.New(context.Background(), auth.Config{Mode: auth.ModeNone, Editor: who, Config: o.Store.Config})
		if err != nil {
			t.Fatal(err)
		}
		o.Auth = a
		if mut != nil {
			mut(o)
		}
	}, dir)
}

func TestPreferencesIdentified(t *testing.T) {
	dir := testutil.CopyExample(t)
	state := filepath.Join(t.TempDir(), "preferences.json")
	f := identified(t, dir, "Tom <Tom@example.com>", func(o *api.Options) {
		o.Prefs = &prefs.Store{Path: state}
		o.ReadOnly = true
	})
	m := metaOf(t, f, nil)
	if m["locale"] != "zh-CN" || m["defaultLocale"] != "zh-CN" {
		t.Fatalf("meta before: %v", m)
	}
	if _, ok := m["user"].(map[string]any)["locale"]; ok {
		t.Fatal("user.locale set before any choice")
	}
	for _, c := range []struct {
		name string
		body any
		code int
		want string
		err  string
	}{
		{"set", map[string]any{"locale": "en-US"}, 200, "en-US", ""},
		{"alias", map[string]any{"locale": "zh-hk"}, 200, "zh-TW", ""},
		{"invalid", map[string]any{"locale": "fr-FR"}, 400, "", "invalid_locale"},
		{"missing field", map[string]any{}, 400, "", "bad_request"},
		{"clear", map[string]any{"locale": ""}, 200, "", ""},
	} {
		code, out := putLocale(t, f, c.body, nil)
		if code != c.code || out["error"] != nilIfEmpty(c.err) {
			t.Fatalf("%s: %d %v", c.name, code, out)
		}
		if c.code == 200 && out["locale"] != c.want {
			t.Fatalf("%s: %v", c.name, out)
		}
	}
	// set again and read it back through meta, with Accept-Language ignored for user.locale
	putLocale(t, f, map[string]any{"locale": "en-US"}, nil)
	m = metaOf(t, f, map[string]string{"Accept-Language": "zh-TW"})
	if m["locale"] != "zh-TW" || m["user"].(map[string]any)["locale"] != "en-US" {
		t.Fatalf("meta after: %v", m)
	}
	b, _ := os.ReadFile(state)
	if string(b) != `{"version":1,"users":{"tom@example.com":{"locale":"en-US"}}}` {
		t.Fatalf("file: %s", b)
	}
	putLocale(t, f, map[string]any{"locale": ""}, nil)
	if m = metaOf(t, f, nil); m["user"].(map[string]any)["locale"] != nil {
		t.Fatalf("not cleared: %v", m)
	}
}

func TestPreferencesProtection(t *testing.T) {
	f := identified(t, testutil.CopyExample(t), "Tom <tom@example.com>", nil)
	body := map[string]any{"locale": "en-US"}
	if code, out, _ := f.do(t, "PUT", "/api/account/preferences", body, map[string]string{"Sec-Fetch-Site": "cross-site"}); code != 403 || out["error"] != "cross_site" {
		t.Fatalf("cross-site: %d %v", code, out)
	}
	if code, out, _ := f.do(t, "PUT", "/api/account/preferences", body, map[string]string{"Origin": "https://evil.example"}); code != 403 || out["error"] != "cross_site" {
		t.Fatalf("foreign origin: %d %v", code, out)
	}
	if code, out, _ := f.do(t, "PUT", "/api/account/preferences", nil, map[string]string{"Sec-Fetch-Site": sameOrigin}); code != 415 {
		t.Fatalf("no content type: %d %v", code, out)
	}
}

func TestPreferencesAnonymousRefused(t *testing.T) {
	f := newFixture(t, nil, "")
	code, out := putLocale(t, f, map[string]any{"locale": "en-US"}, nil)
	if code != 409 || out["error"] != "no_identity" {
		t.Fatalf("%d %v", code, out)
	}
	// meta still carries the Accept-Language match for the console
	m := metaOf(t, f, map[string]string{"Accept-Language": "en-GB,en;q=0.9"})
	if m["locale"] != "en-US" || m["defaultLocale"] != "zh-CN" {
		t.Fatalf("%v", m)
	}
}

func TestMetaLocaleFollowsConfigDefault(t *testing.T) {
	for _, c := range []struct{ block, accept, want, def string }{
		{"", "", "zh-CN", "zh-CN"},
		{"\ni18n: {default: en-US}\n", "", "en-US", "en-US"},
		{"\ni18n: {default: zh-TW}\n", "fr", "zh-TW", "zh-TW"},
		{"\ni18n: {default: zh-TW}\n", "en", "en-US", "zh-TW"},
		{"\ni18n: {default: en-US}\n", "zh-Hant-HK", "zh-TW", "en-US"},
	} {
		dir := testutil.CopyExample(t)
		p := filepath.Join(dir, "rackbook.yml")
		b, _ := os.ReadFile(p)
		os.WriteFile(p, append(b, c.block...), 0o644)
		f := newFixture(t, nil, dir)
		hdr := map[string]string{}
		if c.accept != "" {
			hdr["Accept-Language"] = c.accept
		}
		m := metaOf(t, f, hdr)
		if m["locale"] != c.want || m["defaultLocale"] != c.def {
			t.Fatalf("%q %q: %v", c.block, c.accept, m)
		}
	}
}
