package login

import (
	"encoding/json"
	"strings"
	"testing"
)

func (b *browser) putJSON(target, body string) resp {
	b.t.Helper()
	return b.do("PUT", target, map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"}, strings.NewReader(body))
}

func decode(t *testing.T, r resp) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(r.Body), &m); err != nil {
		t.Fatalf("bad JSON %q", r.Body)
	}
	return m
}

func TestPublicConfigLocale(t *testing.T) {
	for _, c := range []struct {
		name, extras, accept, want, def string
	}{
		{"no header, built-in default", "", "", "zh-CN", "zh-CN"},
		{"english browser", "", "en-GB,en;q=0.9", "en-US", "zh-CN"},
		{"hong kong browser", "", "zh-HK,zh;q=0.9", "zh-TW", "zh-CN"},
		{"hans browser", "", "zh-Hans", "zh-CN", "zh-CN"},
		{"unsupported language falls back to the default", "\ni18n: {default: en-US}\n", "fr-FR", "en-US", "en-US"},
		{"configured default, no header", "\ni18n: {default: zh-TW}\n", "", "zh-TW", "zh-TW"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, options{cfgExtras: c.extras})
			hdr := map[string]string{}
			if c.accept != "" {
				hdr["Accept-Language"] = c.accept
			}
			r := e.browser().do("GET", "/auth/config", hdr, nil)
			if r.StatusCode != 200 {
				t.Fatalf("%d %s", r.StatusCode, r.Body)
			}
			m := decode(t, r)
			if m["locale"] != c.want || m["defaultLocale"] != c.def {
				t.Fatalf("%v", m)
			}
			if !strings.Contains(r.Header.Get("Vary"), "Accept-Language") || r.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("Vary=%q Cache-Control=%q", r.Header.Get("Vary"), r.Header.Get("Cache-Control"))
			}
		})
	}
}

func TestAccountLocale(t *testing.T) {
	e := newEnv(t, options{readOnly: true}) // preferences are not ledger writes
	b := e.browser()
	b.login("editor", "")

	if _, ok := decode(t, b.get("/api/account"))["locale"]; ok {
		t.Fatal("locale present before any choice")
	}
	if r := b.putJSON("/api/account/preferences", `{"locale":"zh-Hant"}`); r.StatusCode != 200 || decode(t, r)["locale"] != "zh-TW" {
		t.Fatalf("set: %d %s", r.StatusCode, r.Body)
	}
	if got := decode(t, b.get("/api/account"))["locale"]; got != "zh-TW" {
		t.Fatalf("account locale = %v", got)
	}
	_, meta := b.meta()
	if meta["user"].(map[string]any)["locale"] != "zh-TW" {
		t.Fatalf("meta: %v", meta["user"])
	}
	// another person is unaffected
	b2 := e.browser()
	b2.login("viewer", "")
	if _, ok := decode(t, b2.get("/api/account"))["locale"]; ok {
		t.Fatal("preference leaked to another user")
	}
	if r := b.putJSON("/api/account/preferences", `{"locale":"xx"}`); r.StatusCode != 400 || decode(t, r)["error"] != "invalid_locale" {
		t.Fatalf("invalid: %d %s", r.StatusCode, r.Body)
	}
	if got := decode(t, b.get("/api/account"))["locale"]; got != "zh-TW" {
		t.Fatalf("an invalid value changed the preference: %v", got)
	}
	if r := b.putJSON("/api/account/preferences", `{"locale":""}`); r.StatusCode != 200 {
		t.Fatalf("clear: %d %s", r.StatusCode, r.Body)
	}
	if _, ok := decode(t, b.get("/api/account"))["locale"]; ok {
		t.Fatal("not cleared")
	}
	// signed out
	if r := e.browser().putJSON("/api/account/preferences", `{"locale":"en-US"}`); r.StatusCode == 200 {
		t.Fatalf("anonymous browser accepted: %d", r.StatusCode)
	}
}
