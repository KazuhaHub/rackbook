package oauthserver_test

import (
	"strings"
	"testing"
)

// The pages shown instead of a redirect speak the person's language: their
// saved console preference, else the browser's, else the ledger's default.
func TestErrorPageLanguage(t *testing.T) {
	t.Parallel()
	e := newEnv(t, opts{})
	cid := e.register("c")
	_, ch := pkce()
	p := e.params(cid, testRedirect, ch)
	p.redirect = "http://localhost:7777/other"
	if _, err := e.prefs.SetLocale("boss@example.com", "zh-TW"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, user, accept, lang, want string
	}{
		{"saved preference wins over the browser", "boss@example.com", "en-US", "zh-TW", "redirect_uri 不是該用戶端註冊過的位址。"},
		{"browser language", "ed@example.com", "en-GB,en;q=0.9", "en-US", "The redirect_uri is not one the client has registered."},
		{"Traditional Chinese browser", "ed@example.com", "zh-HK", "zh-TW", "授權失敗"},
		{"no language: the ledger default", "ed@example.com", "", "zh-CN", "redirect_uri 不是该客户端注册过的地址。"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var hdr []string
			if c.accept != "" {
				hdr = []string{"Accept-Language", c.accept}
			}
			r := e.get(c.user, "/oauth/authorize?"+p.query(), hdr...)
			body := string(r.body)
			if r.StatusCode != 400 || !strings.Contains(body, `<html lang="`+c.lang+`">`) || !strings.Contains(body, c.want) {
				t.Fatalf("%d\n%s", r.StatusCode, body)
			}
			if v := r.Header.Get("Vary"); !strings.Contains(v, "Accept-Language") || r.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("Vary %q, Cache-Control %q", v, r.Header.Get("Cache-Control"))
			}
		})
	}

	// the reasons each have their own words; a refused client names why
	unknown := e.params("rbc_unknown", testRedirect, ch)
	if r := e.get("ed@example.com", "/oauth/authorize?"+unknown.query(), "Accept-Language", "zh-CN"); !strings.Contains(string(r.body), "该客户端没有在此 Rackbook 注册。") {
		t.Fatalf("%s", r.body)
	}
	if r := e.get("ed@example.com", "/oauth/authorize?response_type=code", "Accept-Language", "en"); !strings.Contains(string(r.body), "The request has no client_id.") {
		t.Fatalf("%s", r.body)
	}
	cimd := e.params("https://client.example/a/../meta.json", testRedirect, ch)
	if r := e.get("ed@example.com", "/oauth/authorize?"+cimd.query(), "Accept-Language", "zh-TW"); !strings.Contains(string(r.body), "無法使用該用戶端：client_id must not contain dot segments。") {
		t.Fatalf("%s", r.body)
	}
}
