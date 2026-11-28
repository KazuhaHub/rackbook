package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeadersPerPath(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	csp := func(path string) string {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		for _, k := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
			if w.Header().Get(k) == "" {
				t.Errorf("%s: no %s", path, k)
			}
		}
		return w.Header().Get("Content-Security-Policy")
	}
	for _, p := range []string{"/", "/api/meta", "/records/x", "/oauth/consent", "/authors", "/authority"} {
		if got := csp(p); got != consoleCSP || !strings.Contains(got, "'unsafe-eval'") {
			t.Errorf("%s: %q", p, got)
		}
	}
	for _, p := range []string{"/auth/login", "/auth/local/setup", "/auth/local/reauth", "/auth/local/login", "/auth/oidc/callback"} {
		got := csp(p)
		if got != AuthPageCSP(nil) {
			t.Errorf("%s: %q", p, got)
		}
		for _, bad := range []string{"unsafe-eval", "http:", "https:", "*"} {
			if strings.Contains(got, bad) {
				t.Errorf("%s: the sign-in pages' policy has %q: %s", p, bad, got)
			}
		}
		for _, want := range []string{"script-src 'self';", "connect-src 'self'", "form-action 'self'", "frame-ancestors 'none'", "frame-src 'none'", "object-src 'none'", "base-uri 'self'"} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: no %q in %s", p, want, got)
			}
		}
	}
}

func TestAuthPagePolicyAllowsOnlyTheCaptchaProvider(t *testing.T) {
	got := AuthPageCSP([]string{"https://challenges.cloudflare.com"})
	if !strings.Contains(got, "script-src 'self' https://challenges.cloudflare.com;") || !strings.Contains(got, "frame-src https://challenges.cloudflare.com;") {
		t.Fatal(got)
	}
	if strings.Count(got, "challenges.cloudflare.com") != 2 || strings.Contains(got, "unsafe-eval") {
		t.Fatal(got)
	}
}
