package api_test

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

const (
	logoSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8"><rect width="8" height="8"/></svg>`
	favPNG  = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
)

func brandedFixture(t *testing.T) *fixture {
	t.Helper()
	dir := testutil.CopyExample(t)
	if err := os.MkdirAll(filepath.Join(dir, "branding"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "branding/logo.svg"), []byte(logoSVG), 0o644)
	os.WriteFile(filepath.Join(dir, "branding/favicon.png"), []byte(favPNG), 0o644)
	testutil.Replace(t, dir, "rackbook.yml", "collections:\n", "branding:\n  name: Kazuha Hub\n  logo: branding/logo.svg\n  favicon: branding/favicon.png\n\ncollections:\n")
	return newFixture(t, func(o *api.Options) {
		o.Web = fstest.MapFS{"index.html": {Data: []byte("<html/>")}, "favicon.svg": {Data: []byte("<svg default/>")}}
	}, dir)
}

func get(t *testing.T, f *fixture, method, path string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, f.ts.URL+path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestBrandingImageHeaders(t *testing.T) {
	t.Parallel()
	f := brandedFixture(t)
	for _, tc := range []struct{ path, ct, body string }{
		{"/branding/logo", "image/svg+xml", logoSVG},
		{"/branding/favicon", "image/png", favPNG},
	} {
		resp, body := get(t, f, "GET", tc.path, nil)
		h := resp.Header
		if resp.StatusCode != 200 || body != tc.body {
			t.Fatalf("%s: %d %q", tc.path, resp.StatusCode, body)
		}
		if h.Get("Content-Type") != tc.ct || h.Get("X-Content-Type-Options") != "nosniff" ||
			h.Get("Content-Security-Policy") != "default-src 'none'; style-src 'unsafe-inline'; sandbox" ||
			h.Get("Cache-Control") != "no-cache" || !strings.HasPrefix(h.Get("ETag"), `"`) {
			t.Fatalf("%s headers: %v", tc.path, h)
		}
		// Revalidation: the same ETag gets 304 and no body; another does not.
		resp, body = get(t, f, "GET", tc.path, map[string]string{"If-None-Match": h.Get("ETag")})
		if resp.StatusCode != 304 || body != "" {
			t.Fatalf("%s: If-None-Match: %d %q", tc.path, resp.StatusCode, body)
		}
		if resp, _ = get(t, f, "GET", tc.path, map[string]string{"If-None-Match": `"other"`}); resp.StatusCode != 200 {
			t.Fatalf("%s: %d", tc.path, resp.StatusCode)
		}
		resp, body = get(t, f, "HEAD", tc.path, nil)
		if resp.StatusCode != 200 || body != "" || resp.Header.Get("Content-Type") != tc.ct {
			t.Fatalf("%s HEAD: %d %q", tc.path, resp.StatusCode, body)
		}
	}
}

func TestBrandingImagesAreGetOnly(t *testing.T) {
	t.Parallel()
	f := brandedFixture(t)
	for _, p := range []string{"/branding/logo", "/branding/favicon"} {
		for _, m := range []string{"POST", "PUT", "DELETE"} {
			if resp, _ := get(t, f, m, p, nil); resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: %d", m, p, resp.StatusCode)
			}
		}
	}
}

func TestBrandingDefaults(t *testing.T) {
	t.Parallel()
	f := newFixture(t, func(o *api.Options) {
		o.Web = fstest.MapFS{"index.html": {Data: []byte("<html/>")}, "favicon.svg": {Data: []byte("<svg default/>")}}
	}, "")
	// No custom logo: 404 (the console shows its own mark).
	if resp, _ := get(t, f, "GET", "/branding/logo", nil); resp.StatusCode != 404 {
		t.Fatalf("logo: %d", resp.StatusCode)
	}
	// No custom favicon: the one that ships with the console, with the same headers.
	resp, body := get(t, f, "GET", "/branding/favicon", nil)
	if resp.StatusCode != 200 || body != "<svg default/>" || resp.Header.Get("Content-Type") != "image/svg+xml" ||
		resp.Header.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("favicon: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	_, m, _ := f.do(t, "GET", "/api/meta", nil, nil)
	if b, _ := m["branding"].(map[string]any); b["name"] != "" || b["logo"] != false {
		t.Fatalf("meta.branding: %v", m["branding"])
	}
}

func TestMetaCarriesBranding(t *testing.T) {
	t.Parallel()
	f := brandedFixture(t)
	_, m, _ := f.do(t, "GET", "/api/meta", nil, nil)
	if b, _ := m["branding"].(map[string]any); b["name"] != "Kazuha Hub" || b["logo"] != true {
		t.Fatalf("meta.branding: %v", m["branding"])
	}
}

func TestBrandingFollowsConfigReload(t *testing.T) {
	t.Parallel()
	f := brandedFixture(t) // not a Git repository: files are re-read on every request
	resp, _ := get(t, f, "GET", "/branding/logo", nil)
	old := resp.Header.Get("ETag")
	os.WriteFile(filepath.Join(f.dir, "branding/logo.svg"), []byte(strings.Replace(logoSVG, "8 8", "9 9", 1)), 0o644)
	resp, body := get(t, f, "GET", "/branding/logo", map[string]string{"If-None-Match": old})
	if resp.StatusCode != 200 || !strings.Contains(body, "9 9") || resp.Header.Get("ETag") == old {
		t.Fatalf("%d %q %v", resp.StatusCode, body, resp.Header)
	}
}
