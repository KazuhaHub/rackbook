package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	okSVG = `<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8"><rect width="8" height="8"/></svg>`
	okPNG = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
)

// brandingRepo makes a data repository with the given files and returns the
// result of parsing a config with the given branding block.
func brandingRepo(t *testing.T, files map[string]string, branding string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return Parse([]byte(base+branding), filepath.Join(dir, "rackbook.yml"))
}

func TestBrandingUnsetIsFine(t *testing.T) {
	// A v0.2 config has no branding or label and loads exactly as before.
	c, err := Parse([]byte(base+"auth:\n  mode: oidc\n  oidc: {issuer: 'https://i.example', client_id: x}\n"), "/r/rackbook.yml")
	if err != nil {
		t.Fatal(err)
	}
	if c.BrandLogo() != nil || c.BrandFavicon() != nil || c.Branding.Name != "" || c.Auth.OIDC.Label != "" {
		t.Fatalf("%+v", c.Branding)
	}
	if (*Config)(nil).BrandLogo() != nil {
		t.Fatal("nil config")
	}
}

func TestBrandingLoads(t *testing.T) {
	c, err := brandingRepo(t, map[string]string{
		"branding/logo.svg":  okSVG,
		"branding/fav.png":   okPNG,
		"branding/fav2.ICO":  "\x00\x00\x01\x00\x01\x00",
		"branding/logo2.png": okPNG,
	}, "branding:\n  name: ' Kazuha Hub '\n  logo: branding/logo.svg\n  favicon: branding/fav.png\nauth:\n  oidc: {label: ' 使用 Kazuha Hub SSO 登录 '}\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.Branding.Name != "Kazuha Hub" || c.Auth.OIDC.Label != "使用 Kazuha Hub SSO 登录" {
		t.Fatalf("text is trimmed: %+v %q", c.Branding, c.Auth.OIDC.Label)
	}
	l, f := c.BrandLogo(), c.BrandFavicon()
	if l == nil || l.ContentType != "image/svg+xml" || string(l.Data) != okSVG || !strings.HasPrefix(l.ETag, `"`) || len(l.ETag) != 34 {
		t.Fatalf("logo: %+v", l)
	}
	if f == nil || f.ContentType != "image/png" || f.ETag == l.ETag {
		t.Fatalf("favicon: %+v", f)
	}
	for _, y := range []string{"branding:\n  favicon: branding/fav2.ICO\n", "branding:\n  logo: branding/logo2.png\n"} {
		if _, err := brandingRepo(t, map[string]string{"branding/fav2.ICO": "\x00\x00\x01\x00\x01\x00", "branding/logo2.png": okPNG}, y); err != nil {
			t.Fatalf("%s: %v", y, err)
		}
	}
}

func TestBrandingRejections(t *testing.T) {
	big := okSVG[:len(okSVG)-6] + strings.Repeat(" ", MaxBrandingFile) + "</svg>"
	files := map[string]string{
		"logo.svg":      okSVG,
		"big.svg":       big,
		"notsvg.svg":    `<html><body/></html>`,
		"broken.svg":    `<svg><g></svg>`,
		"empty.svg":     ``,
		"badmagic.png":  "GIF89a....",
		"badico.ico":    "MZ",
		"logo.jpg":      "x",
		"dir.svg/x.txt": "x",
	}
	cases := []struct{ name, block, want string }{
		{"dotdot", "branding: {logo: ../logo.svg}", "escapes"},
		{"dotdot inside", "branding: {logo: a/../../logo.svg}", "escapes"},
		{"absolute", "branding: {logo: /etc/passwd.svg}", "relative"},
		{"too big", "branding: {logo: big.svg}", "limit"},
		{"wrong extension", "branding: {logo: logo.jpg}", "must be a"},
		{"ico as logo", "branding: {logo: badico.ico}", "must be a"},
		{"gif as favicon", "branding: {favicon: logo.gif}", "must be a"},
		{"png bad magic", "branding: {logo: badmagic.png}", "not a PNG"},
		{"ico bad magic", "branding: {favicon: badico.ico}", "not an ICO"},
		{"svg root is html", "branding: {logo: notsvg.svg}", "root element is <html>"},
		{"svg not xml", "branding: {logo: broken.svg}", "not valid XML"},
		{"svg empty", "branding: {logo: empty.svg}", "no <svg>"},
		{"missing", "branding: {logo: nope.svg}", "cannot read"},
		{"directory", "branding: {logo: dir.svg}", "not a regular file"},
		{"inside .rackbook", "branding: {logo: .rackbook/x.svg}", "belongs to Rackbook"},
		{"name too long", "branding: {name: " + strings.Repeat("x", MaxBrandingText+1) + "}", "at most"},
		{"name control char", "branding: {name: \"a\\nb\"}", "control"},
		{"label too long", "auth: {oidc: {label: " + strings.Repeat("x", MaxBrandingText+1) + "}}", "at most"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := brandingRepo(t, files, tc.block+"\n")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v", tc.want, err)
			}
			if tc.name != "name too long" && tc.name != "label too long" && tc.name != "name control char" && !strings.Contains(err.Error(), "branding.") {
				t.Fatalf("the message should name the key: %v", err)
			}
		})
	}
}

func TestBrandingRefusesSymlinkOutOfTheRepo(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "logo.svg"), []byte(okSVG), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, l := range [][2]string{{filepath.Join(outside, "logo.svg"), "link.svg"}, {outside, "linkdir"}} {
		if err := os.Symlink(l[0], filepath.Join(dir, l[1])); err != nil {
			t.Skipf("SKIPPED: cannot create symbolic links here: %v", err)
		}
	}
	// A symlink that stays inside the repository is fine.
	if err := os.WriteFile(filepath.Join(dir, "real.svg"), []byte(okSVG), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.svg", filepath.Join(dir, "inside.svg")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"link.svg", "linkdir/logo.svg"} {
		_, err := Parse([]byte(base+"branding: {logo: "+p+"}\n"), filepath.Join(dir, "rackbook.yml"))
		if err == nil || !strings.Contains(err.Error(), "outside the config directory") {
			t.Errorf("%s: %v", p, err)
		}
	}
	if _, err := Parse([]byte(base+"branding: {logo: inside.svg}\n"), filepath.Join(dir, "rackbook.yml")); err != nil {
		t.Fatal(err)
	}
}
