package validate

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/ledger"
)

func TestFormats(t *testing.T) {
	t.Parallel()
	good := map[string][]string{
		"ip":          {"10.0.0.1", "255.255.255.255", "::1", "2001:db8::1", "fe80::1", "::ffff:1.2.3.4"},
		"ipv4":        {"0.0.0.0", "192.168.1.10", "100.64.0.1"},
		"ipv6":        {"::", "2001:db8:0:0:0:0:0:1", "fd7a:115c:a1e0::1"},
		"cidr":        {"10.0.0.0/8", "192.168.0.0/22", "10.1.2.3/32", "2001:db8::/32", "::/0"},
		"port-spec":   {"TCP 443", "UDP 41641", "tcp 22", "TCP/UDP 53", "TCP 8000-8010", "TCP 80, 443", "UDP 1-65535"},
		"date":        {"2026-01-31", "2024-02-29", "1999-12-31", "0000-01-01", "0099-12-31", "0400-02-29"},
		"textarea":    {"", "any\ntext"},
		"hostname":    {"a", "example.com", "web-1.dc.example.com", "A1.b2", "xn--bcher-kva.example"},
		"uri":         {"https://example.com", "http://10.0.0.1:8080/x?y=1", "ssh://git@host/repo", "mailto:a@b.c", "tel:+1555"},
		"country":     {"US", "CN", "SG", "TW", "HK", "MO", "tbd"},
		"subdivision": {"US-CA", "CN-GD", "TW-TPE", "SG-01", "GB-ENG", "HK-HCW", "tbd"},
	}
	bad := map[string][]string{
		"ip":          {"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "fe80::1%eth0", "abc", "10.0.0.1/24"},
		"ipv4":        {"::1", "1.2.3", "300.0.0.1", " 1.2.3.4", "1.2.3.4 "},
		"ipv6":        {"1.2.3.4", "2001:db8:::1", "12345::1", ":::"},
		"cidr":        {"10.0.0.0", "10.0.0.0/33", "10.0.0.0/-1", "::1/129", "10.0.0/8", "/8", "10.0.0.0/8/8"},
		"port-spec":   {"443", "TCP", "TCP 0", "TCP 65536", "TCP 90-80", "ICMP 1", "TCP  443x", "TCP 80,", "TCP80", "TCP 1-2-3"},
		"date":        {"0100-02-29", "0001-02-29", "2026-02-30", "2026-13-01", "26-01-01", "2026-1-1", "2026/01/01", "2026-01-01T00:00:00Z", ""},
		"hostname":    {"", "-a.com", "a-.com", "a..b", "a_b.com", "a b", "a.com.", strRepeat("a", 64) + ".com"},
		"uri":         {"", "example.com", "//example.com", "http://exa mple.com", "1http://x", "http:"},
		"country":     {"", "us", "Us", "USA", "840", "UK", "UN", "EU", "AN", "ZZ", "XX", "XK", "TBD", "Tbd", "U", " US", "US ", "中国"},
		"subdivision": {"", "us-ca", "US-ca", "US_CA", "US-", "US-CALI", "US-C-A", "ZZ-01", "UK-ENG", "XX-01", "USCA", "TBD", "CA", "US-中"},
	}
	for name, vals := range good {
		for _, v := range vals {
			if err, ok := CheckFormat(name, v); !ok || err != nil {
				t.Errorf("%s %q should be valid: %v", name, v, err)
			}
		}
	}
	for name, vals := range bad {
		for _, v := range vals {
			if err, _ := CheckFormat(name, v); err == nil {
				t.Errorf("%s %q should be invalid", name, v)
			}
		}
	}
	if _, ok := CheckFormat("nope", "x"); ok {
		t.Error("unknown format must report !ok")
	}
}

func strRepeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

// the formats are asserted by the schema validator, not only available
func TestFormatsAreEnforcedByTheLedgerCheck(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	w := func(rel, s string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("rackbook.yml", "collections:\n  hosts:\n    file: hosts.yml\n    schema: hosts.json\n    key: [name]\n")
	w("hosts.json", `{"type": "object", "properties": {"name": {"type": "string"}, "ip": {"type": "string", "format": "ipv4"}, "net": {"type": "string", "format": "cidr"}, "svc": {"type": "string", "format": "port-spec"}, "since": {"type": "string", "format": "date"}, "notes": {"type": "string", "format": "textarea"}}}`)
	w("hosts.yml", "- {name: a, ip: 10.0.0.1, net: 10.0.0.0/8, svc: TCP 443, since: 2026-01-02, notes: x}\n- {name: b, ip: 10.0.0.999, net: 10.0.0.0, svc: 443, since: 2026-02-30}\n")
	cfg, err := config.Load(filepath.Join(dir, "rackbook.yml"))
	if err != nil {
		t.Fatal(err)
	}
	issues := Run(ledger.Load(cfg, nil))
	got := map[string]bool{}
	for _, i := range issues {
		if i.ID != "b" {
			t.Fatalf("record a must be valid: %v", i)
		}
		got[i.Path] = true
	}
	for _, p := range []string{"/ip", "/net", "/svc", "/since"} {
		if !got[p] {
			t.Errorf("no issue for %s: %v", p, issues)
		}
	}
}

func TestCountriesMatchTestdata(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/countries.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Fields(string(raw))
	got := Countries()
	if len(got) != len(want) {
		t.Fatalf("Countries() has %d codes, testdata/countries.txt %d; if x/text changed, regenerate the file and web/src/lib/countries.ts", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("code %d: %s != %s", i, got[i], want[i])
		}
	}
	for _, c := range []string{"US", "CN", "SG", "TW", "HK", "MO", "JP", "DE"} {
		if !isCountryCode(c) {
			t.Errorf("%s must be a country", c)
		}
	}
}

// TestCountriesWebList checks that the console's static list is the same set.
// A missing file is a failure: the console cannot validate countries without it.
func TestCountriesWebList(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "web", "src", "lib", "countries.ts")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s must exist: %v", path, err)
	}
	src := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(string(raw), "")
	src = regexp.MustCompile(`(?m)//.*$`).ReplaceAllString(src, "")
	m := regexp.MustCompile(`(?s)COUNTRY_CODES\s*(?::[^=]*)?=\s*\[(.*?)\]`).FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("%s has no COUNTRY_CODES array literal", path)
	}
	got := map[string]bool{}
	for _, c := range regexp.MustCompile(`["']([A-Z]{2})["']`).FindAllStringSubmatch(m[1], -1) {
		got[c[1]] = true
	}
	want := map[string]bool{}
	for _, c := range Countries() {
		want[c] = true
	}
	for c := range want {
		if !got[c] {
			t.Errorf("%s is a country in Go but missing from countries.ts", c)
		}
	}
	for c := range got {
		if !want[c] {
			t.Errorf("%s is in countries.ts but Go does not accept it as a country", c)
		}
	}
}
