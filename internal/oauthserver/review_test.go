package oauthserver

import (
	"net/netip"
	"testing"
)

func TestBlockedAddr(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "192.168.0.1", "169.254.169.254", "0.0.0.0", "0.1.2.3", "100.64.0.1",
		"192.0.0.5", "198.18.0.1", "240.0.0.1", "255.255.255.255", "224.0.0.1", "::", "::7f00:1", "::a00:1", "::ffff:127.0.0.1",
		"::ffff:10.0.0.1", "64:ff9b::a00:1", "64:ff9b:1::a00:1", "2001::1", "2002:7f00:1::1", "fc00::1", "fd12::1", "fe80::1", "ff02::1",
	}
	for _, s := range blocked {
		if !blockedAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "93.184.216.34", "1.1.1.1", "2606:4700:4700::1111", "2a00:1450:4001:81b::200e", "::ffff:8.8.8.8"} {
		if blockedAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}

func TestValidateRedirectCharacters(t *testing.T) {
	good := []string{
		"https://app.example/cb", "http://localhost:7777/callback", "http://127.0.0.1:1/x", "http://[::1]:5/x",
		"cursor://anysphere.cursor/oauth/callback", "https://xn--e1afmkfd.example/cb", "https://a.example/cb?x=%E4%B8%AD",
	}
	for _, s := range good {
		if err := validateRedirect(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	bad := []string{
		"https://аpp.example/cb",             // Cyrillic a
		"https://app.exаmple/cb",             // Cyrillic a
		"https://app.example/cb\u202e",       // right-to-left override
		"https://app\u200b.example/cb",       // zero-width space
		"https://app.example\u2066/cb",       // bidi isolate
		"https://app.example/\u00ad",         // soft hyphen
		"https://ａpp.example/cb",             // full-width a
		"https://app.example/cb\x00",         // control
		"https://app.example/c b",            // space
		"cursor://аnysphere.cursor/cb",       // look-alike in a private-use scheme host
		"cursor://anysphere.cursor/\u200bcb", // zero-width in a private-use scheme path
		"https://app.example/中",              // any non-ASCII
	}
	for _, s := range bad {
		if err := validateRedirect(s); err == nil {
			t.Errorf("%q should be refused", s)
		}
	}
	for _, id := range []string{"https://аpp.example/c.json", "https://app.example/c\u202e.json", "https://app\u200b.example/c.json"} {
		if _, err := validCIMDURL(id); err == nil {
			t.Errorf("client_id %q should be refused", id)
		}
	}
}

func TestCleanNameDropsFormatCharacters(t *testing.T) {
	if got := cleanName("Safe\u202eEvil\u200bName", "x"); got != "SafeEvilName" {
		t.Fatalf("%q", got)
	}
}

func TestPunycodeLabels(t *testing.T) {
	for host, want := range map[string]bool{"app.example": false, "xn--e1afmkfd.example": true, "a.XN--p1ai": true, "xn.example": false, "axn--b.example": false} {
		if hasPunycode(host) != want {
			t.Errorf("%s: %v", host, !want)
		}
	}
}

// A percent-encoded host would pass a check on the raw text and show as letters
// from another script once decoded.
func TestPercentEncodedHostsAreRefused(t *testing.T) {
	for _, u := range []string{"https://%D0%B0pple.com/cb", "https://app%2Eexample/cb", "cursor://%D0%B0.example/cb", "https://app.example%00/cb", "http://[fe80::1%25en0]/cb"} {
		if err := validateRedirect(u); err == nil {
			t.Errorf("redirect %q should be refused", u)
		}
	}
	if _, err := validCIMDURL("https://%D0%B0pple.com/c.json"); err == nil {
		t.Error("client_id with an encoded host should be refused")
	}
	// An encoded path is fine.
	if err := validateRedirect("https://a.example/cb?x=%E4%B8%AD"); err != nil {
		t.Error(err)
	}
}
