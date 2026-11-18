package tokens

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestGenerateAndMatch(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		s, err := Generate()
		if err != nil || len(s) != 47 || !strings.HasPrefix(s, Prefix) || strings.Trim(s[4:], "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") != "" || seen[s] {
			t.Fatalf("%q %v", s, err)
		}
		seen[s] = true
	}
	s, _ := Generate()
	now := time.Now()
	tok := Token{Name: "a", ShownPrefix: ShownPrefix(s), Hash: HashSecret(s), Scope: ScopeRead, CreatedBy: "x@y", Created: now.Format(time.RFC3339)}
	if err := tok.Validate(); err != nil {
		t.Fatal(err)
	}
	if ShownPrefix(s) != s[:12] || len(HashSecret(s)) != 64 {
		t.Fatal("prefix/hash")
	}
	ts := []Token{tok}
	if got, err := Match(ts, s, now); err != nil || got.Name != "a" {
		t.Fatalf("%v", err)
	}
	other, _ := Generate()
	for _, bad := range []string{other, s[:46], s + "x", "", "rbk_", strings.Replace(s, "rbk_", "xxx_", 1)} {
		if _, err := Match(ts, bad, now); err != ErrNotFound {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	ts[0].Expires = now.Add(-time.Second).Format(time.RFC3339)
	if _, err := Match(ts, s, now); err != ErrExpired {
		t.Fatal(err)
	}
	ts[0].Expires, ts[0].Revoked = "", now.Format(time.RFC3339)
	if _, err := Match(ts, s, now); err != ErrRevoked {
		t.Fatal(err)
	}
}

func TestParseValidatesTheBuiltInSchema(t *testing.T) {
	for name, doc := range map[string]string{
		"bad name":   "tokens:\n- {name: Bad, sha256: " + strings.Repeat("a", 64) + ", scope: read, created_by: a@b}\n",
		"short hash": "tokens:\n- {name: ok, sha256: abc, scope: read, created_by: a@b}\n",
		"bad scope":  "tokens:\n- {name: ok, sha256: " + strings.Repeat("a", 64) + ", scope: root, created_by: a@b}\n",
		"unknown":    "tokens:\n- {name: ok, sha256: " + strings.Repeat("a", 64) + ", scope: read, created_by: a@b, admin: true}\n",
		"no creator": "tokens:\n- {name: ok, sha256: " + strings.Repeat("a", 64) + ", scope: read}\n",
		"dup":        "tokens:\n- {name: ok, sha256: " + strings.Repeat("a", 64) + ", scope: read, created_by: a@b}\n- {name: ok, sha256: " + strings.Repeat("b", 64) + ", scope: read, created_by: a@b}\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if ts, err := Parse(nil); err != nil || len(ts) != 0 {
		t.Fatal(err)
	}
}

func TestClientIPTrustsTheHeaderOnlyFromProxies(t *testing.T) {
	trusted, err := ParseCIDRs([]string{"10.0.0.0/8", "::1"})
	if err != nil {
		t.Fatal(err)
	}
	req := func(remote, hdr string) *http.Request {
		r, _ := http.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if hdr != "" {
			r.Header.Set("CF-Connecting-IP", hdr)
		}
		return r
	}
	for _, c := range []struct{ remote, hdr, want string }{
		{"10.1.2.3:555", "203.0.113.7", "203.0.113.7"},
		{"[::1]:555", "203.0.113.7", "203.0.113.7"},
		{"198.51.100.1:555", "203.0.113.7", "198.51.100.1"}, // not a proxy: header ignored
		{"10.1.2.3:555", "garbage", "10.1.2.3"},
		{"10.1.2.3:555", "", "10.1.2.3"},
	} {
		if got := ClientIP(req(c.remote, c.hdr), trusted); got != c.want {
			t.Errorf("%+v: %s", c, got)
		}
	}
	if got := ClientIP(req("10.1.2.3:1", "203.0.113.7"), nil); got != "10.1.2.3" {
		t.Fatalf("no proxies configured: %s", got)
	}
	if _, err := ParseCIDRs([]string{"nope"}); err == nil {
		t.Fatal("bad CIDR")
	}
	_ = netip.Prefix{}
}

func TestLimiterWindow(t *testing.T) {
	now := time.Now()
	l := &Limiter{Max: 3, Window: time.Minute, Now: func() time.Time { return now }}
	for i := 0; i < 3; i++ {
		if b, _ := l.Blocked("ip"); b {
			t.Fatal("early")
		}
		l.Fail("ip")
	}
	if b, wait := l.Blocked("ip"); !b || wait <= 0 {
		t.Fatal("must block")
	}
	if b, _ := l.Blocked("other"); b {
		t.Fatal("per IP")
	}
	now = now.Add(61 * time.Second)
	if b, _ := l.Blocked("ip"); b {
		t.Fatal("window must expire")
	}
}
