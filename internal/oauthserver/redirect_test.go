package oauthserver

import "testing"

// Claude Code's client metadata registers http://localhost/callback and then
// signs in with a port the system picked; RFC 8252 section 7.3 says that port
// must be accepted. Anything else still has to match exactly.
func TestRedirectAllowedLoopbackPortMayVary(t *testing.T) {
	t.Parallel()
	reg := []string{"http://localhost/callback", "http://127.0.0.1/callback", "http://[::1]/cb?x=1", "https://app.example/cb", "cursor://anysphere.cursor-retrieval/oauth/callback"}
	cases := []struct {
		uri  string
		want bool
	}{
		{"http://localhost/callback", true},
		{"http://localhost:61151/callback", true},
		{"http://127.0.0.1:49152/callback", true},
		{"http://[::1]:8080/cb?x=1", true},
		{"https://app.example/cb", true},
		{"cursor://anysphere.cursor-retrieval/oauth/callback", true},

		{"http://localhost:61151/other", false},        // path differs
		{"http://localhost:61151/callback?a=b", false}, // query differs
		{"http://localhost:61151/callback#f", false},   // fragment
		{"http://user@localhost:61151/callback", false},
		{"http://127.0.0.1:61151/cb?x=2", false},
		{"http://[::1]:8080/cb", false}, // query missing
		{"http://localhost.evil.example:80/callback", false},
		{"http://127.0.0.2:61151/callback", false},  // only the three loopback names
		{"https://localhost:61151/callback", false}, // scheme differs
		{"https://app.example:8443/cb", false},      // non-loopback port must match
		{"http://app.example/cb", false},
		{"", false},
		{"http://localhost:/callback", false},      // empty port
		{"http://localhost:0/callback", false},     // port 0
		{"http://localhost:99999/callback", false}, // out of range
		{"http://localhost:0080/callback", false},  // leading zero
		{"http://localhost:1/caf\u00e9", false},    // raw non-ASCII path
	}
	for _, c := range cases {
		if got := redirectAllowed(reg, c.uri); got != c.want {
			t.Errorf("redirectAllowed(%q) = %v, want %v", c.uri, got, c.want)
		}
	}
	// A loopback URI registered with a port matches other ports too (RFC 8252).
	if !redirectAllowed([]string{"http://localhost:3000/p"}, "http://localhost:9/p") {
		t.Error("loopback redirect registered with a port did not match another port")
	}
	// A registration with no loopback entry never opens up any port.
	if redirectAllowed([]string{"https://app.example/cb"}, "http://localhost:1/cb") {
		t.Error("loopback redirect accepted for a client that registered none")
	}
}
