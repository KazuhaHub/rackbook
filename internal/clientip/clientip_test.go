package clientip

import (
	"net/http/httptest"
	"testing"
)

func TestOf(t *testing.T) {
	trusted, _ := ParseCIDRs([]string{"10.0.0.0/8"})
	req := func(remote, hdr string) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if hdr != "" {
			r.Header.Set("CF-Connecting-IP", hdr)
		}
		return Of(r, trusted)
	}
	if got := req("10.1.2.3:1", "203.0.113.9"); got != "203.0.113.9" {
		t.Errorf("trusted proxy: %s", got)
	}
	if got := req("198.51.100.7:1", "203.0.113.9"); got != "198.51.100.7" {
		t.Errorf("untrusted peers cannot name another client: %s", got)
	}
	if got := req("127.0.0.1:1", "203.0.113.9"); got != "127.0.0.1" {
		t.Errorf("loopback is not trusted unless listed: %s", got)
	}
	if a, b := req("[2001:db8:1:2:aaaa::1]:1", ""), req("[2001:db8:1:2:bbbb::2]:1", ""); a != b || a != "2001:db8:1:2::/64" {
		t.Errorf("IPv6 is bucketed by /64: %s %s", a, b)
	}
}
