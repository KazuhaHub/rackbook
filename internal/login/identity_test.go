package login

import (
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/auth"
)

// An OIDC session carries the issuer and client ID it was issued under and the
// time of the sign-in, for /infra, which pins the provider and wants a recent
// sign-in for writes. A passkey session carries none of them.
func TestIdentityCarriesTheIssuerClientAndSignInTime(t *testing.T) {
	at := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	id := identityOf(session{ID: "me@example.org", Method: auth.MethodOIDC, Iss: "https://idp.example", Cli: "console", Clm: "email", Tid: "t1", OIDCAt: at.Unix()})
	if id.OIDCClaim != "email" || id.OIDCTenant != "t1" || id.OIDCIssuer != "https://idp.example" || id.OIDCClient != "console" || !id.OIDCAt.Equal(at) {
		t.Fatalf("%+v", id)
	}
	pk := identityOf(session{ID: "me@example.org", Method: auth.MethodPasskey, Iss: "x", Cli: "y", OIDCAt: at.Unix()})
	if pk.OIDCIssuer != "" || pk.OIDCClient != "" || !pk.OIDCAt.IsZero() {
		t.Fatalf("a passkey session is not an OIDC sign-in: %+v", pk)
	}
	// an old cookie has no client ID: it does not match any pin
	old := identityOf(session{ID: "me@example.org", Method: auth.MethodOIDC, Iss: "https://idp.example", OIDCAt: at.Unix()})
	if old.OIDCClient != "" {
		t.Fatalf("%+v", old)
	}
	// the cookie round-trips the new field
	c := codec{key: make([]byte, 32)}
	v, err := c.seal(session{ID: "a@b.c", Method: "oidc", Issued: 1, Seen: 1, Iss: "i", Cli: "c"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.open(v)
	if err != nil || got.Cli != "c" || got.Iss != "i" {
		t.Fatalf("%v %+v", err, got)
	}
}

// A real login records the issuer, client ID, identity claim and tenant it
// was established with, so /infra can refuse a session whose provider
// settings came from an edited rackbook.yml.
func TestLoginRecordsWhatTheInfraPinChecks(t *testing.T) {
	for name, c := range map[string]struct{ oidc, claim string }{
		"default claim":    {"", "preferred_username"},
		"another claim":    {"    identity_claim: upn\n", "upn"},
		"subject identity": {"    identity: subject\n", "sub"},
	} {
		e := newEnv(t, options{oidc: c.oidc, roles: "  roles:\n    admin: [\"oidc:sub-admin\"]\n    viewer: [\"*\"]\n"})
		e.idp.Users["admin"]["upn"] = "admin@kazuha.org"
		b := e.browser()
		if r := b.login("admin", ""); r.StatusCode != 303 {
			t.Fatalf("%s: login %d", name, r.StatusCode)
		} else if r.Loc() != "/" {
			t.Fatalf("%s: login went to %s", name, r.Loc())
		}
		sess, err := e.svc.codec.open(b.cookie(SessionCookie).Value)
		if err != nil {
			t.Fatal(err)
		}
		id := identityOf(sess)
		if id.OIDCClaim != c.claim || id.OIDCTenant != tenant || id.OIDCClient != clientID || id.OIDCIssuer != e.idpS.URL {
			t.Errorf("%s: %+v", name, id)
		}
	}
}
