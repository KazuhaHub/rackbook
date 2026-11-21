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
	id := identityOf(session{ID: "me@example.org", Method: auth.MethodOIDC, Iss: "https://idp.example", Cli: "console", OIDCAt: at.Unix()})
	if id.OIDCIssuer != "https://idp.example" || id.OIDCClient != "console" || !id.OIDCAt.Equal(at) {
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
