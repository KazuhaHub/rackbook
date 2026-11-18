package oauthtest

import (
	"crypto/x509"
	"encoding/base64"
	"testing"
)

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func pubDER(t testing.TB, k any) []byte {
	b, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
