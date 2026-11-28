package statekey

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustKey(t *testing.T) *Key {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestLoadKeyMessages(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))
	dir := t.TempDir()
	f := filepath.Join(dir, "key")
	if err := os.WriteFile(f, []byte(good+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fshort := filepath.Join(dir, "short")
	os.WriteFile(fshort, []byte(short), 0o600)

	cases := []struct {
		name, env, file, wantErr string
	}{
		{"missing", "", "", "need the state key: set RACKBOOK_STATE_KEY (base64, 32 or more random bytes"},
		{"missing names the flag", "", "", "--state-key-file"},
		{"both", good, f, "set only one of RACKBOOK_STATE_KEY and --state-key-file"},
		{"short env", short, "", "RACKBOOK_STATE_KEY decodes to 16 bytes, need at least 32"},
		{"short file", "", fshort, "--state-key-file decodes to 16 bytes, need at least 32"},
		{"not base64", "!!!", "", "RACKBOOK_STATE_KEY is not valid base64"},
		{"no such file", "", filepath.Join(dir, "none"), "--state-key-file:"},
		{"env ok", good, "", ""},
		{"file ok", "", f, ""},
		{"url-safe base64 ok", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32)), "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k, err := LoadKey("RACKBOOK_STATE_KEY", c.env, c.file)
			switch {
			case c.wantErr == "" && (err != nil || k == nil):
				t.Fatalf("err = %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Fatalf("err = %v, want %q", err, c.wantErr)
			}
			if err != nil && (strings.Contains(err.Error(), good) || strings.Contains(err.Error(), short)) {
				t.Fatalf("the error leaks the key: %v", err)
			}
		})
	}
}

func TestDistinctFromSessionKey(t *testing.T) {
	k := mustKey(t)
	raw, _ := base64.StdEncoding.DecodeString(k.Base64())
	if err := k.DistinctFrom(raw); err == nil || err.Error() != "the state key must differ from the session key" {
		t.Fatalf("same key: %v", err)
	}
	if err := k.DistinctFrom(bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatalf("different key: %v", err)
	}
}

func TestSubkeysAreHKDFWithDistinctInfo(t *testing.T) {
	k := mustKey(t)
	seen := map[string]Purpose{}
	for _, p := range Purposes {
		want, err := hkdf.Key(sha256.New, k.b, nil, string(p), 32)
		if err != nil {
			t.Fatal(err)
		}
		got := k.Sub(p)
		if !bytes.Equal(got, want) || len(got) != 32 {
			t.Fatalf("%s: not HKDF-SHA256 of the key with info %q", p, p)
		}
		if bytes.Equal(got, k.b) {
			t.Fatalf("%s: the subkey is the key", p)
		}
		if q, dup := seen[string(got)]; dup {
			t.Fatalf("%s and %s share a subkey", p, q)
		}
		seen[string(got)] = p
	}
	for want, p := range map[string]Purpose{
		"rackbook accounts v1": PurposeAccounts, "rackbook secrets v1": PurposeSecrets,
		"rackbook usernames v1": PurposeUsernames, "rackbook admin channel v1": PurposeAdminChannel,
		"rackbook attempts v1": PurposeAttempts, "rackbook passkey handle v1": PurposePasskeyHandle,
	} {
		if string(p) != want {
			t.Fatalf("info string %q changed to %q", want, p)
		}
	}
}

func TestSealOpenRoundTripAndHeader(t *testing.T) {
	k := mustKey(t)
	pt := []byte(`{"secret":"value"}`)
	sealed, err := Seal(k, PurposeAccounts, pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("secret")) || bytes.Contains(sealed, []byte("value")) {
		t.Fatal("the plaintext shows in the file")
	}
	var f map[string]any
	if err := json.Unmarshal(sealed, &f); err != nil {
		t.Fatal(err)
	}
	if f["v"] != float64(1) || f["alg"] != "XChaCha20-Poly1305" || len(f["kid"].(string)) != 8 {
		t.Fatalf("header = %v", f)
	}
	nonce, _ := base64.StdEncoding.DecodeString(f["nonce"].(string))
	if len(nonce) != 24 {
		t.Fatalf("nonce is %d bytes, want 24", len(nonce))
	}
	got, err := Open(k, PurposeAccounts, sealed)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("Open = %q %v", got, err)
	}
	again, _ := Seal(k, PurposeAccounts, pt)
	if bytes.Equal(again, sealed) {
		t.Fatal("two seals of the same text are identical: the nonce is not fresh")
	}
}

func TestOpenRefusesWrongKeyOtherPurposeAndAlteredFiles(t *testing.T) {
	k, other := mustKey(t), mustKey(t)
	sealed, _ := Seal(k, PurposeAccounts, []byte("x"))

	if _, err := Open(other, PurposeAccounts, sealed); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong key: %v", err)
	}
	var kid *KeyIDError
	if _, err := Open(other, PurposeAccounts, sealed); !errors.As(err, &kid) || kid.File != k.KID() || kid.Loaded != other.KID() {
		t.Fatalf("the error should name both key ids: %v", err)
	}
	if _, err := Open(k, PurposeSecrets, sealed); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("another purpose must not open it: %v", err)
	}
	if _, err := Open(k, PurposeAccounts, []byte("garbage")); !errors.Is(err, ErrNotEncrypted) {
		t.Fatalf("garbage: %v", err)
	}
	if _, err := Open(k, PurposeAccounts, nil); !errors.Is(err, ErrNotEncrypted) {
		t.Fatalf("empty: %v", err)
	}

	// the header is the AAD: a changed kid, alg or v fails
	var f map[string]any
	f = nil
	json.Unmarshal(sealed, &f)
	f["kid"] = "00000000"
	b, _ := json.Marshal(f)
	if _, err := Open(k, PurposeAccounts, b); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("changed kid: %v", err)
	}
	f = nil
	json.Unmarshal(sealed, &f)
	f["v"] = 2
	b, _ = json.Marshal(f)
	if _, err := Open(k, PurposeAccounts, b); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("changed v: %v", err)
	}
	// an extra, unauthenticated field is refused rather than ignored
	f = nil
	json.Unmarshal(sealed, &f)
	f["extra"] = "x"
	b, _ = json.Marshal(f)
	if _, err := Open(k, PurposeAccounts, b); !errors.Is(err, ErrNotEncrypted) {
		t.Fatalf("extra field: %v", err)
	}
	// a flipped ciphertext bit
	f = nil
	json.Unmarshal(sealed, &f)
	ct, _ := base64.StdEncoding.DecodeString(f["ct"].(string))
	ct[0] ^= 1
	f["ct"] = base64.StdEncoding.EncodeToString(ct)
	b, _ = json.Marshal(f)
	if _, err := Open(k, PurposeAccounts, b); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("flipped bit: %v", err)
	}
}

func TestKeyNeverPrints(t *testing.T) {
	k := mustKey(t)
	for _, s := range []string{fmt.Sprint(k), fmt.Sprintf("%v %+v %#v %s", k, k, k, k)} {
		if strings.Contains(s, k.Base64()) || strings.Contains(s, fmt.Sprint(k.b)) {
			t.Fatal("the key printed itself")
		}
	}
	k.Zero()
	if !bytes.Equal(k.b, make([]byte, 32)) {
		t.Fatal("Zero left key bytes")
	}
}

func TestMACDiffersPerPurposeAndKey(t *testing.T) {
	k, o := mustKey(t), mustKey(t)
	a := k.MAC(PurposeUsernames, []byte("x"))
	if bytes.Equal(a, k.MAC(PurposeAccounts, []byte("x"))) || bytes.Equal(a, o.MAC(PurposeUsernames, []byte("x"))) || !bytes.Equal(a, k.MAC(PurposeUsernames, []byte("x"))) {
		t.Fatal("MAC is not keyed per purpose and key")
	}
}
