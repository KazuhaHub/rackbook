// Package statekey is the state key of local accounts: loading it, the subkeys derived
// from it, and the encrypted file format every file under it shares
// (docs/design-local-accounts.md, 4.1).
package statekey

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// MinLen is the shortest state key.
const MinLen = 32

// Purpose names a subkey. The strings are the HKDF info values of the design and never change.
type Purpose string

const (
	PurposeAccounts     Purpose = "rackbook accounts v1"
	PurposeSecrets      Purpose = "rackbook secrets v1"
	PurposeUsernames    Purpose = "rackbook usernames v1"
	PurposeAdminChannel Purpose = "rackbook admin channel v1"
	PurposeAttempts     Purpose = "rackbook attempts v1"
)

// Purposes lists every subkey purpose.
var Purposes = []Purpose{PurposeAccounts, PurposeSecrets, PurposeUsernames, PurposeAdminChannel, PurposeAttempts}

const kidInfo = "rackbook key id v1"

// Key is the loaded state key. It never prints itself.
type Key struct {
	b []byte
}

// String and GoString keep the key out of logs and error messages.
func (*Key) String() string   { return "statekey.Key(redacted)" }
func (*Key) GoString() string { return "statekey.Key(redacted)" }

// FromBytes makes a Key from raw bytes (at least MinLen). The bytes are copied.
func FromBytes(b []byte) (*Key, error) {
	if len(b) < MinLen {
		return nil, fmt.Errorf("the state key is %d bytes, need at least %d", len(b), MinLen)
	}
	return &Key{b: append([]byte(nil), b...)}, nil
}

// GenerateKey makes a new random 32-byte key (used by rekey when asked to, and by tests).
func GenerateKey() (*Key, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &Key{b: b}, nil
}

// Base64 returns the key as the text RACKBOOK_STATE_KEY takes. Callers write it only to a
// 0600 key file the operator asked for.
func (k *Key) Base64() string { return base64.StdEncoding.EncodeToString(k.b) }

// Zero overwrites the key in memory.
func (k *Key) Zero() {
	if k == nil {
		return
	}
	clear(k.b)
}

// Equal compares two keys in constant time.
func (k *Key) Equal(o *Key) bool {
	return k != nil && o != nil && subtle.ConstantTimeCompare(k.b, o.b) == 1
}

// Sub derives the subkey for purpose: HKDF-SHA256 with the purpose as info.
func (k *Key) Sub(p Purpose) []byte {
	out, err := hkdf.Key(sha256.New, k.b, nil, string(p), 32)
	if err != nil { // only for a length the function refuses; 32 is never one
		panic("statekey: " + err.Error())
	}
	return out
}

// KID is the 8 hex digits that name the key in file headers. It is derived, not a prefix of the key.
func (k *Key) KID() string {
	out, err := hkdf.Key(sha256.New, k.b, nil, kidInfo, 4)
	if err != nil {
		panic("statekey: " + err.Error())
	}
	return hex.EncodeToString(out)
}

// MAC returns HMAC-SHA256 of data under the subkey of p.
func (k *Key) MAC(p Purpose, data []byte) []byte {
	h := hmac.New(sha256.New, k.Sub(p))
	h.Write(data)
	return h.Sum(nil)
}

// DistinctFrom refuses a state key that is the same as the session key.
func (k *Key) DistinctFrom(session []byte) error {
	if len(session) > 0 && subtle.ConstantTimeCompare(k.b, session) == 1 {
		return errors.New("the state key must differ from the session key")
	}
	return nil
}

// LoadKey decodes the state key from the base64 text of the environment variable name
// (env holds its value) or reads it from file. Exactly one source may be given; the key
// must decode to at least 32 bytes. name is the variable, e.g. "RACKBOOK_STATE_KEY"; the
// flag in the messages is derived from it ("--state-key-file").
func LoadKey(name, env, file string) (*Key, error) {
	env, file = strings.TrimSpace(env), strings.TrimSpace(file)
	flag := "--" + strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(name, "RACKBOOK_"), "_", "-")) + "-file"
	switch {
	case env != "" && file != "":
		return nil, fmt.Errorf("set only one of %s and %s", name, flag)
	case env == "" && file == "":
		return nil, fmt.Errorf("local accounts and secrets set in the console need the state key: set %s (base64, 32 or more random bytes, e.g. `openssl rand -base64 32`) or pass %s", name, flag)
	}
	src := name
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", flag, err)
		}
		env, src = strings.TrimSpace(string(b)), flag
	}
	var raw []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err = enc.DecodeString(env); err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%s is not valid base64", src)
	}
	if len(raw) < MinLen {
		n := len(raw)
		clear(raw)
		return nil, fmt.Errorf("%s decodes to %d bytes, need at least %d", src, n, MinLen)
	}
	return &Key{b: raw}, nil
}

// Header is the plaintext header of an encrypted file. Its JSON form is the additional
// authenticated data, so a changed header fails to open.
type Header struct {
	V   int    `json:"v"`
	Alg string `json:"alg"`
	KID string `json:"kid"`
}

// algName is XChaCha20-Poly1305 with a random 192-bit nonce per file (the design text says AES-256-GCM
// with a 96-bit nonce; a 96-bit random nonce is safe only for about 2^32 messages under one key, and
// an account store is rewritten on every counter, so the longer nonce takes the question away).
const algName = "XChaCha20-Poly1305"

type file struct {
	Header
	Nonce string `json:"nonce"`
	CT    string `json:"ct"`
}

// Errors of Open. Callers tell them apart with errors.Is.
var (
	// ErrNotEncrypted is a file that is not in the format at all.
	ErrNotEncrypted = errors.New("not an encrypted Rackbook state file")
	// ErrWrongKey is a file that does not decrypt with the key: a wrong key, or a damaged or altered file.
	ErrWrongKey = errors.New("does not decrypt: the state key is wrong, or the file was altered")
	// ErrUnsupported is a header this version does not read.
	ErrUnsupported = errors.New("unsupported file version or algorithm")
)

// KeyIDError says which key the file was written under, when it is another one.
type KeyIDError struct{ File, Loaded string }

func (e *KeyIDError) Error() string {
	return fmt.Sprintf("the file was encrypted under key %s, the loaded state key is %s", e.File, e.Loaded)
}
func (e *KeyIDError) Unwrap() error { return ErrWrongKey }

func aad(h Header) []byte {
	b, _ := json.Marshal(h)
	return b
}

func gcm(k *Key, p Purpose) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(k.Sub(p))
}

// Seal encrypts plaintext under the subkey of p with a fresh 192-bit nonce. The result is
// the file's content: a JSON header (the AAD), the nonce and the ciphertext.
func Seal(k *Key, p Purpose, plaintext []byte) ([]byte, error) {
	g, err := gcm(k, p)
	if err != nil {
		return nil, err
	}
	h := Header{V: 1, Alg: algName, KID: k.KID()}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := g.Seal(nil, nonce, plaintext, aad(h))
	out, err := json.Marshal(file{Header: h, Nonce: base64.StdEncoding.EncodeToString(nonce), CT: base64.StdEncoding.EncodeToString(ct)})
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// Open decrypts the content of a file made by Seal.
func Open(k *Key, p Purpose, content []byte) ([]byte, error) {
	var f file
	dec := json.NewDecoder(strings.NewReader(string(content)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, ErrNotEncrypted
	}
	if f.V != 1 || f.Alg != algName {
		return nil, ErrUnsupported
	}
	nonce, err1 := base64.StdEncoding.DecodeString(f.Nonce)
	ct, err2 := base64.StdEncoding.DecodeString(f.CT)
	g, err3 := gcm(k, p)
	if err1 != nil || err2 != nil || err3 != nil || len(nonce) != g.NonceSize() {
		return nil, ErrNotEncrypted
	}
	pt, err := g.Open(nil, nonce, ct, aad(f.Header))
	if err != nil {
		if f.KID != k.KID() {
			return nil, &KeyIDError{File: f.KID, Loaded: k.KID()}
		}
		return nil, ErrWrongKey
	}
	return pt, nil
}
