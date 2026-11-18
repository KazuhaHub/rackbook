// Package tokens implements Rackbook's optional API tokens for scripts that do
// not go through MCPHub. They live in .rackbook/tokens.yml in the data repo as
// SHA-256 hashes (a 32-byte random secret needs no slow hash), are committed
// through the Git write path, and are bounded by the current role of the user
// who created them.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// File is the token file, relative to the config directory.
const File = ".rackbook/tokens.yml"

// Prefix starts every token.
const Prefix = "rbk_"

// secretLen is the number of base62 characters of the secret: 62^43 > 2^256.
const secretLen = 43

// Scopes.
const (
	ScopeRead  = "read"
	ScopeWrite = "write"
)

// Write modes.
const (
	ModePR   = "pr"   // default: every write is a pull request
	ModePush = "push" // create and update go to the tracked branch (admin creators only)
)

// Token is one entry of tokens.yml.
type Token struct {
	Name string `yaml:"name" json:"name"`
	// ShownPrefix is the first characters of the secret, for recognising it.
	ShownPrefix string   `yaml:"prefix" json:"prefix"`
	Hash        string   `yaml:"sha256" json:"-"`
	Scope       string   `yaml:"scope" json:"scope"`
	Collections []string `yaml:"collections,omitempty" json:"collections,omitempty"`
	Actions     []string `yaml:"actions,omitempty" json:"actions,omitempty"`
	WriteMode   string   `yaml:"write_mode,omitempty" json:"writeMode,omitempty"`
	CreatedBy   string   `yaml:"created_by" json:"createdBy"`
	Created     string   `yaml:"created" json:"created"`
	Expires     string   `yaml:"expires,omitempty" json:"expires,omitempty"`
	Revoked     string   `yaml:"revoked,omitempty" json:"revoked,omitempty"`
	RevokedBy   string   `yaml:"revoked_by,omitempty" json:"revokedBy,omitempty"`
}

// ParseTime reads one of the timestamp fields ("" = zero).
func ParseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// Active reports whether the token is neither revoked nor expired at now.
func (t Token) Active(now time.Time) bool {
	if t.Revoked != "" {
		return false
	}
	if t.Expires != "" && !now.Before(ParseTime(t.Expires)) {
		return false
	}
	return true
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,39}$`)

// Actions a token may be narrowed to.
var validActions = map[string]bool{"create": true, "update": true, "delete": true}

// Validate is the built-in schema of one entry.
func (t Token) Validate() error {
	if !nameRe.MatchString(t.Name) {
		return fmt.Errorf("token name %q: use 1-40 characters from a-z 0-9 . _ - starting with a letter or digit", t.Name)
	}
	if len(t.Hash) != 64 {
		return fmt.Errorf("token %s: sha256 must be 64 hex characters", t.Name)
	}
	if _, err := hex.DecodeString(t.Hash); err != nil {
		return fmt.Errorf("token %s: sha256 is not hex", t.Name)
	}
	if t.Scope != ScopeRead && t.Scope != ScopeWrite {
		return fmt.Errorf("token %s: scope must be read or write", t.Name)
	}
	if t.WriteMode != "" && t.WriteMode != ModePR && t.WriteMode != ModePush {
		return fmt.Errorf("token %s: write_mode must be pr or push", t.Name)
	}
	for _, a := range t.Actions {
		if !validActions[a] {
			return fmt.Errorf("token %s: unknown action %q (create, update or delete)", t.Name, a)
		}
	}
	if strings.TrimSpace(t.CreatedBy) == "" {
		return fmt.Errorf("token %s: created_by is required", t.Name)
	}
	for field, v := range map[string]string{"created": t.Created, "expires": t.Expires, "revoked": t.Revoked} {
		if v != "" {
			if _, err := time.Parse(time.RFC3339, v); err != nil {
				return fmt.Errorf("token %s: %s must be an RFC 3339 time", t.Name, field)
			}
		}
	}
	return nil
}

// Document is the content of tokens.yml.
type Document struct {
	Tokens []Token `yaml:"tokens"`
}

const header = "# Rackbook API tokens (managed by Rackbook; the secrets are not stored, only their SHA-256).\n# Revoke with the console or `rackbook token revoke <name>`.\n"

// Parse reads and validates tokens.yml content. Empty content is no tokens.
func Parse(b []byte) ([]Token, error) {
	var d Document
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil && err.Error() != "EOF" {
		return nil, fmt.Errorf("%s: %w", File, err)
	}
	seen := map[string]bool{}
	for _, t := range d.Tokens {
		if err := t.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", File, err)
		}
		if seen[t.Name] {
			return nil, fmt.Errorf("%s: token %q is listed twice", File, t.Name)
		}
		seen[t.Name] = true
	}
	return d.Tokens, nil
}

// Marshal renders tokens.yml.
func Marshal(ts []Token) ([]byte, error) {
	b, err := yaml.Marshal(Document{Tokens: ts})
	if err != nil {
		return nil, err
	}
	return append([]byte(header), b...), nil
}

// Generate makes a new secret: "rbk_" and 32 random bytes in base62.
func Generate() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	n := new(big.Int).SetBytes(buf[:])
	base := big.NewInt(62)
	out := make([]byte, secretLen)
	for i := secretLen - 1; i >= 0; i-- {
		var m big.Int
		n.DivMod(n, base, &m)
		out[i] = alphabet[m.Int64()]
	}
	return Prefix + string(out), nil
}

// ShownPrefix is the part of a secret that stays visible: the first 8
// characters after "rbk_".
func ShownPrefix(secret string) string {
	s := strings.TrimPrefix(secret, Prefix)
	if len(s) > 8 {
		s = s[:8]
	}
	return Prefix + s
}

// HashSecret is the SHA-256 (hex) stored for a secret.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// ErrNotFound means no active token matches the secret. Expiry and revocation
// are reported separately so the server can log them; the client sees 401 for
// all of them.
var (
	ErrNotFound = errors.New("unknown token")
	ErrRevoked  = errors.New("token revoked")
	ErrExpired  = errors.New("token expired")
)

// Match finds the token for secret, comparing every hash in constant time.
func Match(ts []Token, secret string, now time.Time) (*Token, error) {
	if !strings.HasPrefix(secret, Prefix) || len(secret) != len(Prefix)+secretLen {
		return nil, ErrNotFound
	}
	want := HashSecret(secret)
	var found *Token
	for i := range ts {
		if subtle.ConstantTimeCompare([]byte(ts[i].Hash), []byte(want)) == 1 {
			found = &ts[i]
		}
	}
	if found == nil {
		return nil, ErrNotFound
	}
	switch {
	case found.Revoked != "":
		return nil, ErrRevoked
	case !found.Active(now):
		return nil, ErrExpired
	}
	return found, nil
}

// Sorted returns ts by creation time, newest first (a copy).
func Sorted(ts []Token) []Token {
	out := append([]Token(nil), ts...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	return out
}
