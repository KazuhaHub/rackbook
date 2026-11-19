package oauthserver

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"github.com/kazuhahub/rackbook/internal/fsutil"
)

// Names the signing key can come from, besides the config file option.
const (
	// KeyEnv holds the PEM text of the key.
	KeyEnv = "RACKBOOK_OAUTH_SIGNING_KEY"
	// CredentialName is the systemd credential (LoadCredential=) that holds it.
	CredentialName = "oauth-signing-key"
	// DefaultKeyFile is generated in the state directory on first start.
	DefaultKeyFile = "oauth-signing-key.pem"
)

type signingKey struct {
	priv *ecdsa.PrivateKey
	kid  string
}

func newSigningKey(priv *ecdsa.PrivateKey) (*signingKey, error) {
	if priv.Curve != elliptic.P256() {
		return nil, errors.New("the signing key must be an ES256 key (ECDSA on curve P-256)")
	}
	jwk := jose.JSONWebKey{Key: &priv.PublicKey}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return &signingKey{priv: priv, kid: base64.RawURLEncoding.EncodeToString(tp)}, nil
}

// parseKey reads an unencrypted PKCS#8 or SEC 1 PEM private key.
func parseKey(pemBytes []byte) (*signingKey, error) {
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			return nil, errors.New("no PEM private key found")
		}
		switch block.Type {
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			ec, ok := k.(*ecdsa.PrivateKey)
			if !ok {
				return nil, errors.New("the signing key must be an ES256 key (ECDSA on curve P-256)")
			}
			return newSigningKey(ec)
		case "EC PRIVATE KEY":
			ec, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			return newSigningKey(ec)
		}
	}
}

// loadKey finds the signing key: the configured file, then RACKBOOK_OAUTH_SIGNING_KEY,
// then the systemd credential, and otherwise <stateDir>/oauth-signing-key.pem,
// which is generated (mode 0600) when it does not exist yet. source says where
// it came from, for the log.
func loadKey(configFile, stateDir string, getenv func(string) string) (k *signingKey, source string, err error) {
	read := func(path string) (*signingKey, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		k, err := parseKey(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return k, nil
	}
	if configFile != "" {
		k, err := read(configFile)
		return k, configFile, err
	}
	if v := strings.TrimSpace(getenv(KeyEnv)); v != "" {
		k, err := parseKey([]byte(v))
		if err != nil {
			return nil, KeyEnv, fmt.Errorf("%s: %w", KeyEnv, err)
		}
		return k, KeyEnv, nil
	}
	if dir := getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		p := filepath.Join(dir, CredentialName)
		if _, err := os.Stat(p); err == nil {
			k, err := read(p)
			return k, "systemd credential " + CredentialName, err
		}
	}
	p := filepath.Join(stateDir, DefaultKeyFile)
	k, err = read(p)
	if err == nil {
		if runtime.GOOS != "windows" {
			if st, serr := os.Stat(p); serr == nil && st.Mode().Perm()&0o077 != 0 {
				return nil, p, fmt.Errorf("%s is readable by other users (mode %v): run chmod 600 on it", p, st.Mode().Perm())
			}
		}
		return k, p, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, p, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, p, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, p, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := fsutil.WriteFileAtomic(p, out, 0o600); err != nil {
		return nil, p, fmt.Errorf("could not write the new signing key: %w", err)
	}
	k, err = newSigningKey(priv)
	return k, p + " (generated)", err
}

// jwks is the public key set served at /oauth/jwks: the current key only.
func (k *signingKey) jwks() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.priv.PublicKey, KeyID: k.kid, Algorithm: string(jose.ES256), Use: "sig"}}}
}
