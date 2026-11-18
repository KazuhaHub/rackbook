// Package oauthtest is an in-process OAuth authorization server for tests: it
// signs access tokens and serves its metadata, JWKS and an introspection
// endpoint over HTTP on localhost. It can imitate MCPHub (ES256, RFC 8414),
// Entra ID (RS256, an issuer path /v2.0, OIDC metadata only) and Keycloak (a
// realm path).
package oauthtest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Config shapes the issuer.
type Config struct {
	Alg       string // ES256 (default), RS256, PS256, EdDSA
	Path      string // issuer path, e.g. "/v2.0" or "/realms/x"
	Discovery string // "rfc8414" (default), "oidc" or "both"
}

// Issuer serves metadata and JWKS.
type Issuer struct {
	t   testing.TB
	cfg Config
	srv *httptest.Server
	URL string // the issuer identifier (no trailing slash)

	mu   sync.Mutex
	keys []*key // published keys; the first one signs by default

	// MetadataIssuer overrides the issuer the metadata claims (to test a mismatch).
	MetadataIssuer string
	// JWKSURI overrides the jwks_uri the metadata points to.
	JWKSURI string
	// Introspect answers /introspect; nil = 404. It receives the token and
	// the basic-auth client id and secret.
	Introspect func(token, clientID, secret string) map[string]any

	Metadata        atomic.Int32 // metadata requests served
	JWKS            atomic.Int32 // JWKS requests served
	IntrospectCalls atomic.Int32
}

type key struct {
	kid  string
	alg  jose.SignatureAlgorithm
	priv any
	pub  any
}

// New starts an ES256 issuer with RFC 8414 metadata and one key, kid "k1".
func New(t testing.TB) *Issuer { return NewWith(t, Config{}) }

// NewWith starts an issuer.
func NewWith(t testing.TB, c Config) *Issuer {
	t.Helper()
	if c.Alg == "" {
		c.Alg = "ES256"
	}
	if c.Discovery == "" {
		c.Discovery = "rfc8414"
	}
	i := &Issuer{t: t, cfg: c}
	i.AddKey("k1")
	i.srv = httptest.NewServer(http.HandlerFunc(i.serve))
	t.Cleanup(i.srv.Close)
	i.URL = i.srv.URL + c.Path
	return i
}

func newKey(t testing.TB, kid, alg string) *key {
	k := &key{kid: kid, alg: jose.SignatureAlgorithm(alg)}
	switch alg {
	case "ES256":
		p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(t, err)
		k.priv, k.pub = p, &p.PublicKey
	case "RS256", "PS256":
		p, err := rsa.GenerateKey(rand.Reader, 2048)
		must(t, err)
		k.priv, k.pub = p, &p.PublicKey
	case "EdDSA":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		must(t, err)
		k.priv, k.pub = priv, pub
	default:
		t.Fatalf("unsupported alg %s", alg)
	}
	return k
}

func must(t testing.TB, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

// AddKey publishes a new key of the issuer's algorithm.
func (i *Issuer) AddKey(kid string) {
	k := newKey(i.t, kid, i.cfg.Alg)
	i.mu.Lock()
	i.keys = append(i.keys, k)
	i.mu.Unlock()
}

// DropKey stops publishing a key.
func (i *Issuer) DropKey(kid string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	var keep []*key
	for _, k := range i.keys {
		if k.kid != kid {
			keep = append(keep, k)
		}
	}
	i.keys = keep
}

func (i *Issuer) serve(w http.ResponseWriter, r *http.Request) {
	p := i.cfg.Path
	switch r.URL.Path {
	case "/.well-known/oauth-authorization-server" + p:
		if i.cfg.Discovery == "oidc" {
			http.NotFound(w, r)
			return
		}
		i.metadata(w)
	case p + "/.well-known/openid-configuration":
		if i.cfg.Discovery == "rfc8414" {
			http.NotFound(w, r)
			return
		}
		i.metadata(w)
	case p + "/jwks.json":
		i.JWKS.Add(1)
		i.mu.Lock()
		defer i.mu.Unlock()
		set := jose.JSONWebKeySet{}
		for _, k := range i.keys {
			set.Keys = append(set.Keys, jose.JSONWebKey{Key: k.pub, KeyID: k.kid, Algorithm: string(k.alg), Use: "sig"})
		}
		json.NewEncoder(w).Encode(set)
	case "/introspect":
		i.IntrospectCalls.Add(1)
		if i.Introspect == nil || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		r.ParseForm()
		id, secret, _ := r.BasicAuth()
		json.NewEncoder(w).Encode(i.Introspect(r.PostForm.Get("token"), id, secret))
	default:
		http.NotFound(w, r)
	}
}

func (i *Issuer) metadata(w http.ResponseWriter) {
	i.Metadata.Add(1)
	iss := i.MetadataIssuer
	if iss == "" {
		iss = i.URL
	}
	uri := i.JWKSURI
	if uri == "" {
		uri = i.URL + "/jwks.json"
	}
	md := map[string]any{"issuer": iss, "jwks_uri": uri}
	if i.Introspect != nil {
		md["introspection_endpoint"] = strings.TrimSuffix(i.URL, i.cfg.Path) + "/introspect"
	}
	json.NewEncoder(w).Encode(md)
}

// IntrospectURL is the issuer's introspection endpoint.
func (i *Issuer) IntrospectURL() string { return strings.TrimSuffix(i.URL, i.cfg.Path) + "/introspect" }

// Options describes a token; zero values give a good one.
type Options struct {
	Issuer   string // default: the issuer URL
	Audience any    // string or []string
	Subject  string // default "alice"
	ClientID string // default "client-1"; "-" omits client_id
	Scope    string // the scope claim, space-separated
	Scp      any    // an scp claim (string or []string), as Entra sends
	KID      string // default: the first published key
	Typ      string // default "at+jwt"; "-" omits typ
	Alg      string // "" = the issuer's; "HS256" builds a confusion token, "RS256" a token from a foreign RSA key
	NoExp    bool
	NoSub    bool
	Exp      time.Time // default now+15m
	IAT      time.Time // default now
	NBF      time.Time // zero = none
	Extra    map[string]any
	Now      time.Time // default time.Now()
}

// Mint signs a token.
func (i *Issuer) Mint(o Options) string {
	i.t.Helper()
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	i.mu.Lock()
	k := i.keys[0]
	for _, c := range i.keys {
		if c.kid == o.KID {
			k = c
		}
	}
	i.mu.Unlock()
	if o.Issuer == "" {
		o.Issuer = i.URL
	}
	if o.Subject == "" && !o.NoSub {
		o.Subject = "alice"
	}
	if o.ClientID == "" {
		o.ClientID = "client-1"
	}
	if o.Typ == "" {
		o.Typ = "at+jwt"
	}
	if o.Exp.IsZero() {
		o.Exp = o.Now.Add(15 * time.Minute)
	}
	if o.IAT.IsZero() {
		o.IAT = o.Now
	}
	claims := map[string]any{"iss": o.Issuer, "aud": o.Audience, "iat": o.IAT.Unix(), "jti": "jti-1"}
	if o.ClientID != "-" {
		claims["client_id"] = o.ClientID
	}
	if o.Scope != "" || o.Scp == nil {
		claims["scope"] = o.Scope
	}
	if o.Scp != nil {
		claims["scp"] = o.Scp
	}
	if !o.NoSub {
		claims["sub"] = o.Subject
	}
	if !o.NoExp {
		claims["exp"] = o.Exp.Unix()
	}
	if !o.NBF.IsZero() {
		claims["nbf"] = o.NBF.Unix()
	}
	for kk, v := range o.Extra {
		claims[kk] = v
	}
	kid := o.KID
	if kid == "" {
		kid = k.kid
	}
	hdr := (&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), kid)
	if o.Typ != "-" {
		hdr = hdr.WithType(jose.ContentType(o.Typ))
	}
	sk := jose.SigningKey{Algorithm: k.alg, Key: k.priv}
	switch o.Alg {
	case "":
	case "HS256":
		// The classic confusion attack: the public key bytes as the HMAC secret.
		sk = jose.SigningKey{Algorithm: jose.HS256, Key: pubDER(i.t, k.pub)}
	case "RS256", "ES256", "EdDSA", "PS256":
		f := newKey(i.t, "foreign", o.Alg)
		sk = jose.SigningKey{Algorithm: f.alg, Key: f.priv}
	default:
		i.t.Fatalf("unsupported alg %q", o.Alg)
	}
	sig, err := jose.NewSigner(sk, hdr)
	must(i.t, err)
	raw, err := jwt.Signed(sig).Claims(claims).Serialize()
	must(i.t, err)
	return raw
}

// Unsigned returns an alg none token with the same claims as o.
func (i *Issuer) Unsigned(o Options) string {
	good := i.Mint(o)
	parts := strings.Split(good, ".")
	return b64(`{"alg":"none","typ":"at+jwt","kid":"k1"}`) + "." + parts[1] + "."
}
