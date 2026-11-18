// Package oauth verifies the access tokens of the OAuth authorization servers
// that Rackbook's /mcp endpoint trusts (auth.mcp.trusted_issuers): MCPHub,
// Microsoft Entra ID, Keycloak, or any other server that publishes standard
// metadata. Verification is offline and strict.
//
//   - Only the issuer's configured signing algorithms are accepted (default
//     ES256, RS256, PS256, EdDSA). HS* and none are never parsed, whatever the
//     config says.
//   - typ must be at+jwt (RFC 9068; any case, or application/at+jwt). An issuer
//     that does not set it (Entra) may be configured with require_typ_at_jwt:
//     false, which also accepts typ JWT or none, but still refuses ID tokens:
//     typ id_token, a token whose aud is not the configured audience, and a
//     token with a nonce but no scope.
//   - iss and aud must equal the configured values exactly (aud may be an array
//     that contains the audience); exp and sub are required; iat and nbf are
//     honoured with 60 s of clock skew.
//   - Keys come from the issuer's JWKS: jwks_uri of its RFC 8414 metadata
//     (/.well-known/oauth-authorization-server), else of its OIDC metadata
//     (/.well-known/openid-configuration), whose issuer must equal the
//     configured one; or jwks_url from the config. Everything is fetched over
//     HTTPS (http only for localhost), cached, and refetched at most once a
//     minute, on an unknown kid or when the cache is older than KeyTTL.
//   - Opaque tokens are checked by RFC 7662 introspection when the issuer has
//     an introspection block (results cached 60 s).
package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/kazuhahub/rackbook/internal/config"
)

const (
	// Skew is the clock skew tolerated for exp, nbf and iat.
	Skew = 60 * time.Second
	// MinRefetch is the shortest time between two fetches of one issuer's
	// metadata or JWKS.
	MinRefetch = time.Minute
	// KeyTTL is how long a fetched JWKS is used before it is refreshed, so a
	// key the issuer dropped (emergency rotation) stops verifying.
	KeyTTL = 10 * time.Minute
	// IntrospectionTTL is how long an introspection answer is reused.
	IntrospectionTTL = 60 * time.Second

	maxBody = 1 << 20
	minRSA  = 2048
)

// ErrInvalid wraps every reason a token is refused. Callers answer 401.
var ErrInvalid = errors.New("invalid access token")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Claims is a verified access token.
type Claims struct {
	Issuer   string
	Alias    string // the issuer's alias from the config
	Kind     string // config.KindOAuth or config.KindMCPHub
	Subject  string
	Username string // the claim named by username_claim (default sub)
	ClientID string
	Scopes   []string
	Expiry   time.Time
	JTI      string
}

// Verifier verifies tokens for the issuers of auth.mcp.trusted_issuers. It
// keeps one key cache per issuer and is safe for concurrent use. The set of
// trusted issuers is passed on every call, so a config reload applies at once.
type Verifier struct {
	// HTTP fetches metadata, JWKS and introspection; nil = a client with a 10 s
	// timeout that follows no redirects.
	HTTP *http.Client
	// Now is the clock; nil = time.Now.
	Now func() time.Time
	// Getenv reads client secrets; nil = os.Getenv.
	Getenv func(string) string

	mu      sync.Mutex
	issuers map[string]*issuerState
	intro   map[[32]byte]introEntry
}

type introEntry struct {
	claims *Claims // nil = negative
	until  time.Time
}

type issuerState struct {
	mu        sync.Mutex
	keys      map[string]jose.JSONWebKey
	keysAt    time.Time // last successful JWKS fetch
	attempted time.Time // last JWKS attempt
	introURL  string
	introTry  time.Time
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) client() *http.Client {
	if v.HTTP != nil {
		return v.HTTP
	}
	return &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (v *Verifier) state(key string) *issuerState {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.issuers == nil {
		v.issuers = map[string]*issuerState{}
	}
	st := v.issuers[key]
	if st == nil {
		st = &issuerState{}
		v.issuers[key] = st
	}
	return st
}

func allAlgs() []jose.SignatureAlgorithm {
	var out []jose.SignatureAlgorithm
	for a := range config.AllowedAlgorithms {
		out = append(out, jose.SignatureAlgorithm(a))
	}
	return out
}

// Verify checks raw against the trusted issuers of m.
func (v *Verifier) Verify(ctx context.Context, raw string, m config.AuthMCP) (*Claims, error) {
	if !looksLikeJWT(raw) {
		return v.verifyOpaque(ctx, raw, m)
	}
	// Only algorithms that some issuer may list are parsed at all: none and HS*
	// fail here, before any key is looked at.
	tok, err := jwt.ParseSigned(raw, allAlgs())
	if err != nil {
		return nil, invalid("not a JWT signed with an accepted algorithm")
	}
	if len(tok.Headers) != 1 {
		return nil, invalid("exactly one signature is required")
	}
	h := tok.Headers[0]
	// The issuer is read before the signature is checked only to choose which
	// trusted issuer's rules and keys to check it with.
	var peek struct {
		Iss string `json:"iss"`
	}
	if err := tok.UnsafeClaimsWithoutVerification(&peek); err != nil {
		return nil, invalid("unreadable claims")
	}
	var ti *config.TrustedIssuer
	for i := range m.TrustedIssuers {
		if m.TrustedIssuers[i].Issuer == peek.Iss { // exact: no trailing-slash or case folding
			ti = &m.TrustedIssuers[i]
		}
	}
	if ti == nil {
		return nil, invalid("issuer is not trusted")
	}
	okAlg := false
	for _, a := range ti.AlgorithmList() {
		okAlg = okAlg || a == h.Algorithm
	}
	if !okAlg {
		return nil, invalid("algorithm %s is not allowed for this issuer", h.Algorithm)
	}
	typ, _ := h.ExtraHeaders[jose.HeaderType].(string)
	atJWT := isATJWT(typ)
	if !atJWT && (ti.NeedTypATJWT() || !strings.EqualFold(typ, "jwt") && typ != "") {
		return nil, invalid("typ must be at+jwt")
	}
	if h.KeyID == "" {
		return nil, invalid("the header has no kid")
	}
	aud := m.Audience(*ti)
	if aud == "" {
		return nil, invalid("no audience configured")
	}

	key, err := v.key(ctx, *ti, h.KeyID)
	if err != nil {
		return nil, err
	}
	var std jwt.Claims
	var all map[string]any
	if err := tok.Claims(key.Key, &std, &all); err != nil {
		return nil, invalid("bad signature")
	}
	if std.Expiry == nil {
		return nil, invalid("exp is required")
	}
	if std.Subject == "" {
		return nil, invalid("sub is required")
	}
	exp := jwt.Expected{Issuer: ti.Issuer, AnyAudience: jwt.Audience{aud}, Time: v.now()}
	if err := std.ValidateWithLeeway(exp, Skew); err != nil {
		return nil, invalid("%v", err)
	}
	c := &Claims{Issuer: std.Issuer, Alias: ti.Name(), Kind: kindOf(*ti), Subject: std.Subject, Username: std.Subject, Expiry: std.Expiry.Time(), JTI: std.ID}
	if s, ok := all["client_id"].(string); ok {
		c.ClientID = s
	} else if s, ok := all["azp"].(string); ok { // Entra v2, Keycloak
		c.ClientID = s
	} else if s, ok := all["appid"].(string); ok { // Entra v1
		c.ClientID = s
	}
	c.Scopes, _ = scopesOf(all, ti.ScopeClaim)
	hasScope := len(c.Scopes) > 0
	if !atJWT {
		// Not an RFC 9068 token, so make sure it is not an ID token in disguise.
		if _, nonce := all["nonce"]; nonce && !hasScope {
			return nil, invalid("looks like an ID token (nonce, no scope)")
		}
	}
	if cl := ti.UsernameClaim; cl != "" && cl != "sub" {
		u, _ := all[cl].(string)
		if strings.TrimSpace(u) == "" {
			return nil, invalid("claim %q (username_claim) is missing", cl)
		}
		c.Username = u
	}
	return c, nil
}

func kindOf(ti config.TrustedIssuer) string {
	if ti.Kind == config.KindMCPHub {
		return config.KindMCPHub
	}
	return config.KindOAuth
}

func looksLikeJWT(raw string) bool {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var h map[string]any
	return json.Unmarshal(b, &h) == nil
}

func isATJWT(typ string) bool {
	typ = strings.ToLower(typ)
	return typ == "at+jwt" || typ == "application/at+jwt"
}

// scopesOf reads the scopes from claim (or scope, then scp) as a
// space-separated string or an array. present says a scope claim exists.
func scopesOf(all map[string]any, claim string) (scopes []string, present bool) {
	names := []string{"scope", "scp"}
	if claim != "" {
		names = []string{claim}
	}
	for _, n := range names {
		switch x := all[n].(type) {
		case string:
			return strings.Fields(x), true
		case []any:
			for _, e := range x {
				if s, ok := e.(string); ok {
					scopes = append(scopes, strings.Fields(s)...)
				}
			}
			return scopes, true
		}
	}
	return nil, false
}

// key returns the issuer's key for kid, fetching the JWKS when needed.
func (v *Verifier) key(ctx context.Context, ti config.TrustedIssuer, kid string) (*jose.JSONWebKey, error) {
	st := v.state(ti.Issuer + "\x00" + ti.JWKSURL)
	st.mu.Lock()
	defer st.mu.Unlock()
	now := v.now()
	stale := st.keys == nil || now.Sub(st.keysAt) >= KeyTTL
	if k, ok := st.keys[kid]; ok && !stale {
		return &k, nil
	}
	// Unknown kid or an old cache: refetch, but never more than once a minute.
	if st.attempted.IsZero() || now.Sub(st.attempted) >= MinRefetch {
		st.attempted = now
		if err := v.refresh(ctx, st, ti); err != nil && st.keys == nil {
			return nil, fmt.Errorf("%w: cannot load the issuer's keys: %v", ErrInvalid, err)
		}
		// With keys already cached, keep verifying when the issuer is briefly down.
	}
	if k, ok := st.keys[kid]; ok {
		return &k, nil
	}
	return nil, invalid("unknown signing key")
}

func (v *Verifier) refresh(ctx context.Context, st *issuerState, ti config.TrustedIssuer) error {
	jwksURL := ti.JWKSURL
	if jwksURL == "" {
		md, err := v.discover(ctx, ti.Issuer)
		if err != nil {
			return err
		}
		jwksURL = md.JWKSURI
		if u, err := url.Parse(jwksURL); err != nil || u.Scheme != "https" && !isLocalHTTP(u) {
			return fmt.Errorf("jwks_uri %q must be https", jwksURL)
		}
		st.introURL = md.IntrospectionEndpoint
	}
	if err := config.ValidURL(jwksURL, true); err != nil {
		return fmt.Errorf("jwks_uri: %w", err)
	}
	var set jose.JSONWebKeySet
	if err := v.getJSON(ctx, jwksURL, &set); err != nil {
		return err
	}
	keys := map[string]jose.JSONWebKey{}
	for _, k := range set.Keys {
		if k.KeyID == "" || !k.Valid() || !k.IsPublic() {
			continue // never accept a private key published in a JWKS, nor a key without kid
		}
		switch pk := k.Key.(type) {
		case *ecdsa.PublicKey, ed25519.PublicKey:
		case *rsa.PublicKey:
			if pk.N.BitLen() < minRSA {
				continue
			}
		default:
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Algorithm != "" {
			allowed := false
			for _, a := range ti.AlgorithmList() {
				allowed = allowed || a == k.Algorithm
			}
			if !allowed {
				continue
			}
		}
		keys[k.KeyID] = k
	}
	st.keys, st.keysAt = keys, v.now()
	return nil
}

// metadataURLs are where an issuer's metadata may be: RFC 8414 (the well-known
// segment inserted before the issuer's path), then OIDC Discovery (appended to
// the issuer, the form Entra and Keycloak use), then OIDC with the segment
// inserted.
func metadataURLs(issuer string) ([]string, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, err
	}
	base := u.Scheme + "://" + u.Host
	p := strings.TrimRight(u.Path, "/")
	return []string{
		base + "/.well-known/oauth-authorization-server" + p,
		base + p + "/.well-known/openid-configuration",
		base + "/.well-known/openid-configuration" + p,
	}, nil
}

// MetadataURL is the RFC 8414 metadata URL of an issuer.
func MetadataURL(issuer string) (string, error) {
	us, err := metadataURLs(issuer)
	if err != nil {
		return "", err
	}
	return us[0], nil
}

type metadata struct {
	Issuer                string `json:"issuer"`
	JWKSURI               string `json:"jwks_uri"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
}

func (v *Verifier) discover(ctx context.Context, issuer string) (*metadata, error) {
	if err := config.ValidURL(issuer, false); err != nil {
		return nil, err
	}
	urls, err := metadataURLs(issuer)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, mu := range urls {
		var md metadata
		if err := v.getJSON(ctx, mu, &md); err != nil {
			lastErr = err
			continue
		}
		if md.Issuer != issuer {
			return nil, fmt.Errorf("metadata at %s names issuer %q, expected %q", mu, md.Issuer, issuer)
		}
		if md.JWKSURI == "" {
			return nil, fmt.Errorf("metadata at %s has no jwks_uri", mu)
		}
		return &md, nil
	}
	return nil, fmt.Errorf("no issuer metadata found (tried %s): %v", strings.Join(urls, ", "), lastErr)
}

func isLocalHTTP(u *url.URL) bool {
	if u == nil || u.Scheme != "http" {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

func (v *Verifier) getJSON(ctx context.Context, rawURL string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	return v.doJSON(req, out)
}

func (v *Verifier) doJSON(req *http.Request, out any) error {
	resp, err := v.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: %s", req.Method, req.URL, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s %s: %w", req.Method, req.URL, err)
	}
	return nil
}

// Introspection (RFC 7662) ---------------------------------------------------

func (v *Verifier) verifyOpaque(ctx context.Context, raw string, m config.AuthMCP) (*Claims, error) {
	key := sha256.Sum256([]byte(raw))
	now := v.now()
	v.mu.Lock()
	e, ok := v.intro[key]
	v.mu.Unlock()
	if ok && now.Before(e.until) {
		if e.claims == nil {
			return nil, invalid("token is not active")
		}
		if now.Before(e.claims.Expiry.Add(Skew)) {
			return e.claims, nil
		}
	}
	var lastErr error
	tried := false
	for i := range m.TrustedIssuers {
		ti := m.TrustedIssuers[i]
		if ti.Introspection == nil {
			continue
		}
		tried = true
		c, err := v.introspect(ctx, raw, ti, m.Audience(ti))
		if err != nil {
			lastErr = err
			continue
		}
		v.cacheIntro(key, c, now.Add(IntrospectionTTL))
		return c, nil
	}
	if !tried {
		return nil, invalid("opaque tokens are not accepted (no issuer has an introspection block)")
	}
	v.cacheIntro(key, nil, now.Add(10*time.Second))
	return nil, lastErr
}

func (v *Verifier) cacheIntro(key [32]byte, c *Claims, until time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.intro == nil || len(v.intro) > 2000 {
		v.intro = map[[32]byte]introEntry{}
	}
	v.intro[key] = introEntry{c, until}
}

func (v *Verifier) introspect(ctx context.Context, raw string, ti config.TrustedIssuer, aud string) (*Claims, error) {
	in := ti.Introspection
	endpoint := in.Endpoint
	if endpoint == "" {
		st := v.state(ti.Issuer + "\x00" + ti.JWKSURL)
		st.mu.Lock()
		if st.introURL == "" && (st.introTry.IsZero() || v.now().Sub(st.introTry) >= MinRefetch) {
			st.introTry = v.now()
			if md, err := v.discover(ctx, ti.Issuer); err == nil {
				st.introURL = md.IntrospectionEndpoint
			}
		}
		endpoint = st.introURL
		st.mu.Unlock()
	}
	if endpoint == "" {
		return nil, invalid("issuer %s has no introspection endpoint", ti.Name())
	}
	if err := config.ValidURL(endpoint, false); err != nil {
		return nil, invalid("introspection endpoint: %v", err)
	}
	getenv := v.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	secret := getenv(in.ClientSecretEnv)
	if secret == "" {
		return nil, invalid("introspection: environment variable %s is empty", in.ClientSecretEnv)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	form := url.Values{"token": {raw}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(in.ClientID), url.QueryEscape(secret))
	var out map[string]any
	if err := v.doJSON(req, &out); err != nil {
		return nil, invalid("introspection failed: %v", err)
	}
	if a, _ := out["active"].(bool); !a {
		return nil, invalid("token is not active")
	}
	if iss, ok := out["iss"].(string); ok && iss != ti.Issuer {
		return nil, invalid("issuer mismatch")
	}
	if !audContains(out["aud"], aud) {
		return nil, invalid("audience mismatch")
	}
	sub, _ := out["sub"].(string)
	if sub == "" {
		return nil, invalid("sub is required")
	}
	now := v.now()
	expF, ok := out["exp"].(float64)
	if !ok {
		return nil, invalid("exp is required")
	}
	exp := time.Unix(int64(expF), 0)
	if now.After(exp.Add(Skew)) {
		return nil, invalid("token expired")
	}
	if nb, ok := out["nbf"].(float64); ok && now.Add(Skew).Before(time.Unix(int64(nb), 0)) {
		return nil, invalid("token not valid yet")
	}
	c := &Claims{Issuer: ti.Issuer, Alias: ti.Name(), Kind: kindOf(ti), Subject: sub, Username: sub, Expiry: exp}
	c.ClientID, _ = out["client_id"].(string)
	c.Scopes, _ = scopesOf(out, ti.ScopeClaim)
	if cl := ti.UsernameClaim; cl != "" && cl != "sub" {
		u, _ := out[cl].(string)
		if strings.TrimSpace(u) == "" {
			return nil, invalid("claim %q (username_claim) is missing", cl)
		}
		c.Username = u
	}
	return c, nil
}

func audContains(v any, aud string) bool {
	switch x := v.(type) {
	case string:
		return x == aud
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok && s == aud {
				return true
			}
		}
	}
	return false
}
