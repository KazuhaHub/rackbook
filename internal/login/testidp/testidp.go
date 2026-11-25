// Package testidp is a small OpenID Connect provider for tests and local
// demos: discovery, a JWKS, an authorization endpoint that signs the user in
// at once (or shows a chooser), and a token endpoint that checks PKCE and the
// client secret and issues RS256 ID tokens. It is not a real IdP and must
// never be exposed beyond localhost.
package testidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Claims are the ID-token claims of a user, besides the standard ones.
type Claims map[string]any

// IdP is the provider. Create it with New, then serve Handler over HTTPS.
type IdP struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// RedirectURIs are the redirect URIs the client may use.
	RedirectURIs []string
	// Users are offered by the chooser page, by key. User is the key signed in
	// at once when /authorize has no ?user= and the chooser is off.
	Users map[string]Claims
	User  string
	// Chooser shows a page with one link per user instead of signing User in.
	Chooser bool
	// Mutate, if set, edits the claims of every issued ID token (tests).
	Mutate func(c map[string]any)
	// TokenStatus, if non-zero, makes the token endpoint fail with it.
	TokenStatus int

	key *rsa.PrivateKey
	kid string

	mu    sync.Mutex
	codes map[string]code
}

type code struct {
	claims    Claims
	nonce     string
	challenge string
	redirect  string
	client    string
	expires   time.Time
}

// New returns a provider that signs with the RSA key of the test process
// (signingKey). issuer is the https URL it will be served at.
func New(issuer, clientID, secret string, redirectURIs ...string) *IdP {
	key, err := signingKey()
	if err != nil {
		panic(err)
	}
	return &IdP{
		Issuer: issuer, ClientID: clientID, ClientSecret: secret, RedirectURIs: redirectURIs,
		key: key, kid: "testidp-1", codes: map[string]code{}, Users: map[string]Claims{},
	}
}

// Handler serves discovery, /authorize, /token and /keys.
func (p *IdP) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /keys", p.keys)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	return mux
}

func (p *IdP) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                p.Issuer,
		"authorization_endpoint":                p.Issuer + "/authorize",
		"token_endpoint":                        p.Issuer + "/token",
		"jwks_uri":                              p.Issuer + "/keys",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (p *IdP) keys(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: p.kid, Algorithm: "RS256", Use: "sig"}}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func (p *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	okRedirect := false
	for _, u := range p.RedirectURIs {
		okRedirect = okRedirect || u == redirect
	}
	if q.Get("client_id") != p.ClientID || !okRedirect || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	user := q.Get("user")
	if user == "" && p.Chooser && len(p.Users) > 0 {
		p.chooser(w, r)
		return
	}
	if user == "" {
		user = p.User
	}
	claims, ok := p.Users[user]
	if !ok {
		http.Error(w, "unknown user", http.StatusBadRequest)
		return
	}
	c := newCode()
	p.mu.Lock()
	p.codes[c] = code{claims: claims, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: redirect, client: q.Get("client_id"), expires: time.Now().Add(time.Minute)}
	p.mu.Unlock()
	to, _ := url.Parse(redirect)
	v := to.Query()
	v.Set("code", c)
	if s := q.Get("state"); s != "" {
		v.Set("state", s)
	}
	to.RawQuery = v.Encode()
	http.Redirect(w, r, to.String(), http.StatusFound)
}

func (p *IdP) chooser(w http.ResponseWriter, r *http.Request) {
	names := make([]string, 0, len(p.Users))
	for k := range p.Users {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Test identity provider</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:30rem;margin:4rem auto;padding:0 1rem}a{display:block;padding:.7rem 1rem;margin:.5rem 0;border:1px solid #8886;border-radius:.5rem;text-decoration:none;color:inherit}a:hover{background:#8882}small{color:#888}</style>
<h1>Test identity provider</h1><p>Local stand-in for Microsoft Entra ID. Pick who signs in.</p>`)
	for _, k := range names {
		q := r.URL.Query()
		q.Set("user", k)
		who, _ := p.Users[k]["preferred_username"].(string)
		fmt.Fprintf(&b, `<a href="/authorize?%s">%s<br><small>%s</small></a>`, html.EscapeString(q.Encode()), html.EscapeString(k), html.EscapeString(who))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

func newCode() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func (p *IdP) token(w http.ResponseWriter, r *http.Request) {
	if p.TokenStatus != 0 {
		http.Error(w, `{"error":"server_error"}`, p.TokenStatus)
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthErr(w, "invalid_request")
		return
	}
	id, secret, basic := r.BasicAuth()
	if !basic {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	} else if u, err := url.QueryUnescape(id); err == nil {
		id = u
		secret, _ = url.QueryUnescape(secret)
	}
	if id != p.ClientID || subtle.ConstantTimeCompare([]byte(secret), []byte(p.ClientSecret)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]string{"error": "invalid_client"})
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		oauthErr(w, "unsupported_grant_type")
		return
	}
	p.mu.Lock()
	c, ok := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code")) // one use
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !ok || time.Now().After(c.expires) || c.redirect != r.PostForm.Get("redirect_uri") ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
		oauthErr(w, "invalid_grant")
		return
	}
	now := time.Now()
	claims := map[string]any{
		"iss": p.Issuer, "sub": fmt.Sprint(c.claims["sub"]), "aud": p.ClientID,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": c.nonce,
	}
	for k, v := range c.claims {
		claims[k] = v
	}
	if p.Mutate != nil {
		p.Mutate(claims)
	}
	idToken, err := p.sign(claims)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, map[string]any{"access_token": newCode(), "token_type": "Bearer", "expires_in": 3600, "id_token": idToken})
}

func oauthErr(w http.ResponseWriter, code string) {
	w.WriteHeader(http.StatusBadRequest)
	writeJSON(w, map[string]string{"error": code})
}

func (p *IdP) sign(claims map[string]any) (string, error) {
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: p.key, KeyID: p.kid}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	obj, err := s.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// signingKey is the one signing key of the test process. A 2048-bit RSA key
// takes hundreds of milliseconds to generate under -race and every login test
// starts a provider; no test needs two providers with different keys (one that
// needs a foreign key makes its own).
var signingKey = sync.OnceValues(func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) })
