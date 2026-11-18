package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	graphScope      = "https://graph.microsoft.com/.default"
	tokenRefreshGap = 5 * time.Minute
	assertionTTL    = 5 * time.Minute
	maxAttempts     = 5
	maxRetryWait    = 60 * time.Second
	maxPages        = 10000
	maxBody         = 32 << 20
)

// loadKeyPair reads a PEM file holding an RSA private key (PKCS#8 or PKCS#1)
// and a certificate whose public key matches it.
func loadKeyPair(path string) (*rsa.PrivateKey, *x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var key *rsa.PrivateKey
	var certs []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if err != nil {
				return nil, nil, errors.New("certificate_file: cannot parse the PKCS#8 private key")
			}
			rk, ok := k.(*rsa.PrivateKey)
			if !ok {
				return nil, nil, errors.New("certificate_file: the private key is not RSA")
			}
			key = rk
		case "RSA PRIVATE KEY":
			rk, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
			if err != nil {
				return nil, nil, errors.New("certificate_file: cannot parse the PKCS#1 private key")
			}
			key = rk
		case "ENCRYPTED PRIVATE KEY":
			return nil, nil, errors.New("certificate_file: encrypted private keys are not supported")
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, nil, errors.New("certificate_file: cannot parse a certificate")
			}
			certs = append(certs, c)
		}
	}
	if key == nil {
		return nil, nil, errors.New("certificate_file: no RSA private key found")
	}
	if len(certs) == 0 {
		return nil, nil, errors.New("certificate_file: no certificate found")
	}
	if key.N.BitLen() < 2048 {
		return nil, nil, fmt.Errorf("certificate_file: RSA key is %d bits, need at least 2048", key.N.BitLen())
	}
	for _, c := range certs {
		if key.PublicKey.Equal(c.PublicKey) {
			return key, c, nil
		}
	}
	return nil, nil, errors.New("certificate_file: no certificate matches the private key")
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// tokenSource obtains and caches Graph access tokens with a certificate
// client assertion.
type tokenSource struct {
	endpoint string
	clientID string
	key      *rsa.PrivateKey
	x5t      string
	x5tS256  string
	http     *http.Client
	now      func() time.Time

	mu  sync.Mutex
	tok string
	exp time.Time
}

func newTokenSource(cfg EntraConfig, key *rsa.PrivateKey, cert *x509.Certificate, hc *http.Client) *tokenSource {
	s1 := sha1.Sum(cert.Raw)
	s2 := sha256.Sum256(cert.Raw)
	return &tokenSource{
		endpoint: cfg.AuthorityHost + "/" + url.PathEscape(cfg.TenantID) + "/oauth2/v2.0/token",
		clientID: cfg.ClientID,
		key:      key,
		x5t:      b64(s1[:]),
		x5tS256:  b64(s2[:]),
		http:     hc,
		now:      time.Now,
	}
}

func (t *tokenSource) assertion(now time.Time) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "x5t": t.x5t, "x5t#S256": t.x5tS256})
	claims, _ := json.Marshal(map[string]any{
		"aud": t.endpoint,
		"iss": t.clientID,
		"sub": t.clientID,
		"jti": hex.EncodeToString(jti),
		"nbf": now.Unix(),
		"iat": now.Unix(),
		"exp": now.Add(assertionTTL).Unix(),
	})
	signing := b64(hdr) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, t.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64(sig), nil
}

// Token returns a valid access token, requesting a new one when the cached
// token expires within five minutes.
func (t *tokenSource) Token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if t.tok != "" && now.Add(tokenRefreshGap).Before(t.exp) {
		return t.tok, nil
	}
	as, err := t.assertion(now)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"scope":                 {graphScope},
		"client_id":             {t.clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {as},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := t.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	var out struct {
		AccessToken string          `json:"access_token"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
		Error       string          `json:"error"`
		Description string          `json:"error_description"`
	}
	_ = json.Unmarshal(body, &out)
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		if out.Error != "" {
			return "", fmt.Errorf("token request: HTTP %d %s: %s", resp.StatusCode, out.Error, firstLine(out.Description))
		}
		return "", fmt.Errorf("token request: HTTP %d", resp.StatusCode)
	}
	secs, _ := strconv.Atoi(strings.Trim(string(out.ExpiresIn), `"`))
	if secs <= 0 {
		secs = 3600
	}
	t.tok = out.AccessToken
	t.exp = now.Add(time.Duration(secs) * time.Second)
	return t.tok, nil
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return s
}

// graphClient reads Microsoft Graph collections.
type graphClient struct {
	base  string
	ts    *tokenSource
	http  *http.Client
	sleep func(context.Context, time.Duration) error
}

func newGraphClient(base string, ts *tokenSource, hc *http.Client) *graphClient {
	return &graphClient{base: base, ts: ts, http: hc, sleep: sleepCtx}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tm.C:
		return nil
	}
}

type graphKeyCred struct {
	KeyID       string     `json:"keyId"`
	DisplayName string     `json:"displayName"`
	Start       *time.Time `json:"startDateTime"`
	End         *time.Time `json:"endDateTime"`
}

type graphObject struct {
	ID                  string         `json:"id"`
	AppID               string         `json:"appId"`
	DisplayName         string         `json:"displayName"`
	PasswordCredentials []graphKeyCred `json:"passwordCredentials"`
	KeyCredentials      []graphKeyCred `json:"keyCredentials"`
}

type graphPage struct {
	Value []graphObject `json:"value"`
	Next  string        `json:"@odata.nextLink"`
}

const selectQuery = "?$select=id,appId,displayName,passwordCredentials,keyCredentials&$top=999"

// list returns every object of a Graph collection ("applications",
// "servicePrincipals"), following nextLink on the Graph base URL only.
func (g *graphClient) list(ctx context.Context, collection string) ([]graphObject, error) {
	var all []graphObject
	next := g.base + "/" + collection + selectQuery
	for n := 0; next != ""; n++ {
		if n >= maxPages {
			return nil, fmt.Errorf("graph %s: too many pages", collection)
		}
		body, err := g.get(ctx, next)
		if err != nil {
			return nil, fmt.Errorf("graph %s: %w", collection, err)
		}
		var p graphPage
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, fmt.Errorf("graph %s: bad JSON: %w", collection, err)
		}
		all = append(all, p.Value...)
		next = p.Next
		if next != "" && !strings.HasPrefix(next, g.base+"/") {
			return nil, fmt.Errorf("graph %s: refusing nextLink outside the Graph base URL", collection)
		}
	}
	return all, nil
}

func (g *graphClient) get(ctx context.Context, u string) ([]byte, error) {
	for attempt := 1; ; attempt++ {
		tok, err := g.ts.Token(ctx)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		resp, err := g.http.Do(req)
		if err != nil {
			return nil, err
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
		if rerr != nil {
			return nil, rerr
		}
		switch resp.StatusCode {
		case http.StatusOK:
			return body, nil
		case http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			if attempt >= maxAttempts {
				return nil, fmt.Errorf("HTTP %d after %d attempts", resp.StatusCode, attempt)
			}
			wait := retryWait(resp.Header.Get("Retry-After"), attempt)
			if err := g.sleep(ctx, wait); err != nil {
				return nil, err
			}
		default:
			var e struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			_ = json.Unmarshal(body, &e)
			if e.Error.Code != "" {
				return nil, fmt.Errorf("HTTP %d %s: %s", resp.StatusCode, e.Error.Code, firstLine(e.Error.Message))
			}
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
	}
}

func retryWait(h string, attempt int) time.Duration {
	wait := time.Duration(1<<attempt) * time.Second
	if s, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && s >= 0 {
		wait = time.Duration(s) * time.Second
	}
	if wait > maxRetryWait {
		wait = maxRetryWait
	}
	return wait
}

// credential is one normalised Entra credential.
type credential struct {
	Type        string // password | certificate
	OwnerKind   string // application | servicePrincipal
	AppID       string
	OwnerID     string
	AppName     string
	KeyID       string
	DisplayName string
	Start       *time.Time
	End         *time.Time
}

// fetchCredentials reads applications (and optionally service principals)
// and returns every credential they carry, before any filtering.
func (g *graphClient) fetchCredentials(ctx context.Context, servicePrincipals bool) ([]credential, error) {
	var out []credential
	add := func(objs []graphObject, kind string) {
		for _, o := range objs {
			if o.AppID == "" {
				continue
			}
			conv := func(list []graphKeyCred, typ string) {
				for _, k := range list {
					if k.KeyID == "" {
						continue
					}
					out = append(out, credential{
						Type: typ, OwnerKind: kind, AppID: o.AppID, OwnerID: o.ID, AppName: o.DisplayName,
						KeyID: k.KeyID, DisplayName: k.DisplayName, Start: k.Start, End: k.End,
					})
				}
			}
			conv(o.PasswordCredentials, "password")
			conv(o.KeyCredentials, "certificate")
		}
	}
	apps, err := g.list(ctx, "applications")
	if err != nil {
		return nil, err
	}
	add(apps, "application")
	if servicePrincipals {
		sps, err := g.list(ctx, "servicePrincipals")
		if err != nil {
			return nil, err
		}
		add(sps, "servicePrincipal")
	}
	return out, nil
}
