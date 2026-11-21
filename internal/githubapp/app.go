// Package githubapp mints GitHub App installation access tokens. An RS256 app
// JWT (valid a few minutes) is exchanged for a short-lived installation token
// that is narrowed, per request, to one repository and the permissions the
// caller names. Tokens live in memory only, are refreshed shortly before they
// expire, and never appear in an error message or a log line.
package githubapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultAPI is the REST base URL of github.com.
const DefaultAPI = "https://api.github.com"

// RefreshBefore is how long before its expiry a cached token is replaced.
const RefreshBefore = 5 * time.Minute

// Permissions names the repository permissions one token carries. An empty
// field is not requested.
type Permissions struct {
	Contents     string // "read" or "write"
	PullRequests string // "read" or "write"
}

func (p Permissions) key() string { return "c=" + p.Contents + ",p=" + p.PullRequests }

func (p Permissions) body() map[string]string {
	m := map[string]string{}
	if p.Contents != "" {
		m["contents"] = p.Contents
	}
	if p.PullRequests != "" {
		m["pull_requests"] = p.PullRequests
	}
	return m
}

// Options configures an App.
type Options struct {
	AppID string // numeric App ID (or client ID)
	Key   *rsa.PrivateKey
	API   string // REST base URL; default DefaultAPI
	HTTP  *http.Client
	Now   func() time.Time
}

type cached struct {
	token   string
	expires time.Time
}

// App is one GitHub App credential. It is safe for concurrent use.
type App struct {
	o  Options
	mu sync.Mutex // also serialises refreshes, so a burst makes one request
	// installs maps "owner/repo" to the installation id.
	installs map[string]int64
	tokens   map[string]cached
}

// ParseKey reads the App's private key (PEM, PKCS#1 or PKCS#8 RSA).
func ParseKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(bytes.TrimSpace(data))
	if block == nil {
		return nil, errors.New("not a PEM private key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("not an RSA private key in PKCS#1 or PKCS#8 form")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("the GitHub App key must be an RSA key")
	}
	return rk, nil
}

// New checks the options and returns an App. It makes no request.
func New(o Options) (*App, error) {
	if strings.TrimSpace(o.AppID) == "" || strings.ContainsAny(o.AppID, " \t\r\n/") {
		return nil, errors.New("the GitHub App id is missing or malformed")
	}
	if o.Key == nil {
		return nil, errors.New("the GitHub App private key is missing")
	}
	if o.API == "" {
		o.API = DefaultAPI
	}
	o.API = strings.TrimRight(o.API, "/")
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &App{o: o, installs: map[string]int64{}, tokens: map[string]cached{}}, nil
}

// API is the REST base URL the App talks to.
func (a *App) API() string { return a.o.API }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jwt makes the app JWT: iat a minute in the past (clock drift), exp nine
// minutes ahead (GitHub allows ten).
func (a *App) jwt() (string, error) {
	now := a.o.Now()
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": a.o.AppID})
	signing := b64(hdr) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.o.Key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64(sig), nil
}

func (a *App) call(ctx context.Context, method, path string, bearer string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.o.API+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "rackbook")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.o.HTTP.Do(req)
	if err != nil {
		var ue *url.Error // keep the message, drop nothing secret: the URL holds none
		if errors.As(err, &ue) {
			return fmt.Errorf("github app: %s %s: %w", method, path, ue.Err)
		}
		return fmt.Errorf("github app: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		return &StatusError{Method: method, Path: path, Status: resp.StatusCode, Message: e.Message}
	}
	return json.Unmarshal(data, out)
}

// StatusError is a non-2xx answer from the GitHub API.
type StatusError struct {
	Method, Path string
	Status       int
	Message      string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("github app: %s %s: %d %s", e.Method, e.Path, e.Status, e.Message)
}

func validName(s string) bool {
	return s != "" && !strings.ContainsAny(s, "/\\ ?#%") && s != "." && s != ".."
}

// Token returns an installation access token for owner/repo carrying exactly
// the given permissions. It is cached until RefreshBefore its expiry.
func (a *App) Token(ctx context.Context, owner, repo string, p Permissions) (string, error) {
	if !validName(owner) || !validName(repo) {
		return "", fmt.Errorf("github app: unusable repository %q/%q", owner, repo)
	}
	if len(p.body()) == 0 {
		return "", errors.New("github app: no permissions requested")
	}
	full := owner + "/" + repo
	ck := full + "|" + p.key()
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.tokens[ck]; ok && a.o.Now().Add(RefreshBefore).Before(c.expires) {
		return c.token, nil
	}
	delete(a.tokens, ck)
	jwt, err := a.jwt()
	if err != nil {
		return "", fmt.Errorf("github app: sign the app JWT: %w", err)
	}
	id, ok := a.installs[full]
	if !ok {
		var inst struct {
			ID int64 `json:"id"`
		}
		if err := a.call(ctx, http.MethodGet, "/repos/"+owner+"/"+repo+"/installation", jwt, nil, &inst); err != nil {
			var se *StatusError
			if errors.As(err, &se) && se.Status == http.StatusNotFound {
				return "", fmt.Errorf("%w (is the GitHub App installed on %s?)", err, full)
			}
			return "", err
		}
		if inst.ID == 0 {
			return "", errors.New("github app: no installation id in the answer")
		}
		id = inst.ID
		a.installs[full] = id
	}
	var tok struct {
		Token   string    `json:"token"`
		Expires time.Time `json:"expires_at"`
	}
	err = a.call(ctx, http.MethodPost, "/app/installations/"+strconv.FormatInt(id, 10)+"/access_tokens", jwt,
		map[string]any{"repositories": []string{repo}, "permissions": p.body()}, &tok)
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.Status == http.StatusNotFound {
			delete(a.installs, full) // the installation moved or was removed: look it up again next time
		}
		return "", err
	}
	if tok.Token == "" || tok.Expires.IsZero() {
		return "", errors.New("github app: the access token answer is incomplete")
	}
	a.tokens[ck] = cached{token: tok.Token, expires: tok.Expires}
	return tok.Token, nil
}
