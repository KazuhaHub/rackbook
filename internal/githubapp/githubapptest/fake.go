// Package githubapptest is a fake GitHub for tests: a REST API that issues
// installation tokens to a verified app JWT, and a smart-HTTP git server (git
// http-backend) that accepts only a currently valid token for the repository
// and the permission the operation needs.
package githubapptest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Issued is one token the API handed out.
type Issued struct {
	Token   string
	Repo    string // owner/repo
	Perms   map[string]string
	Expires time.Time
}

// API is the fake REST API.
type API struct {
	*httptest.Server
	AppID    string
	Key      *rsa.PrivateKey
	Lifetime time.Duration // default one hour

	mu        sync.Mutex
	now       func() time.Time
	installed map[string]int64 // owner/repo -> installation id
	issued    []Issued
	pulls     []string
	lookups   int
	jwtErrs   int
}

// NewAPI starts the fake. now is the shared test clock (nil = real time).
func NewAPI(t testing.TB, appID string, now func() time.Time) *API {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if now == nil {
		now = time.Now
	}
	a := &API{AppID: appID, Key: key, Lifetime: time.Hour, now: now, installed: map[string]int64{}}
	a.Server = httptest.NewServer(http.HandlerFunc(a.serve))
	t.Cleanup(a.Server.Close)
	return a
}

// KeyPEM is the App's private key in PKCS#1 PEM form.
func (a *API) KeyPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(a.Key)})
}

// Install makes the App installed on owner/repo.
func (a *API) Install(repo string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.installed[repo] = int64(1000 + len(a.installed))
}

// Issued lists the tokens handed out so far.
func (a *API) Issued() []Issued {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Issued{}, a.issued...)
}

// Lookups is how many installation lookups were made.
func (a *API) Lookups() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lookups
}

// Valid reports whether token is unexpired, was issued for repo and carries
// permission perm at the given level (a "write" token also satisfies "read").
func (a *API) Valid(token, repo, perm, level string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, i := range a.issued {
		if i.Token != token || i.Repo != repo || !a.now().Before(i.Expires) {
			continue
		}
		have := i.Perms[perm]
		if have == level || (level == "read" && have == "write") {
			return true
		}
	}
	return false
}

func (a *API) checkJWT(r *http.Request) bool {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&a.Key.PublicKey, crypto.SHA256, sum[:], sig) != nil {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var c struct {
		Iss string `json:"iss"`
		Exp int64  `json:"exp"`
		Iat int64  `json:"iat"`
	}
	if json.Unmarshal(raw, &c) != nil || c.Iss != a.AppID {
		return false
	}
	n := a.now().Unix()
	return c.Exp > n && c.Exp-c.Iat <= 600+60 && c.Iat <= n
}

// PullRequests lists the pull requests opened: owner/repo and the head branch.
func (a *API) PullRequests() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string{}, a.pulls...)
}

// servePull handles POST /repos/<owner>/<repo>/pulls with an installation
// token that carries pull_requests: write for that repository.
func (a *API) servePull(w http.ResponseWriter, r *http.Request) {
	repo := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/repos/"), "/pulls")
	if !a.Valid(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), repo, "pull_requests", "write") {
		http.Error(w, `{"message":"Resource not accessible by integration"}`, http.StatusForbidden)
		return
	}
	var body struct {
		Head string `json:"head"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	a.mu.Lock()
	a.pulls = append(a.pulls, repo+" "+body.Head)
	n := len(a.pulls)
	a.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"html_url": fmt.Sprintf("https://github.com/%s/pull/%d", repo, n)})
}

func (a *API) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/repos/") && strings.HasSuffix(r.URL.Path, "/pulls") {
		a.servePull(w, r)
		return
	}
	if !a.checkJWT(r) {
		a.mu.Lock()
		a.jwtErrs++
		a.mu.Unlock()
		http.Error(w, `{"message":"A JSON web token could not be decoded"}`, http.StatusUnauthorized)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	path := r.URL.Path
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/repos/") && strings.HasSuffix(path, "/installation"):
		repo := strings.TrimSuffix(strings.TrimPrefix(path, "/repos/"), "/installation")
		a.lookups++
		id, ok := a.installed[repo]
		if !ok {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]int64{"id": id})
	case r.Method == http.MethodPost && strings.HasPrefix(path, "/app/installations/") && strings.HasSuffix(path, "/access_tokens"):
		var id int64
		fmt.Sscanf(strings.TrimPrefix(path, "/app/installations/"), "%d", &id)
		var body struct {
			Repositories []string          `json:"repositories"`
			Permissions  map[string]string `json:"permissions"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Repositories) != 1 || len(body.Permissions) == 0 {
			http.Error(w, `{"message":"token must be narrowed to one repository and named permissions"}`, http.StatusUnprocessableEntity)
			return
		}
		var repo string
		for full, i := range a.installed {
			if i == id && strings.HasSuffix(full, "/"+body.Repositories[0]) {
				repo = full
			}
		}
		if repo == "" {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		exp := a.now().Add(a.Lifetime).UTC().Truncate(time.Second)
		tok := fmt.Sprintf("ghs_fake%03d_%s", len(a.issued)+1, strings.ReplaceAll(repo, "/", "_"))
		a.issued = append(a.issued, Issued{Token: tok, Repo: repo, Perms: body.Permissions, Expires: exp})
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": tok, "expires_at": exp.Format(time.RFC3339)})
	default:
		http.NotFound(w, r)
	}
}

// Git is a smart-HTTP git server over bare repositories under Root, laid out
// as <Root>/<owner>/<repo>.git. Requests need a Basic Authorization header
// carrying a token the API issued for that repository: contents read to fetch,
// contents write to push.
type Git struct {
	*httptest.Server
	Root string
	API  *API

	mu     sync.Mutex
	denied int
	served int
}

// NewGit starts the server. backend is the path of git-http-backend; the
// caller finds it (git --exec-path) because only gitstore's runner may start git.
func NewGit(t testing.TB, api *API, backend string) *Git {
	t.Helper()
	g := &Git{Root: t.TempDir(), API: api}
	h := &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + g.Root, "GIT_HTTP_EXPORT_ALL=1"}}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.authorised(r) {
			g.mu.Lock()
			g.denied++
			g.mu.Unlock()
			w.Header().Set("WWW-Authenticate", `Basic realm="fake"`)
			http.Error(w, "denied", http.StatusUnauthorized)
			return
		}
		g.mu.Lock()
		g.served++
		g.mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(g.Server.Close)
	return g
}

func (g *Git) authorised(r *http.Request) bool {
	user, tok, ok := r.BasicAuth()
	if !ok || user != "x-access-token" {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		return false
	}
	repo := parts[0] + "/" + strings.TrimSuffix(parts[1], ".git")
	level := "read"
	if strings.HasSuffix(r.URL.Path, "/git-receive-pack") || r.URL.Query().Get("service") == "git-receive-pack" {
		level = "write"
	}
	return g.API.Valid(tok, repo, "contents", level)
}

// Denied and Served count requests the server refused and handled.
func (g *Git) Denied() int { g.mu.Lock(); defer g.mu.Unlock(); return g.denied }
func (g *Git) Served() int { g.mu.Lock(); defer g.mu.Unlock(); return g.served }

// Path is where the bare repository owner/repo lives (the caller runs `git
// init --bare --initial-branch=main` there and sets http.receivepack to true).
// It also installs the App on that repository.
func (g *Git) Path(t testing.TB, repo string) string {
	t.Helper()
	dir := filepath.Join(g.Root, filepath.FromSlash(repo)+".git")
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	g.API.Install(repo)
	return dir
}

// URL is the clone URL of owner/repo.
func (g *Git) URL(repo string) string { return g.Server.URL + "/" + repo + ".git" }
