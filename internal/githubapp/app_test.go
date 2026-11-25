package githubapp_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/githubapp"
	"github.com/kazuhahub/rackbook/internal/githubapp/githubapptest"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func setup(t *testing.T) (*githubapptest.API, *githubapp.App, *clock) {
	t.Helper()
	clk := &clock{t: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	api := githubapptest.NewAPI(t, "12345", clk.now)
	key, err := githubapp.ParseKey(api.KeyPEM())
	if err != nil {
		t.Fatal(err)
	}
	app, err := githubapp.New(githubapp.Options{AppID: "12345", Key: key, API: api.URL, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	return api, app, clk
}

var write = githubapp.Permissions{Contents: "write"}

func TestTokenIsNarrowedCachedAndRefreshedBeforeExpiry(t *testing.T) {
	api, app, clk := setup(t)
	api.Install("org/ledger")
	ctx := context.Background()

	t1, err := app.Token(ctx, "org", "ledger", write)
	if err != nil {
		t.Fatal(err)
	}
	iss := api.Issued()
	if len(iss) != 1 || iss[0].Repo != "org/ledger" || len(iss[0].Perms) != 1 || iss[0].Perms["contents"] != "write" {
		t.Fatalf("token request was not narrowed: %+v", iss)
	}
	// Cached: no second token and no second installation lookup.
	if t2, _ := app.Token(ctx, "org", "ledger", write); t2 != t1 || len(api.Issued()) != 1 {
		t.Fatalf("expected the cached token, issued %d", len(api.Issued()))
	}
	// 54 minutes in (6 minutes left): still cached. 56 minutes (4 left): refreshed.
	clk.add(54 * time.Minute)
	if t2, _ := app.Token(ctx, "org", "ledger", write); t2 != t1 {
		t.Fatal("refreshed too early")
	}
	clk.add(2 * time.Minute)
	t3, err := app.Token(ctx, "org", "ledger", write)
	if err != nil || t3 == t1 || len(api.Issued()) != 2 {
		t.Fatalf("expected a refresh 5 minutes before expiry: %v issued=%d", err, len(api.Issued()))
	}
	if api.Lookups() != 1 {
		t.Fatalf("installation id should be looked up once, got %d", api.Lookups())
	}
	if !api.Valid(t3, "org/ledger", "contents", "write") || api.Valid(t3, "org/other", "contents", "write") {
		t.Fatal("token validity is wrong")
	}
}

func TestPermissionsAreCachedSeparately(t *testing.T) {
	api, app, _ := setup(t)
	api.Install("org/infra")
	ctx := context.Background()
	rd, _ := app.Token(ctx, "org", "infra", githubapp.Permissions{Contents: "read"})
	pr, _ := app.Token(ctx, "org", "infra", githubapp.Permissions{PullRequests: "write"})
	if rd == "" || pr == "" || rd == pr {
		t.Fatalf("expected two tokens: %q %q", rd, pr)
	}
	if got := api.Issued()[0].Perms; len(got) != 1 || got["contents"] != "read" {
		t.Fatalf("read token: %v", got)
	}
	if got := api.Issued()[1].Perms; len(got) != 1 || got["pull_requests"] != "write" {
		t.Fatalf("pr token: %v", got)
	}
}

func TestNotInstalledAndBadKeyErrorsNeverCarryATokenOrKey(t *testing.T) {
	api, app, clk := setup(t)
	_, err := app.Token(context.Background(), "org", "missing", write)
	if err == nil || !strings.Contains(err.Error(), "installed on org/missing") {
		t.Fatalf("want a not-installed hint, got %v", err)
	}
	var se *githubapp.StatusError
	if !errors.As(err, &se) || se.Status != 404 {
		t.Fatalf("want a 404 StatusError, got %v", err)
	}
	// An App with someone else's key is refused by the API: its own key (the
	// fakes share one per process) and the fake's clock, so only the signature is wrong.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := githubapp.New(githubapp.Options{AppID: "12345", Key: otherKey, API: api.URL, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	api.Install("org/ledger")
	_, err = bad.Token(context.Background(), "org", "ledger", write)
	if err == nil || !errors.As(err, &se) || se.Status != 401 {
		t.Fatalf("want 401, got %v", err)
	}
	if strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatal("key material in an error")
	}
}

func TestRejectsBadInput(t *testing.T) {
	if _, err := githubapp.ParseKey([]byte("nope")); err == nil {
		t.Fatal("garbage parsed as a key")
	}
	_, app, _ := setup(t)
	for _, c := range [][2]string{{"", "r"}, {"o", ""}, {"o/x", "r"}, {"o", ".."}} {
		if _, err := app.Token(context.Background(), c[0], c[1], write); err == nil {
			t.Fatalf("accepted %v", c)
		}
	}
	if _, err := app.Token(context.Background(), "o", "r", githubapp.Permissions{}); err == nil {
		t.Fatal("accepted no permissions")
	}
	if _, err := githubapp.New(githubapp.Options{AppID: "", Key: nil}); err == nil {
		t.Fatal("accepted empty options")
	}
}

func TestConcurrentTokenCallsShareOneRequest(t *testing.T) {
	api, app, _ := setup(t)
	api.Install("org/ledger")
	var wg sync.WaitGroup
	toks := make([]string, 16)
	for i := range toks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := app.Token(context.Background(), "org", "ledger", write)
			if err != nil {
				t.Error(err)
			}
			toks[i] = tok
		}()
	}
	wg.Wait()
	for _, tk := range toks {
		if tk == "" || tk != toks[0] {
			t.Fatalf("callers got different tokens: %v", toks)
		}
	}
	if n := len(api.Issued()); n > 2 { // a late caller may start a second flight only after the first finished and cached: never
		t.Fatalf("issued %d tokens for 16 concurrent callers", n)
	}
	// Different repositories do not wait for each other.
	api.Install("org/infra")
	if _, err := app.Token(context.Background(), "org", "infra", githubapp.Permissions{Contents: "read"}); err != nil {
		t.Fatal(err)
	}
}

func TestRefusesAPIURLsThatAreNotHTTPS(t *testing.T) {
	key, _ := githubapp.ParseKey(githubapptest.NewAPI(t, "1", nil).KeyPEM())
	if _, err := githubapp.New(githubapp.Options{AppID: "1", Key: key, API: "http://ghe.example.org/api/v3"}); err == nil {
		t.Fatal("accepted plain http")
	}
	if _, err := githubapp.New(githubapp.Options{AppID: "1", Key: key, API: "https://ghe.example.org/api/v3"}); err != nil {
		t.Fatal(err)
	}
	if _, err := githubapp.New(githubapp.Options{AppID: "1", Key: key, API: "http://127.0.0.1:9"}); err != nil {
		t.Fatalf("loopback http is for tests: %v", err)
	}
	if githubapp.GitHost("https://api.github.com") != "github.com" || githubapp.GitHost("https://ghe.example.org/api/v3") != "ghe.example.org" {
		t.Fatal("GitHost")
	}
}
