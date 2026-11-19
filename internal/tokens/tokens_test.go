package tokens

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateAndMatch(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		s, err := Generate()
		if err != nil || len(s) != 47 || !strings.HasPrefix(s, Prefix) || strings.Trim(s[4:], "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") != "" || seen[s] {
			t.Fatalf("%q %v", s, err)
		}
		seen[s] = true
	}
	s, _ := Generate()
	now := time.Now()
	tok := Token{Name: "a", ShownPrefix: ShownPrefix(s), Hash: HashSecret(s), Scope: ScopeRead, CreatedBy: "x@y", Created: now.Format(time.RFC3339)}
	if err := tok.Validate(); err != nil {
		t.Fatal(err)
	}
	if ShownPrefix(s) != s[:12] || len(HashSecret(s)) != 64 {
		t.Fatal("prefix/hash")
	}
	ts := []Token{tok}
	if got, err := Match(ts, s, now); err != nil || got.Name != "a" {
		t.Fatalf("%v", err)
	}
	other, _ := Generate()
	for _, bad := range []string{other, s[:46], s + "x", "", "rbk_", strings.Replace(s, "rbk_", "xxx_", 1)} {
		if _, err := Match(ts, bad, now); err != ErrNotFound {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	ts[0].Expires = now.Add(-time.Second).Format(time.RFC3339)
	if _, err := Match(ts, s, now); err != ErrExpired {
		t.Fatal(err)
	}
	ts[0].Expires, ts[0].Revoked = "", now.Format(time.RFC3339)
	if _, err := Match(ts, s, now); err != ErrRevoked {
		t.Fatal(err)
	}
}

func TestParseValidatesTheBuiltInSchema(t *testing.T) {
	for name, doc := range map[string]string{
		"bad name":   "tokens:\n- {name: Bad, sha256: " + strings.Repeat("a", 64) + ", scope: read, created_by: a@b}\n",
		"short hash": "tokens:\n- {name: ok, sha256: abc, scope: read, created_by: a@b}\n",
		"bad scope":  "tokens:\n- {name: ok, sha256: " + strings.Repeat("a", 64) + ", scope: root, created_by: a@b}\n",
		"unknown":    "tokens:\n- {name: ok, sha256: " + strings.Repeat("a", 64) + ", scope: read, created_by: a@b, admin: true}\n",
		"no creator": "tokens:\n- {name: ok, sha256: " + strings.Repeat("a", 64) + ", scope: read}\n",
		"dup":        "tokens:\n- {name: ok, sha256: " + strings.Repeat("a", 64) + ", scope: read, created_by: a@b}\n- {name: ok, sha256: " + strings.Repeat("b", 64) + ", scope: read, created_by: a@b}\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if ts, err := Parse(nil); err != nil || len(ts) != 0 {
		t.Fatal(err)
	}
}

func TestLimiterWindow(t *testing.T) {
	now := time.Now()
	l := &Limiter{Max: 3, Window: time.Minute, Now: func() time.Time { return now }}
	for i := 0; i < 3; i++ {
		if b, _ := l.Blocked("ip"); b {
			t.Fatal("early")
		}
		l.Fail("ip")
	}
	if b, wait := l.Blocked("ip"); !b || wait <= 0 {
		t.Fatal("must block")
	}
	if b, _ := l.Blocked("other"); b {
		t.Fatal("per IP")
	}
	now = now.Add(61 * time.Second)
	if b, _ := l.Blocked("ip"); b {
		t.Fatal("window must expire")
	}
}

func TestLimiterEvictsLeastRecentlyUsedNotEverything(t *testing.T) {
	l := &Limiter{Max: 1}
	l.Fail("victim")
	for i := 0; i < maxClients; i++ {
		l.Fail(fmt.Sprintf("c%d", i))
		l.Blocked("victim") // keeps it recent
	}
	if blocked, _ := l.Blocked("victim"); !blocked {
		t.Fatal("a client that keeps failing must stay blocked when the table is full")
	}
}

func TestSubjectMethodIsTheCreatorsRecordedMethod(t *testing.T) {
	for via, want := range map[string]string{"oidc": "oidc", "passkey": "passkey", "": "none", "mcphub": "none", "token": "none", "bogus": "none"} {
		if got := (Token{CreatedVia: via}).SubjectMethod(); got != want {
			t.Errorf("%q: %q, want %q", via, got, want)
		}
	}
}

func TestLastUseSurvivesRestartWithUsePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token-use.json")
	now := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	r := &Registry{UsePath: path, Now: func() time.Time { return now }}
	r.Touch("entra-sync")
	// a second use within the minute does not rewrite the file
	now = now.Add(30 * time.Second)
	r.Touch("entra-sync")
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "08:00:00Z") {
		t.Fatalf("file: %s", b)
	}
	// a new Registry (a restart) reads the file
	r2 := &Registry{UsePath: path}
	if got, ok := r2.LastUsed("entra-sync"); !ok || !got.Equal(time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("%v %v", got, ok)
	}
	if _, ok := r2.LastUsed("notify"); ok {
		t.Fatal("unknown token has a last use")
	}
	// without UsePath nothing is written and nothing survives
	r3 := &Registry{}
	r3.Touch("x")
	if _, ok := (&Registry{}).LastUsed("x"); ok {
		t.Fatal("memory-only registry shared state")
	}
}
