package hubstatus

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const doc = `{"apiVersion":"v1","time":"2026-11-20T12:00:00Z","main":"abc123","issuer":"x",
"hosts":[{"name":"a","report":{"appliedCommit":"abc123","result":"ok","time":"2026-11-20T11:59:00Z","receivedAt":"2026-11-20T11:59:01Z",
"features":[{"name":"beszel-agent","result":"ok"}]}},{"name":"b"}],
"certs":[{"name":"a.example","owner":"a","notAfter":"2027-01-01T00:00:00Z","failing":true,"lastError":"dns","failures":3}],
"iplists":{"providers":[],"lists":[{"name":"cloudflare","entries":22,"version":"v1","warnings":["w"],"history":[]}]}}`

func TestParseFresh(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 1, 0, 0, time.UTC)
	s := Parse([]byte(doc), time.Time{}, now)
	if !s.Available() || s.AgeSeconds != 60 || s.Status.Main != "abc123" || len(s.Status.Hosts) != 2 {
		t.Fatalf("%+v", s)
	}
	if r := s.Status.Hosts[0].Report; r == nil || r.AppliedCommit != "abc123" || r.Features[0].Name != "beszel-agent" || s.Status.Hosts[1].Report != nil {
		t.Fatalf("hosts: %+v", s.Status.Hosts)
	}
	if c := s.Status.Certs[0]; !c.Failing || c.LastError != "dns" || c.Owner != "a" {
		t.Fatalf("cert: %+v", c)
	}
	if l := s.Status.IPLists.Lists[0]; l.Entries != 22 || l.Warnings[0] != "w" {
		t.Fatalf("list: %+v", l)
	}
}

func TestParseStaleAfterThreeMinutes(t *testing.T) {
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	if s := Parse([]byte(doc), time.Time{}, at.Add(3*time.Minute)); s.State != StateOK {
		t.Fatalf("exactly 3 minutes is still current: %+v", s)
	}
	s := Parse([]byte(doc), time.Time{}, at.Add(3*time.Minute+time.Second))
	if s.State != StateStale || s.Available() || s.Status != nil || s.AgeSeconds != 181 {
		t.Fatalf("%+v", s)
	}
}

func TestParseClockAhead(t *testing.T) {
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	// a little ahead (clock difference) is current, with age 0
	if s := Parse([]byte(doc), time.Time{}, at.Add(-30*time.Second)); s.State != StateOK || s.AgeSeconds != 0 {
		t.Fatalf("%+v", s)
	}
	// far ahead is not believed: a dead timer must not look alive until that time
	if s := Parse([]byte(doc), time.Time{}, at.Add(-time.Hour)); s.State != StateInvalid || s.Available() {
		t.Fatalf("%+v", s)
	}
}

func TestParseInvalid(t *testing.T) {
	now := time.Now()
	for name, raw := range map[string]string{
		"not json":   "nope",
		"empty":      "",
		"version":    `{"apiVersion":"v2","time":"2026-11-20T12:00:00Z"}`,
		"no version": `{"time":"2026-11-20T12:00:00Z"}`,
		"no time":    `{"apiVersion":"v1"}`,
	} {
		if s := Parse([]byte(raw), time.Time{}, now); s.State != StateInvalid || s.Error == "" {
			t.Errorf("%s: %+v", name, s)
		}
	}
	// a missing time falls back to the file's modification time
	if s := Parse([]byte(`{"apiVersion":"v1"}`), now.Add(-time.Minute), now); s.State != StateOK {
		t.Errorf("mtime fallback: %+v", s)
	}
}

func TestLoadMissingAndPresent(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 20, 12, 0, 30, 0, time.UTC)
	if s := Load(filepath.Join(dir, "none.json"), now); s.State != StateMissing || s.Available() {
		t.Fatalf("%+v", s)
	}
	p := filepath.Join(dir, "status.json")
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	if s := Load(p, now); !s.Available() || s.AgeSeconds != 30 {
		t.Fatalf("%+v", s)
	}
	if s := Load(dir, now); s.State != StateInvalid { // a directory cannot be read
		t.Fatalf("%+v", s)
	}
}
