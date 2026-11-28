package accounts

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
)

func auditMonths(t *testing.T, e *env) []string {
	t.Helper()
	ents, err := os.ReadDir(e.auditDir())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range ents {
		if len(f.Name()) == len("audit-2026-09.jsonl") && f.Name()[:6] == "audit-" {
			out = append(out, f.Name()[6:13])
		}
	}
	return out
}

func TestRetentionKeepsTheStoresMonthUntilTheCheckpoint(t *testing.T) {
	e := newEnv(t)
	e.clk.Set(time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC))
	s := e.mustOpen()
	e.mustInvite(s, "alice") // the store's last change is in September
	e.clk.Set(time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC))
	e.log.Record(audit.Event{Event: "login", Identity: "x"})
	e.clk.Set(time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC))
	e.log.Record(audit.Event{Event: "login", Identity: "x"})
	if got := auditMonths(t, e); len(got) != 3 {
		t.Fatalf("months = %v", got)
	}

	// retention of one month would delete September; the pin holds it, and the log says so
	e.retMo = 1
	e.restart()
	if got := auditMonths(t, e); len(got) != 3 || got[0] != "2026-09" {
		t.Fatalf("the pinned month was deleted: %v", got)
	}
	// opening the store writes the checkpoint that retention asked for: the pin moves to November
	s = e.mustOpen()
	if cps := e.eventsNamed("account_store_checkpoint"); len(cps) != 1 || !hasChange(cps[0]) {
		t.Fatalf("checkpoint events = %+v", cps)
	}
	if got := s.Snapshot().AuditMonth; got != "2026-11" {
		t.Fatalf("the store's audit month = %s", got)
	}
	if e.pin.Month() != "2026-11" {
		t.Fatalf("pin = %s", e.pin.Month())
	}
	// the next pass deletes September; the store's start check is still satisfied
	e.restart()
	if got := auditMonths(t, e); len(got) != 2 || got[0] != "2026-10" {
		t.Fatalf("months after the checkpoint = %v", got)
	}
	if _, err := e.open(); err != nil {
		t.Fatalf("start after retention: %v", err)
	}
	e.verifyChain()
}

func TestDailyRetentionHeldBackWritesACheckpoint(t *testing.T) {
	e := newEnv(t)
	e.clk.Set(time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC))
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	e.clk.Set(time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC))
	// the running process: the pin's Held callback is what the daily job calls
	before := len(e.eventsNamed("account_store_checkpoint"))
	e.pin.Held()
	if got := len(e.eventsNamed("account_store_checkpoint")); got != before+1 {
		t.Fatalf("checkpoints: %d -> %d", before, got)
	}
	if s.Snapshot().AuditMonth != "2026-11" || e.pin.Month() != "2026-11" {
		t.Fatalf("month %s pin %s", s.Snapshot().AuditMonth, e.pin.Month())
	}
}

func TestFirstCounterWriteOfANewMonthWritesACheckpoint(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	before := s.Snapshot()
	e.clk.Set(time.Date(2026, 12, 2, 10, 0, 0, 0, time.UTC))
	if err := s.Counter(nil, func(st *State) error { st.Accounts["alice"].ConsecutiveFailures++; return nil }); err != nil {
		t.Fatal(err)
	}
	after := s.Snapshot()
	if after.AuditMonth != "2026-12" || after.AuditSeq <= before.AuditSeq || after.Accounts["alice"].ConsecutiveFailures != 1 {
		t.Fatalf("meta = %+v", after.Meta)
	}
	if got := e.eventsNamed("account_store_checkpoint"); len(got) != 1 || got[0].Time.Month() != 12 {
		t.Fatalf("checkpoint events = %+v", got)
	}
	// the second counter of the month does not write another
	if err := s.Counter(nil, func(st *State) error { st.Accounts["alice"].ConsecutiveFailures++; return nil }); err != nil {
		t.Fatal(err)
	}
	if got := len(e.eventsNamed("account_store_checkpoint")); got != 1 {
		t.Fatalf("%d checkpoints", got)
	}
}

func TestPinWhenTheStoresCannotBeRead(t *testing.T) {
	e := newEnv(t)
	e.clk.Set(time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC))
	e.mustInvite(e.mustOpen(), "alice")
	if p := NewPin(e.dir, e.key); p.Month() != "2026-09" {
		t.Fatalf("pin = %q", p.Month())
	}
	if p := NewPin(e.dir, mustNewKey(t)); p.Month() != unknownMonth {
		t.Fatalf("wrong key: pin = %q, want everything held", p.Month())
	}
	if p := NewPin(e.dir, nil); p.Month() != unknownMonth {
		t.Fatalf("no key: pin = %q, want everything held", p.Month())
	}
	if p := NewPin(t.TempDir(), nil); p.Month() != "" {
		t.Fatalf("no stores: pin = %q", p.Month())
	}
	// a start with the wrong key deletes nothing
	e.clk.Set(time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC))
	e.log.Record(audit.Event{Event: "login", Identity: "x"})
	e.log.Close()
	l, err := audit.Open(e.auditDir(), audit.Options{Now: e.clk.Now, RetentionMonths: 1, Pin: NewPin(e.dir, mustNewKey(t))})
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if _, err := os.Stat(filepath.Join(e.auditDir(), "audit-2026-09.jsonl")); err != nil {
		t.Fatal("retention deleted a month although the pin could not be read")
	}
}

func TestPinIsTheOlderOfBothStores(t *testing.T) {
	e := newEnv(t)
	e.clk.Set(time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC))
	sec, _ := e.openSecrets()
	mustApply(t, sec, Update{Set: map[string]string{SecretCaptcha: "x"}})
	e.clk.Set(time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC))
	e.mustInvite(e.mustOpen(), "alice")
	if p := NewPin(e.dir, e.key); p.Month() != "2026-09" {
		t.Fatalf("pin = %q, want the secrets store's older month", p.Month())
	}
}
