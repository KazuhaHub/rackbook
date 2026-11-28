package audit_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/statekey"
)

// The account writer meets audit.ErrNotDurable: the line has its seq, so .pending stays, the writer stops, and the next
// start finishes the change. It lives here because the seams of the log are reachable only from this package's tests.
func TestAccountWriterOnANotDurableAuditLine(t *testing.T) {
	key, err := statekey.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	open := func() (*audit.Log, *accounts.Store) {
		l, err := audit.Open(filepath.Join(state, "audit"), audit.Options{Now: clock})
		if err != nil {
			t.Fatal(err)
		}
		s, err := accounts.Open(accounts.Options{StateDir: state, Key: key, Log: l, Now: clock})
		if err != nil {
			t.Fatal(err)
		}
		return l, s
	}
	invite := func(s *accounts.Store, name string) error {
		_, err := s.Change(audit.Event{Event: "account_invited", Target: "local:" + name}, func(st *accounts.State) error {
			a, err := accounts.NewAccount(name, name, "local:root", now)
			st.Accounts[name] = a
			return err
		})
		return err
	}
	l, s := open()
	if err := invite(s, "alice"); err != nil {
		t.Fatal(err)
	}
	// December: the first line goes into a new month file, whose directory fsync fails
	now = time.Date(2026, 12, 2, 10, 0, 0, 0, time.UTC)
	l.SetSyncDirFn(func(string) error { return errors.New("dir fsync failed") })
	err = invite(s, "bob")
	if !errors.Is(err, accounts.ErrAuditUnavailable) || !errors.Is(err, audit.ErrNotDurable) {
		t.Fatalf("err = %v", err)
	}
	if s.Snapshot().Accounts["bob"] != nil {
		t.Fatal("the in-memory state moved before the new store was in place")
	}
	if _, err := os.Stat(filepath.Join(state, "accounts", "accounts.enc.pending")); err != nil {
		t.Fatalf(".pending must stay, the line has its seq: %v", err)
	}
	// the writer is stopped, for changes and for counters
	if err := invite(s, "carol"); !errors.Is(err, accounts.ErrStoreFailed) {
		t.Fatalf("a second change: %v", err)
	}
	if err := s.Counter(nil, func(*accounts.State) error { return nil }); !errors.Is(err, accounts.ErrStoreFailed) {
		t.Fatalf("a counter: %v", err)
	}
	l.Close()

	// the next start finishes the change
	l2, s2 := open()
	defer l2.Close()
	if !s2.Recovered() || s2.Snapshot().Accounts["bob"] == nil || s2.Snapshot().Accounts["alice"] == nil {
		t.Fatalf("recovered=%v names=%v", s2.Recovered(), s2.Snapshot().Names())
	}
	if rep, err := audit.Verify(filepath.Join(state, "audit")); err != nil || len(rep.Problems) != 0 {
		t.Fatalf("Verify: %v %v", rep.Problems, err)
	}
	if err := invite(s2, "carol"); err != nil {
		t.Fatalf("writable again after the restart: %v", err)
	}
}
