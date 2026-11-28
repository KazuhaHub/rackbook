package audit

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestRecordSyncIsOnDiskWhenItReturns(t *testing.T) {
	l, dir := newLog(t, Options{})
	seq, month, err := l.RecordSyncMonth(Event{Event: "account_invited", Target: "local:alice", Detail: []string{"change:abc"}})
	if err != nil || seq != 1 || month != "2026-11" {
		t.Fatalf("RecordSyncMonth = %d %q %v", seq, month, err)
	}
	seq2, err := l.RecordSync(ev("login"))
	if err != nil || seq2 != 2 {
		t.Fatalf("RecordSync = %d %v", seq2, err)
	}
	// without any Close, a fresh reader of the directory sees both lines, chained
	if rep, err := Verify(dir); err != nil || len(rep.Problems) != 0 {
		t.Fatalf("Verify: %v %v", rep.Problems, err)
	}
	l2, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	var got []Event
	if err := l2.EachEvent("", func(e Event, m string) bool { got = append(got, e); return true }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Target != "local:alice" || got[0].Detail[0] != "change:abc" {
		t.Fatalf("events = %+v", got)
	}
	if st, err := os.Stat(filepath.Join(dir, "audit-2026-11.jsonl")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", st, err)
	}
}

func TestRecordSyncReturnsAnErrorWhereRecordDropsSilently(t *testing.T) {
	l, _ := newLog(t, Options{})
	l.mu.Lock()
	l.failed = "disk full"
	l.mu.Unlock()
	l.Record(ev("login")) // returns nothing; the event is dropped
	if _, err := l.RecordSync(ev("login")); err == nil {
		t.Fatal("RecordSync in the failed state must return an error")
	}
	if seq, _ := l.Head(); seq != 0 {
		t.Fatalf("nothing may have been written, seq = %d", seq)
	}
	var nilLog *Log
	if _, err := nilLog.RecordSync(ev("x")); !errors.Is(err, ErrNoLog) {
		t.Fatalf("nil log: %v", err)
	}
}

func TestRecordSyncFailureOnWriteIsReturned(t *testing.T) {
	l, _ := newLog(t, Options{})
	l.stat = func(*os.File) (os.FileInfo, error) { return nil, errors.New("stat failed") }
	if _, err := l.RecordSync(ev("login")); err == nil {
		t.Fatal("want an error when the size cannot be read")
	}
	if seq, _ := l.Head(); seq != 0 {
		t.Fatalf("seq = %d", seq)
	}
}

type testPin struct {
	month string
	held  atomic.Int32
}

func (p *testPin) Month() string { return p.month }
func (p *testPin) Held()         { p.held.Add(1) }

// threeMonths writes one event in each of Sep, Oct and Nov 2026 and closes the log.
func threeMonths(t *testing.T) string {
	t.Helper()
	l, dir := newLog(t, Options{})
	for _, m := range []time.Month{9, 10, 11} {
		l.Record(Event{Event: "login", Identity: "a@example.com", Time: at(2026, m, 5)})
	}
	l.Close()
	return dir
}

func reopen(t *testing.T, dir string, pin RetentionPin) []string {
	t.Helper()
	l, err := Open(dir, Options{RetentionMonths: 1, Pin: pin, Now: (&fakeClock{time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)}).Now})
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	files, err := listFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestRetentionPin(t *testing.T) {
	cases := []struct {
		name     string
		pin      string
		wantLeft int
		wantHeld bool
	}{
		{"no pin: September is deleted", "", 2, false},
		{"pin on a kept month changes nothing", "2026-10", 2, false},
		{"pin on September holds September", "2026-09", 3, true},
		{"an unknown pin holds everything", "0000-00", 3, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := threeMonths(t)
			pin := &testPin{month: c.pin}
			left := reopen(t, dir, pin)
			if len(left) != c.wantLeft {
				t.Fatalf("files = %v", left)
			}
			if (pin.held.Load() > 0) != c.wantHeld {
				t.Fatalf("Held called %d times, want held=%v", pin.held.Load(), c.wantHeld)
			}
			if rep, err := Verify(dir); err != nil || len(rep.Problems) != 0 {
				t.Fatalf("Verify: %v %v", rep.Problems, err)
			}
		})
	}
}

func TestRetentionPinMovesForwardWithTheCheckpoint(t *testing.T) {
	dir := threeMonths(t)
	pin := &testPin{month: "2026-09"}
	if len(reopen(t, dir, pin)) != 3 {
		t.Fatal("the pin must hold September")
	}
	pin.month = "2026-11" // the checkpoint wrote the store in November
	left := reopen(t, dir, pin)
	if len(left) != 2 || left[0] != "audit-2026-10.jsonl" {
		t.Fatalf("after the checkpoint September goes: %v", left)
	}
}

func TestRecordSyncFsyncFailureLeavesNoLineAndNoSeq(t *testing.T) {
	l, dir := newLog(t, Options{})
	if _, err := l.RecordSync(ev("login")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "audit-2026-11.jsonl")
	before, _ := os.ReadFile(path)
	l.syncFile = func(*os.File) error { return errors.New("fsync failed") }
	if seq, err := l.RecordSync(ev("login")); err == nil || errors.Is(err, ErrNotDurable) || seq != 0 {
		t.Fatalf("seq %d err %v: a failed fsync is a failed append", seq, err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("a failed fsync left a line in the file")
	}
	l.syncFile = (*os.File).Sync
	if seq, err := l.RecordSync(ev("login")); err != nil || seq != 2 {
		t.Fatalf("the seq must not have moved: %d %v", seq, err)
	}
	if rep, err := Verify(dir); err != nil || len(rep.Problems) != 0 {
		t.Fatalf("Verify: %v %v", rep.Problems, err)
	}
}

func TestRecordSyncDirectoryFsyncOfANewMonthFileFails(t *testing.T) {
	l, dir := newLog(t, Options{})
	l.syncDirFn = func(string) error { return errors.New("dir fsync failed") }
	seq, _, err := l.RecordSyncMonth(Event{Event: "login", Identity: "a@example.com", Time: at(2026, 12, 1)})
	if !errors.Is(err, ErrNotDurable) || seq != 1 {
		t.Fatalf("seq %d err %v: RecordSync must fail, and say the line has its seq", seq, err)
	}
	// the line is there and took its seq: the next append is 2, never 1 again
	l.syncDirFn = syncDir
	if seq, err := l.RecordSync(Event{Event: "login", Identity: "a@example.com", Time: at(2026, 12, 2)}); err != nil || seq != 2 {
		t.Fatalf("next seq = %d %v", seq, err)
	}
	if rep, err := Verify(dir); err != nil || len(rep.Problems) != 0 {
		t.Fatalf("Verify: %v %v", rep.Problems, err)
	}
	// Record (which returns nothing) is unaffected
	l.syncDirFn = func(string) error { return errors.New("dir fsync failed") }
	l.Record(Event{Event: "login", Identity: "a@example.com", Time: at(2027, 1, 2)})
	if seq, _ := l.Head(); seq != 3 {
		t.Fatalf("seq = %d", seq)
	}
}

func TestRecordSyncCloseFailureAfterASuccessfulFsync(t *testing.T) {
	l, dir := newLog(t, Options{})
	l.closeFile = func(f *os.File) error { f.Close(); return errors.New("close failed") }
	seq, _, err := l.RecordSyncMonth(ev("login"))
	if !errors.Is(err, ErrNotDurable) || seq != 1 {
		t.Fatalf("seq %d err %v", seq, err)
	}
	l.closeFile = (*os.File).Close
	if seq, err := l.RecordSync(ev("login")); err != nil || seq != 2 {
		t.Fatalf("the seq of the written line was reused: %d %v", seq, err)
	}
	var n int
	if err := l.EachEvent("", func(Event, string) bool { n++; return true }); err != nil || n != 2 {
		t.Fatalf("%d lines, %v", n, err)
	}
	if rep, err := Verify(dir); err != nil || len(rep.Problems) != 0 {
		t.Fatalf("Verify: %v %v", rep.Problems, err)
	}
}

func TestRetentionPinOutranksAnUnfinishedDelete(t *testing.T) {
	dir := threeMonths(t)
	// head.json claims October is the first file, as if an earlier pass had got that far
	b, err := os.ReadFile(filepath.Join(dir, "head.json"))
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	if err := json.Unmarshal(b, &h); err != nil {
		t.Fatal(err)
	}
	l, _ := Open(dir, Options{})
	prev, _ := firstPrevOf(filepath.Join(dir, "audit-2026-10.jsonl"))
	l.Close()
	h["first_file"], h["first_prev"] = "audit-2026-10.jsonl", prev
	b, _ = json.Marshal(h)
	os.WriteFile(filepath.Join(dir, "head.json"), b, 0o600)
	pin := &testPin{month: "2026-09"}
	left := reopen(t, dir, pin)
	if len(left) != 3 {
		t.Fatalf("the pin must outrank a delete that an earlier run did not finish: %v", left)
	}
}
