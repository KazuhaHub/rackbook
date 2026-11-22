package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/auth"
)

func seqs(es []Event) string {
	var s []string
	for _, e := range es {
		s = append(s, fmt.Sprint(e.Seq))
	}
	return strings.Join(s, ",")
}

func TestReadNewestFirstWithFiltersAndACursor(t *testing.T) {
	l, dir := newLog(t, Options{})
	for i := 1; i <= 8; i++ {
		e := Event{Event: "login", Identity: "a@example.com"}
		if i%2 == 0 {
			e = Event{Event: "logout", Identity: "b@example.com", Area: "infra"}
		}
		e.Time = at(2026, 10, 20).AddDate(0, 0, i*9) // Oct 29 ... Dec 31: three month files
		l.Record(e)
	}
	if files, _ := listFiles(dir); len(files) != 3 {
		t.Fatalf("%v", files)
	}
	p, err := l.Read(Query{})
	if err != nil || seqs(p.Events) != "8,7,6,5,4,3,2,1" || p.More {
		t.Fatalf("%v %+v", err, p)
	}
	// pages by seq cursor
	p, _ = l.Read(Query{Limit: 3})
	if seqs(p.Events) != "8,7,6" || !p.More || p.Next != 6 {
		t.Fatalf("%+v", p)
	}
	p, _ = l.Read(Query{Limit: 3, Before: p.Next})
	if seqs(p.Events) != "5,4,3" || p.Next != 3 {
		t.Fatalf("%+v", p)
	}
	p, _ = l.Read(Query{Limit: 3, Before: p.Next})
	if seqs(p.Events) != "2,1" {
		t.Fatalf("%+v", p)
	}
	if p, _ = l.Read(Query{Identity: "b@example.com"}); seqs(p.Events) != "8,6,4,2" {
		t.Fatalf("%+v", p)
	}
	if p, _ = l.Read(Query{Events: []string{"login"}}); seqs(p.Events) != "7,5,3,1" {
		t.Fatalf("%+v", p)
	}
	if p, _ = l.Read(Query{Filter: func(e Event) bool { return e.Area == "infra" && e.Seq > 2 }}); seqs(p.Events) != "8,6,4" {
		t.Fatalf("%+v", p)
	}
	// the time range is inclusive on both ends
	since, until := at(2026, 11, 16), at(2026, 12, 4)
	if p, _ = l.Read(Query{Since: since, Until: until}); seqs(p.Events) != "5,4,3" {
		t.Fatalf("%+v", p)
	}
	// a scan budget stops early and says so
	p, _ = l.Read(Query{Identity: "a@example.com", MaxScan: 2})
	if !p.More || len(p.Events) != 1 || p.Next != 7 {
		t.Fatalf("%+v", p)
	}
	var nilLog *Log
	if p, err := nilLog.Read(Query{}); err != nil || len(p.Events) != 0 {
		t.Fatal(err, p)
	}
}

func TestReadIgnoresAnUnfinishedLastLineAndAFileThatIsGone(t *testing.T) {
	l, dir := newLog(t, Options{})
	fill(t, l, 6) // two in October, four in November
	f, _ := os.OpenFile(filepath.Join(dir, "audit-2026-11.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"seq":7,"time":"2026-11-22T10:00:00Z","event":"log`)
	f.Close()
	if p, err := l.Read(Query{}); err != nil || seqs(p.Events) != "6,5,4,3,2,1" {
		t.Fatalf("%v %+v", err, p)
	}
	if err := os.Remove(filepath.Join(dir, "audit-2026-10.jsonl")); err != nil {
		t.Fatal(err)
	}
	if p, err := l.Read(Query{}); err != nil || seqs(p.Events) != "6,5,4,3" {
		t.Fatalf("%v %+v", err, p)
	}
}

func TestReadAcrossManyBlocks(t *testing.T) {
	l, dir := newLog(t, Options{})
	pad := strings.Repeat("x", 300)
	const n = 1500 // about 600 KiB: many 64 KiB blocks
	for i := 0; i < n; i++ {
		l.Record(Event{Event: "login", Identity: "a@example.com", Reason: pad})
	}
	if st, _ := os.Stat(filepath.Join(dir, "audit-2026-11.jsonl")); st.Size() < 5*backBlock {
		t.Fatalf("only %d bytes", st.Size())
	}
	var got []int64
	var before int64
	for {
		p, err := l.Read(Query{Limit: 400, Before: before})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range p.Events {
			got = append(got, e.Seq)
		}
		if !p.More {
			break
		}
		before = p.Next
	}
	if len(got) != n {
		t.Fatalf("%d events", len(got))
	}
	for i, s := range got {
		if s != int64(n-i) {
			t.Fatalf("position %d holds seq %d", i, s)
		}
	}
}

func commitEv(area, hash, who string, detail ...string) Event {
	return Event{Event: "commit", Area: area, Repo: "r", Hash: hash, Identity: who, Name: "N " + who, Method: "oidc", Detail: detail}
}

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hashC = "cccccccccccccccccccccccccccccccccccccccc"
)

func TestCommitIndexIsACacheOfTheChain(t *testing.T) {
	l, dir := newLog(t, Options{})
	l.Record(commitEv("ledger", hashA, "a@example.com", "token:ci"))
	l.Record(ev("login"))
	l.Record(commitEv("infra", hashB, "b@example.com"))
	keyA, keyB := CommitKey{"ledger", hashA}, CommitKey{"infra", hashB}

	got := l.LookupCommits([]CommitKey{keyA, keyB, {"ledger", hashB}, {"ledger", hashC}})
	if len(got) != 2 || got[keyA].Identity != "a@example.com" || got[keyA].Token != "ci" || got[keyA].Seq != 1 || got[keyA].Method != "oidc" ||
		got[keyB].Name != "N b@example.com" {
		t.Fatalf("the area is part of the key: %+v", got)
	}
	st, err := os.Stat(filepath.Join(dir, indexName))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", err, st)
	}
	var disk commitIndex
	b, _ := os.ReadFile(filepath.Join(dir, indexName))
	if json.Unmarshal(b, &disk) != nil || disk.Version != indexVersion || disk.LastSeq != 3 || len(disk.Commits) != 2 || !strings.HasPrefix(disk.LastLineHash, "sha256:") {
		t.Fatalf("%s", b)
	}
	if rep := mustVerify(t, dir); !rep.OK {
		t.Fatalf("the index file is not part of the chain: %+v", rep)
	}

	// incremental: only the new line is read
	l.Record(commitEv("ledger", hashC, "c@example.com"))
	if got := l.LookupCommits([]CommitKey{{"ledger", hashC}}); got[CommitKey{"ledger", hashC}].Seq != 4 {
		t.Fatalf("%+v", got)
	}
	b, _ = os.ReadFile(filepath.Join(dir, indexName))
	disk = commitIndex{}
	_ = json.Unmarshal(b, &disk)
	if disk.LastSeq != 4 || len(disk.Commits) != 3 {
		t.Fatalf("%+v", disk)
	}

	// a new process starts from the file
	l2, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if got := l2.LookupCommits([]CommitKey{keyA}); got[keyA].Identity != "a@example.com" {
		t.Fatalf("%+v", got)
	}
}

func TestCommitIndexCanAlwaysBeDeletedOrBroken(t *testing.T) {
	l, dir := newLog(t, Options{})
	l.Record(commitEv("ledger", hashA, "a@example.com"))
	l.Record(ev("login"))
	l.Record(commitEv("ledger", hashB, "b@example.com"))
	keys := []CommitKey{{"ledger", hashA}, {"ledger", hashB}}
	want := l.LookupCommits(keys)
	if len(want) != 2 {
		t.Fatalf("%+v", want)
	}
	path := filepath.Join(dir, indexName)
	check := func(what string) {
		t.Helper()
		l2, err := Open(dir, Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer l2.Close()
		got := l2.LookupCommits(keys)
		if len(got) != 2 || got[keys[0]] != want[keys[0]] || got[keys[1]] != want[keys[1]] {
			t.Fatalf("%s: %+v", what, got)
		}
		if b, err := os.ReadFile(path); err != nil || !bytes.Contains(b, []byte(`"last_seq":3`)) {
			t.Fatalf("%s: the index was not written again: %v %s", what, err, b)
		}
	}
	good, _ := os.ReadFile(path)

	os.Remove(path)
	check("deleted")

	os.WriteFile(path, []byte("{not json"), 0o600)
	check("corrupt")

	os.WriteFile(path, []byte(`{"version":9,"commits":{}}`), 0o600)
	check("another version")

	// last_line_hash no longer matches the line at last_seq: rebuilt, so a
	// forged entry in the cache does not survive.
	forged := bytes.Replace(good, []byte(`"last_line_hash":"sha256:`), []byte(`"last_line_hash":"sha256:0`), 1)
	forged = bytes.Replace(forged, []byte(`"commits":{`), []byte(`"commits":{"ledger:`+hashC+`":{"seq":2,"identity":"mallory"},`), 1)
	os.WriteFile(path, forged, 0o600)
	check("last line changed")
	l3, _ := Open(dir, Options{})
	defer l3.Close()
	if got := l3.LookupCommits([]CommitKey{{"ledger", hashC}}); len(got) != 0 {
		t.Fatalf("forged entry survived: %+v", got)
	}

	// last_seq beyond the log (lines cut): rebuilt too
	os.WriteFile(path, bytes.Replace(good, []byte(`"last_seq":3`), []byte(`"last_seq":30`), 1), 0o600)
	check("last_seq not in the log")
}

func TestCommitIndexMatchesOlderShortHashesOnlyWhenTheyAreUnambiguous(t *testing.T) {
	l, _ := newLog(t, Options{})
	l.Record(commitEv("ledger", hashA[:7], "a@example.com"))
	l.Record(commitEv("ledger", hashB[:10], "b@example.com"))
	l.Record(commitEv("ledger", hashB[:8], "c@example.com")) // two lines fit the same full hash
	l.Record(commitEv("ledger", "ccccccc", "d@example.com"))
	fullB := hashB
	got := l.LookupCommits([]CommitKey{{"ledger", hashA}, {"ledger", fullB}, {"infra", hashA}, {"ledger", hashC}})
	if len(got) != 2 || got[CommitKey{"ledger", hashA}].Identity != "a@example.com" || got[CommitKey{"ledger", hashC}].Identity != "d@example.com" {
		t.Fatalf("%+v", got)
	}
	l.Record(commitEv("ledger", "abcdef", "e@example.com")) // under seven characters: never a prefix match
	if got := l.LookupCommits([]CommitKey{{"ledger", "abcdef0123456789abcdef0123456789abcdef01"}}); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
	// the full hash written from now on is found exactly, whatever short ones exist
	l.Record(commitEv("ledger", fullB, "f@example.com"))
	if got := l.LookupCommits([]CommitKey{{"ledger", fullB}}); got[CommitKey{"ledger", fullB}].Identity != "f@example.com" {
		t.Fatalf("%+v", got)
	}
}

func TestAckClearsARecordedProblemAndUnblocksRetention(t *testing.T) {
	clk := &fakeClock{at(2026, 1, 20)}
	l, dir := newLog(t, Options{Now: clk.Now})
	for _, m := range []time.Month{1, 2} {
		for d := 1; d <= 2; d++ {
			e := ev("login")
			e.Time = at(2026, m, d)
			l.Record(e)
		}
	}
	l.Close()
	p := filepath.Join(dir, "audit-2026-02.jsonl")
	write(t, p, lines(t, p)[:1]) // the last line cut
	clk.t = at(2026, 3, 15)
	l2, err := Open(dir, Options{Now: clk.Now}) // records the cut in the March file
	if err != nil {
		t.Fatal(err)
	}
	clk.t = at(2026, 4, 2)
	l2.Record(ev("login"))
	l2.Close()
	clk.t = at(2026, 6, 5)
	l3, err := Open(dir, Options{Now: clk.Now, RetentionMonths: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer l3.Close()
	st := l3.Status()
	if st.OK || len(st.Problems) != 1 || st.Problems[0].Kind != KindCutFromEnd || !st.Problems[0].Recorded || st.LastSeq != 5 {
		t.Fatalf("%+v", st)
	}
	if files, _ := listFiles(dir); len(files) != 2 {
		t.Fatalf("retention keeps the month with the problem: %v", files)
	}
	who := &auth.Identity{ID: "boss@example.com", Name: "Boss", Method: "oidc"}

	for _, through := range []int64{0, 99} {
		if err := l3.Ack(who, through); err == nil {
			t.Fatalf("through %d is not a seq of the log", through)
		}
	}
	if err := l3.Ack(who, st.Problems[0].RecordedAt-1); err != ErrNothingToAck {
		t.Fatalf("an ack before the problem covers nothing: %v", err)
	}
	if err := l3.Ack(who, st.LastSeq); err != nil {
		t.Fatal(err)
	}
	if st := l3.Status(); !st.OK || len(st.Problems) != 0 || st.Problem != "" || st.LastSeq != 6 {
		t.Fatalf("%+v", st)
	}
	if err := l3.Ack(who, 6); err != ErrNothingToAck {
		t.Fatalf("%v", err)
	}
	// the ack is a line of the chain, by who
	pg, _ := l3.Read(Query{Events: []string{ChainProblemAckEvent}})
	if len(pg.Events) != 1 || pg.Events[0].Identity != "boss@example.com" || pg.Events[0].Detail[0] != "through:5" {
		t.Fatalf("%+v", pg.Events)
	}
	// verify still lists the problem, marked acknowledged, and still fails
	rep := mustVerify(t, dir)
	if rep.OK || len(rep.Problems) != 1 || !rep.Problems[0].Acked || rep.Problems[0].AckedAt != 6 || len(rep.Pending()) != 0 || rep.Repairable() {
		t.Fatalf("%+v", rep)
	}
	if d := rep.Problems[0].Describe(); !strings.Contains(d, "acknowledged at seq 6") {
		t.Fatal(d)
	}
	l3.prune()
	if files, _ := listFiles(dir); strings.Join(files, " ") != "audit-2026-06.jsonl" {
		t.Fatalf("an acknowledged problem no longer blocks retention: %v", files)
	}
	// a restart reads the ack from the chain
	l3.Close()
	l4, err := Open(dir, Options{Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer l4.Close()
	if st := l4.Status(); !st.OK || len(st.Problems) != 0 {
		t.Fatalf("%+v", st)
	}
}

func pendingKinds(l *Log) string {
	var k []string
	for _, p := range l.Status().Problems {
		k = append(k, fmt.Sprintf("%s@%d", p.Kind, p.Seq))
	}
	return strings.Join(k, ",")
}

func countChainProblems(t *testing.T, dir string) int { return len(chainProblems(t, dir)) }

// An acknowledgement covers the evidence the administrator saw: a line that is
// rewritten afterwards is a new problem even though kind and seq are the same.
func TestAckDoesNotHideALineRewrittenAfterwards(t *testing.T) {
	l, dir := newLog(t, Options{})
	fill(t, l, 6)
	l.Close()
	p := filepath.Join(dir, "audit-2026-11.jsonl")
	ls := lines(t, p)
	ls[1] = bytes.Replace(ls[1], []byte("a@example.com"), []byte("b@example.com"), 1)
	write(t, p, ls)
	who := &auth.Identity{ID: "boss@example.com", Method: "oidc"}
	l2, err := Open(dir, Options{Now: (&fakeClock{at(2026, 11, 22)}).Now})
	if err != nil {
		t.Fatal(err)
	}
	if pendingKinds(l2) != "edited@4" {
		t.Fatalf("%s", pendingKinds(l2))
	}
	if err := l2.Ack(who, l2.Status().LastSeq); err != nil {
		t.Fatal(err)
	}
	l2.Close()
	// the same old break, seen again at the next start: still acknowledged, recorded once
	l2b, _ := Open(dir, Options{Now: (&fakeClock{at(2026, 11, 22)}).Now})
	if !l2b.Status().OK || countChainProblems(t, dir) != 1 {
		t.Fatalf("%+v %d", l2b.Status(), countChainProblems(t, dir))
	}
	l2b.Close()
	// line 4 is rewritten again, keeping its prev
	ls = lines(t, p)
	ls[1] = bytes.Replace(ls[1], []byte("b@example.com"), []byte("c@example.com"), 1)
	write(t, p, ls)
	l3, err := Open(dir, Options{Now: (&fakeClock{at(2026, 11, 22)}).Now})
	if err != nil {
		t.Fatal(err)
	}
	defer l3.Close()
	if st := l3.Status(); st.OK || pendingKinds(l3) != "edited@4" || countChainProblems(t, dir) != 2 {
		t.Fatalf("a rewrite after the acknowledgement must be reported again: %+v", st)
	}
}

func TestAckDoesNotHideANewHeadProblemAndANewCut(t *testing.T) {
	l, dir := newLog(t, Options{})
	fill(t, l, 6)
	l.Close()
	head := filepath.Join(dir, "head.json")
	if err := os.WriteFile(head, []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	who := &auth.Identity{ID: "boss@example.com", Method: "oidc"}
	l2, err := Open(dir, Options{Now: (&fakeClock{at(2026, 11, 22)}).Now})
	if err != nil {
		t.Fatal(err)
	}
	if pendingKinds(l2) != "head_mismatch@0" {
		t.Fatalf("%s", pendingKinds(l2))
	}
	if err := l2.Ack(who, l2.Status().LastSeq); err != nil {
		t.Fatal(err)
	}
	l2.Record(ev("login"))
	l2.Record(ev("login"))
	l2.Close()
	// head.json is garbage again and lines are cut from the end
	p := filepath.Join(dir, "audit-2026-11.jsonl")
	ls := lines(t, p)
	write(t, p, ls[:len(ls)-2])
	if err := os.WriteFile(head, []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l3, err := Open(dir, Options{Now: (&fakeClock{at(2026, 11, 22)}).Now})
	if err != nil {
		t.Fatal(err)
	}
	defer l3.Close()
	if l3.Status().OK || pendingKinds(l3) != "head_mismatch@0" || countChainProblems(t, dir) != 2 {
		t.Fatalf("%+v", l3.Status())
	}
}

// An entry added to index.json by hand does not verify a commit: each hit is
// checked against the chain.
func TestForgedIndexEntryDoesNotVerify(t *testing.T) {
	l, dir := newLog(t, Options{})
	l.Record(commitEv("ledger", hashA, "a@example.com"))
	l.Record(ev("login"))
	l.Record(commitEv("ledger", hashB, "b@example.com"))
	keys := []CommitKey{{"ledger", hashA}, {"ledger", hashB}, {"ledger", hashC}}
	if got := l.LookupCommits(keys); len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	path := filepath.Join(dir, indexName)
	b, _ := os.ReadFile(path)
	forged := bytes.Replace(b, []byte(`"commits":{`), []byte(`"commits":{"ledger:`+hashC+`":{"seq":2,"identity":"mallory"},"ledger:`+hashA+`":{"seq":3,"identity":"mallory"},`), 1)
	if bytes.Equal(forged, b) {
		t.Fatal("no forged entry")
	}
	os.WriteFile(path, forged, 0o600)
	l2, _ := Open(dir, Options{})
	defer l2.Close()
	got := l2.LookupCommits(keys)
	if _, ok := got[CommitKey{"ledger", hashC}]; ok {
		t.Fatalf("a forged entry verified a commit: %+v", got)
	}
	if got[CommitKey{"ledger", hashA}].Identity != "a@example.com" || got[CommitKey{"ledger", hashB}].Identity != "b@example.com" {
		t.Fatalf("the real entries stay: %+v", got)
	}
}

// Resuming after a scan budget ran out reaches every match, and a file of a
// later month than Until is not read at all.
func TestReadResumesAfterTheScanBudgetAndSkipsNewerMonths(t *testing.T) {
	l, dir := newLog(t, Options{})
	for i := 1; i <= 30; i++ {
		e := Event{Event: "login", Identity: "a@example.com"}
		if i%10 == 0 {
			e.Identity = "rare@example.com"
		}
		e.Time = at(2026, 8, 1).AddDate(0, 0, i*4) // Aug 5 ... Nov 29
		l.Record(e)
	}
	var got []int64
	var before int64
	calls := 0
	for {
		p, err := l.Read(Query{Identity: "rare@example.com", Before: before, MaxScan: 4})
		if err != nil {
			t.Fatal(err)
		}
		calls++
		if p.Scanned > 4 {
			t.Fatalf("scanned %d", p.Scanned)
		}
		for _, e := range p.Events {
			got = append(got, e.Seq)
		}
		if !p.More {
			break
		}
		before = p.Next
	}
	if fmt.Sprint(got) != "[30 20 10]" || calls < 7 {
		t.Fatalf("%v after %d calls", got, calls)
	}
	// Until in September: the October and November files are not opened (made unreadable)
	for _, f := range []string{"audit-2026-10.jsonl", "audit-2026-11.jsonl"} {
		if err := os.Chmod(filepath.Join(dir, f), 0); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		for _, f := range []string{"audit-2026-10.jsonl", "audit-2026-11.jsonl"} {
			os.Chmod(filepath.Join(dir, f), 0o600)
		}
	}()
	if os.Geteuid() != 0 {
		p, err := l.Read(Query{Until: at(2026, 9, 30), Limit: 3})
		if err != nil || len(p.Events) != 3 || p.Events[0].Time.After(at(2026, 9, 30)) {
			t.Fatalf("%v %+v", err, p)
		}
	}
}

// A chain break right after a commit line makes that one commit unverified; it
// does not make every lookup rebuild the index.
func TestChainBreakAfterACommitLineDoesNotRebuildTheIndexEveryTime(t *testing.T) {
	l, dir := newLog(t, Options{})
	l.Record(ev("login"))
	l.Record(commitEv("ledger", hashA, "a@example.com"))
	l.Record(ev("login"))
	l.Record(commitEv("ledger", hashB, "b@example.com"))
	l.Record(ev("login"))
	l.Close()
	p := filepath.Join(dir, "audit-2026-11.jsonl")
	ls := lines(t, p)
	ls[1] = bytes.Replace(ls[1], []byte(`"name":"N a@example.com"`), []byte(`"name":"N mallory"`), 1) // line 2 edited: line 3 no longer chains to it
	write(t, p, ls)
	l2, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	keys := []CommitKey{{"ledger", hashA}, {"ledger", hashB}}
	for i := 0; i < 6; i++ {
		got := l2.LookupCommits(keys)
		if _, ok := got[keys[0]]; ok {
			t.Fatalf("a commit line that nothing vouches for is unverified: %+v", got)
		}
		if got[keys[1]].Identity != "b@example.com" {
			t.Fatalf("the other commit stays verified: %+v", got)
		}
	}
	if l2.index.rebuilds > 1 {
		t.Fatalf("the index was rebuilt %d times", l2.index.rebuilds)
	}
}

// Reading deep into a big month file seeks near the cursor instead of parsing
// every newer line.
func TestDeepReadDoesNotParseTheNewerLines(t *testing.T) {
	l, _ := newLog(t, Options{})
	for i := 0; i < 5000; i++ {
		l.Record(ev("login"))
	}
	linesParsed.Store(0)
	p, err := l.Read(Query{Before: 120, Limit: 5})
	if err != nil || seqs(p.Events) != "119,118,117,116,115" {
		t.Fatalf("%v %+v", err, seqs(p.Events))
	}
	if n := linesParsed.Load(); n > 1200 {
		t.Fatalf("%d lines parsed for a read at seq 120 of 5000", n)
	}
	// the file grows: the offsets follow
	for i := 0; i < 700; i++ {
		l.Record(ev("login"))
	}
	if p, _ := l.Read(Query{Before: 5600, Limit: 3}); seqs(p.Events) != "5599,5598,5597" {
		t.Fatalf("%s", seqs(p.Events))
	}
	if p, _ := l.Read(Query{Before: 5200, Limit: 2}); seqs(p.Events) != "5199,5198" {
		t.Fatalf("%s", seqs(p.Events))
	}
}
