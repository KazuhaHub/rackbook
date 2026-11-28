package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/ansiblerepo"
	"github.com/kazuhahub/rackbook/internal/auth"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }

func newLog(t *testing.T, o Options) (*Log, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "audit")
	if o.Now == nil {
		o.Now = (&fakeClock{time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)}).Now
	}
	l, err := Open(dir, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	return l, dir
}

func ev(name string) Event { return Event{Event: name, Identity: "a@example.com"} }

func at(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 12, 0, 0, 0, time.UTC) }

func lines(t *testing.T, path string) [][]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
}

func write(t *testing.T, path string, ls [][]byte) {
	t.Helper()
	if err := os.WriteFile(path, append(bytes.Join(ls, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func kinds(r Report) string {
	var k []string
	for _, p := range r.Problems {
		k = append(k, fmt.Sprintf("%s@%d", p.Kind, p.Seq))
	}
	return strings.Join(k, ",")
}

func mustVerify(t *testing.T, dir string) Report {
	t.Helper()
	r, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// fill records n events: two in October, the rest in November 2026.
func fill(t *testing.T, l *Log, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		e := ev("login")
		e.Time = at(2026, 11, 1+i)
		if i <= 2 {
			e.Time = at(2026, 10, 20+i)
		}
		l.Record(e)
	}
}

func TestChainAcrossAMonthBoundary(t *testing.T) {
	t.Parallel()
	l, dir := newLog(t, Options{})
	fill(t, l, 6)
	rep := mustVerify(t, dir)
	if !rep.OK || rep.Lines != 6 || rep.Files != 2 {
		t.Fatalf("%+v", rep)
	}
	oct, nov := lines(t, filepath.Join(dir, "audit-2026-10.jsonl")), lines(t, filepath.Join(dir, "audit-2026-11.jsonl"))
	if len(oct) != 2 || len(nov) != 4 {
		t.Fatalf("%d %d", len(oct), len(nov))
	}
	var first, third Event
	_ = json.Unmarshal(oct[0], &first)
	_ = json.Unmarshal(nov[0], &third)
	if first.Seq != 1 || first.Prev != "" || third.Seq != 3 || third.Prev != hashOf(oct[1]) {
		t.Fatalf("the first line of a month points to the last of the one before: %+v %+v", first, third)
	}
	for _, n := range []string{"audit-2026-10.jsonl", "audit-2026-11.jsonl", "head.json"} {
		st, err := os.Stat(filepath.Join(dir, n))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", n, err, st)
		}
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", st.Mode())
	}
	var h head
	b, _ := os.ReadFile(filepath.Join(dir, "head.json"))
	_ = json.Unmarshal(b, &h)
	if h.Seq != 6 || h.File != "audit-2026-11.jsonl" || h.FirstFile != "audit-2026-10.jsonl" || h.FirstPrev != "" || h.Hash != hashOf(nov[3]) {
		t.Fatalf("%+v", h)
	}
	// A reopened log carries on from the last line.
	l2, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	e := ev("logout")
	e.Time = at(2026, 11, 20)
	l2.Record(e)
	if rep := mustVerify(t, dir); !rep.OK || rep.Lines != 7 {
		t.Fatalf("%+v", rep)
	}
	if st := l2.Status(); !st.OK {
		t.Fatalf("%+v", st)
	}
}

func TestEventTimeIsUTCAndLateEventsDoNotGoBack(t *testing.T) {
	t.Parallel()
	l, dir := newLog(t, Options{})
	e := ev("login")
	e.Time = time.Date(2026, 12, 1, 1, 0, 0, 0, time.FixedZone("x", 3*3600)) // still November in UTC
	l.Record(e)
	e = ev("login")
	e.Time = at(2026, 12, 2)
	l.Record(e)
	e = ev("login")
	e.Time = at(2026, 10, 2) // older than the newest file: appended there
	l.Record(e)
	if rep := mustVerify(t, dir); !rep.OK || rep.Files != 2 || rep.Lines != 3 {
		t.Fatalf("%+v", rep)
	}
	if got := lines(t, filepath.Join(dir, "audit-2026-11.jsonl")); len(got) != 1 || !strings.Contains(string(got[0]), `"time":"2026-11-30T22:00:00Z"`) {
		t.Fatalf("%s", got)
	}
}

func TestTamperIsDetected(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		tamper func(t *testing.T, dir string)
		want   string
	}{
		{"an edited line", func(t *testing.T, dir string) {
			p := filepath.Join(dir, "audit-2026-11.jsonl")
			ls := lines(t, p)
			ls[1] = bytes.Replace(ls[1], []byte("a@example.com"), []byte("b@example.com"), 1)
			write(t, p, ls)
		}, "edited@4"}, // lines 3..6 are in November; the second of them is seq 4
		{"a deleted middle line", func(t *testing.T, dir string) {
			p := filepath.Join(dir, "audit-2026-11.jsonl")
			ls := lines(t, p)
			write(t, p, append(ls[:1:1], ls[2:]...))
		}, "missing@4"},
		{"reordered lines", func(t *testing.T, dir string) {
			p := filepath.Join(dir, "audit-2026-11.jsonl")
			ls := lines(t, p)
			ls[1], ls[2] = ls[2], ls[1]
			write(t, p, ls)
		}, "missing@4,reordered@4,missing@5"},
		{"the last line cut with head unchanged", func(t *testing.T, dir string) {
			p := filepath.Join(dir, "audit-2026-11.jsonl")
			ls := lines(t, p)
			write(t, p, ls[:len(ls)-1])
		}, "cut_from_end@6"},
		{"two last lines cut", func(t *testing.T, dir string) {
			p := filepath.Join(dir, "audit-2026-11.jsonl")
			ls := lines(t, p)
			write(t, p, ls[:len(ls)-2])
		}, "cut_from_end@5"},
		{"head changed", func(t *testing.T, dir string) {
			p := filepath.Join(dir, "head.json")
			b, _ := os.ReadFile(p)
			b = bytes.Replace(b, []byte(`"seq":6`), []byte(`"seq":5`), 1)
			os.WriteFile(p, b, 0o600)
		}, "head_mismatch@6"},
		{"head hash changed", func(t *testing.T, dir string) {
			p := filepath.Join(dir, "head.json")
			b, _ := os.ReadFile(p)
			b = bytes.Replace(b, []byte(`"hash":"sha256:`), []byte(`"hash":"sha256:0`), 1)
			os.WriteFile(p, b, 0o600)
		}, "head_mismatch@6"},
		{"the oldest month deleted", func(t *testing.T, dir string) {
			os.Remove(filepath.Join(dir, "audit-2026-10.jsonl"))
		}, "missing@0"},
		{"a garbled line", func(t *testing.T, dir string) {
			p := filepath.Join(dir, "audit-2026-11.jsonl")
			ls := lines(t, p)
			ls[2] = []byte("{not json")
			write(t, p, ls)
		}, "edited@5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l, dir := newLog(t, Options{})
			fill(t, l, 6)
			tc.tamper(t, dir)
			rep := mustVerify(t, dir)
			if rep.OK || kinds(rep) != tc.want {
				t.Fatalf("got %q, want %q (%+v)", kinds(rep), tc.want, rep.Problems)
			}
			if rep.Repairable() {
				t.Fatal("tampering is not a crash case")
			}
		})
	}
}

func TestTamperedLogStillOpensAndIsReported(t *testing.T) {
	t.Parallel()
	l, dir := newLog(t, Options{})
	fill(t, l, 6)
	p := filepath.Join(dir, "audit-2026-11.jsonl")
	ls := lines(t, p)
	ls[1] = bytes.Replace(ls[1], []byte("a@example.com"), []byte("b@example.com"), 1)
	write(t, p, ls)
	before, _ := os.ReadFile(p)
	var logs bytes.Buffer
	l2, err := Open(dir, Options{Logger: slogTo(&logs), Now: (&fakeClock{at(2026, 11, 22)}).Now})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if st := l2.Status(); st.OK || st.FirstBrokenSeq != 4 || !strings.Contains(st.Problem, "edited") {
		t.Fatalf("%+v", st)
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "firstBrokenSeq=4") {
		t.Fatalf("%s", logs.String())
	}
	if after, _ := os.ReadFile(p); !bytes.HasPrefix(after, before) || bytes.Count(after, []byte("\n")) != 5 {
		t.Fatal("open only appends the chain_problem event")
	}
	l2.Record(ev("logout")) // appends as it is
	rep := mustVerify(t, dir)
	if rep.Lines != 8 || kinds(rep) != "edited@4" || !rep.Problems[0].Recorded || rep.Problems[0].RecordedAt != 7 {
		t.Fatalf("%s %+v", kinds(rep), rep.Problems)
	}
}

func TestCrashRepairTornLine(t *testing.T) {
	t.Parallel()
	l, dir := newLog(t, Options{})
	fill(t, l, 4)
	p := filepath.Join(dir, "audit-2026-11.jsonl")
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"seq":5,"time":"2026-11-22T10:00:00Z","event":"log`)
	f.Close()
	if rep := mustVerify(t, dir); kinds(rep) != "truncated_tail@5" || !rep.Repairable() {
		t.Fatalf("%s", kinds(rep))
	}
	l2, err := Open(dir, Options{Now: (&fakeClock{at(2026, 11, 22)}).Now})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if st := l2.Status(); !st.OK {
		t.Fatalf("%+v", st)
	}
	torn, err := os.ReadFile(filepath.Join(dir, "torn-5.jsonl"))
	if err != nil || !strings.HasPrefix(string(torn), `{"seq":5`) {
		t.Fatalf("%v %q", err, torn)
	}
	l2.Record(ev("logout"))
	rep := mustVerify(t, dir)
	if !rep.OK || rep.Lines != 5 {
		t.Fatalf("%s %+v", kinds(rep), rep)
	}
	var last Event
	ls := lines(t, p)
	_ = json.Unmarshal(ls[len(ls)-1], &last)
	if last.Seq != 5 {
		t.Fatalf("the chain continues from the last complete line: %+v", last)
	}
}

func TestCrashRepairHeadOneBehind(t *testing.T) {
	t.Parallel()
	l, dir := newLog(t, Options{})
	fill(t, l, 4)
	headPath := filepath.Join(dir, "head.json")
	old, _ := os.ReadFile(headPath)
	e := ev("logout")
	e.Time = at(2026, 11, 22)
	l.Record(e)
	if err := os.WriteFile(headPath, old, 0o600); err != nil { // the crash: line 5 written, head not yet
		t.Fatal(err)
	}
	if rep := mustVerify(t, dir); kinds(rep) != "head_behind_one@5" || !rep.Repairable() {
		t.Fatalf("%s", kinds(rep))
	}
	l2, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if st := l2.Status(); !st.OK {
		t.Fatalf("%+v", st)
	}
	if rep := mustVerify(t, dir); !rep.OK {
		t.Fatalf("%s", kinds(rep))
	}
	// One line behind is repaired only when that line is correctly chained.
	l2.Record(ev("login"))
	os.WriteFile(headPath, old, 0o600) // now two behind
	if rep := mustVerify(t, dir); kinds(rep) != "head_mismatch@6" {
		t.Fatalf("%s", kinds(rep))
	}
}

func TestHeadBehindIsNotRepairedWhenTheLastLineDoesNotChain(t *testing.T) {
	t.Parallel()
	l, dir := newLog(t, Options{})
	fill(t, l, 4)
	headPath := filepath.Join(dir, "head.json")
	old, _ := os.ReadFile(headPath)
	l.Record(ev("logout"))
	os.WriteFile(headPath, old, 0o600)
	p := filepath.Join(dir, "audit-2026-11.jsonl")
	ls := lines(t, p)
	ls[len(ls)-1] = bytes.Replace(ls[len(ls)-1], []byte(`"prev":"sha256:`), []byte(`"prev":"sha256:0`), 1)
	write(t, p, ls)
	if rep := mustVerify(t, dir); rep.Repairable() {
		t.Fatalf("%s", kinds(rep))
	}
	l2, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if l2.Status().OK {
		t.Fatal("must be reported")
	}
	// not repaired: written into the chain, and only then does head.json move on
	rep := mustVerify(t, dir)
	if kinds(rep) != "edited@4,head_mismatch@5" || !rep.Problems[0].Recorded || !rep.Problems[1].Recorded {
		t.Fatalf("%+v", rep.Problems)
	}
}

func chainProblems(t *testing.T, dir string) []Event {
	t.Helper()
	var out []Event
	files, _ := listFiles(dir)
	for _, f := range files {
		for _, ln := range lines(t, filepath.Join(dir, f)) {
			var e Event
			_ = json.Unmarshal(ln, &e)
			if e.Event == ChainProblemEvent {
				out = append(out, e)
			}
		}
	}
	return out
}

func TestCutLinesAreRecordedInTheChain(t *testing.T) {
	t.Parallel()
	l, dir := newLog(t, Options{})
	fill(t, l, 6)
	l.Close()
	p := filepath.Join(dir, "audit-2026-11.jsonl")
	ls := lines(t, p)
	oldHead, _ := os.ReadFile(filepath.Join(dir, "head.json"))
	var oh head
	_ = json.Unmarshal(oldHead, &oh)
	write(t, p, ls[:len(ls)-1]) // the last line cut, head.json unchanged
	if rep := mustVerify(t, dir); kinds(rep) != "cut_from_end@6" || rep.Problems[0].Recorded {
		t.Fatalf("%+v", rep.Problems)
	}
	l2, err := Open(dir, Options{Now: (&fakeClock{at(2026, 11, 22)}).Now})
	if err != nil {
		t.Fatal(err)
	}
	if st := l2.Status(); st.OK || st.FirstBrokenSeq != 6 || !strings.Contains(st.Problem, "recorded at seq 6") {
		t.Fatalf("%+v", st)
	}
	// the evidence is the first thing appended, and carries what head.json said
	cp := chainProblems(t, dir)
	if len(cp) != 1 || cp[0].Seq != 6 || cp[0].Code != KindCutFromEnd || cp[0].Detail[0] != "seq=6" ||
		cp[0].Detail[1] != "head_seq=6" || cp[0].Detail[2] != "head_hash="+oh.Hash {
		t.Fatalf("%+v", cp)
	}
	l2.Record(ev("login"))
	l2.Close()
	// restart again: nothing new is recorded, the cut is still listed
	l3, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l3.Close()
	l3.Record(ev("login"))
	if len(chainProblems(t, dir)) != 1 {
		t.Fatal("a problem is recorded once")
	}
	rep := mustVerify(t, dir)
	if rep.OK || len(rep.Problems) != 1 || rep.Problems[0].Kind != KindCutFromEnd || rep.Problems[0].Seq != 6 ||
		!rep.Problems[0].Recorded || rep.Problems[0].RecordedAt != 6 || rep.Lines != 8 {
		t.Fatalf("%+v", rep)
	}
	if rep.Repairable() || l3.Status().OK {
		t.Fatal("a recorded problem is still a problem until acknowledged")
	}
	if !strings.Contains(rep.Problems[0].Describe(), "recorded at seq 6") {
		t.Fatal(rep.Problems[0].Describe())
	}
}

func TestEveryKindOfBreakIsRecordedOnce(t *testing.T) {
	t.Parallel()
	for name, tamper := range map[string]func(ls [][]byte) [][]byte{
		"edited": func(ls [][]byte) [][]byte {
			ls[1] = bytes.Replace(ls[1], []byte("a@example.com"), []byte("b@example.com"), 1)
			return ls
		},
		"missing": func(ls [][]byte) [][]byte { return append(ls[:1:1], ls[2:]...) },
		"reordered": func(ls [][]byte) [][]byte {
			ls[1], ls[2] = ls[2], ls[1]
			return ls
		},
	} {
		t.Run(name, func(t *testing.T) {
			l, dir := newLog(t, Options{})
			fill(t, l, 6)
			l.Close()
			p := filepath.Join(dir, "audit-2026-11.jsonl")
			write(t, p, tamper(lines(t, p)))
			first := mustVerify(t, dir)
			for i := 0; i < 2; i++ { // two restarts
				l2, err := Open(dir, Options{})
				if err != nil {
					t.Fatal(err)
				}
				l2.Close()
			}
			rep := mustVerify(t, dir)
			if rep.OK || len(rep.Problems) != len(first.Problems) || len(chainProblems(t, dir)) != len(first.Problems) {
				t.Fatalf("before %v, after %v (%d events)", kinds(first), kinds(rep), len(chainProblems(t, dir)))
			}
			for _, pr := range rep.Problems {
				if !pr.Recorded {
					t.Fatalf("%+v", pr)
				}
			}
		})
	}
}

func TestRetention(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{at(2026, 11, 22)}
	l, dir := newLog(t, Options{Now: clk.Now})
	for _, m := range []time.Month{1, 2, 3, 9, 10, 11} {
		for d := 1; d <= 2; d++ {
			e := ev("login")
			e.Time = at(2026, m, d)
			l.Record(e)
		}
	}
	l.Close()
	if rep := mustVerify(t, dir); !rep.OK || rep.Files != 6 {
		t.Fatalf("%+v", rep)
	}
	// 2 whole months before November: files older than September go.
	l2, err := Open(dir, Options{RetentionMonths: 2, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	files, _ := listFiles(dir)
	if strings.Join(files, " ") != "audit-2026-09.jsonl audit-2026-10.jsonl audit-2026-11.jsonl" {
		t.Fatalf("%v", files)
	}
	rep := mustVerify(t, dir)
	if !rep.OK || rep.Files != 3 || rep.Lines != 6 {
		t.Fatalf("%s %+v", kinds(rep), rep)
	}
	var h head
	b, _ := os.ReadFile(filepath.Join(dir, "head.json"))
	_ = json.Unmarshal(b, &h)
	if h.FirstFile != "audit-2026-09.jsonl" || h.FirstPrev == "" {
		t.Fatalf("%+v", h)
	}
	// The log keeps growing and verifies; deleting yet more months works too.
	clk.t = at(2027, 1, 5)
	e := ev("login")
	l2.Record(e)
	l2.opts.RetentionMonths = 2
	l2.prune()
	files, _ = listFiles(dir)
	if strings.Join(files, " ") != "audit-2026-11.jsonl audit-2027-01.jsonl" {
		t.Fatalf("%v", files)
	}
	if rep := mustVerify(t, dir); !rep.OK || rep.Lines != 3 {
		t.Fatalf("%s %+v", kinds(rep), rep)
	}
	// Deleting a kept month is still caught.
	os.Remove(filepath.Join(dir, "audit-2026-11.jsonl"))
	if rep := mustVerify(t, dir); rep.OK {
		t.Fatal("a missing month must be detected")
	}
}

func TestRetentionKeepsTheCurrentMonthAndEverythingWhenZero(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{at(2026, 11, 22)}
	l, dir := newLog(t, Options{Now: clk.Now})
	fill(t, l, 4)
	l.Close()
	l2, _ := Open(dir, Options{Now: clk.Now}) // 0: keep all
	l2.Close()
	if files, _ := listFiles(dir); len(files) != 2 {
		t.Fatalf("%v", files)
	}
	clk.t = at(2030, 1, 1) // far later: the newest file is still never deleted
	l3, _ := Open(dir, Options{RetentionMonths: 1, Now: clk.Now})
	l3.Close()
	if files, _ := listFiles(dir); len(files) != 1 || files[0] != "audit-2026-11.jsonl" {
		t.Fatalf("%v", files)
	}
	if rep := mustVerify(t, dir); !rep.OK {
		t.Fatalf("%s", kinds(rep))
	}
}

func TestRetentionWaitsForAProblemThatIsNotRecordedYet(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{at(2026, 11, 22)}
	var logs bytes.Buffer
	l, dir := newLog(t, Options{Now: clk.Now, RetentionMonths: 1, Logger: slogTo(&logs)})
	fill(t, l, 4)
	clk.t = at(2027, 1, 5)
	p := filepath.Join(dir, "audit-2026-11.jsonl")
	ls := lines(t, p)
	ls[0] = bytes.Replace(ls[0], []byte("a@example.com"), []byte("b@example.com"), 1)
	write(t, p, ls) // tampered while the server runs
	l.prune()
	if files, _ := listFiles(dir); len(files) != 2 {
		t.Fatalf("evidence must not be deleted: %v", files)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "retention skipped") {
		t.Fatalf("a skipped run says why: %s", logs.String())
	}
}

func TestRetentionRunsAfterAProblemIsRecordedAndKeepsTheFileHoldingIt(t *testing.T) {
	t.Parallel()
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
	ls := lines(t, p)
	write(t, p, ls[:1]) // the last line cut
	clk.t = at(2026, 3, 15)
	l2, err := Open(dir, Options{Now: clk.Now}) // records the cut in the March file
	if err != nil {
		t.Fatal(err)
	}
	clk.t = at(2026, 4, 2)
	l2.Record(ev("login"))
	l2.Close()
	clk.t = at(2026, 6, 5)
	var logs bytes.Buffer
	l3, err := Open(dir, Options{Now: clk.Now, RetentionMonths: 1, Logger: slogTo(&logs)})
	if err != nil {
		t.Fatal(err)
	}
	defer l3.Close()
	files, _ := listFiles(dir)
	if strings.Join(files, " ") != "audit-2026-03.jsonl audit-2026-04.jsonl" {
		t.Fatalf("retention must run, and keep the file with the chain_problem: %v\n%s", files, logs.String())
	}
	if !strings.Contains(logs.String(), "keeps a file that holds a chain_problem") {
		t.Fatalf("%s", logs.String())
	}
	rep := mustVerify(t, dir)
	if rep.OK || len(rep.Problems) != 1 || rep.Problems[0].Kind != KindCutFromEnd || !rep.Problems[0].Recorded {
		t.Fatalf("%+v", rep)
	}
	if l3.Status().OK {
		t.Fatal("still not OK")
	}
}

func TestFirstFileCannotHideAnEditInAnOldMonth(t *testing.T) {
	t.Parallel()
	l, dir := newLog(t, Options{})
	for _, m := range []time.Month{9, 10, 11} {
		for d := 1; d <= 2; d++ {
			e := ev("login")
			e.Time = at(2026, m, d)
			l.Record(e)
		}
	}
	l.Close()
	sep := filepath.Join(dir, "audit-2026-09.jsonl")
	ls := lines(t, sep)
	ls[1] = bytes.Replace(ls[1], []byte("a@example.com"), []byte("mallory@example.com"), 1)
	write(t, sep, ls)
	// point head.json past the old month, with the prev October's first line already has
	var h head
	b, _ := os.ReadFile(filepath.Join(dir, "head.json"))
	_ = json.Unmarshal(b, &h)
	oct := lines(t, filepath.Join(dir, "audit-2026-10.jsonl"))
	var first Event
	_ = json.Unmarshal(oct[0], &first)
	h.FirstFile, h.FirstPrev = "audit-2026-10.jsonl", first.Prev
	nb, _ := json.Marshal(h)
	os.WriteFile(filepath.Join(dir, "head.json"), nb, 0o600)
	rep := mustVerify(t, dir)
	got := kinds(rep)
	if rep.OK || !strings.Contains(got, "first_file_mismatch@0") || !strings.Contains(got, "edited@2") || rep.Files != 3 {
		t.Fatalf("%s %+v", got, rep)
	}
	// without the head.json trick the edit is found as well
	h.FirstFile, h.FirstPrev = "audit-2026-09.jsonl", ""
	nb, _ = json.Marshal(h)
	os.WriteFile(filepath.Join(dir, "head.json"), nb, 0o600)
	if got := kinds(mustVerify(t, dir)); got != "edited@2" {
		t.Fatalf("%s", got)
	}
}

func TestVerifyLooksAgainBeforeReportingAHeadMismatch(t *testing.T) {
	l, dir := newLog(t, Options{})
	fill(t, l, 6)
	l.Close()
	headPath := filepath.Join(dir, "head.json")
	good, _ := os.ReadFile(headPath)
	stale := bytes.Replace(good, []byte(`"seq":6`), []byte(`"seq":3`), 1) // a server mid-append
	os.WriteFile(headPath, stale, 0o600)
	calls := 0
	beforeRescan = func() { calls++; os.WriteFile(headPath, good, 0o600) } // the rename lands
	defer func() { beforeRescan = nil }()
	if rep := mustVerify(t, dir); !rep.OK || calls != 1 {
		t.Fatalf("%s calls=%d", kinds(rep), calls)
	}
	// a real mismatch is still reported after the second look
	os.WriteFile(headPath, stale, 0o600)
	beforeRescan = func() { calls++ }
	if rep := mustVerify(t, dir); rep.OK || calls != 2 {
		t.Fatalf("%s calls=%d", kinds(rep), calls)
	}
}

// tornDir is a log of five lines followed by a partial line, with head.json at headSeq.
func tornDir(t *testing.T, headSeq int) string {
	t.Helper()
	l, dir := newLog(t, Options{})
	fill(t, l, 5)
	l.Close()
	b, _ := os.ReadFile(filepath.Join(dir, "head.json"))
	if headSeq != 5 { // a head that does not fit the last complete line
		var h head
		_ = json.Unmarshal(b, &h)
		h.Seq = int64(headSeq)
		b, _ = json.Marshal(h)
		os.WriteFile(filepath.Join(dir, "head.json"), b, 0o600)
	}
	f, _ := os.OpenFile(filepath.Join(dir, "audit-2026-11.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"seq":6,"time":"2026-11`)
	f.Close()
	return dir
}

func TestUnexplainedTornTailIsSetAsideRecordedAndAuditingContinues(t *testing.T) {
	t.Parallel()
	dir := tornDir(t, 4) // head behind AND a partial line: not what a crash leaves
	rep := mustVerify(t, dir)
	if rep.Repairable() || !strings.Contains(kinds(rep), "edited@6") {
		t.Fatalf("%s", kinds(rep))
	}
	var logs bytes.Buffer
	l, err := Open(dir, Options{Logger: slogTo(&logs), Now: (&fakeClock{at(2026, 11, 22)}).Now})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	torn, err := os.ReadFile(filepath.Join(dir, "torn-6.jsonl"))
	if err != nil || !strings.HasPrefix(string(torn), `{"seq":6`) {
		t.Fatalf("the partial bytes are set aside: %v %q", err, torn)
	}
	if st := l.Status(); st.OK || st.FirstBrokenSeq != 6 {
		t.Fatalf("%+v", st)
	}
	cp := chainProblems(t, dir)
	if len(cp) == 0 || cp[0].Code != KindEdited || cp[0].Detail[0] != "seq=6" || cp[0].Detail[1] != "head_seq=4" || cp[0].Detail[3] != "torn=torn-6.jsonl" {
		t.Fatalf("%+v", cp)
	}
	l.Record(ev("login")) // keeps auditing
	rep = mustVerify(t, dir)
	if rep.OK || rep.Problems[0].Kind != KindEdited || rep.Problems[0].Seq != 6 || !rep.Problems[0].Recorded {
		t.Fatalf("%+v", rep.Problems)
	}
	for _, p := range rep.Problems {
		if !p.Recorded {
			t.Fatalf("%+v", p)
		}
	}
	if rep.Lines != 5+len(cp)+1 {
		t.Fatalf("%d lines", rep.Lines)
	}
}

func TestFailingToSetTheTailAsideFailsTheLog(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	dir := tornDir(t, 5)
	p := filepath.Join(dir, "audit-2026-11.jsonl")
	before, _ := os.ReadFile(p)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skip(err)
	}
	defer os.Chmod(dir, 0o700)
	var logs bytes.Buffer
	l, err := Open(dir, Options{Logger: slogTo(&logs)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if st := l.Status(); st.OK || !strings.Contains(st.Problem, "could not be set aside") {
		t.Fatalf("%+v", st)
	}
	os.Chmod(dir, 0o700) // even when writing would work again, the failed log stays failed
	l.Record(ev("login"))
	if after, _ := os.ReadFile(p); !bytes.Equal(before, after) {
		t.Fatal("nothing may be written after a failed set-aside")
	}
	if !strings.Contains(logs.String(), "failed state") {
		t.Fatalf("%s", logs.String())
	}
}

func TestNoWriteWhenTheFileSizeIsUnknown(t *testing.T) {
	t.Parallel()
	l, dir := newLog(t, Options{})
	l.Record(ev("login"))
	p := filepath.Join(dir, "audit-2026-11.jsonl")
	before, _ := os.ReadFile(p)
	l.stat = func(*os.File) (os.FileInfo, error) { return nil, errors.New("stat failed") }
	l.Record(ev("logout"))
	if after, _ := os.ReadFile(p); !bytes.Equal(before, after) {
		t.Fatal("nothing may be written, and nothing truncated")
	}
	l.stat = (*os.File).Stat
	l.Record(ev("logout"))
	if rep := mustVerify(t, dir); !rep.OK || rep.Lines != 2 {
		t.Fatalf("%s %+v", kinds(rep), rep)
	}
}

func TestMigrationStopsOnTheFirstAppendError(t *testing.T) {
	t.Parallel()
	l0, dir := newLog(t, Options{})
	l0.Close()
	l, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	l.failed = "test: every append is refused"
	old := filepath.Join(t.TempDir(), "infra-audit.jsonl")
	os.WriteFile(old, []byte(`{"time":"2026-09-03T08:00:00Z","who":"ann@example.com","action":"a1","outcome":"conflict"}
{"time":"2026-09-03T08:01:00Z","who":"ann@example.com","action":"a2","outcome":"conflict"}
`), 0o600)
	var logs bytes.Buffer
	l.log = slogTo(&logs)
	if err := l.MigrateInfra(old); err == nil {
		t.Fatal("the append error must be returned")
	}
	l.Close()
	b, _ := os.ReadFile(filepath.Join(dir, "migrated"))
	var m marker
	if json.Unmarshal(b, &m) != nil || m.State != "in_progress" || m.SourceLines != 2 {
		t.Fatalf("the marker must stay in_progress: %s", b)
	}
	if rep := mustVerify(t, dir); rep.Lines != 0 {
		t.Fatalf("nothing may be appended: %+v", rep)
	}
}

func TestAddrModes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		mode AddrMode
		in   string
		want string
	}{
		{AddrTruncate, "203.0.113.7", "203.0.113.0"},
		{AddrTruncate, "2001:db8:1:2:3:4:5:6", "2001:db8:1::"},
		{AddrTruncate, "2001:db8:1:2::/64", "2001:db8:1::"}, // the form internal/clientip returns
		{AddrTruncate, "::ffff:203.0.113.7", "203.0.113.0"},
		{AddrTruncate, "not an address", ""},
		{AddrTruncate, "", ""},
		{"", "203.0.113.7", "203.0.113.0"}, // the default
		{AddrFull, "203.0.113.7", "203.0.113.7"},
		{AddrFull, "2001:db8:1:2::/64", "2001:db8:1:2::/64"},
		{AddrFull, "not an address", "not an address"},
		{AddrNone, "203.0.113.7", ""},
	}
	for _, tc := range tests {
		t.Run(string(tc.mode)+"/"+tc.in, func(t *testing.T) {
			l, dir := newLog(t, Options{Addr: tc.mode})
			l.Record(Event{Event: "login", Addr: tc.in})
			var e Event
			_ = json.Unmarshal(lines(t, filepath.Join(dir, "audit-2026-11.jsonl"))[0], &e)
			if e.Addr != tc.want {
				t.Fatalf("got %q, want %q", e.Addr, tc.want)
			}
		})
	}
	if _, err := ParseAddrMode("bogus"); err == nil {
		t.Fatal("a bad mode must be refused")
	}
	if m, err := ParseAddrMode(""); err != nil || m != AddrTruncate {
		t.Fatalf("%v %v", m, err)
	}
}

func TestMigrateInfra(t *testing.T) {
	t.Parallel()
	l, dir := newLog(t, Options{})
	old := filepath.Join(t.TempDir(), "infra-audit.jsonl")
	entries := []string{
		`{"time":"2026-09-03T08:00:00Z","who":"ann@example.com","action":"infra(secrets/alpha): reveal","outcome":"revealed","files":["secrets/alpha.sops.yml"]}`,
		`{"time":"2026-09-03T08:01:00Z","who":"ann@example.com","action":"infra(secrets/alpha): reveal","outcome":"rate_limited","files":["secrets/alpha.sops.yml"],"detail":["hourly"]}`,
		`{"time":"2026-09-03T08:02:00Z","who":"ann@example.com","action":"infra(secrets/alpha): reveal","outcome":"no_such_key"}`,
		`{"time":"2026-10-04T09:00:00Z","who":"bob@example.com","action":"infra(secrets/alpha): reencrypt","outcome":"reencrypted"}`,
		`not json`,
		`{"time":"2026-10-05T09:00:00Z","who":"bob@example.com","action":"infra(host_vars/alpha): edit","outcome":"conflict","files":["host_vars/alpha.yml"],"detail":["abc123"]}`,
	}
	os.WriteFile(old, []byte(strings.Join(entries, "\n")+"\n"), 0o600)
	var logs bytes.Buffer
	l.log = slogTo(&logs)
	if err := l.MigrateInfra(old); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "does not parse") {
		t.Fatalf("an unparsable line must be warned about: %s", logs.String())
	}
	var got []Event
	for _, f := range []string{"audit-2026-09.jsonl", "audit-2026-10.jsonl"} {
		for _, ln := range lines(t, filepath.Join(dir, f)) {
			var e Event
			_ = json.Unmarshal(ln, &e)
			got = append(got, e)
		}
	}
	if len(got) != 5 {
		t.Fatalf("%d events", len(got))
	}
	want := []struct{ event, outcome, code, host string }{
		{"secret_revealed", "revealed", "", "alpha"},
		{"secret_reveal_refused", "rate_limited", "", "alpha"},
		{"secret_reveal_refused", "no_such_key", "", "alpha"},
		{"reencrypted", "reencrypted", "", "alpha"},
		{"write_refused", "conflict", "conflict", ""},
	}
	for i, w := range want {
		e := got[i]
		if e.Event != w.event || e.Outcome != w.outcome || e.Code != w.code || e.Host != w.host || e.Area != "infra" || e.Seq != int64(i+1) {
			t.Errorf("%d: %+v", i, e)
		}
	}
	if got[0].Identity != "ann@example.com" || !got[0].Time.Equal(time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)) || got[0].Files[0] != "secrets/alpha.sops.yml" || got[0].Action == "" {
		t.Errorf("%+v", got[0])
	}
	if got[1].Detail[0] != "hourly" || got[4].Detail[0] != "abc123" {
		t.Errorf("detail: %+v %+v", got[1], got[4])
	}
	if _, err := os.Stat(filepath.Join(dir, "migrated")); err != nil {
		t.Fatal("the marker must exist")
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatal("the old file stays")
	}
	if rep := mustVerify(t, dir); !rep.OK || rep.Lines != 5 {
		t.Fatalf("%s", kinds(rep))
	}
	// Once only.
	if err := l.MigrateInfra(old); err != nil {
		t.Fatal(err)
	}
	if rep := mustVerify(t, dir); rep.Lines != 5 {
		t.Fatalf("migrated twice: %d lines", rep.Lines)
	}
	// Nothing to copy: no marker.
	l2, dir2 := newLog(t, Options{})
	if err := l2.MigrateInfra(filepath.Join(t.TempDir(), "none.jsonl")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir2, "migrated")); err == nil {
		t.Fatal("no marker without an old file")
	}
}

func TestInfraAuditorKeepsTheServerLogLines(t *testing.T) {
	t.Parallel()
	l, dir := newLog(t, Options{})
	var logs bytes.Buffer
	next := &ansiblerepo.AuditLog{Log: slogTo(&logs)}
	a := &InfraAuditor{Log: l, Next: next}
	a.Record(ansiblerepo.AuditEntry{Time: at(2026, 11, 3), Who: "ann@example.com", Action: "x", Outcome: "validation_failed", Detail: []string{"secret"}})
	if !strings.Contains(logs.String(), "infra edit not committed") {
		t.Fatalf("%s", logs.String())
	}
	var e Event
	_ = json.Unmarshal(lines(t, filepath.Join(dir, "audit-2026-11.jsonl"))[0], &e)
	if e.Event != "write_refused" || e.Code != "validation_failed" || e.Identity != "ann@example.com" {
		t.Fatalf("%+v", e)
	}
	(&InfraAuditor{Next: next}).Record(ansiblerepo.AuditEntry{}) // no log: still fine
	var nilAuditor *InfraAuditor
	nilAuditor.Record(ansiblerepo.AuditEntry{})
}

func TestConcurrentRecord(t *testing.T) {
	t.Parallel()
	l, dir := newLog(t, Options{})
	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				l.Record(Event{Event: "login", Identity: fmt.Sprint(g, ":", i)})
			}
		}()
	}
	wg.Wait()
	if rep := mustVerify(t, dir); !rep.OK || rep.Lines != 500 {
		t.Fatalf("%s %+v", kinds(rep), rep)
	}
}

func TestNilLogIsANoop(t *testing.T) {
	t.Parallel()
	var l *Log
	l.Record(ev("login"))
	l.Close()
	if err := l.MigrateInfra("x"); err != nil {
		t.Fatal(err)
	}
	if !l.Status().OK {
		t.Fatal("a nil log has no problem")
	}
	var a *auth.Identity
	e := Event{}
	e.By(a)
	if e.Identity != "" {
		t.Fatal("no identity")
	}
	e.By(&auth.Identity{ID: "ann", Name: "Ann", Method: auth.MethodToken, Token: "ci"})
	if e.Identity != "ann" || e.Method != "token" || len(e.Detail) != 1 || e.Detail[0] != "token:ci" {
		t.Fatalf("%+v", e)
	}
}

func TestAWriteErrorIsLoggedNotReturned(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	l, dir := newLog(t, Options{Logger: slogTo(&logs)})
	l.Record(ev("login"))
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skip(err)
	}
	defer os.Chmod(dir, 0o700)
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	e := ev("login")
	e.Time = at(2027, 1, 1) // needs a new file
	l.Record(e)
	if !strings.Contains(logs.String(), "could not record an event") {
		t.Fatalf("%s", logs.String())
	}
	os.Chmod(dir, 0o700)
	l.Record(ev("logout"))
	if rep := mustVerify(t, dir); !rep.OK || rep.Lines != 2 {
		t.Fatalf("%s %+v", kinds(rep), rep)
	}
}

func TestVerifyEmptyAndMissingDirectory(t *testing.T) {
	t.Parallel()
	_, dir := newLog(t, Options{})
	if rep := mustVerify(t, dir); !rep.OK || rep.Lines != 0 {
		t.Fatalf("%+v", rep)
	}
	if _, err := Verify(filepath.Join(dir, "nope")); err == nil {
		t.Fatal("a missing directory is an error")
	}
	// Every file deleted but head.json: lines were cut from the end.
	l, dir2 := newLog(t, Options{})
	fill(t, l, 3)
	os.Remove(filepath.Join(dir2, "audit-2026-10.jsonl"))
	os.Remove(filepath.Join(dir2, "audit-2026-11.jsonl"))
	if rep := mustVerify(t, dir2); !strings.Contains(kinds(rep), "cut_from_end") {
		t.Fatalf("%s", kinds(rep))
	}
}

func TestMigrationResumesAfterACrash(t *testing.T) {
	t.Parallel()
	entries := []string{
		`{"time":"2026-09-03T08:00:00Z","who":"ann@example.com","action":"a1","outcome":"revealed"}`,
		`{"time":"2026-09-03T08:01:00Z","who":"ann@example.com","action":"a2","outcome":"conflict"}`,
		`not json`,
		`{"time":"2026-09-03T08:02:00Z","who":"ann@example.com","action":"a3","outcome":"conflict"}`,
		`{"time":"2026-10-03T08:03:00Z","who":"ann@example.com","action":"a4","outcome":"reencrypted"}`,
		`{"time":"2026-10-03T08:04:00Z","who":"ann@example.com","action":"a5","outcome":"forbidden"}`,
	}
	const n = 5 // parsable lines
	for _, k := range []int{0, 1, 3, 4} {
		t.Run(fmt.Sprint("crash after ", k), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "audit")
			old := filepath.Join(t.TempDir(), "infra-audit.jsonl")
			os.WriteFile(old, []byte(strings.Join(entries, "\n")+"\n"), 0o600)
			l, err := Open(dir, Options{InfraPath: old, migrateStop: func(i int) bool { return i == k }})
			if err != nil {
				t.Fatal(err)
			}
			l.Close()
			b, _ := os.ReadFile(filepath.Join(dir, "migrated"))
			var m marker
			if json.Unmarshal(b, &m) != nil || m.State != "in_progress" || m.SourceLines != n || m.FirstSeq != 1 {
				t.Fatalf("%s", b)
			}
			if rep := mustVerify(t, dir); rep.Lines != k {
				t.Fatalf("%d lines copied, want %d", rep.Lines, k)
			}
			l2, err := Open(dir, Options{InfraPath: old})
			if err != nil {
				t.Fatal(err)
			}
			l2.Close()
			l3, err := Open(dir, Options{InfraPath: old}) // and once more: nothing happens
			if err != nil {
				t.Fatal(err)
			}
			l3.Close()
			b, _ = os.ReadFile(filepath.Join(dir, "migrated"))
			m = marker{}
			if json.Unmarshal(b, &m) != nil || m.State != "done" {
				t.Fatalf("%s", b)
			}
			rep := mustVerify(t, dir)
			if !rep.OK || rep.Lines != n {
				t.Fatalf("exactly %d migrated events wanted: %s %+v", n, kinds(rep), rep)
			}
			var got []string
			files, _ := listFiles(dir)
			for _, f := range files {
				for _, ln := range lines(t, filepath.Join(dir, f)) {
					var e Event
					_ = json.Unmarshal(ln, &e)
					got = append(got, e.Action)
				}
			}
			if strings.Join(got, ",") != "a1,a2,a3,a4,a5" {
				t.Fatalf("%v", got)
			}
		})
	}
}

func TestUnfinishedRetentionDeleteIsNotAProblemAndIsFinished(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{at(2026, 11, 22)}
	l, dir := newLog(t, Options{Now: clk.Now})
	for _, m := range []time.Month{9, 10, 11} {
		for d := 1; d <= 2; d++ {
			e := ev("login")
			e.Time = at(2026, m, d)
			l.Record(e)
		}
	}
	l.Close()
	// the crash: head.json already points at October, the September file is still there
	var h head
	b, _ := os.ReadFile(filepath.Join(dir, "head.json"))
	_ = json.Unmarshal(b, &h)
	var first Event
	_ = json.Unmarshal(lines(t, filepath.Join(dir, "audit-2026-10.jsonl"))[0], &first)
	h.FirstFile, h.FirstPrev = "audit-2026-10.jsonl", first.Prev
	nb, _ := json.Marshal(h)
	os.WriteFile(filepath.Join(dir, "head.json"), nb, 0o600)
	if rep := mustVerify(t, dir); !rep.OK || rep.Files != 3 {
		t.Fatalf("a pending delete is not a problem: %s %+v", kinds(rep), rep)
	}
	// the next run of the retention removes it
	var logs bytes.Buffer
	l2, err := Open(dir, Options{Now: clk.Now, RetentionMonths: 3, Logger: slogTo(&logs)})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if files, _ := listFiles(dir); strings.Join(files, " ") != "audit-2026-10.jsonl audit-2026-11.jsonl" {
		t.Fatalf("%v\n%s", files, logs.String())
	}
	if rep := mustVerify(t, dir); !rep.OK || rep.Lines != 4 || len(chainProblems(t, dir)) != 0 {
		t.Fatalf("%s %+v", kinds(rep), rep)
	}
	if !l2.Status().OK {
		t.Fatalf("%+v", l2.Status())
	}
}

func TestEditedOlderFileIsNotAPendingDelete(t *testing.T) {
	t.Parallel()
	l, dir := newLog(t, Options{})
	for _, m := range []time.Month{9, 10} {
		for d := 1; d <= 2; d++ {
			e := ev("login")
			e.Time = at(2026, m, d)
			l.Record(e)
		}
	}
	l.Close()
	var h head
	b, _ := os.ReadFile(filepath.Join(dir, "head.json"))
	_ = json.Unmarshal(b, &h)
	var first Event
	_ = json.Unmarshal(lines(t, filepath.Join(dir, "audit-2026-10.jsonl"))[0], &first)
	h.FirstFile, h.FirstPrev = "audit-2026-10.jsonl", first.Prev
	nb, _ := json.Marshal(h)
	os.WriteFile(filepath.Join(dir, "head.json"), nb, 0o600)
	sep := filepath.Join(dir, "audit-2026-09.jsonl")
	ls := lines(t, sep)
	ls[0] = bytes.Replace(ls[0], []byte("a@example.com"), []byte("mallory@example.com"), 1)
	write(t, sep, ls)
	if got := kinds(mustVerify(t, dir)); !strings.Contains(got, "first_file_mismatch@0") || !strings.Contains(got, "edited@1") {
		t.Fatalf("%s", got)
	}
}

func TestRetentionScanDoesNotHoldTheLock(t *testing.T) {
	clk := &fakeClock{at(2026, 11, 22)}
	var logs bytes.Buffer
	l, dir := newLog(t, Options{Now: clk.Now, Logger: slogTo(&logs)})
	fill(t, l, 4)
	l.opts.RetentionMonths = 1
	clk.t = at(2027, 1, 5)
	// an append lands while the scan has finished and the lock is not held yet
	pruneAfterScan = func() { l.Record(ev("login")) }
	defer func() { pruneAfterScan = nil }()
	l.prune() // would deadlock if the lock were held across the scan
	if files, _ := listFiles(dir); len(files) != 3 {
		t.Fatalf("a run that sees the log move on deletes nothing: %v", files)
	}
	if !strings.Contains(logs.String(), "changed while it was read") {
		t.Fatalf("%s", logs.String())
	}
	pruneAfterScan = nil
	l.prune()
	if files, _ := listFiles(dir); len(files) != 1 {
		t.Fatalf("%v", files)
	}
	if rep := mustVerify(t, dir); !rep.OK {
		t.Fatalf("%s", kinds(rep))
	}
}
