package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// anchorOf is the anchor of l's head on day, as the anchor job writes it.
func anchorOf(t *testing.T, l *Log, day string) Anchor {
	t.Helper()
	seq, hash := l.Head()
	return Anchor{Day: day, Seq: seq, Hash: hash, At: day + "T03:00:00Z"}
}

func anchorFile(as ...Anchor) []byte {
	var b []byte
	for _, a := range as {
		b = append(b, a.Line()...)
	}
	return b
}

func recordN(l *Log, n int, name string) {
	for i := 0; i < n; i++ {
		l.Record(Event{Event: name, Identity: "a@example.com", Time: at(2026, 11, 20+i%3)})
	}
}

func problemKinds(st Status) string {
	var k []string
	for _, p := range st.Problems {
		k = append(k, p.Kind)
	}
	return strings.Join(k, ",")
}

func countEvents(t *testing.T, dir, event string) int {
	t.Helper()
	n := 0
	files, _ := listFiles(dir)
	for _, f := range files {
		for _, l := range lines(t, filepath.Join(dir, f)) {
			if strings.Contains(string(l), `"event":"`+event+`"`) {
				n++
			}
		}
	}
	return n
}

func TestParseAnchorsKeepsGoodLinesAndCountsTheOthers(t *testing.T) {
	good := Anchor{Day: "2026-11-20", Seq: 5, Hash: hashOf([]byte("x")), At: "2026-11-20T03:00:00Z"}
	file := string(good.Line()) +
		"\n" + // an empty line is not a problem
		"not json\n" +
		`{"day":"2026-11-21","seq":6,"hash":"` + good.Hash + `","at":"2026-11-21T03:00:00Z","extra":1}` + "\n" + // unknown field
		`{"day":"2026-11-21","seq":0,"hash":"` + good.Hash + `","at":"2026-11-21T03:00:00Z"}` + "\n" +
		`{"day":"yesterday","seq":6,"hash":"` + good.Hash + `","at":"2026-11-21T03:00:00Z"}` + "\n" +
		`{"day":"2026-11-21","seq":6,"hash":"sha256:zz","at":"2026-11-21T03:00:00Z"}` + "\n" +
		`{"day":"2026-11-21","seq":6,"hash":"` + good.Hash + `","at":"2026-11-21T03:00:00Z"} {"x":1}` + "\n" +
		string(Anchor{Day: "2026-11-22", Seq: 9, Hash: good.Hash, At: "2026-11-22T03:00:00Z"}.Line())
	a := ParseAnchors([]byte(file))
	if len(a.List) != 2 || a.List[0].Seq != 5 || a.List[1].Seq != 9 {
		t.Fatalf("%+v", a.List)
	}
	if got := a.Malformed; len(got) != 6 || got[0] != 3 || got[5] != 8 {
		t.Fatalf("malformed lines %v", got)
	}
	if last, ok := a.Last(); !ok || last.Seq != 9 {
		t.Fatalf("last %+v", last)
	}
	if _, ok := ParseAnchors(nil).Last(); ok {
		t.Fatal("an empty file has no last anchor")
	}
}

func TestAnchorsOfAnIntactLogPassAndWriteNothing(t *testing.T) {
	l, dir := newLog(t, Options{})
	recordN(l, 6, "login")
	a1 := anchorOf(t, l, "2026-11-20")
	recordN(l, 4, "login")
	a2 := anchorOf(t, l, "2026-11-21")
	recordN(l, 2, "logout") // the log moves on after the last anchor: that is fine
	before := countEvents(t, dir, ChainProblemEvent)
	sum, err := l.CheckAnchors(anchorFile(a1, a2))
	if err != nil || sum.Checked != 2 || sum.Skipped != 0 {
		t.Fatalf("%+v %v", sum, err)
	}
	if st := l.Status(); !st.OK || len(st.Problems) != 0 {
		t.Fatalf("%+v", st)
	}
	if countEvents(t, dir, ChainProblemEvent) != before {
		t.Fatal("nothing should have been recorded")
	}
	rep, err := VerifyWithAnchors(dir, anchorFile(a1, a2))
	if err != nil || !rep.OK || rep.Anchors == nil || rep.Anchors.Checked != 2 {
		t.Fatalf("%+v %v", rep, err)
	}
	// no anchor file at all, or an empty one: nothing to check
	if rep, err := VerifyWithAnchors(dir, nil); err != nil || !rep.OK || rep.Anchors.Checked != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
}

// rewritten is a log whose own chain is intact but that differs from the one the
// anchors were taken from, as one rebuilt by somebody with the files and head.json.
func rewritten(t *testing.T, n int, changeAt int) (*Log, string) {
	t.Helper()
	l, dir := newLog(t, Options{})
	for i := 1; i <= n; i++ {
		who := "a@example.com"
		if i == changeAt {
			who = "mallory@example.com"
		}
		l.Record(Event{Event: "login", Identity: who, Time: at(2026, 11, 20)})
	}
	return l, dir
}

func TestAnchorMismatchIsRecordedOnceAndAcknowledged(t *testing.T) {
	orig, _ := rewritten(t, 8, 0)
	anchors := anchorFile(anchorOf(t, orig, "2026-11-19"))
	// an anchor taken at seq 5 of the original; the rebuilt log differs at seq 3
	l5, _ := rewritten(t, 5, 0)
	good5 := anchorOf(t, l5, "2026-11-18")
	anchors = append(anchorFile(good5), anchors...)

	l, dir := rewritten(t, 8, 3)
	sum, err := l.CheckAnchors(anchors)
	if err != nil || sum.Checked != 2 {
		t.Fatalf("%+v %v", sum, err)
	}
	st := l.Status()
	if st.OK || problemKinds(st) != KindAnchorMismatch {
		t.Fatalf("%+v", st)
	}
	p := st.Problems[0]
	// seq 5 differs too, because the chain carries the change forward: the first anchor is the first bad one
	if p.Seq != 5 || !p.Recorded || p.Fingerprint == "" || !strings.Contains(p.Detail, "2026-11-18") {
		t.Fatalf("%+v", p)
	}
	if n := countEvents(t, dir, ChainProblemEvent); n != 1 {
		t.Fatalf("%d chain_problem events", n)
	}
	// the same condition on every later pull: still one event
	for i := 0; i < 3; i++ {
		if _, err := l.CheckAnchors(anchors); err != nil {
			t.Fatal(err)
		}
	}
	if n := countEvents(t, dir, ChainProblemEvent); n != 1 {
		t.Fatalf("%d chain_problem events after repeats", n)
	}
	// and across a restart: the chain holds it, and it is still pending
	l.Close()
	l2, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if st := l2.Status(); st.OK || problemKinds(st) != KindAnchorMismatch {
		t.Fatalf("after restart %+v", st)
	}
	if _, err := l2.CheckAnchors(anchors); err != nil {
		t.Fatal(err)
	}
	if n := countEvents(t, dir, ChainProblemEvent); n != 1 {
		t.Fatalf("%d chain_problem events after restart", n)
	}
	// verify lists it once, as recorded; it counts until it is acknowledged
	rep, err := VerifyWithAnchors(dir, anchors)
	if err != nil || rep.OK || len(rep.Problems) != 1 || !rep.Problems[0].Recorded || rep.Repairable() {
		t.Fatalf("%+v %v", rep, err)
	}
	// acknowledgement clears the banner and stops further recording
	seq, _ := l2.Head()
	if err := l2.Ack(nil, seq); err != nil {
		t.Fatal(err)
	}
	if st := l2.Status(); !st.OK {
		t.Fatalf("%+v", st)
	}
	if _, err := l2.CheckAnchors(anchors); err != nil {
		t.Fatal(err)
	}
	if st := l2.Status(); !st.OK || countEvents(t, dir, ChainProblemEvent) != 1 {
		t.Fatalf("acknowledged problem came back: %+v", st)
	}
	rep, _ = VerifyWithAnchors(dir, anchors)
	if rep.OK || !rep.Problems[0].Acked {
		t.Fatalf("an acknowledged anchor problem stays listed: %+v", rep)
	}
}

func TestAnchorAheadWhenTheLogWasCutOrReset(t *testing.T) {
	orig, _ := rewritten(t, 9, 0)
	a := anchorOf(t, orig, "2026-11-21")
	cut, dir := rewritten(t, 6, 0) // the same lines, but the last three are gone and head.json was rewritten
	sum, err := cut.CheckAnchors(anchorFile(a))
	if err != nil || sum.Checked != 1 {
		t.Fatalf("%+v %v", sum, err)
	}
	st := cut.Status()
	if st.OK || problemKinds(st) != KindAnchorAhead || st.Problems[0].Seq != 9 || !strings.Contains(st.Problems[0].Detail, "2026-11-21") {
		t.Fatalf("%+v", st)
	}
	// the log growing without reaching the anchored seq is the same condition
	recordN(cut, 1, "login") // seq 8: the chain_problem event took seq 7
	if _, err := cut.CheckAnchors(anchorFile(a)); err != nil {
		t.Fatal(err)
	}
	if n := countEvents(t, dir, ChainProblemEvent); n != 1 {
		t.Fatalf("%d chain_problem events", n)
	}
	// a log that was reset to nothing
	empty, edir := newLog(t, Options{})
	if _, err := empty.CheckAnchors(anchorFile(a)); err != nil {
		t.Fatal(err)
	}
	if st := empty.Status(); problemKinds(st) != KindAnchorAhead {
		t.Fatalf("%+v", st)
	}
	_ = edir
}

func TestAnchorsBeforeTheFirstKeptLineAreSkipped(t *testing.T) {
	clk := &fakeClock{at(2026, 11, 22)}
	l, dir := newLog(t, Options{Now: clk.Now})
	var anchors []Anchor
	for _, m := range []time.Month{8, 9, 10, 11} {
		for d := 1; d <= 3; d++ {
			e := ev("login")
			e.Time = at(2026, m, d)
			l.Record(e)
		}
		anchors = append(anchors, anchorOf(t, l, "2026-"+pad(int(m))+"-03"))
	}
	l.Close()
	// retention keeps two whole months before November: August goes, and its anchor with it
	l2, err := Open(dir, Options{RetentionMonths: 2, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if files, _ := listFiles(dir); len(files) != 3 {
		t.Fatalf("%v", files)
	}
	sum, err := l2.CheckAnchors(anchorFile(anchors...))
	if err != nil || sum.Skipped != 1 || sum.Checked != 3 {
		t.Fatalf("%+v %v", sum, err)
	}
	if st := l2.Status(); !st.OK {
		t.Fatalf("%+v", st)
	}
	rep, err := VerifyWithAnchors(dir, anchorFile(anchors...))
	if err != nil || !rep.OK || rep.Anchors.Skipped != 1 || rep.Anchors.Checked != 3 {
		t.Fatalf("%+v %v", rep, err)
	}
	// A log that merely starts later than seq 1 (no retention happened) is missing lines:
	// an anchor in them is not skipped.
	if err := os.Remove(filepath.Join(dir, "head.json")); err != nil {
		t.Fatal(err)
	}
	rep, err = VerifyWithAnchors(dir, anchorFile(anchors...))
	if err != nil || rep.Anchors.Skipped != 0 || rep.Anchors.Checked != 4 {
		t.Fatalf("%+v %v", rep, err)
	}
	found := false
	for _, p := range rep.Problems {
		found = found || p.Kind == KindAnchorMismatch
	}
	if !found {
		t.Fatalf("an anchor in lines that are gone must not pass: %+v", rep.Problems)
	}
}

func pad(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

func TestAnchorsAcrossManyLinesUseTheOffsetIndex(t *testing.T) {
	l, dir := newLog(t, Options{})
	var as []Anchor
	for i := 1; i <= 1300; i++ {
		l.Record(ev("login"))
		if i%400 == 0 {
			as = append(as, anchorOf(t, l, "2026-11-"+pad(i/400)))
		}
	}
	sum, err := l.CheckAnchors(anchorFile(as...))
	if err != nil || sum.Checked != 3 || !l.Status().OK {
		t.Fatalf("%+v %v %+v", sum, err, l.Status())
	}
	// a wrong hash on the last of them is found
	as[2].Hash = hashOf([]byte("other"))
	rep, err := VerifyWithAnchors(dir, anchorFile(as...))
	if err != nil || rep.OK || rep.Problems[0].Kind != KindAnchorMismatch || rep.Problems[0].Seq != 1200 {
		t.Fatalf("%+v %v", rep, err)
	}
}
