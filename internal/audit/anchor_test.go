package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var full = AnchorOptions{Full: true, Now: time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)}

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
	rev, err := l.ReviewAnchors(anchorFile(a1, a2), nil, full)
	if err != nil || rev.Summary.Checked != 2 || rev.Summary.Skipped != 0 {
		t.Fatalf("%+v %v", rev, err)
	}
	if st := l.Status(); !st.OK || len(st.Problems) != 0 {
		t.Fatalf("%+v", st)
	}
	if countEvents(t, dir, ChainProblemEvent) != before {
		t.Fatal("nothing should have been recorded")
	}
	rep, err := VerifyWithAnchors(dir, anchorFile(a1, a2), AnchorOptions{})
	if err != nil || !rep.OK || rep.Anchors == nil || rep.Anchors.Checked != 2 {
		t.Fatalf("%+v %v", rep, err)
	}
	// no anchor file at all, or an empty one: nothing to check
	if rep, err := VerifyWithAnchors(dir, nil, AnchorOptions{}); err != nil || !rep.OK || rep.Anchors.Checked != 0 {
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
	rev, err := l.ReviewAnchors(anchors, nil, full)
	if err != nil || rev.Summary.Checked != 2 {
		t.Fatalf("%+v %v", rev, err)
	}
	st := l.Status()
	if st.OK || problemKinds(st) != KindAnchorMismatch+","+KindAnchorMismatch {
		t.Fatalf("%+v", st)
	}
	p := st.Problems[0]
	// seq 5 differs too, because the chain carries the change forward: every wrong anchor is a problem of its own
	if p.Seq != 5 || !p.Recorded || p.Fingerprint == "" || !strings.Contains(p.Detail, "2026-11-18") {
		t.Fatalf("%+v", p)
	}
	if n := countEvents(t, dir, ChainProblemEvent); n != 2 {
		t.Fatalf("%d chain_problem events", n)
	}
	// the same condition on every later pull: still one event
	for i := 0; i < 3; i++ {
		if _, err := l.ReviewAnchors(anchors, nil, full); err != nil {
			t.Fatal(err)
		}
	}
	if n := countEvents(t, dir, ChainProblemEvent); n != 2 {
		t.Fatalf("%d chain_problem events after repeats", n)
	}
	// and across a restart: the chain holds it, and it is still pending
	l.Close()
	l2, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if st := l2.Status(); st.OK || problemKinds(st) != KindAnchorMismatch+","+KindAnchorMismatch {
		t.Fatalf("after restart %+v", st)
	}
	if _, err := l2.ReviewAnchors(anchors, nil, full); err != nil {
		t.Fatal(err)
	}
	if n := countEvents(t, dir, ChainProblemEvent); n != 2 {
		t.Fatalf("%d chain_problem events after restart", n)
	}
	// verify lists it once, as recorded; it counts until it is acknowledged
	rep, err := VerifyWithAnchors(dir, anchors, AnchorOptions{})
	if err != nil || rep.OK || len(rep.Problems) != 2 || !rep.Problems[0].Recorded || rep.Repairable() {
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
	if _, err := l2.ReviewAnchors(anchors, nil, full); err != nil {
		t.Fatal(err)
	}
	if st := l2.Status(); !st.OK || countEvents(t, dir, ChainProblemEvent) != 2 {
		t.Fatalf("acknowledged problem came back: %+v", st)
	}
	rep, _ = VerifyWithAnchors(dir, anchors, AnchorOptions{})
	if rep.OK || !rep.Problems[0].Acked {
		t.Fatalf("an acknowledged anchor problem stays listed: %+v", rep)
	}
}

func TestAnchorAheadWhenTheLogWasCutOrReset(t *testing.T) {
	orig, _ := rewritten(t, 9, 0)
	a := anchorOf(t, orig, "2026-11-21")
	cut, dir := rewritten(t, 6, 0) // the same lines, but the last three are gone and head.json was rewritten
	rev, err := cut.ReviewAnchors(anchorFile(a), nil, full)
	if err != nil || rev.Summary.Checked != 1 {
		t.Fatalf("%+v %v", rev, err)
	}
	st := cut.Status()
	if st.OK || problemKinds(st) != KindAnchorAhead || st.Problems[0].Seq != 9 || !strings.Contains(st.Problems[0].Detail, "2026-11-21") {
		t.Fatalf("%+v", st)
	}
	// the log growing without reaching the anchored seq is the same condition
	recordN(cut, 1, "login") // seq 8: the chain_problem event took seq 7
	if _, err := cut.ReviewAnchors(anchorFile(a), nil, full); err != nil {
		t.Fatal(err)
	}
	if n := countEvents(t, dir, ChainProblemEvent); n != 1 {
		t.Fatalf("%d chain_problem events", n)
	}
	// a log that was reset to nothing
	empty, edir := newLog(t, Options{})
	if _, err := empty.ReviewAnchors(anchorFile(a), nil, full); err != nil {
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
	rev, err := l2.ReviewAnchors(anchorFile(anchors...), nil, full)
	if err != nil || rev.Summary.Skipped != 1 || rev.Summary.Checked != 3 {
		t.Fatalf("%+v %v", rev, err)
	}
	if st := l2.Status(); !st.OK {
		t.Fatalf("%+v", st)
	}
	rep, err := VerifyWithAnchors(dir, anchorFile(anchors...), AnchorOptions{RetentionMonths: 2, Now: at(2026, 11, 22)})
	if err != nil || !rep.OK || rep.Anchors.Skipped != 1 || rep.Anchors.Checked != 3 {
		t.Fatalf("%+v %v", rep, err)
	}
	// The default of verify is no skipping: without the retention the August anchor is a problem.
	rep, err = VerifyWithAnchors(dir, anchorFile(anchors...), AnchorOptions{})
	if err != nil || rep.OK || rep.Anchors.Skipped != 0 || rep.Problems[0].Kind != KindAnchorMismatch || rep.Problems[0].Seq != anchors[0].Seq {
		t.Fatalf("%+v %v", rep, err)
	}
}

// forgedHead builds a log of months 8 to 11 with an anchor at the end of each, and then does what
// somebody with the files does: deletes the early months and rewrites head.json to say the log
// starts at the first month left.
func forgedHead(t *testing.T, retention int) (*Log, string, []Anchor) {
	t.Helper()
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
	files, _ := listFiles(dir)
	prev, err := firstPrevOf(filepath.Join(dir, files[2]))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files[:2] {
		if err := os.Remove(filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	var h head
	b, _ := os.ReadFile(filepath.Join(dir, "head.json"))
	_ = json.Unmarshal(b, &h)
	h.FirstFile, h.FirstPrev = files[2], prev
	nb, _ := json.Marshal(h)
	if err := os.WriteFile(filepath.Join(dir, "head.json"), nb, 0o600); err != nil {
		t.Fatal(err)
	}
	l2, err := Open(dir, Options{Now: clk.Now, RetentionMonths: retention})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l2.Close)
	return l2, dir, anchors
}

func TestAForgedHeadFileCannotHideAnchorsWhenTheServerKeepsEverything(t *testing.T) {
	// --audit-retention-months 0: nothing is ever skipped, whatever head.json says
	l, dir, anchors := forgedHead(t, 0)
	rev, err := l.ReviewAnchors(anchorFile(anchors...), nil, full)
	if err != nil || rev.Summary.Skipped != 0 {
		t.Fatalf("%+v %v", rev, err)
	}
	if st := l.Status(); st.OK || problemKinds(st) != KindAnchorMismatch+","+KindAnchorMismatch {
		t.Fatalf("the cut-off anchors must be problems: %+v", st)
	}
	rep, err := VerifyWithAnchors(dir, anchorFile(anchors...), AnchorOptions{})
	if err != nil || rep.OK || rep.Anchors.Skipped != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestAForgedHeadFileCannotHideAnchorsOfTheKeptMonths(t *testing.T) {
	// With a retention, only anchors of months older than the oldest file kept may be skipped, and
	// never the newest.
	l, dir, anchors := forgedHead(t, 2)
	rev, err := l.ReviewAnchors(anchorFile(anchors...), nil, full)
	if err != nil || rev.Summary.Skipped != 2 || rev.Summary.Checked != 2 {
		t.Fatalf("%+v %v", rev, err)
	}
	if st := l.Status(); !st.OK {
		t.Fatalf("August and September are older than the kept October: %+v", st)
	}
	// the same files with an anchor day inside the oldest kept month, whose line is gone: a problem
	moved := append([]Anchor{}, anchors...)
	moved[0].Day = "2026-10-02" // the 1st itself would be allowed: the writer can anchor the month before just after midnight
	rep, err := VerifyWithAnchors(dir, anchorFile(moved...), AnchorOptions{RetentionMonths: 2, Now: at(2026, 11, 22)})
	if err != nil || rep.OK || rep.Problems[0].Kind != KindAnchorMismatch || rep.Problems[0].Seq != anchors[0].Seq {
		t.Fatalf("%+v %v", rep, err)
	}
	// and the newest anchor is never skipped, however old it says it is
	rep, err = VerifyWithAnchors(dir, anchorFile(anchors[0]), AnchorOptions{RetentionMonths: 2, Now: at(2026, 11, 22)})
	if err != nil || rep.OK || rep.Anchors.Skipped != 0 {
		t.Fatalf("%+v %v", rep, err)
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
	rev, err := l.ReviewAnchors(anchorFile(as...), nil, full)
	if err != nil || rev.Summary.Checked != 3 || !l.Status().OK {
		t.Fatalf("%+v %v %+v", rev, err, l.Status())
	}
	// a wrong hash on the last of them is found
	as[2].Hash = hashOf([]byte("other"))
	rep, err := VerifyWithAnchors(dir, anchorFile(as...), AnchorOptions{})
	if err != nil || rep.OK || rep.Problems[0].Kind != KindAnchorMismatch || rep.Problems[0].Seq != 1200 {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestAnAcknowledgedAnchorProblemDoesNotHideALaterOne(t *testing.T) {
	// the log as it really is, 20 lines
	l, dir := newLog(t, Options{})
	recordN(l, 20, "login")
	real15 := Anchor{Day: "2026-11-02", Seq: 15, Hash: hashOf([]byte("what a rewrite left")), At: "2026-11-02T03:00:00Z"}
	bogus5 := Anchor{Day: "2026-11-01", Seq: 5, Hash: hashOf([]byte("nothing")), At: "2026-11-01T03:00:00Z"}

	// first only the bogus anchor at seq 5 is there: recorded, and acknowledged
	if _, err := l.ReviewAnchors(anchorFile(bogus5), nil, full); err != nil {
		t.Fatal(err)
	}
	st := l.Status()
	if st.OK || len(st.Problems) != 1 || st.Problems[0].Seq != 5 {
		t.Fatalf("%+v", st)
	}
	seq, _ := l.Head()
	if err := l.Ack(nil, seq); err != nil {
		t.Fatal(err)
	}
	if !l.Status().OK {
		t.Fatal("acknowledged")
	}
	// later an anchor at seq 15 that does not match joins it: that one is a new problem
	if _, err := l.ReviewAnchors(anchorFile(bogus5, real15), nil, full); err != nil {
		t.Fatal(err)
	}
	st = l.Status()
	if st.OK || len(st.Problems) != 1 || st.Problems[0].Seq != 15 || st.Problems[0].Kind != KindAnchorMismatch {
		t.Fatalf("the second problem was hidden by the first one's acknowledgement: %+v", st)
	}
	if n := countEvents(t, dir, ChainProblemEvent); n != 2 {
		t.Fatalf("%d chain_problem events", n)
	}
	// dropping an anchor (retention) does not make anything new
	seq, _ = l.Head()
	if err := l.Ack(nil, seq); err != nil {
		t.Fatal(err)
	}
	if _, err := l.ReviewAnchors(anchorFile(real15), nil, full); err != nil {
		t.Fatal(err)
	}
	if !l.Status().OK || countEvents(t, dir, ChainProblemEvent) != 2 {
		t.Fatalf("%+v", l.Status())
	}
}

func TestManyWrongAnchorsAreCappedPerPassWithASummary(t *testing.T) {
	l, dir := newLog(t, Options{})
	recordN(l, 40, "login")
	var as []Anchor
	for i := 1; i <= 25; i++ {
		as = append(as, Anchor{Day: "2026-10-" + pad(i), Seq: int64(i), Hash: hashOf([]byte{byte(i)}), At: "2026-10-" + pad(i) + "T03:00:00Z"})
	}
	if _, err := l.ReviewAnchors(anchorFile(as...), nil, full); err != nil {
		t.Fatal(err)
	}
	if n := countEvents(t, dir, ChainProblemEvent); n != 21 {
		t.Fatalf("%d events, want 20 and a summary", n)
	}
	st := l.Status()
	if last := st.Problems[len(st.Problems)-1]; last.Kind != KindAnchorMore || !strings.Contains(last.Detail, "5 more") {
		t.Fatalf("%+v", last)
	}
	// the next pass records the five left, and not the summary again
	if _, err := l.ReviewAnchors(anchorFile(as...), nil, full); err != nil {
		t.Fatal(err)
	}
	if n := countEvents(t, dir, ChainProblemEvent); n != 26 {
		t.Fatalf("%d events", n)
	}
}

// logWithHashes records n lines and returns the real (seq, hash) of each as an anchor of the given day.
func logWithHashes(t *testing.T, n int) (*Log, []Anchor) {
	t.Helper()
	l, _ := newLog(t, Options{})
	var as []Anchor
	for i := 1; i <= n; i++ {
		recordN(l, 1, "login")
		as = append(as, anchorOf(t, l, "2026-11-01"))
	}
	return l, as
}

func TestAnchorsThatCannotBeAnchorsAreInvalid(t *testing.T) {
	l, real := logWithHashes(t, 10)
	a := func(day string, seq int64) Anchor { x := real[seq-1]; x.Day, x.At = day, day+"T03:00:00Z"; return x }
	now := time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name    string
		as      []Anchor
		invalid int
	}{
		{"a day far in the future", []Anchor{a("2099-01-01", 3)}, 1},
		{"tomorrow is allowed for a skewed clock", []Anchor{a("2026-11-26", 3)}, 0},
		{"two days ahead is not", []Anchor{a("2026-11-27", 3)}, 1},
		{"the day goes back", []Anchor{a("2026-11-03", 4), a("2026-11-02", 5)}, 1},
		{"the same day twice", []Anchor{a("2026-11-03", 4), a("2026-11-03", 5)}, 1},
		{"the seq goes back", []Anchor{a("2026-11-02", 5), a("2026-11-03", 4)}, 1},
		{"in order", []Anchor{a("2026-11-02", 4), a("2026-11-03", 5)}, 0},
	} {
		rep, err := VerifyWithAnchors(l.dir, anchorFile(c.as...), AnchorOptions{Now: now})
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, p := range rep.Problems {
			if p.Kind == KindAnchorInvalid {
				n++
			}
		}
		if n != c.invalid {
			t.Errorf("%s: %d invalid, want %d (%s)", c.name, n, c.invalid, kinds(rep))
		}
	}
}

func TestAForgedAnchorThatIsAcknowledgedDoesNotBecomeTheBaseline(t *testing.T) {
	l, real := logWithHashes(t, 12)
	now := time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)
	opt := AnchorOptions{Full: true, Now: now}
	a1 := real[3]
	a1.Day = "2026-11-10"
	// a forged line: tomorrow, and a seq far beyond the log's end
	forged := Anchor{Day: "2026-11-26", Seq: 1 << 50, Hash: hashOf([]byte("x")), At: "2026-11-26T00:00:00Z"}
	if _, err := l.ReviewAnchors(anchorFile(a1, forged), nil, opt); err != nil {
		t.Fatal(err)
	}
	st := l.Status()
	if st.OK || problemKinds(st) != KindAnchorAhead {
		t.Fatalf("%+v", st)
	}
	seq, _ := l.Head()
	if err := l.Ack(nil, seq); err != nil {
		t.Fatal(err)
	}
	// real anchors that come after: compared with the last anchor that matched, not with the forged
	// line, so they are valid and the writer may trust them
	a2 := real[7]
	a2.Day = "2026-11-24"
	rev, err := l.ReviewAnchors(anchorFile(a1, forged, a2), nil, opt)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Status().OK || len(rev.Good) != 2 || rev.Good[1] != a2 {
		t.Fatalf("%+v %+v", rev, l.Status())
	}
	// a forged line with a seq that exists but a hash that does not, dated ahead, is a mismatch and no baseline either
	bad := real[9]
	bad.Day, bad.Hash = "2026-11-26", hashOf([]byte("not it"))
	a3 := real[10]
	a3.Day = "2026-11-25"
	rev, err = l.ReviewAnchors(anchorFile(a1, forged, a2, bad, a3), nil, opt)
	if err != nil || len(rev.Good) != 3 || rev.Good[2] != a3 {
		t.Fatalf("%+v %v", rev, err)
	}
	if st := l.Status(); st.OK || problemKinds(st) != KindAnchorMismatch {
		t.Fatalf("%+v", st)
	}
}

func TestAnInvalidAnchorIsNotTrusted(t *testing.T) {
	l, _ := newLog(t, Options{})
	recordN(l, 10, "login")
	future := Anchor{Day: "2099-01-01", Seq: 3, Hash: hashOf([]byte("x")), At: "2099-01-01T03:00:00Z"}
	rev, err := l.ReviewAnchors(anchorFile(future), nil, AnchorOptions{Now: time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)})
	if err != nil || len(rev.Good) != 0 {
		t.Fatalf("%+v %v", rev, err)
	}
	if st := l.Status(); problemKinds(st) != KindAnchorInvalid+","+KindAnchorMismatch && problemKinds(st) != KindAnchorInvalid {
		t.Fatalf("%+v", st)
	}
}

func TestARewrittenAnchorFileIsAProblemThatNamesTheCommit(t *testing.T) {
	a1 := Anchor{Day: "2026-11-01", Seq: 3, Hash: hashOf([]byte("a")), At: "2026-11-01T03:00:00Z"}
	a2 := Anchor{Day: "2026-11-02", Seq: 7, Hash: hashOf([]byte("b")), At: "2026-11-02T03:00:00Z"}
	forged := a2
	forged.Hash = hashOf([]byte("forged"))
	p := RewrittenAnchor("c3", anchorFile(a1, a2), anchorFile(a1, forged))
	if p.Kind != KindAnchorRewritten || p.Seq != 7 || !strings.Contains(p.Detail, "commit c3") || p.Fingerprint == "" {
		t.Fatalf("%+v", p)
	}
	if q := RewrittenAnchor("c4", anchorFile(a1, a2), anchorFile(a1)); q.Seq != 7 || q.Fingerprint == p.Fingerprint {
		t.Fatalf("%+v", q)
	}
	// a rewritten commit is recorded as a chain problem, once, and acknowledged like any other
	l, dir := newLog(t, Options{})
	recordN(l, 3, "login")
	for i := 0; i < 2; i++ {
		if _, err := l.ReviewAnchors(nil, []Problem{p}, full); err != nil {
			t.Fatal(err)
		}
	}
	if n := countEvents(t, dir, ChainProblemEvent); n != 1 || problemKinds(l.Status()) != KindAnchorRewritten {
		t.Fatalf("%d events, %+v", n, l.Status())
	}
}

func TestAnchorCacheSkipsWhatMatchedBeforeButNotTheNewest(t *testing.T) {
	l, _ := newLog(t, Options{})
	var as []Anchor
	for i := 1; i <= 3; i++ {
		recordN(l, 2, "login")
		as = append(as, anchorOf(t, l, "2026-11-"+pad(i)))
	}
	now := AnchorOptions{Now: time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)}
	if _, err := l.ReviewAnchors(anchorFile(as...), nil, now); err != nil {
		t.Fatal(err)
	}
	if len(l.anchorOK.ok) != 3 {
		t.Fatalf("cache %v", l.anchorOK.ok)
	}
	// the cache is what a later pass relies on: an entry that is gone is looked up again
	l.anchorOK.ok = map[string]bool{}
	if _, err := l.ReviewAnchors(anchorFile(as...), nil, now); err != nil || len(l.anchorOK.ok) != 3 {
		t.Fatalf("%v %v", err, l.anchorOK.ok)
	}
}

// retentionLog records lines at the given times with fake "now" and an anchor after each group
// the caller asks for. It returns the Log reopened with the retention, so month files that
// retention would delete are gone.
func retentionLog(t *testing.T, now time.Time, retention int, times ...time.Time) (*Log, string) {
	t.Helper()
	clk := &fakeClock{now}
	l, dir := newLog(t, Options{Now: clk.Now})
	for _, tm := range times {
		e := ev("login")
		e.Time = tm
		l.Record(e)
	}
	l.Close()
	l2, err := Open(dir, Options{Now: clk.Now, RetentionMonths: retention})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l2.Close)
	return l2, dir
}

func lineAnchor(t *testing.T, dir string, seq int64, day string) Anchor {
	t.Helper()
	files, _ := listFiles(dir)
	_, h, err := lineHashAt(dir, files, &offsetIndex{}, seq)
	if err != nil || h == "" {
		t.Fatalf("line %d: %q %v", seq, h, err)
	}
	return Anchor{Day: day, Seq: seq, Hash: h, At: day + "T00:30:00Z"}
}

func TestAnAnchorOfTheMonthBeforeWrittenOnThe1stMayBeSkippedByRetention(t *testing.T) {
	// retention 1 in December keeps November and December: October goes. The anchor of an October
	// line, written just after midnight on 2026-11-01, is dated on the 1st of the oldest kept month.
	clk := &fakeClock{at(2026, 12, 2)}
	l, dir := newLog(t, Options{Now: clk.Now})
	for _, tm := range []time.Time{at(2026, 10, 30), at(2026, 10, 31), at(2026, 11, 5), at(2026, 11, 20)} {
		e := ev("login")
		e.Time = tm
		l.Record(e)
	}
	l.Close()
	oct := lineAnchor(t, dir, 2, "2026-11-01")
	l2, err := Open(dir, Options{Now: clk.Now, RetentionMonths: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if files, _ := listFiles(dir); len(files) != 1 {
		t.Fatalf("October should be gone: %v", files)
	}
	head := lineAnchor(t, dir, 4, "2026-11-20")
	rev, err := l2.ReviewAnchors(anchorFile(oct, head), nil, AnchorOptions{Full: true})
	if err != nil || rev.Summary.Skipped != 1 || rev.Summary.Checked != 1 || !l2.Status().OK {
		t.Fatalf("%+v %v %+v", rev, err, l2.Status())
	}
	// dated the 2nd it is not: that is no anchor that was written for a month retention dropped
	oct.Day = "2026-11-02"
	rep, err := VerifyWithAnchors(dir, anchorFile(oct, head), AnchorOptions{RetentionMonths: 1, Now: clk.Now()})
	if err != nil || rep.OK || rep.Problems[len(rep.Problems)-1].Kind != KindAnchorMismatch {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestACutIntoTheCurrentMonthIsNotRetention(t *testing.T) {
	now := at(2026, 11, 22)
	l, dir := retentionLog(t, now, 1, at(2026, 10, 30), at(2026, 11, 3), at(2026, 11, 4), at(2026, 11, 5), at(2026, 11, 6))
	// the anchors as the server wrote them, taken before somebody removed the first lines of November
	early := lineAnchor(t, dir, 3, "2026-11-10")
	head := lineAnchor(t, dir, 5, "2026-11-20")
	p := filepath.Join(dir, "audit-2026-11.jsonl")
	ls := lines(t, p)
	write(t, p, ls[2:]) // lines 2 and 3 are gone from the front of the current month's file (seq 1 is October's)
	_ = l
	rep, err := VerifyWithAnchors(dir, anchorFile(early, head), AnchorOptions{RetentionMonths: 1, Now: now})
	if err != nil || rep.Anchors.Skipped != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	found := false
	for _, pr := range rep.Problems {
		found = found || (pr.Kind == KindAnchorMismatch && pr.Seq == 3)
	}
	if !found {
		t.Fatalf("an anchor of a line cut from the current month must be a problem: %s", kinds(rep))
	}
}

func TestMonthsYoungerThanTheRetentionCutoffAreNotRetentions(t *testing.T) {
	// retention 3 in November keeps August onward. A log that lost September and October has not
	// been through retention, whatever head.json says.
	now := at(2026, 11, 22)
	clk := &fakeClock{now}
	l, dir := newLog(t, Options{Now: clk.Now})
	for _, m := range []time.Month{8, 9, 10, 11} {
		e := ev("login")
		e.Time = at(2026, m, 3)
		l.Record(e)
	}
	l.Close()
	files, _ := listFiles(dir)
	aug := lineAnchor(t, dir, 1, "2026-08-04")
	sep := lineAnchor(t, dir, 2, "2026-09-04")
	head := lineAnchor(t, dir, 4, "2026-11-05")
	for _, f := range files[:3] {
		if err := os.Remove(filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := VerifyWithAnchors(dir, anchorFile(aug, sep, head), AnchorOptions{RetentionMonths: 3, Now: now})
	if err != nil || rep.Anchors.Skipped != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	n := 0
	for _, p := range rep.Problems {
		if p.Kind == KindAnchorMismatch {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("both anchors of the lost months must be problems: %s", kinds(rep))
	}
	// the same files, as a retention of 1 month would have left them in November, are fine
	rep, err = VerifyWithAnchors(dir, anchorFile(aug, sep, head), AnchorOptions{RetentionMonths: 1, Now: now})
	if err != nil || rep.Anchors.Skipped != 2 {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestNothingIsSkippedWhenNoAnchorMatchedTheLog(t *testing.T) {
	now := at(2026, 11, 22)
	_, dir := retentionLog(t, now, 2, at(2026, 8, 3), at(2026, 9, 3), at(2026, 10, 3), at(2026, 11, 3))
	if files, _ := listFiles(dir); len(files) != 3 {
		t.Fatalf("%v", files)
	}
	// the August anchor would be skipped if a later anchor matched; with only a forged tail none does
	aug := Anchor{Day: "2026-08-04", Seq: 1, Hash: hashOf([]byte("a")), At: "2026-08-04T00:00:00Z"}
	tail := Anchor{Day: "2026-11-06", Seq: 3, Hash: hashOf([]byte("forged")), At: "2026-11-06T00:00:00Z"}
	rep, err := VerifyWithAnchors(dir, anchorFile(aug, tail), AnchorOptions{RetentionMonths: 2, Now: now})
	if err != nil || rep.Anchors.Skipped != 0 || rep.Anchors.Checked != 2 {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestTheNewestAnchorForRetentionIsTheNewestThatMatched(t *testing.T) {
	now := at(2026, 11, 22)
	_, dir := retentionLog(t, now, 2, at(2026, 8, 3), at(2026, 9, 3), at(2026, 10, 3), at(2026, 11, 3))
	seqSep := lineAnchor(t, dir, 2, "2026-08-31") // an anchor of the first kept month's line, dated before it
	oct := lineAnchor(t, dir, 3, "2026-10-04")
	// a forged line at the end of the file: not the newest that matched, so it does not make
	// the two real ones before it look like "not the newest"; and they stay as they are
	forgedTail := Anchor{Day: "2026-11-05", Seq: 4, Hash: hashOf([]byte("forged")), At: "2026-11-05T00:00:00Z"}
	rep, err := VerifyWithAnchors(dir, anchorFile(seqSep, oct, forgedTail), AnchorOptions{RetentionMonths: 2, Now: now})
	if err != nil || rep.Anchors.Skipped != 0 || len(rep.Problems) != 1 || rep.Problems[0].Kind != KindAnchorMismatch || rep.Problems[0].Seq != 4 {
		t.Fatalf("%+v %v", rep, err)
	}
}
