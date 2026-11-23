package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// The daily anchor (docs/design-audit.md, 3.1): once a day the head of the log
// (seq and the hash of that line) is committed to .rackbook/audit-anchors in the
// data repository. These are the problem kinds that checking the anchors finds.
const (
	// KindAnchorMismatch: the line at an anchored seq is not the line that was anchored.
	KindAnchorMismatch = "anchor_mismatch"
	// KindAnchorAhead: an anchor names a seq the log does not have (the log was cut or reset).
	KindAnchorAhead = "anchor_ahead"
)

// AnchorsPath is the anchor file in the data repository.
const AnchorsPath = ".rackbook/audit-anchors"

// Anchor is one line of the anchor file, JSON Lines.
type Anchor struct {
	Day  string `json:"day"`  // UTC, YYYY-MM-DD
	Seq  int64  `json:"seq"`  // the head seq at that time
	Hash string `json:"hash"` // "sha256:<hex>" of the line at that seq
	At   string `json:"at"`   // RFC 3339, when it was written
}

// Line is the anchor as it is appended to the file, with its newline.
func (a Anchor) Line() []byte {
	b, _ := json.Marshal(a)
	return append(b, '\n')
}

var hashRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// valid says the anchor has every field in its form.
func (a Anchor) valid() bool {
	if _, err := time.Parse("2006-01-02", a.Day); err != nil {
		return false
	}
	if _, err := time.Parse(time.RFC3339, a.At); err != nil {
		return false
	}
	return a.Seq > 0 && hashRe.MatchString(a.Hash)
}

// Anchors is a parsed anchor file: the lines that are anchors, in file order,
// and the numbers (from 1) of the lines that are not.
type Anchors struct {
	List      []Anchor
	Malformed []int
}

// ParseAnchors reads the anchor file. A line that is not exactly an anchor
// (it does not parse, has a field Rackbook does not know, or a field is out of
// form) is counted in Malformed and otherwise ignored; empty lines are skipped.
func ParseAnchors(b []byte) Anchors {
	var out Anchors
	for i, line := range bytes.Split(b, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var a Anchor
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if dec.Decode(&a) != nil || dec.More() || !a.valid() {
			out.Malformed = append(out.Malformed, i+1)
			continue
		}
		out.List = append(out.List, a)
	}
	return out
}

// Last is the newest anchor in file order.
func (a Anchors) Last() (Anchor, bool) {
	if len(a.List) == 0 {
		return Anchor{}, false
	}
	return a.List[len(a.List)-1], true
}

// Problem kinds of the anchors besides the two of the log itself.
const (
	// KindAnchorRewritten: a commit changed or removed lines that were already in the anchor
	// file (it must only ever grow by appended lines). The commit is in the problem.
	KindAnchorRewritten = "anchor_rewritten"
	// KindAnchorInvalid: an anchor that cannot be one: its day is in the future, or its day or
	// seq does not come after the anchor before it.
	KindAnchorInvalid = "anchor_invalid"
	// KindAnchorMore: more anchors are wrong than one pass records one by one.
	KindAnchorMore = "anchor_more"
)

// maxAnchorProblems is how many wrong anchors one pass records; the rest is one summary entry.
const maxAnchorProblems = 20

// AnchorSummary is what checking the anchors looked at.
type AnchorSummary struct {
	Checked   int    `json:"checked"`             // anchors compared with the log
	Skipped   int    `json:"skipped,omitempty"`   // anchors older than the kept log (retention)
	Malformed []int  `json:"malformed,omitempty"` // lines of the file that are not anchors
	Note      string `json:"note,omitempty"`      // something that was not checked, and why
}

// AnchorOptions tells how the anchors are checked.
type AnchorOptions struct {
	// RetentionMonths is the server's --audit-retention-months. With 0 (keep everything) no
	// anchor is ever skipped. With more, an anchor is skipped as removed by retention only if ALL
	// of these hold: its seq is below the first line kept; its day is on or before the first day
	// of the oldest month file kept (the writer can anchor a line of the month before just after
	// midnight on the 1st); that oldest month is not newer than the month retention would keep
	// from now, with a month of slack (retention never deletes a month younger than its cutoff, so
	// if such months are gone that is not retention); and it is older in the file than the newest
	// anchor that matched the log. head.json is not consulted: it can be rewritten together with the
	// log. What a deletion that looks like retention can still hide is at most the lines retention
	// itself would drop, plus the first day of the oldest kept month.
	RetentionMonths int
	// Now is the time for "a day in the future" and for the retention cutoff; zero is time.Now().
	Now time.Time
	// Full checks every anchor. Otherwise an anchor that matched before in this process is not
	// looked up again, except the newest one that matched.
	Full bool
}

// AnchorReview is what ReviewAnchors found.
type AnchorReview struct {
	Summary AnchorSummary
	// Good are the anchors that are valid and passed: the ones a writer may trust.
	Good []Anchor
}

// anchorEvidence is what an anchor problem rests on, for its fingerprint.
func anchorEvidence(a Anchor, found string) string {
	return a.Day + "|" + strconv.FormatInt(a.Seq, 10) + "|" + a.Hash + "|" + found
}

func shortHash(h string) string {
	if len(h) > len("sha256:")+12 {
		return h[:len("sha256:")+12]
	}
	return h
}

// anchorCache remembers the anchors that matched the log in this process.
type anchorCache struct {
	mu sync.Mutex
	ok map[string]bool
}

func (c *anchorCache) has(a Anchor) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ok[anchorEvidence(a, a.Hash)]
}

func (c *anchorCache) add(a Anchor) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ok == nil {
		c.ok = map[string]bool{}
	}
	c.ok[anchorEvidence(a, a.Hash)] = true
}

// evaluateAnchors compares every anchor with the log, and returns each wrong one as a problem of
// its own, in file order. lastSeq is the seq of the last line. The anchors that matched are the
// baseline for order: a line that does not match (ahead, mismatch, future) never becomes the
// "previous" anchor that later ones must come after.
func evaluateAnchors(dir string, idx *offsetIndex, lastSeq int64, anchors Anchors, opt AnchorOptions, cache *anchorCache) (AnchorReview, []Problem, error) {
	rev := AnchorReview{Summary: AnchorSummary{Malformed: anchors.Malformed}}
	list := anchors.List
	if len(list) == 0 {
		return rev, nil, nil
	}
	files, err := listFiles(dir)
	if err != nil {
		return rev, nil, err
	}
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	latest := now.AddDate(0, 0, 1).Format("2006-01-02")
	type found struct {
		file, got string
		done      bool
	}
	res := make([]found, len(list))
	lookup := func(i int) (string, string, error) {
		if !res[i].done {
			f, g, err := lineHashAt(dir, files, idx, list[i].Seq)
			if err != nil {
				return "", "", err
			}
			res[i] = found{f, g, true}
		}
		return res[i].file, res[i].got, nil
	}
	candidate := func(a Anchor) bool { return a.Day <= latest && a.Seq <= lastSeq }

	// The newest anchor that matched the log, looked up fresh: from the end, the first that matches.
	newest := -1
	for i := len(list) - 1; i >= 0; i-- {
		if !candidate(list[i]) {
			continue
		}
		if _, got, err := lookup(i); err != nil {
			return rev, nil, err
		} else if got == list[i].Hash {
			newest = i
			break
		}
	}

	// Retention: what may be skipped, if anything.
	skipBelow, skipDay := int64(0), ""
	if opt.RetentionMonths > 0 && newest >= 0 && len(files) > 0 {
		m := fileRe.FindStringSubmatch(files[0])[1]
		if t, err := time.Parse("2006-01", m); err == nil && monthIndex(t) <= monthIndex(now)-opt.RetentionMonths+1 {
			if f, err := os.Open(filepath.Join(dir, files[0])); err == nil {
				skipBelow, _ = firstSeq(f)
				f.Close()
			}
			skipDay = m + "-01"
		}
	}

	var out []Problem
	var base *Anchor // the last anchor that matched
	for i, a := range list {
		switch {
		case a.Day > latest:
			reason := fmt.Sprintf("the anchor of %s is dated after today", a.Day)
			out = append(out, Problem{Seq: a.Seq, Kind: KindAnchorInvalid, Detail: reason,
				Fingerprint: fingerprint(KindAnchorInvalid, a.Seq, "", anchorEvidence(a, reason))})
			continue
		case a.Seq > lastSeq:
			rev.Summary.Checked++
			out = append(out, Problem{Seq: a.Seq, Kind: KindAnchorAhead,
				Detail:      fmt.Sprintf("the anchor of %s is at seq %d, the log ends at seq %d", a.Day, a.Seq, lastSeq),
				Fingerprint: fingerprint(KindAnchorAhead, a.Seq, "", anchorEvidence(a, ""))})
			continue
		case skipDay != "" && i < newest && a.Seq < skipBelow && a.Day <= skipDay:
			rev.Summary.Skipped++
			rev.Good = append(rev.Good, a)
			continue
		}
		rev.Summary.Checked++
		var file, got string
		if !opt.Full && i != newest && cache.has(a) {
			got = a.Hash
		} else if file, got, err = lookup(i); err != nil {
			return rev, nil, err
		}
		if got != a.Hash {
			d := fmt.Sprintf("the anchor of %s says seq %d is %s, the line is %s", a.Day, a.Seq, shortHash(a.Hash), shortHash(got))
			if got == "" {
				d = fmt.Sprintf("the anchor of %s is at seq %d, which the log does not have", a.Day, a.Seq)
			}
			out = append(out, Problem{Seq: a.Seq, Kind: KindAnchorMismatch, File: file, Detail: d,
				Fingerprint: fingerprint(KindAnchorMismatch, a.Seq, "", anchorEvidence(a, got))})
			continue
		}
		if base != nil && (a.Day <= base.Day || a.Seq <= base.Seq) {
			reason := fmt.Sprintf("the anchor of %s (seq %d) does not come after the one of %s (seq %d)", a.Day, a.Seq, base.Day, base.Seq)
			out = append(out, Problem{Seq: a.Seq, Kind: KindAnchorInvalid, Detail: reason,
				Fingerprint: fingerprint(KindAnchorInvalid, a.Seq, "", anchorEvidence(a, reason))})
			continue
		}
		cache.add(a)
		rev.Good = append(rev.Good, a)
		base = &list[i]
	}
	return rev, out, nil
}

// RewrittenAnchor is the problem for a commit whose version of the anchor file is not its
// parent's with lines appended: base is the parent's version, content the commit's. The problem
// carries the commit; its seq is that of the first anchor of base that was changed or removed.
func RewrittenAnchor(commit string, base, content []byte) Problem {
	seq := firstChangedSeq(base, content)
	return Problem{Seq: seq, Kind: KindAnchorRewritten,
		Detail:      "commit " + commit + " changed or removed lines that were already in " + AnchorsPath,
		Fingerprint: fingerprint(KindAnchorRewritten, seq, "", commit)}
}

// firstChangedSeq is the seq of the first anchor of old that is not the same line in now; the
// number of the line when that line is no anchor.
func firstChangedSeq(old, now []byte) int64 {
	ol, nl := bytes.Split(old, []byte("\n")), bytes.Split(now, []byte("\n"))
	for i, l := range ol {
		if i < len(nl) && bytes.Equal(l, nl[i]) {
			continue
		}
		if a := ParseAnchors(l); len(a.List) == 1 {
			return a.List[0].Seq
		}
		return int64(i + 1)
	}
	return 1
}

// lineHashAt finds the line with the given seq and returns its file and hash
// ("sha256:..."); the hash is "" when the log has no complete line with it.
func lineHashAt(dir string, files []string, idx *offsetIndex, seq int64) (string, string, error) {
	for i := len(files) - 1; i >= 0; i-- {
		path := filepath.Join(dir, files[i])
		f, err := os.Open(path)
		if err != nil {
			return "", "", err
		}
		first, ok := firstSeq(f)
		if !ok || first > seq {
			f.Close()
			continue
		}
		h, err := readLineHash(f, idx.startFor(files[i], f, seq), seq)
		f.Close()
		return files[i], h, err
	}
	return "", "", nil
}

// readLineHash reads forward from off (-1 = the start) for the complete line
// with seq.
func readLineHash(f *os.File, off, seq int64) (string, error) {
	if off < 0 {
		off = 0
	}
	br := bufio.NewReaderSize(io.NewSectionReader(f, off, 1<<62), 1<<16)
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return "", nil // a last line without its newline is not complete
			}
			return "", err
		}
		raw := line[:len(line)-1]
		n, ok := lineSeq(raw)
		if !ok {
			continue
		}
		if n == seq {
			return hashOf(raw), nil
		}
	}
}

var seqPrefix = []byte(`{"seq":`)

// lineSeq is the seq of a log line. Lines are written with seq first, which
// is read without parsing the rest; anything else goes through the JSON parser.
func lineSeq(line []byte) (int64, bool) {
	if rest, ok := bytes.CutPrefix(line, seqPrefix); ok {
		end := 0
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		if end > 0 && end < len(rest) && rest[end] == ',' {
			if n, err := strconv.ParseInt(string(rest[:end]), 10, 64); err == nil {
				return n, true
			}
		}
	}
	var e struct {
		Seq int64 `json:"seq"`
	}
	if json.Unmarshal(line, &e) != nil {
		return 0, false
	}
	return e.Seq, true
}

// VerifyWithAnchors is Verify plus the anchors: file is the content of the
// anchor file (nil when there is none), whose summary is Report.Anchors. An anchor
// problem that a chain_problem event already holds is listed once, as recorded; any
// other is added as found now (at most maxAnchorProblems, then a summary). extra are
// problems found elsewhere (anchor_rewritten from the history of the file).
func VerifyWithAnchors(dir string, file []byte, opt AnchorOptions, extra ...Problem) (Report, error) {
	s, err := scanDir(dir)
	if err != nil {
		return Report{}, err
	}
	rep := s.report
	opt.Full = true
	rev, probs, err := evaluateAnchors(dir, &offsetIndex{}, s.lastSeq, ParseAnchors(file), opt, nil)
	if err != nil {
		return Report{}, err
	}
	rep.Anchors = &rev.Summary
	have := map[string]bool{}
	for _, p := range rep.Problems {
		have[problemKey(p.Kind, p.Seq, p.Fingerprint)] = true
	}
	var fresh []Problem
	probs = append(append([]Problem{}, extra...), probs...)
	for _, p := range probs {
		if !have[problemKey(p.Kind, p.Seq, p.Fingerprint)] {
			fresh = append(fresh, p)
		}
	}
	rep.Problems = append(rep.Problems, capProblems(fresh, len(probs))...)
	rep.OK = len(rep.Problems) == 0
	return rep, nil
}

// capProblems keeps the first maxAnchorProblems and adds one summary for the rest. total is how
// many wrong anchors there are altogether, for the summary's fingerprint.
func capProblems(ps []Problem, total int) []Problem {
	if len(ps) <= maxAnchorProblems {
		return ps
	}
	rest := ps[maxAnchorProblems:]
	out := append([]Problem{}, ps[:maxAnchorProblems]...)
	return append(out, Problem{Seq: rest[0].Seq, Kind: KindAnchorMore,
		Detail:      fmt.Sprintf("%d more anchors are wrong than are listed one by one; run rackbook audit verify --repo to see them all", len(rest)),
		Fingerprint: fingerprint(KindAnchorMore, 0, "", strconv.Itoa(total))})
}

func problemKey(kind string, seq int64, fp string) string {
	return kind + "|" + strconv.FormatInt(seq, 10) + "|" + fp
}

// Head is the seq of the newest line and its hash ("sha256:<hex>"); (0, "")
// for an empty log.
func (l *Log) Head() (int64, string) {
	if l == nil {
		return 0, ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq, l.hash
}

// ReviewAnchors compares the anchors in file (the anchor file as it is at the tip of the data
// repository) with the log. extra are problems found elsewhere (anchor_rewritten). Each
// problem that no chain_problem event holds yet is written into the chain, the way the check
// at start writes its own, and joins what Status reports (and the banner shows). Every wrong
// anchor has a fingerprint of its own, so acknowledging one never hides another; a problem
// that is already recorded, acknowledged or not, is left alone, so the same condition is
// recorded once however often this runs. At most maxAnchorProblems are recorded per pass,
// and one summary entry for the rest. The retention of the log is the one it was opened with.
func (l *Log) ReviewAnchors(file []byte, extra []Problem, opt AnchorOptions) (AnchorReview, error) {
	if l == nil {
		return AnchorReview{}, nil
	}
	l.mu.Lock()
	lastSeq := l.seq
	l.mu.Unlock()
	opt.RetentionMonths = l.opts.RetentionMonths
	if opt.Now.IsZero() {
		opt.Now = l.opts.Now()
	}
	rev, probs, err := evaluateAnchors(l.dir, &l.offsets, lastSeq, ParseAnchors(file), opt, &l.anchorOK)
	if err != nil {
		return rev, err
	}
	probs = append(extra[:len(extra):len(extra)], probs...)
	l.mu.Lock()
	defer l.mu.Unlock()
	var fresh []Problem
	for _, p := range probs {
		if !l.known[problemKey(p.Kind, p.Seq, p.Fingerprint)] {
			fresh = append(fresh, p)
		}
	}
	for _, p := range capProblems(fresh, len(probs)) {
		k := problemKey(p.Kind, p.Seq, p.Fingerprint)
		if l.known[k] || l.failed != "" {
			continue
		}
		e := Event{Event: ChainProblemEvent, Code: p.Kind, Detail: []string{"seq=" + strconv.FormatInt(p.Seq, 10),
			"head_seq=" + strconv.FormatInt(l.seq, 10), "head_hash=" + l.hash, p.Detail, "fp=" + p.Fingerprint}}
		if err := l.append(e); err != nil {
			l.log.Error("audit log: could not record an anchor problem", "kind", p.Kind, "seq", p.Seq, "err", err)
			continue
		}
		if l.known == nil {
			l.known = map[string]bool{}
		}
		l.known[k] = true
		p.Recorded, p.RecordedAt = true, l.seq
		wasOK := l.status.OK
		l.status.Problems = append(l.status.Problems, p)
		l.status.OK = false
		if wasOK || l.status.Problem == "" {
			l.status.Problem, l.status.FirstBrokenSeq = p.Describe(), p.Seq
		}
		l.log.Error("audit log: an anchor problem", "kind", p.Kind, "seq", p.Seq, "problem", p.Detail)
	}
	return rev, nil
}

// ActivitySince reports whether the log has an event after seq that quiet does
// not call ignorable. The anchor job uses it to tell that the log moved on since
// the last anchor: its own commit event comes after the anchored seq and must
// not make the next day's anchor due by itself.
func (l *Log) ActivitySince(seq int64, quiet func(Event) bool) (bool, error) {
	if l == nil {
		return false, nil
	}
	l.mu.Lock()
	last := l.seq
	l.mu.Unlock()
	if last <= seq {
		return false, nil
	}
	files, err := listFiles(l.dir)
	if err != nil {
		return false, err
	}
	for i := len(files) - 1; i >= 0; i-- {
		f, err := os.Open(filepath.Join(l.dir, files[i]))
		if err != nil {
			return false, err
		}
		if first, ok := firstSeq(f); !ok || first > seq+1 {
			f.Close()
			if i == 0 {
				// the lines after seq begin before the oldest file present: lines are gone, which is activity
				return true, nil
			}
			continue
		}
		busy, err := eventsAfter(f, l.offsets.startFor(files[i], f, seq+1), seq, last, quiet)
		f.Close()
		if err != nil || busy {
			return busy, err
		}
		// the lines after seq may continue in the next file
		for _, name := range files[i+1:] {
			g, err := os.Open(filepath.Join(l.dir, name))
			if err != nil {
				return false, err
			}
			busy, err := eventsAfter(g, 0, seq, last, quiet)
			g.Close()
			if err != nil || busy {
				return busy, err
			}
		}
		return false, nil
	}
	return false, nil
}

// eventsAfter reads complete lines of f from off and reports whether one has a
// seq in (after, last] and is not quiet. A line that does not parse is activity.
func eventsAfter(f *os.File, off, after, last int64, quiet func(Event) bool) (bool, error) {
	if off < 0 {
		off = 0
	}
	br := bufio.NewReaderSize(io.NewSectionReader(f, off, 1<<62), 1<<16)
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return false, nil
			}
			return false, err
		}
		raw := line[:len(line)-1]
		if n, ok := lineSeq(raw); ok && n <= after {
			continue
		} else if ok && n > last {
			return false, nil
		}
		var e Event
		if json.Unmarshal(raw, &e) != nil || !quiet(e) {
			return true, nil
		}
	}
}
