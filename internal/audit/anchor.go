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

// AnchorSummary is what checking the anchors looked at.
type AnchorSummary struct {
	Checked   int   `json:"checked"`             // anchors compared with the log
	Skipped   int   `json:"skipped,omitempty"`   // anchors before the first kept line (retention)
	Malformed []int `json:"malformed,omitempty"` // lines of the file that are not anchors
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

// verifyAnchors compares each anchor still in the kept log with the line at its
// seq. Anchors before the first kept line are skipped. It returns, per kind,
// only the first anchor that is wrong. lastSeq is the seq of the last line.
func verifyAnchors(dir string, idx *offsetIndex, lastSeq int64, anchors Anchors) (AnchorSummary, []Problem, error) {
	sum := AnchorSummary{Malformed: anchors.Malformed}
	if len(anchors.List) == 0 {
		return sum, nil, nil
	}
	files, err := listFiles(dir)
	if err != nil {
		return sum, nil, err
	}
	// Retention moved the start of the log (head.json says so): earlier anchors
	// have nothing to be compared with. Without that, a log that starts later than
	// seq 1 is missing lines, and an anchor in them is a mismatch.
	firstKept := int64(1)
	if b, err := os.ReadFile(filepath.Join(dir, headName)); err == nil && len(files) > 0 {
		var h head
		if json.Unmarshal(b, &h) == nil && h.FirstFile != "" {
			if f, err := os.Open(filepath.Join(dir, files[0])); err == nil {
				if s, ok := firstSeq(f); ok {
					firstKept = s
				}
				f.Close()
			}
		}
	}
	var mismatch, ahead *Problem
	for _, a := range anchors.List {
		if a.Seq < firstKept {
			sum.Skipped++
			continue
		}
		sum.Checked++
		switch {
		case a.Seq > lastSeq:
			if ahead == nil {
				ahead = &Problem{Seq: a.Seq, Kind: KindAnchorAhead,
					Detail:      fmt.Sprintf("the anchor of %s is at seq %d, the log ends at seq %d", a.Day, a.Seq, lastSeq),
					Fingerprint: fingerprint(KindAnchorAhead, a.Seq, "", anchorEvidence(a, ""))}
			}
		case mismatch == nil:
			file, got, err := lineHashAt(dir, files, idx, a.Seq)
			if err != nil {
				return sum, nil, err
			}
			if got != a.Hash {
				d := fmt.Sprintf("the anchor of %s says seq %d is %s, the line is %s", a.Day, a.Seq, shortHash(a.Hash), shortHash(got))
				if got == "" {
					d = fmt.Sprintf("the anchor of %s is at seq %d, which the log does not have", a.Day, a.Seq)
				}
				mismatch = &Problem{Seq: a.Seq, Kind: KindAnchorMismatch, File: file, Detail: d,
					Fingerprint: fingerprint(KindAnchorMismatch, a.Seq, "", anchorEvidence(a, got))}
			}
		}
	}
	var out []Problem
	if mismatch != nil {
		out = append(out, *mismatch)
	}
	if ahead != nil {
		out = append(out, *ahead)
	}
	return sum, out, nil
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
// anchor file (nil when there is none), whose summary is Report.Anchors. An anchor problem that a
// chain_problem event already holds is listed once, as recorded; any other is
// added as found now.
func VerifyWithAnchors(dir string, file []byte) (Report, error) {
	s, err := scanDir(dir)
	if err != nil {
		return Report{}, err
	}
	rep := s.report
	sum, probs, err := verifyAnchors(dir, &offsetIndex{}, s.lastSeq, ParseAnchors(file))
	if err != nil {
		return Report{}, err
	}
	rep.Anchors = &sum
	have := map[string]bool{}
	for _, p := range rep.Problems {
		have[problemKey(p.Kind, p.Seq, p.Fingerprint)] = true
	}
	for _, p := range probs {
		if !have[problemKey(p.Kind, p.Seq, p.Fingerprint)] {
			rep.Problems = append(rep.Problems, p)
		}
	}
	rep.OK = len(rep.Problems) == 0
	return rep, nil
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

// CheckAnchors compares the anchors in file (the anchor file as it is at the
// tip of the data repository) with the log. A problem that no chain_problem
// event holds yet is written into the chain, the way the check at start
// writes its own, and joins what Status reports (and the banner shows); one
// that is already recorded, acknowledged or not, is left alone, so the same
// condition is recorded once however often this runs.
func (l *Log) CheckAnchors(file []byte) (AnchorSummary, error) {
	if l == nil {
		return AnchorSummary{}, nil
	}
	l.mu.Lock()
	lastSeq := l.seq
	l.mu.Unlock()
	sum, probs, err := verifyAnchors(l.dir, &l.offsets, lastSeq, ParseAnchors(file))
	if err != nil {
		return sum, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, p := range probs {
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
		l.log.Error("audit log: an anchor does not match the log", "kind", p.Kind, "seq", p.Seq, "problem", p.Detail)
	}
	return sum, nil
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
