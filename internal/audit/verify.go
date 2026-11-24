package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Problem kinds found by Verify.
const (
	KindEdited        = "edited"         // a line does not parse, or the next line does not chain to it
	KindMissing       = "missing"        // lines (or whole months) are gone
	KindReordered     = "reordered"      // a line has an older seq than the one before it
	KindTruncatedTail = "truncated_tail" // the last line has no newline: a write cut short (crash)
	KindHeadBehind    = "head_behind_one"
	KindHeadMismatch  = "head_mismatch"
	KindCutFromEnd    = "cut_from_end" // head.json is ahead of the files
	// KindFirstFileMismatch: head.json's first_file is not the oldest month file present.
	KindFirstFileMismatch = "first_file_mismatch"
)

// Problem is one thing Verify found. Seq is the line it concerns.
type Problem struct {
	Seq    int64  `json:"seq"`
	Kind   string `json:"kind"`
	File   string `json:"file,omitempty"`
	Detail string `json:"detail,omitempty"`
	// Recorded says a chain_problem event inside the chain (at RecordedAt)
	// already holds this problem: the server saw it at start and wrote it down
	// before head.json moved on. It stays listed, and still counts as a problem.
	Recorded   bool  `json:"recorded,omitempty"`
	RecordedAt int64 `json:"recorded_at,omitempty"`
	// Acked says an administrator acknowledged the recorded problem with a
	// chain_problem_ack event (at AckedAt). It stays listed and still counts
	// in the report; it no longer blocks retention or shows in Status.
	Acked   bool  `json:"acked,omitempty"`
	AckedAt int64 `json:"acked_at,omitempty"`
	// Fingerprint identifies the evidence of the problem (the lines involved, or
	// head.json and the end of the files), not only its kind and seq: the same
	// unchanged break keeps it, a later rewrite or a new cut does not. A
	// chain_problem event holds it as "fp=<hex>", and an acknowledgement covers
	// only the fingerprints it saw.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// fingerprint is the short digest of a problem's kind, place and evidence.
func fingerprint(kind string, seq int64, file, evidence string) string {
	h := sha256.Sum256([]byte(kind + "\x00" + strconv.FormatInt(seq, 10) + "\x00" + file + "\x00" + evidence))
	return hex.EncodeToString(h[:16])
}

// Report is the result of Verify.
type Report struct {
	OK       bool      `json:"ok"`
	Files    int       `json:"files"`
	Lines    int       `json:"lines"`
	Problems []Problem `json:"problems"`
	// Anchors says what the anchor file was compared with; set only when the
	// anchors were checked (VerifyWithAnchors).
	Anchors *AnchorSummary `json:"anchors,omitempty"`
}

// Repairable says every problem is one of the two crash cases the server
// repairs at start (they are not tampering).
func (r Report) Repairable() bool {
	for _, p := range r.Problems {
		if p.Kind != KindTruncatedTail && p.Kind != KindHeadBehind {
			return false
		}
	}
	return true
}

type head struct {
	Seq       int64  `json:"seq"`
	Hash      string `json:"hash"`
	File      string `json:"file"`
	FirstFile string `json:"first_file"`
	FirstPrev string `json:"first_prev"`
}

const headName = "head.json"

var fileRe = regexp.MustCompile(`^audit-(\d{4}-\d{2})\.jsonl$`)

func monthFile(month string) string { return "audit-" + month + ".jsonl" }

func hashOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// listFiles returns the month files of dir, oldest first.
func listFiles(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.Type().IsRegular() && fileRe.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// scan is what a pass over the files found; Open uses it to continue the chain.
type scan struct {
	report    Report
	head      *head
	lastSeq   int64
	lastHash  string
	lastFile  string // newest month file of the directory (it may be empty)
	firstFile string // first file walked
	firstPrev string // Prev of its first line
	tornFile  string // file whose last line has no newline
	tornAt    int64  // offset where that partial line starts
	headBad   bool   // head.json exists but does not parse
	headRaw   []byte // head.json as it was read (nil when it is missing)
	ev        string // the evidence of the problem the next add records
	tornCrash bool   // the cut-short last line fits a crash (head.json is at the last complete line)
	firstSeq  int64  // seq of the first line walked
	recorded  []Problem
	acks      []ack

	fileLast        map[string]string // hash of the last complete line of each file
	probsAfterFirst map[string]int    // problems found up to and including each file's first line
	pending         []string          // files older than head.first_file that are a retention delete not finished
}

// Verify checks the log in dir (the audit directory). It reads and never
// writes.
func Verify(dir string) (Report, error) {
	s, err := scanDir(dir)
	if err != nil {
		return Report{}, err
	}
	return s.report, nil
}

// beforeRescan is a test seam: it runs between the two passes.
var beforeRescan func()

// scanDir scans the directory. A problem that a running server could cause
// for a moment (head.json is replaced after a line is written, a month file
// is deleted after head.json moved on) is looked at once more before it is
// reported, so verifying against a live server gives no false failure.
func scanDir(dir string) (*scan, error) {
	s, err := scanOnce(dir)
	if err != nil {
		return nil, err
	}
	for _, p := range s.report.Problems {
		switch p.Kind {
		case KindHeadMismatch, KindHeadBehind, KindCutFromEnd, KindFirstFileMismatch:
			if beforeRescan != nil {
				beforeRescan()
			}
			return scanOnce(dir)
		}
	}
	return s, nil
}

// scanOnce reads every month file present, oldest first, and only then
// head.json, which a live server rewrites after each line.
func scanOnce(dir string) (*scan, error) {
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}
	files, err := listFiles(dir)
	if err != nil {
		return nil, err
	}
	s := &scan{fileLast: map[string]string{}, probsAfterFirst: map[string]int{}}
	r := &s.report
	add := func(seq int64, kind, file, format string, args ...any) {
		r.Problems = append(r.Problems, Problem{Seq: seq, Kind: kind, File: file, Detail: fmt.Sprintf(format, args...), Fingerprint: fingerprint(kind, seq, file, s.ev)})
	}
	if len(files) > 0 {
		s.lastFile = files[len(files)-1]
	}
	walk := files
	var prevSeq int64
	prevHash, prevBad, first := "", false, true
	var lastChained bool
	var lastPrev string
	for fi, name := range walk {
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		r.Files++
		fileFirst := true
		br := bufio.NewReaderSize(f, 1<<16)
		var off int64
		for {
			line, rerr := br.ReadBytes('\n')
			if rerr != nil && rerr != io.EOF {
				f.Close()
				return nil, rerr
			}
			if len(line) == 0 {
				break
			}
			complete := line[len(line)-1] == '\n'
			if !complete && fi == len(walk)-1 {
				s.tornFile, s.tornAt = name, off
				break
			}
			off += int64(len(line))
			raw := bytes.TrimSuffix(line, []byte("\n"))
			h := hashOf(raw)
			var e Event
			perr := json.Unmarshal(raw, &e)
			r.Lines++
			chained := false
			if first {
				s.firstFile = name
			}
			switch {
			case perr != nil:
				s.ev = h
				add(prevSeq+1, KindEdited, name, "the line does not parse")
				prevSeq++
				prevBad = true
			case first:
				// checked against head.json once it is read
				s.firstSeq, s.firstPrev, chained = e.Seq, e.Prev, true
				prevSeq, prevBad = e.Seq, false
			case e.Seq != prevSeq+1:
				s.ev = prevHash + "|" + h
				if e.Seq <= prevSeq {
					add(e.Seq, KindReordered, name, "seq %d comes after seq %d", e.Seq, prevSeq)
				} else {
					add(prevSeq+1, KindMissing, name, "seq jumps from %d to %d", prevSeq, e.Seq)
				}
				prevSeq, prevBad = e.Seq, false
			case e.Prev != prevHash:
				if !prevBad {
					// line N as it is now, and what line N+1 says line N was
					s.ev = prevHash + "|" + e.Prev
					add(prevSeq, KindEdited, name, "seq %d does not chain to the line before it", e.Seq)
				}
				prevSeq, prevBad = e.Seq, false
			default:
				chained = true
				prevSeq, prevBad = e.Seq, false
			}
			if perr == nil && e.Event == ChainProblemEvent {
				s.recorded = append(s.recorded, recordedProblem(e, name))
			}
			if perr == nil && e.Event == ChainProblemAckEvent {
				if through, ok := ackThrough(e); ok {
					s.acks = append(s.acks, ack{seq: e.Seq, through: through})
				}
			}
			first = false
			lastChained, lastPrev = chained, e.Prev
			prevHash = h
			s.fileLast[name] = h
			if fileFirst {
				s.probsAfterFirst[name] = len(r.Problems)
				fileFirst = false
			}
			s.lastSeq, s.lastHash = prevSeq, h
			if rerr == io.EOF {
				break
			}
		}
		f.Close()
	}
	if b, err := os.ReadFile(filepath.Join(dir, headName)); err == nil {
		var h head
		s.headRaw = b
		if json.Unmarshal(b, &h) != nil {
			s.ev = s.headEvidence()
			add(0, KindHeadMismatch, headName, "head.json does not parse")
			s.headBad = true
		} else {
			s.head = &h
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s.checkTorn(add)
	s.checkFirst(add, files, r.Lines > 0)
	s.checkHead(add, lastChained, lastPrev)
	s.mergeRecorded()
	r.OK = len(r.Problems) == 0
	return s, nil
}

// checkTorn reports a last line without a newline. It is a crash (repaired at
// start) only when head.json is at the last complete line, which is what an
// append cut short leaves; anything else is not something a crash does.
func (s *scan) checkTorn(add func(int64, string, string, string, ...any)) {
	if s.tornFile == "" {
		return
	}
	s.ev = s.tornFile + "|" + s.lastHash + "|" + strconv.FormatInt(s.tornAt, 10)
	s.tornCrash = (s.head != nil && s.head.Seq == s.lastSeq) || (s.head == nil && !s.headBad && s.lastSeq == 0)
	if s.tornCrash {
		add(s.lastSeq+1, KindTruncatedTail, s.tornFile, "the last line has no newline")
		return
	}
	add(s.lastSeq+1, KindEdited, s.tornFile, "the last line is cut short, but head.json does not show a write in progress")
}

// checkFirst checks where the oldest file present begins. head.first_file
// must name that file; first_prev is trusted only then. If an older file
// exists, that is a problem, and the older files are still verified: from
// genesis, or from their own first prev (which nothing vouches for).
func (s *scan) checkFirst(add func(int64, string, string, string, ...any), files []string, haveLines bool) {
	if !haveLines || len(files) == 0 {
		return
	}
	oldest := files[0]
	s.ev = oldest + "|" + s.firstPrev
	if s.head != nil {
		s.ev += "|" + s.head.FirstFile + "|" + s.head.FirstPrev
	}
	wantPrev, trusted := "", true // no head, or no first_file: the log starts at genesis
	if s.head != nil && s.head.FirstFile != "" {
		switch {
		case s.head.FirstFile == oldest:
			wantPrev = s.head.FirstPrev
		case s.head.FirstFile > oldest:
			// Either a delete that retention did not finish (head.json moves first, then the
			// files go), or a forged first_file. The older files were verified from their own
			// start; they are a pending delete only if they chain without a problem into the
			// first kept file, whose first line points at their last line, as head.json says.
			if !s.pendingDelete(files) {
				add(0, KindFirstFileMismatch, oldest, "head.json says the log starts at %s, but %s is older", s.head.FirstFile, oldest)
			}
			trusted = false
		default:
			add(0, KindMissing, s.head.FirstFile, "the first kept month file is gone")
			return
		}
	}
	switch {
	case !trusted:
		if s.firstPrev == "" && s.firstSeq != 1 {
			add(1, KindMissing, oldest, "the log does not start at its first line: earlier lines are gone")
		}
	case wantPrev == "" && (s.firstSeq != 1 || s.firstPrev != ""):
		add(1, KindMissing, oldest, "the log does not start at its first line: earlier lines are gone")
	case wantPrev != "" && s.firstPrev != wantPrev:
		add(s.firstSeq, KindEdited, oldest, "the first kept line does not match head.json")
	}
}

// pendingDelete reports whether the files older than head.first_file are a
// retention delete that was not finished, and remembers them if so.
func (s *scan) pendingDelete(files []string) bool {
	i := sort.SearchStrings(files, s.head.FirstFile)
	if i == 0 || i == len(files) || files[i] != s.head.FirstFile || s.head.FirstPrev == "" {
		return false
	}
	if n, ok := s.probsAfterFirst[s.head.FirstFile]; !ok || n != 0 {
		return false
	}
	for j := i - 1; j >= 0; j-- {
		if h, ok := s.fileLast[files[j]]; ok {
			if h != s.head.FirstPrev {
				return false
			}
			s.pending = files[:i]
			return true
		}
	}
	return false
}

// ChainProblemEvent is the event the server appends when it starts on a chain
// that does not verify (other than the two crash cases).
const ChainProblemEvent = "chain_problem"

// headEvidence is what a problem with head.json rests on: the bytes of
// head.json and where the files end. A new garbage head.json, or lines cut
// from the end, is a different fingerprint.
func (s *scan) headEvidence() string {
	d := "none"
	if s.headRaw != nil {
		d = hashOf(s.headRaw)
	}
	return d + "|" + strconv.FormatInt(s.lastSeq, 10) + "|" + s.lastHash
}

// ChainProblemAckEvent is the event an administrator's acknowledgement is
// recorded as: Detail holds "through:<seq>", and every recorded chain problem
// whose chain_problem event has a seq up to that one counts as acknowledged.
const ChainProblemAckEvent = "chain_problem_ack"

type ack struct{ seq, through int64 }

func ackThrough(e Event) (int64, bool) {
	for _, d := range e.Detail {
		if v, ok := strings.CutPrefix(d, "through:"); ok {
			n, err := strconv.ParseInt(v, 10, 64)
			return n, err == nil && n > 0
		}
	}
	return 0, false
}

// recordedProblem reads a chain_problem event: Code is the kind and Detail
// holds "seq=<first broken seq>", "head_seq=" and "head_hash=".
func recordedProblem(e Event, file string) Problem {
	p := Problem{Kind: e.Code, File: file, Recorded: true, RecordedAt: e.Seq}
	var rest []string
	for _, d := range e.Detail {
		if v, ok := strings.CutPrefix(d, "seq="); ok {
			p.Seq, _ = strconv.ParseInt(v, 10, 64)
		} else if v, ok := strings.CutPrefix(d, "fp="); ok {
			p.Fingerprint = v
		} else {
			rest = append(rest, d)
		}
	}
	p.Detail = strings.Join(rest, " ")
	return p
}

// mergeRecorded lists every recorded problem, and drops a problem found now
// that a chain_problem event already holds (same kind and seq).
func (s *scan) mergeRecorded() {
	if len(s.recorded) == 0 {
		return
	}
	// An acknowledgement counts only when it comes after the problem it covers.
	for i := range s.recorded {
		p := &s.recorded[i]
		for _, a := range s.acks {
			if a.seq > p.RecordedAt && a.through >= p.RecordedAt {
				p.Acked, p.AckedAt = true, a.seq
				break
			}
		}
	}
	type key struct {
		kind string
		seq  int64
		fp   string
	}
	have := map[key]bool{}
	for _, p := range s.recorded {
		if p.Fingerprint != "" {
			have[key{p.Kind, p.Seq, p.Fingerprint}] = true
		} else if !p.Acked {
			// recorded before fingerprints: kind and seq are all there is, and an
			// acknowledgement of it never extends to what it did not see
			have[key{p.Kind, p.Seq, ""}] = true
		}
	}
	var out []Problem
	for _, p := range s.report.Problems {
		if !have[key{p.Kind, p.Seq, p.Fingerprint}] && !have[key{p.Kind, p.Seq, ""}] {
			out = append(out, p)
		}
	}
	s.report.Problems = append(out, s.recorded...)
}

// Pending are the problems that still need attention: everything except a
// recorded problem that was acknowledged.
func (r Report) Pending() []Problem {
	var out []Problem
	for _, p := range r.Problems {
		if !(p.Recorded && p.Acked) {
			out = append(out, p)
		}
	}
	return out
}

// fresh are the problems no chain_problem event holds yet.
func (r Report) fresh() []Problem {
	var out []Problem
	for _, p := range r.Problems {
		if !p.Recorded {
			out = append(out, p)
		}
	}
	return out
}

// checkHead compares the last line with head.json.
func (s *scan) checkHead(add func(int64, string, string, string, ...any), lastChained bool, lastPrev string) {
	s.ev = s.headEvidence()
	h := s.head
	if h == nil {
		if s.headBad {
			return
		}
		if s.lastSeq == 1 && lastChained && s.lastHash != "" {
			add(1, KindHeadBehind, headName, "head.json is missing and the log has one line")
		} else if s.lastSeq > 0 {
			add(s.lastSeq, KindHeadMismatch, headName, "head.json is missing")
		}
		return
	}
	switch {
	case h.Seq == s.lastSeq && h.Hash == s.lastHash:
	case h.Seq == s.lastSeq:
		add(s.lastSeq, KindHeadMismatch, headName, "the last line does not match head.json")
	case h.Seq > s.lastSeq:
		add(s.lastSeq+1, KindCutFromEnd, headName, "head.json is at seq %d, the files end at seq %d", h.Seq, s.lastSeq)
	case h.Seq == s.lastSeq-1 && lastChained && lastPrev == h.Hash:
		add(s.lastSeq, KindHeadBehind, headName, "head.json is one line behind")
	default:
		add(s.lastSeq, KindHeadMismatch, headName, "head.json is at seq %d, the files end at seq %d", h.Seq, s.lastSeq)
	}
}

// Describe is the one-line form of a Problem for humans.
func (p Problem) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s at seq %d", p.Kind, p.Seq)
	if p.File != "" {
		fmt.Fprintf(&b, " (%s)", p.File)
	}
	if p.Recorded {
		fmt.Fprintf(&b, " (recorded at seq %d)", p.RecordedAt)
	}
	if p.Acked {
		fmt.Fprintf(&b, " (acknowledged at seq %d)", p.AckedAt)
	}
	if p.Detail != "" {
		b.WriteString(": " + p.Detail)
	}
	return b.String()
}
