package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Options configures a Log.
type Options struct {
	Addr            AddrMode // how much of Event.Addr is kept; "" = truncate
	RetentionMonths int      // month files older than this many whole months are deleted; 0 = keep all
	Logger          *slog.Logger
	Now             func() time.Time
	// InfraPath is the old infra-audit.jsonl to copy into the log (see
	// MigrateInfra); "" = none. Open does it before anything else can append.
	InfraPath string

	migrateStop func(copied int) bool // test seam: true stops the copy as a crash would
}

// Status is what the check at start found. Problem names the first thing
// wrong; FirstBrokenSeq is the line it concerns.
type Status struct {
	OK             bool
	Problem        string
	FirstBrokenSeq int64
}

// Log appends events to the audit directory. A nil *Log does nothing.
type Log struct {
	dir  string
	opts Options
	log  *slog.Logger

	mu        sync.Mutex
	seq       int64
	hash      string // "sha256:<hex>" of the last line, "" before the first
	curFile   string // newest month file; a month never goes backwards
	firstFile string
	firstPrev string
	status    Status
	failed    string // set when the log cannot safely append: Record then writes nothing

	stat func(*os.File) (os.FileInfo, error) // test seam: f.Stat

	stop chan struct{}
	wg   sync.WaitGroup
	once sync.Once
}

// Open opens (and creates) the audit directory, checks the chain, repairs the
// two crash cases, applies the retention and starts the daily retention job.
// A chain that is broken in any other way is logged and appended to as it is.
func Open(dir string, opts Options) (*Log, error) {
	if opts.Addr == "" {
		opts.Addr = AddrTruncate
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	l := &Log{dir: dir, opts: opts, log: opts.Logger, stop: make(chan struct{}), stat: (*os.File).Stat}
	if l.log == nil {
		l.log = slog.New(slog.DiscardHandler)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	if err := l.check(); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	if err := l.MigrateInfra(opts.InfraPath); err != nil {
		l.log.Error("audit log: could not copy the old infra audit file; the next start continues", "err", err)
	}
	if opts.RetentionMonths > 0 {
		l.prune()
		l.wg.Add(1)
		go l.daily()
	}
	return l, nil
}

// Close stops the daily retention job.
func (l *Log) Close() {
	if l == nil {
		return
	}
	l.once.Do(func() { close(l.stop) })
	l.wg.Wait()
}

// Status reports what the check at start found.
func (l *Log) Status() Status {
	if l == nil {
		return Status{OK: true}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.status
}

// check verifies the directory, repairs a torn last line and a head.json one
// line behind, and sets the state to continue from the last line. Any other
// problem is written into the chain as chain_problem events before anything
// else is appended and head.json moves on, so the evidence stays in the chain.
func (l *Log) check() error {
	s, err := scanDir(l.dir)
	if err != nil {
		return err
	}
	failed := ""
	var torn *Problem // a cut-short last line that head.json does not explain
	if s.tornFile != "" {
		name, err := l.setAsideTail(s)
		if err != nil {
			failed = "the last line is cut short and could not be set aside: " + err.Error()
			l.log.Error("audit log: could not set aside the last, incomplete line; nothing will be written", "file", s.tornFile, "err", err)
		} else {
			if !s.tornCrash {
				torn = &Problem{Seq: s.lastSeq + 1, Kind: KindEdited, File: s.tornFile, Detail: "torn=" + name}
			}
			if s, err = scanDir(l.dir); err != nil {
				return err
			}
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failed = failed
	l.setState(s)
	fresh := s.report.fresh()
	var serious []Problem
	for _, p := range fresh {
		if p.Kind != KindHeadBehind && p.Kind != KindTruncatedTail {
			serious = append(serious, p)
		}
	}
	if torn != nil {
		serious = append([]Problem{*torn}, serious...)
	}
	changed := false
	switch {
	case len(serious) > 0 && l.failed == "":
		l.recordProblems(serious, s.head)
		changed = true
	case l.failed == "" && len(fresh) > 0 && onlyKind(Report{Problems: fresh}, KindHeadBehind):
		if err := l.writeHead(); err != nil {
			l.log.Error("audit log: could not bring head.json up to date", "err", err)
		} else {
			l.log.Warn("audit log: head.json was one line behind (a crash); brought up to date", "seq", l.seq)
			changed = true
		}
	}
	if changed {
		if s, err = scanDir(l.dir); err != nil {
			return err
		}
		l.setState(s)
	}
	rep := s.report
	l.status = Status{OK: rep.OK}
	if l.failed != "" {
		l.status = Status{Problem: l.failed, FirstBrokenSeq: s.lastSeq + 1}
	} else if !rep.OK {
		p := rep.Problems[0]
		l.status.Problem, l.status.FirstBrokenSeq = p.Describe(), p.Seq
		l.log.Error("audit log: the chain does not verify; appending to it as it is (run `rackbook audit verify`)",
			"firstBrokenSeq", p.Seq, "problem", p.Describe(), "problems", len(rep.Problems))
	}
	return nil
}

// setState continues from the last line found. The first file is the oldest
// one present, with the prev of its first line. The caller holds mu.
func (l *Log) setState(s *scan) {
	l.seq, l.hash, l.curFile = s.lastSeq, s.lastHash, s.lastFile
	l.firstFile, l.firstPrev = s.firstFile, s.firstPrev
}

// maxChainProblems bounds how many events one start writes for a broken chain.
const maxChainProblems = 50

// recordProblems appends one chain_problem event per problem: Code is the
// kind, Detail the broken seq and what head.json said before (seq and hash).
// head.json moves on only with these appends. The caller holds mu.
func (l *Log) recordProblems(ps []Problem, h *head) {
	if len(ps) > maxChainProblems {
		ps = ps[:maxChainProblems]
	}
	for _, p := range ps {
		e := Event{Event: ChainProblemEvent, Code: p.Kind, Detail: []string{"seq=" + strconv.FormatInt(p.Seq, 10)}}
		if h != nil {
			e.Detail = append(e.Detail, "head_seq="+strconv.FormatInt(h.Seq, 10), "head_hash="+h.Hash)
		} else {
			e.Detail = append(e.Detail, "head=none")
		}
		if p.Detail != "" {
			e.Detail = append(e.Detail, p.Detail)
		}
		if err := l.append(e); err != nil {
			l.log.Error("audit log: could not record a chain problem", "kind", p.Kind, "seq", p.Seq, "err", err)
			return
		}
	}
}

func onlyKind(r Report, kind string) bool {
	for _, p := range r.Problems {
		if p.Kind != kind {
			return false
		}
	}
	return true
}

// setAsideTail moves the partial last line to torn-<seq>.jsonl and cuts the
// month file back to its last complete line.
func (l *Log) setAsideTail(s *scan) (string, error) {
	path := filepath.Join(l.dir, s.tornFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if s.tornAt > int64(len(b)) {
		return "", errors.New("the file changed while it was read")
	}
	tail := b[s.tornAt:]
	name := "torn-" + strconv.FormatInt(s.lastSeq+1, 10) + ".jsonl"
	var tf *os.File
	for n := 1; ; n++ {
		tf, err = os.OpenFile(filepath.Join(l.dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) || n > 1000 {
			return "", err
		}
		name = "torn-" + strconv.FormatInt(s.lastSeq+1, 10) + "-" + strconv.Itoa(n) + ".jsonl"
	}
	_, werr := tf.Write(tail)
	if werr == nil {
		werr = tf.Sync()
	}
	if cerr := tf.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return "", werr
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := f.Truncate(s.tornAt); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := syncDir(l.dir); err != nil {
		return "", err
	}
	l.log.Warn("audit log: the last line was cut short; set aside", "file", name, "bytes", len(tail), "crash", s.tornCrash)
	return name, nil
}

// Record appends e. It assigns Seq, Prev and, when zero, Time. A failure is
// logged and never returned: the audit must not break the request.
func (l *Log) Record(e Event) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.append(e); err != nil {
		l.log.Error("audit log: could not record an event", "event", e.Event, "err", err)
	}
}

func (l *Log) append(e Event) error {
	if l.failed != "" {
		return errors.New("the log is in a failed state: " + l.failed)
	}
	if e.Time.IsZero() {
		e.Time = l.opts.Now()
	}
	e.Time = e.Time.UTC()
	e.Addr = applyAddr(e.Addr, l.opts.Addr)
	e.Seq = l.seq + 1
	if l.hash != "" {
		e.Prev = l.hash
	} else {
		e.Prev = ""
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	month := e.Time.Format("2006-01")
	name := monthFile(month)
	if name < l.curFile {
		name = l.curFile // a late event goes into the newest file: the chain is read in file order
	}
	path := filepath.Join(l.dir, name)
	_, statErr := os.Stat(path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	st, err := l.stat(f)
	if err != nil {
		f.Close()
		return err // the size is unknown: write nothing, never truncate blindly
	}
	size := st.Size()
	_, werr := f.Write(append(raw, '\n'))
	if werr == nil {
		werr = f.Sync()
	}
	if werr != nil && f.Truncate(size) != nil {
		// a partial line may be left: never glue another one onto it
		l.failed = "a write failed and the partial line could not be removed: " + werr.Error()
		l.status = Status{Problem: l.failed, FirstBrokenSeq: l.seq + 1}
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	if errors.Is(statErr, os.ErrNotExist) {
		if err := syncDir(l.dir); err != nil {
			l.log.Error("audit log: could not sync the directory", "err", err)
		}
	}
	l.seq, l.hash, l.curFile = e.Seq, hashOf(raw), name
	if l.firstFile == "" {
		l.firstFile, l.firstPrev = name, e.Prev
	}
	if err := l.writeHead(); err != nil {
		l.log.Error("audit log: could not write head.json", "err", err)
	}
	return nil
}

// writeHead replaces head.json: temp file, fsync, rename, fsync of the directory.
func (l *Log) writeHead() error {
	b, err := json.Marshal(head{Seq: l.seq, Hash: l.hash, File: l.curFile, FirstFile: l.firstFile, FirstPrev: l.firstPrev})
	if err != nil {
		return err
	}
	tmp := filepath.Join(l.dir, headName+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(b, '\n'))
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(tmp)
		return werr
	}
	if err := os.Rename(tmp, filepath.Join(l.dir, headName)); err != nil {
		return err
	}
	return syncDir(l.dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
