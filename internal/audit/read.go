package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"time"
)

// Limits of one Read call.
const (
	DefaultReadLimit = 100
	MaxReadLimit     = 1000
	// DefaultMaxScan bounds the lines one Read looks at, so a request for a
	// rare event cannot read the whole log.
	DefaultMaxScan = 100_000
)

// Query selects events for Read. Zero fields select everything.
type Query struct {
	Since, Until time.Time // both inclusive
	Identity     string    // exact match on Event.Identity
	Events       []string  // event kinds
	Before       int64     // only events with a smaller seq: the cursor of the page before
	// Filter, when set, must accept an event for it to be returned.
	Filter  func(Event) bool
	Limit   int // DefaultReadLimit when 0, at most MaxReadLimit
	MaxScan int // lines to look at, DefaultMaxScan when 0
}

// Page is the result of Read: events newest first (by seq).
type Page struct {
	Events []Event
	// More says there may be older matches. Next is the Before to continue with:
	// the seq of the last event returned, or, when the scan budget ran out first,
	// of the last line looked at (the page may then hold no event at all).
	More bool
	Next int64
	// Scanned is how many lines were looked at.
	Scanned int
}

func (q Query) match(e Event) bool {
	switch {
	case q.Before > 0 && e.Seq >= q.Before:
		return false
	case !q.Since.IsZero() && e.Time.Before(q.Since):
		return false
	case !q.Until.IsZero() && e.Time.After(q.Until):
		return false
	case q.Identity != "" && e.Identity != q.Identity:
		return false
	case len(q.Events) > 0 && !slices.Contains(q.Events, e.Event):
		return false
	}
	return q.Filter == nil || q.Filter(e)
}

// Read returns the newest events that match q, reading the month files from
// the end. It does not take the writer's lock: a line is appended with one
// write, and a last line without its newline is ignored. A month file that
// retention deletes while it is read is skipped.
func (l *Log) Read(q Query) (Page, error) {
	if l == nil {
		return Page{}, nil
	}
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultReadLimit
	}
	limit = min(limit, MaxReadLimit)
	maxScan := q.MaxScan
	if maxScan <= 0 {
		maxScan = DefaultMaxScan
	}
	files, err := listFiles(l.dir)
	if err != nil {
		return Page{}, err
	}
	var page Page
	scanned := 0
	var lastSeq int64
	stop := errors.New("stop")
	for i := len(files) - 1; i >= 0; i-- {
		if !q.Since.IsZero() {
			// A line is in the file of its own month, or a later one (a late event
			// goes into the newest file): older files hold nothing from Since on.
			var y, m int
			if _, err := parseMonth(files[i], &y, &m); err == nil && y*12+m-1 < monthIndex(q.Since.UTC()) {
				break
			}
		}
		if !q.Until.IsZero() {
			// Lines are filed under their own month (an event written late goes
			// into the newest file, which only happens for events with an explicit
			// old time): a file of a later month than Until holds nothing up to it.
			var y, m int
			if _, err := parseMonth(files[i], &y, &m); err == nil && y*12+m-1 > monthIndex(q.Until.UTC()) {
				continue
			}
		}
		f, err := os.Open(filepath.Join(l.dir, files[i]))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return Page{}, err
		}
		if q.Before > 0 {
			// a file that starts at or after Before is all seen: do not read it
			if first, ok := firstSeq(f); ok && first >= q.Before {
				f.Close()
				continue
			}
		}
		end := int64(-1)
		if q.Before > 0 {
			end = l.offsets.seekEnd(files[i], f, q.Before)
		}
		err = eachLineBackward(f, end, func(raw []byte, _ int64) error {
			var e Event
			if json.Unmarshal(raw, &e) != nil {
				return nil
			}
			linesParsed.Add(1)
			if q.Before > 0 && e.Seq >= q.Before {
				return nil // already seen by the page before: not part of this scan's budget
			}
			if scanned >= maxScan {
				page.More, page.Next = true, lastSeq
				return stop
			}
			scanned++
			lastSeq = e.Seq
			if !q.match(e) {
				return nil
			}
			page.Events = append(page.Events, e)
			if len(page.Events) >= limit {
				page.More, page.Next = true, e.Seq
				return stop
			}
			return nil
		})
		f.Close()
		if errors.Is(err, stop) {
			break
		}
		if err != nil {
			return Page{}, err
		}
	}
	page.Scanned = scanned
	return page, nil
}

// linesParsed counts the lines Read parsed (the tests check that a deep read does not parse the whole file).
var linesParsed atomic.Int64

const backBlock = 64 << 10

// eachLineBackward calls fn with every complete line of f before offset end
// (a line start, or -1 for the whole file), the last one first.
// A last line without a newline is not complete and is skipped, as are empty
// lines. fn returns an error to stop; Read returns it.
func eachLineBackward(f *os.File, end int64, fn func(line []byte, off int64) error) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	pos := st.Size()
	if end >= 0 && end < pos {
		pos = end // a line start: everything after it is left unread
	}
	var carry []byte
	skip := true // the first piece from the end is empty, or a line cut short
	for pos > 0 {
		n := min(int64(backBlock), pos)
		pos -= n
		chunk := make([]byte, n, int(n)+len(carry))
		if _, err := f.ReadAt(chunk, pos); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		data := append(chunk, carry...)
		parts := bytes.Split(data, []byte{'\n'})
		first := 1
		if pos == 0 {
			first = 0
		}
		offs := make([]int64, len(parts)) // data starts at file offset pos
		o := pos
		for i, part := range parts {
			offs[i], o = o, o+int64(len(part))+1
		}
		for i := len(parts) - 1; i >= first; i-- {
			if skip {
				skip = false
				continue
			}
			if len(parts[i]) == 0 {
				continue
			}
			if err := fn(parts[i], offs[i]); err != nil {
				return err
			}
		}
		if pos > 0 {
			carry = slices.Clone(parts[0])
		}
	}
	return nil
}

// firstSeq is the seq of the first line of f.
func firstSeq(f *os.File) (int64, bool) {
	line, err := bufio.NewReader(io.NewSectionReader(f, 0, 1<<20)).ReadBytes('\n')
	if err != nil {
		return 0, false
	}
	var e Event
	if json.Unmarshal(line, &e) != nil {
		return 0, false
	}
	return e.Seq, true
}
