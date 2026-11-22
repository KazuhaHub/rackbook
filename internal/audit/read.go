package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
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
	// More says there may be older matches. Next is the Before to continue with.
	More bool
	Next int64
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
		f, err := os.Open(filepath.Join(l.dir, files[i]))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return Page{}, err
		}
		err = eachLineBackward(f, func(raw []byte) error {
			var e Event
			if json.Unmarshal(raw, &e) != nil {
				return nil
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
	return page, nil
}

const backBlock = 64 << 10

// eachLineBackward calls fn with every complete line of f, the last one first.
// A last line without a newline is not complete and is skipped, as are empty
// lines. fn returns an error to stop; Read returns it.
func eachLineBackward(f *os.File, fn func(line []byte) error) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	pos := st.Size()
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
		for i := len(parts) - 1; i >= first; i-- {
			if skip {
				skip = false
				continue
			}
			if len(parts[i]) == 0 {
				continue
			}
			if err := fn(parts[i]); err != nil {
				return err
			}
		}
		if pos > 0 {
			carry = slices.Clone(parts[0])
		}
	}
	return nil
}
