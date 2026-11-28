package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// RetentionPin names a month that retention must not delete, nor any month after it
// (design-local-accounts.md, 4.6: the account store's last change must stay readable).
type RetentionPin interface {
	// Month is "YYYY-MM", or "" when nothing is pinned. A pin that cannot be
	// determined returns "0000-00", which holds every month.
	Month() string
	// Held is called, with no lock of the log held, after a retention pass kept
	// a month that the retention alone would have deleted.
	Held()
}

// ErrNoLog is returned by RecordSync on a nil log.
var ErrNoLog = errors.New("there is no audit log")

// RecordSync appends e and fsyncs it. It returns the seq it got, or an error,
// including when the log is in its failed state. It never drops an event silently.
// Account changes and local sign-ins use it and fail closed (design-local-accounts.md, 10).
func (l *Log) RecordSync(e Event) (seq int64, err error) {
	seq, _, err = l.RecordSyncMonth(e)
	return seq, err
}

// RecordSyncMonth is RecordSync that also returns the month ("YYYY-MM") of the file the
// line went into, which is the month the retention pin names.
func (l *Log) RecordSyncMonth(e Event) (seq int64, month string, err error) {
	if l == nil {
		return 0, "", ErrNoLog
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.append(e); err != nil {
		return 0, "", err
	}
	return l.seq, monthOfFile(l.curFile), nil
}

func monthOfFile(name string) string {
	if sub := fileRe.FindStringSubmatch(name); sub != nil {
		return sub[1]
	}
	return ""
}

// FirstMonth is the month of the oldest month file the log keeps, "" for an empty log.
func (l *Log) FirstMonth() string {
	if l == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return monthOfFile(l.firstFile)
}

// MonthExists says whether the month file of month ("YYYY-MM") is on disk.
func (l *Log) MonthExists(month string) bool {
	if l == nil || month == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(l.dir, monthFile(month)))
	return err == nil
}

// EachEvent reads the retained log forward, from the file of fromMonth ("" = the first) on,
// and calls fn with every complete line and the month of its file until fn returns false.
// It takes no lock: a line is appended with one write, and a last line without its newline
// is ignored.
func (l *Log) EachEvent(fromMonth string, fn func(e Event, month string) bool) error {
	if l == nil {
		return nil
	}
	files, err := listFiles(l.dir)
	if err != nil {
		return err
	}
	for _, name := range files {
		if fromMonth != "" && name < monthFile(fromMonth) {
			continue
		}
		f, err := os.Open(filepath.Join(l.dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		more, err := eachLine(f, monthOfFile(name), fn)
		f.Close()
		if err != nil {
			return err
		}
		if !more {
			return nil
		}
	}
	return nil
}

func eachLine(f *os.File, month string, fn func(Event, string) bool) (bool, error) {
	r := bufio.NewReaderSize(f, 1<<16)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return true, nil // a last line without its newline is not complete
			}
			return false, err
		}
		var e Event
		if json.Unmarshal(line, &e) != nil {
			continue
		}
		if !fn(e, month) {
			return false, nil
		}
	}
}
