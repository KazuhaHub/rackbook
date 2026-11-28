package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// pruneAfterScan is a test seam: it runs after the scan, before the lock is taken.
var pruneAfterScan func()

// daily applies the retention once a day until Close.
func (l *Log) daily() {
	defer l.wg.Done()
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			l.prune()
		}
	}
}

// monthIndex counts months so that "N whole months before" is a subtraction.
func monthIndex(t time.Time) int { return t.Year()*12 + int(t.Month()) - 1 }

// prune deletes the month files older than RetentionMonths whole months
// before the current month. It never deletes the newest file, nor a file that
// holds a chain_problem event that nobody acknowledged yet (the evidence stays), and does nothing while the
// chain has a problem that is not recorded in it yet or the log is failed.
// Before deleting, head.json records the first kept file and the Prev of its
// first line, so verification starts there.
func (l *Log) prune() {
	if l.opts.RetentionMonths <= 0 {
		return
	}
	if l.pruneOnce() && l.opts.Pin != nil {
		l.opts.Pin.Held() // no lock of the log is held here: the callee may append
	}
}

// pruneOnce is one retention pass. It reports whether the retention pin held a
// month back that the retention alone would have deleted.
func (l *Log) pruneOnce() (held bool) {
	pin := ""
	if l.opts.Pin != nil {
		pin = l.opts.Pin.Month()
	}
	// The scan reads whole files: it runs without the lock, so appends are not held up.
	// The lock is taken to change anything, and only if nothing was appended meanwhile.
	l.mu.Lock()
	seq, failed := l.seq, l.failed
	l.mu.Unlock()
	if seq == 0 {
		return false
	}
	if failed != "" {
		l.log.Warn("audit log: retention skipped: the log is in a failed state", "reason", failed)
		return held
	}
	s, err := scanDir(l.dir)
	if err != nil {
		l.log.Error("audit log: retention could not read the log", "err", err)
		return held
	}
	if fresh := s.report.fresh(); len(fresh) > 0 {
		l.log.Warn("audit log: retention skipped: the chain has a problem that is not recorded in it yet", "problem", fresh[0].Describe())
		return held
	}
	holds := map[string]bool{}
	for _, p := range s.recorded {
		if !p.Acked {
			holds[p.File] = true
		}
	}
	files, err := listFiles(l.dir)
	if err != nil {
		l.log.Error("audit log: retention could not list the files", "err", err)
		return held
	}
	cutoff := monthIndex(l.opts.Now().UTC()) - l.opts.RetentionMonths
	keep := 0
	for keep < len(files)-1 {
		var y, m int
		if _, err := parseMonth(files[keep], &y, &m); err != nil || y*12+m-1 >= cutoff {
			break
		}
		if pin != "" && files[keep] >= monthFile(pin) {
			l.log.Warn("audit log: retention delayed: the month holds the account store's last change", "file", files[keep], "pin", pin)
			held = true
			break
		}
		if holds[files[keep]] {
			l.log.Warn("audit log: retention keeps a file that holds a chain_problem event", "file", files[keep])
			break
		}
		keep++
	}
	if keep < len(s.pending) {
		keep = len(s.pending) // a delete an earlier run did not finish
	}
	if keep == 0 {
		return held
	}
	prev, err := firstPrevOf(filepath.Join(l.dir, files[keep]))
	if err != nil {
		l.log.Error("audit log: retention could not read the first kept file", "file", files[keep], "err", err)
		return held
	}
	if pruneAfterScan != nil {
		pruneAfterScan()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seq != seq || l.failed != "" {
		l.log.Warn("audit log: retention skipped: the log changed while it was read; it tries again on the next run")
		return held
	}
	oldFirst, oldPrev := l.firstFile, l.firstPrev
	l.firstFile, l.firstPrev = files[keep], prev
	if err := l.writeHead(); err != nil {
		l.firstFile, l.firstPrev = oldFirst, oldPrev
		l.log.Error("audit log: retention could not write head.json", "err", err)
		return held
	}
	for _, name := range files[:keep] {
		if err := os.Remove(filepath.Join(l.dir, name)); err != nil {
			l.log.Error("audit log: retention could not delete a file", "file", name, "err", err)
			continue
		}
		l.log.Info("audit log: deleted a month past the retention", "file", name, "retentionMonths", l.opts.RetentionMonths)
	}
	return held
}

func parseMonth(name string, y, m *int) (bool, error) {
	sub := fileRe.FindStringSubmatch(name)
	if sub == nil {
		return false, errors.New("not a month file")
	}
	t, err := time.Parse("2006-01", sub[1])
	if err != nil {
		return false, err
	}
	*y, *m = t.Year(), int(t.Month())
	return true, nil
}

// firstPrevOf reads the Prev of the first line of a month file.
func firstPrevOf(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	line, err := bufio.NewReader(f).ReadBytes('\n')
	if err != nil {
		return "", err // an empty or unterminated file has no first line to start from
	}
	var e Event
	if err := json.Unmarshal(line, &e); err != nil {
		return "", err
	}
	return e.Prev, nil
}
