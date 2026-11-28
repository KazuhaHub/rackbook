package accounts

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/fsutil"
	"github.com/kazuhahub/rackbook/internal/statekey"
)

// doc is an encrypted document the engine keeps: the account store or secrets.enc.
type doc interface{ meta() *Meta }

// Start codes: why a store refused to start (4.3, 4.4).
type Code string

const (
	CodeMissing        Code = "missing"         // the store is gone, but the log has changes
	CodeWrongKey       Code = "wrong_key"       // the file does not decrypt with this key
	CodeCorrupt        Code = "corrupt"         // the file is not an encrypted state file
	CodeAuditTruncated Code = "audit_truncated" // the audit log was rolled back or truncated
	CodeMonthPruned    Code = "month_pruned"    // the store's month was deleted by retention
	CodeGap            Code = "gap"             // the store is older than the audit log
	CodeUsernamesMAC   Code = "usernames_mac"   // the usernames file has a bad MAC
	CodeFailed         Code = "failed"          // an I/O step failed
)

// StartError is a refusal to start. Doc, when set, is the store as it was loaded, for
// accept-restore; Gap is set for CodeGap.
type StartError struct {
	Code   Code
	Msg    string
	Detail []string
	Gap    *Gap
	Doc    any
	// FileKID and LoadedKID are the key ids of the file and of the loaded key, when the file's header could be read.
	FileKID, LoadedKID string
}

func (e *StartError) Error() string { return e.Msg }

// Gap describes a store that lacks audited changes.
type Gap struct {
	StoreChange string
	StoreSeq    int64
	// Events are the change events after the store's own, oldest first.
	Events []audit.Event
}

// ErrAuditUnavailable is the error of a change or a counter write that could not append its
// audit event (503 audit_unavailable). Nothing was changed.
var ErrAuditUnavailable = errors.New("audit_unavailable: the audit log cannot be written")

// ErrStoreFailed is returned once a write failed after its audit event was recorded: the
// store is behind the log, and a restart recovers it (4.3). Until then every write is refused.
var ErrStoreFailed = errors.New("the store failed after an audited change; restart to recover it")

type auditError struct{ err error }

func (e *auditError) Error() string   { return ErrAuditUnavailable.Error() + ": " + e.err.Error() }
func (e *auditError) Unwrap() []error { return []error{ErrAuditUnavailable, e.err} }

// errCrash is what a test hook returns to stop the writer where a crash would.
var errCrash = errors.New("simulated crash")

type engineConfig[D doc] struct {
	Dir     string // directory of the files
	Base    string // "accounts.enc" or "secrets.enc"
	Purpose statekey.Purpose
	Marker  string // "change:" or "secrets_change:"
	// Events are the event names this document's writer emits as changes.
	Events map[string]bool
	Key    *statekey.Key
	Log    *audit.Log
	Now    func() time.Time
	Logger *slog.Logger
	// Hook is called after each step of a change (see commit); an error stops the writer
	// as a crash would. Tests only.
	Hook func(step string) error
	New  func() D
	// OnSet is called with the meta of every document that becomes current.
	OnSet func(Meta)
}

// engine is the single writer of one encrypted document: a mutex held from building the new
// state to the directory fsync, files written as *.tmp and renamed, audit first.
type engine[D doc] struct {
	c engineConfig[D]

	wmu    sync.Mutex // the single writer
	cur    D
	failed error
	mu     sync.RWMutex // guards cur for readers

	recovered bool
}

func newEngine[D doc](c engineConfig[D]) *engine[D] {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	return &engine[D]{c: c}
}

func (e *engine[D]) path(suffix string) string { return filepath.Join(e.c.Dir, e.c.Base+suffix) }

func (e *engine[D]) clone(d D) D {
	b, err := json.Marshal(d)
	if err != nil {
		panic("accounts: " + err.Error())
	}
	n := e.c.New()
	if err := json.Unmarshal(b, n); err != nil {
		panic("accounts: " + err.Error())
	}
	return n
}

// snapshot is a deep copy of the committed document.
func (e *engine[D]) snapshot() D {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.clone(e.cur)
}

func (e *engine[D]) setCur(d D) {
	e.mu.Lock()
	e.cur = d
	e.mu.Unlock()
	if e.c.OnSet != nil {
		e.c.OnSet(*d.meta())
	}
}

// ---- files

// readDoc reads and decrypts one file of the document. fs.ErrNotExist is returned as is.
func (e *engine[D]) readDoc(path string) (D, error) {
	var zero D
	b, err := os.ReadFile(path)
	if err != nil {
		return zero, err
	}
	pt, err := statekey.Open(e.c.Key, e.c.Purpose, b)
	if err != nil {
		return zero, err
	}
	d := e.c.New()
	if err := json.Unmarshal(pt, d); err != nil {
		return zero, fmt.Errorf("%w: %v", statekey.ErrNotEncrypted, err)
	}
	return d, nil
}

func (e *engine[D]) seal(d D) ([]byte, error) {
	pt, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return statekey.Seal(e.c.Key, e.c.Purpose, pt)
}

// writeFile writes data as path+".tmp", fsyncs it, renames it into place and fsyncs the directory,
// so a named file is always complete.
func writeFile(path string, data []byte) error {
	tmp := path + ".tmp"
	// a leftover or planted .tmp, a symlink included, is removed (the link itself, never its target) and the
	// new one is created exclusively with mode 0600, so a write can never follow a link
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
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
	if err := fsutil.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// renameSync renames and fsyncs the directory.
func renameSync(from, to string) error {
	if err := fsutil.Rename(from, to); err != nil {
		return err
	}
	return syncDir(filepath.Dir(to))
}

// EnsureDir creates dir with mode 0700 and refuses a directory that cannot be made so.
func EnsureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if st.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("%s has mode %v and could not be changed to 0700: %w", dir, st.Mode().Perm(), err)
		}
	}
	return nil
}

func (e *engine[D]) removeTmp() error {
	ents, err := os.ReadDir(e.c.Dir)
	if err != nil {
		return err
	}
	for _, ent := range ents {
		n := ent.Name()
		// any entry that is not a directory, a symlink included; in the accounts directory every .tmp is ours
		if !ent.IsDir() && strings.HasSuffix(n, ".tmp") && (strings.HasPrefix(n, e.c.Base) || e.c.Base == accountsFile) {
			if err := os.Remove(filepath.Join(e.c.Dir, n)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

// moveAside renames a file to <name>.evidence-<time>, so it stays for the operator.
func (e *engine[D]) moveAside(suffix string) (string, error) {
	from := e.path(suffix)
	stamp := e.c.Now().UTC().Format("20060102T150405Z")
	to := from + ".evidence-" + stamp
	for n := 1; ; n++ {
		if _, err := os.Lstat(to); errors.Is(err, fs.ErrNotExist) {
			break
		}
		to = fmt.Sprintf("%s.evidence-%s-%d", from, stamp, n)
	}
	if err := renameSync(from, to); err != nil {
		return "", err
	}
	e.c.Logger.Warn("account store: a file did not fit and was set aside as evidence", "file", filepath.Base(to))
	return filepath.Base(to), nil
}

// Evidence lists the evidence files of the document, which stay until accept-restore or an operator removes them.
func (e *engine[D]) evidence() []string {
	ents, _ := os.ReadDir(e.c.Dir)
	var out []string
	for _, ent := range ents {
		if strings.HasPrefix(ent.Name(), e.c.Base) && strings.Contains(ent.Name(), ".evidence-") {
			out = append(out, ent.Name())
		}
	}
	slices.Sort(out)
	return out
}

// ---- audit access

type changeEvent struct {
	ev    audit.Event
	month string
	id    string
}

func (e *engine[D]) changeID(ev audit.Event) string {
	if !e.c.Events[ev.Event] {
		return ""
	}
	for _, d := range ev.Detail {
		if id, ok := strings.CutPrefix(d, e.c.Marker); ok {
			return id
		}
	}
	return ""
}

// changesFrom lists the change events of this document with seq >= fromSeq, oldest first, reading
// the log from the file of fromMonth on.
func (e *engine[D]) changesFrom(fromMonth string, fromSeq int64) ([]changeEvent, error) {
	var out []changeEvent
	err := e.c.Log.EachEvent(fromMonth, func(ev audit.Event, month string) bool {
		if ev.Seq >= fromSeq {
			if id := e.changeID(ev); id != "" {
				out = append(out, changeEvent{ev, month, id})
			}
		}
		return true
	})
	return out, err
}

// auditedAnywhere says whether any retained change event carries id: an older audited .pending is
// evidence (4.3 step 5), not a file to delete.
func (e *engine[D]) auditedAnywhere(id string) bool {
	found := false
	_ = e.c.Log.EachEvent("", func(ev audit.Event, _ string) bool {
		found = e.changeID(ev) == id
		return !found
	})
	return found
}

func (e *engine[D]) anyChange() (bool, error) {
	found := false
	err := e.c.Log.EachEvent("", func(ev audit.Event, _ string) bool {
		found = e.changeID(ev) != ""
		return !found
	})
	return found, err
}

// ---- start

func (e *engine[D]) fail(code Code, doc any, format string, a ...any) *StartError {
	return &StartError{Code: code, Msg: fmt.Sprintf(format, a...), Doc: doc}
}

func keyErr(err error, what string) *StartError {
	switch {
	case errors.Is(err, statekey.ErrWrongKey):
		var kid *statekey.KeyIDError
		if errors.As(err, &kid) {
			return &StartError{Code: CodeWrongKey, FileKID: kid.File, LoadedKID: kid.Loaded,
				Msg: fmt.Sprintf("%s needs state key %s, but the loaded key is %s (after an interrupted rekey the files may need different keys: load the key each file names, then run rekey again)", what, kid.File, kid.Loaded)}
		}
		return &StartError{Code: CodeWrongKey, Msg: fmt.Sprintf("%s does not decrypt with the loaded key although it names it: the file was altered or damaged", what)}
	case errors.Is(err, statekey.ErrNotEncrypted), errors.Is(err, statekey.ErrUnsupported):
		return &StartError{Code: CodeCorrupt, Msg: fmt.Sprintf("%s is not readable: %v", what, err)}
	}
	return &StartError{Code: CodeFailed, Msg: fmt.Sprintf("%s: %v", what, err)}
}

// start runs the start sequence of 4.3 and leaves the committed document in e.cur. It returns a
// *StartError when the server must not start.
func (e *engine[D]) start() *StartError {
	if err := e.removeTmp(); err != nil { // step 1
		return e.fail(CodeFailed, nil, "%s: %v", e.c.Dir, err)
	}
	what := e.c.Base
	cur, err := e.readDoc(e.path("")) // step 2
	fromNext := false
	switch {
	case errors.Is(err, fs.ErrNotExist):
		has, err := e.anyChange()
		if err != nil {
			return e.fail(CodeFailed, nil, "audit log: %v", err)
		}
		if has {
			return e.fail(CodeMissing, nil, "%s is missing but the audit log has changes to it; restore it from a backup, or run `rackbook accounts discard-store` if the key is lost", what)
		}
		d := e.c.New()
		d.meta().Change = newChangeID()
		if err := e.writeNew(d); err != nil {
			return e.fail(CodeFailed, nil, "%s: %v", what, err)
		}
		e.setCur(d)
		return e.finish()
	case err != nil:
		// a rekey that wrote its new files and then stopped: the new-key .next is the file
		var nerr error
		if errors.Is(err, statekey.ErrWrongKey) {
			cur, nerr = e.readDoc(e.path(".next"))
			fromNext = nerr == nil
		}
		if !fromNext {
			return keyErr(err, what)
		}
	}
	m := cur.meta()
	if se := e.checkAudit(cur); se != nil { // step 3
		return se
	}
	chs, err := e.changesFrom(m.AuditMonth, m.AuditSeq)
	if err != nil {
		return e.fail(CodeFailed, nil, "audit log: %v", err)
	}
	if m.AuditSeq > 0 && (len(chs) == 0 || chs[0].ev.Seq != m.AuditSeq || chs[0].id != m.Change) {
		return e.truncated(cur, "the audit log does not hold the store's last change (seq %d): it was rolled back or edited", m.AuditSeq)
	}
	var last *changeEvent
	if len(chs) > 0 {
		last = &chs[len(chs)-1]
	}
	ids := map[string]bool{}
	for _, c := range chs {
		ids[c.id] = true
	}

	// step 4: .next
	if _, err := os.Lstat(e.path(".next")); err == nil {
		nxt, nerr := cur, error(nil) // with fromNext, cur is the .next file already
		if !fromNext {
			nxt, nerr = e.readDoc(e.path(".next"))
		}
		switch {
		case nerr == nil && last != nil && nxt.meta().Change == last.id:
			if err := renameSync(e.path(".next"), e.path("")); err != nil {
				return e.fail(CodeFailed, nil, "%s: %v", what, err)
			}
			cur, m = nxt, nxt.meta()
		case fromNext:
			return keyErr(statekey.ErrWrongKey, what)
		default:
			if _, err := e.moveAside(".next"); err != nil {
				return e.fail(CodeFailed, nil, "%s: %v", what, err)
			}
		}
	} else if fromNext {
		return keyErr(statekey.ErrWrongKey, what)
	}

	// step 5: .pending
	if _, err := os.Lstat(e.path(".pending")); err == nil {
		pend, perr := e.readDoc(e.path(".pending"))
		storeHasE := last == nil || m.Change == last.id
		switch {
		case perr != nil:
			if _, err := e.moveAside(".pending"); err != nil {
				return e.fail(CodeFailed, nil, "%s: %v", what, err)
			}
		case last != nil && pend.meta().Change == last.id && !storeHasE:
			// a crash after the audit event and before the new store was in place: finish step 3
			pm := pend.meta()
			pm.AuditSeq, pm.AuditMonth = last.ev.Seq, last.month
			if err := e.writeNew(pend); err != nil {
				return e.fail(CodeFailed, nil, "%s: %v", what, err)
			}
			if _, err := e.c.Log.RecordSync(audit.Event{Event: "account_store_problem", Code: "recovered", Detail: []string{"store:" + e.c.Base, "change_seq:" + fmt.Sprint(last.ev.Seq)}}); err != nil {
				return e.fail(CodeFailed, nil, "audit log: %v", err)
			}
			cur, m = pend, pm
			e.recovered = true
			e.c.Logger.Warn("account store: recovered a change from its pending file", "store", e.c.Base, "seq", last.ev.Seq)
		case last != nil && pend.meta().Change == last.id:
			// the store has E already: a crash between the rename and the deletion
			if err := os.Remove(e.path(".pending")); err != nil {
				return e.fail(CodeFailed, nil, "%s: %v", what, err)
			}
		case !ids[pend.meta().Change] && !e.auditedAnywhere(pend.meta().Change):
			// never audited, never answered
			if err := os.Remove(e.path(".pending")); err != nil {
				return e.fail(CodeFailed, nil, "%s: %v", what, err)
			}
		default:
			if _, err := e.moveAside(".pending"); err != nil {
				return e.fail(CodeFailed, nil, "%s: %v", what, err)
			}
		}
	}

	// step 6: the gap check, always, after any rename
	if last != nil && m.Change != last.id {
		g := &Gap{StoreChange: m.Change, StoreSeq: m.AuditSeq}
		for _, c := range chs {
			if c.ev.Seq > m.AuditSeq {
				g.Events = append(g.Events, c.ev)
			}
		}
		return &StartError{Code: CodeGap, Doc: cur, Gap: g,
			Msg: fmt.Sprintf("the %s is older than the audit log (it lacks %d audited change(s)): run `rackbook accounts accept-restore`", what, len(g.Events))}
	}
	e.setCur(cur)
	return e.finish()
}

// checkAudit is step 3: the store's audit month must still exist, and its seq must be within the log.
func (e *engine[D]) checkAudit(cur D) *StartError {
	m := cur.meta()
	if m.AuditSeq == 0 {
		return nil
	}
	if head, _ := e.c.Log.Head(); m.AuditSeq > head {
		se := e.truncated(cur, "the audit log was rolled back or truncated: the store is at seq %d, the log ends at %d", m.AuditSeq, head)
		se.Detail = []string{fmt.Sprintf("store_seq:%d", m.AuditSeq), fmt.Sprintf("log_end:%d", head)}
		return se
	}
	if !e.c.Log.MonthExists(m.AuditMonth) {
		if first := e.c.Log.FirstMonth(); first != "" && first > m.AuditMonth {
			return &StartError{Code: CodeMonthPruned, Doc: cur,
				Msg: fmt.Sprintf("the audit month %s of the store was deleted by retention (the retention pin was bypassed): run `rackbook accounts accept-restore --reset-all-accounts`", m.AuditMonth)}
		}
		return e.truncated(cur, "the audit log was rolled back or truncated: the month file %s of the store's last change is gone", m.AuditMonth)
	}
	return nil
}

func (e *engine[D]) truncated(cur D, format string, a ...any) *StartError {
	head, _ := e.c.Log.Head()
	m := cur.meta()
	return &StartError{Code: CodeAuditTruncated, Doc: cur,
		Detail: []string{fmt.Sprintf("store_seq:%d", m.AuditSeq), fmt.Sprintf("log_end:%d", head)},
		Msg:    fmt.Sprintf(format, a...) + ": run `rackbook accounts accept-restore --accept-audit-truncation`"}
}

// finish is step 7: leftovers go.
func (e *engine[D]) finish() *StartError {
	for _, s := range []string{".pending", ".next"} {
		if err := os.Remove(e.path(s)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return e.fail(CodeFailed, nil, "%s: %v", e.c.Base, err)
		}
	}
	return nil
}

// writeNew writes d as the store file itself (a first store, a recovered one, a restore).
func (e *engine[D]) writeNew(d D) error {
	data, err := e.seal(d)
	if err != nil {
		return err
	}
	return writeFile(e.path(""), data)
}

// ---- writing

func (e *engine[D]) hook(step string) error {
	if e.c.Hook == nil {
		return nil
	}
	return e.c.Hook(step)
}

// commit is a change (4.3). The caller holds wmu.
//
// If the audit line is written but the log reports audit.ErrNotDurable (the close of the file, or the fsync of the
// directory of a new month file, failed), the line has its seq and the change is as good as audited: commit stops
// there, leaves .pending, refuses every later write (ErrStoreFailed) and answers with ErrAuditUnavailable, but the
// change MAY STILL COMPLETE at the next start, which finishes it from .pending ("recovered"). The caller must not
// tell the person the change failed for good. fn edits a copy of the committed state; prep
// may refuse it; ev is the audit event, to which the change id is added.
func (e *engine[D]) commit(ev audit.Event, fn func(D) error, prep func(cur, next D) error, after func(next D) error) (int64, error) {
	if e.failed != nil {
		return 0, e.failed
	}
	if !e.c.Events[ev.Event] {
		return 0, fmt.Errorf("%q is not a change event of %s", ev.Event, e.c.Base)
	}
	e.mu.RLock()
	cur := e.cur
	e.mu.RUnlock()
	next := e.clone(cur)
	if fn != nil {
		if err := fn(next); err != nil {
			return 0, err
		}
	}
	if prep != nil {
		if err := prep(cur, next); err != nil {
			return 0, err
		}
	}
	nm := next.meta()
	nm.Change = newChangeID()
	// 1. the new state goes to .pending
	data, err := e.seal(next)
	if err != nil {
		return 0, err
	}
	if err := writeFile(e.path(".pending"), data); err != nil {
		os.Remove(e.path(".pending"))
		return 0, err
	}
	if err := e.hook("pending"); err != nil {
		e.failed = err
		return 0, err
	}
	// 2. the audit event, with RecordSync; a failure changes nothing
	ev.Detail = append(slices.Clone(ev.Detail), e.c.Marker+nm.Change)
	seq, month, err := e.c.Log.RecordSyncMonth(ev)
	if errors.Is(err, audit.ErrNotDurable) {
		// the line is in the log and has its seq, so .pending stays: the next start finishes the change
		e.failed = fmt.Errorf("%w: %v", ErrStoreFailed, err)
		return seq, &auditError{err}
	}
	if err != nil {
		os.Remove(e.path(".pending"))
		return 0, &auditError{err}
	}
	if err := e.hook("event"); err != nil {
		e.failed = err
		return seq, err
	}
	// 3. the event's seq and month go into the state, which is encrypted once into .next and renamed over the store
	nm.AuditSeq, nm.AuditMonth = seq, month
	fail := func(err error) (int64, error) {
		e.failed = fmt.Errorf("%w: %v", ErrStoreFailed, err)
		return seq, e.failed
	}
	if after != nil {
		if err := after(next); err != nil {
			return fail(err)
		}
	}
	if data, err = e.seal(next); err != nil {
		return fail(err)
	}
	if err := writeFile(e.path(".next"), data); err != nil {
		return fail(err)
	}
	if err := e.hook("next"); err != nil {
		e.failed = err
		return seq, err
	}
	if err := renameSync(e.path(".next"), e.path("")); err != nil {
		return fail(err)
	}
	e.setCur(next)
	if err := e.hook("rename"); err != nil {
		e.failed = err
		return seq, err
	}
	if err := os.Remove(e.path(".pending")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		e.c.Logger.Warn("account store: could not delete the pending file; the next start does", "err", err)
	}
	return seq, nil
}

// counter writes the state again without a change: the change id and audit seq stay. ev, when
// not nil, is appended first with RecordSync (8.6).
func (e *engine[D]) counter(ev *audit.Event, fn func(D) error, check func(cur, next D, ev *audit.Event) error) error {
	if e.failed != nil {
		return e.failed
	}
	e.mu.RLock()
	cur := e.cur
	e.mu.RUnlock()
	next := e.clone(cur)
	if err := fn(next); err != nil {
		return err
	}
	*next.meta() = *cur.meta() // a counter never moves the change or the audit position
	if check != nil {
		if err := check(cur, next, ev); err != nil {
			return err
		}
	}
	if ev != nil {
		if _, _, err := e.c.Log.RecordSyncMonth(*ev); err != nil {
			return &auditError{err}
		}
	}
	data, err := e.seal(next)
	if err != nil {
		return err
	}
	if err := writeFile(e.path(""), data); err != nil {
		return err
	}
	e.setCur(next)
	return nil
}
