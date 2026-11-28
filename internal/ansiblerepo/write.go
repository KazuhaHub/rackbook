package ansiblerepo

// The write path: one edit is one commit on the followed branch, pushed with
// the plain fast-forward push of gitstore (never forced). Rackbook has no
// pull-request step and CI does not gate the branch, so everything that could
// break a deploy is checked here, before the commit (validate.go).
//
// Conflicts. Every edit carries the object ID of each file as the editor saw
// it (Base). The clone is fetched and reset to the remote branch first; a file
// whose current ID is not its Base was changed by somebody else, and the edit is
// refused with a diff (ConflictError). When only the push fails because the
// branch moved, the edit is replayed on the new tip, up to three times; the
// same check runs again each time, so a replay happens only when none of the
// files it touches changed.

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/gitstore"
)

// maxAttempts is how often an edit is replayed on a moved branch.
const maxAttempts = 3

// Errors of the write path.
var (
	// ErrReadOnly: the repository has no write credential.
	ErrReadOnly = errors.New("the infra repository is read-only here")
	// ErrNoChange: the edit would not change any file.
	ErrNoChange = errors.New("nothing changed")
	// ErrBusy: the branch moved on every attempt.
	ErrBusy = errors.New("the branch kept moving; try again")
	// ErrNoAuthor: the person has no identity to put on a commit.
	ErrNoAuthor = errors.New("no identity for the commit author")
)

// ConflictError: a file changed upstream since the editor loaded it, or the
// revert was refused because later commits touched the same files.
type ConflictError struct {
	Reason string     // "changed" or "later_commits"
	Files  []string   // the files concerned
	Later  []string   // later_commits: those commits
	Diffs  []FileDiff // what the edit would have changed against the current files
}

func (e *ConflictError) Error() string {
	if e.Reason == "later_commits" {
		return "later commits touched the same files: " + strings.Join(e.Later, ", ")
	}
	return "changed since it was loaded: " + strings.Join(e.Files, ", ")
}

// ValidationError: the checks found problems.
type ValidationError struct{ Issues []Issue }

func (e *ValidationError) Error() string {
	for _, i := range e.Issues {
		if i.Severity != SevWarning {
			return "the checks refused the edit: " + i.Message
		}
	}
	return "the checks refused the edit"
}

// FileEdit is a change to one file.
type FileEdit struct {
	Path string
	// Base is the object ID of the file the editor saw ("" = it did not exist).
	Base string
	// Make returns the new content from the current one (nil = it does not exist).
	Make func(cur []byte) ([]byte, error)
}

// Edit is one change, one commit.
type Edit struct {
	// Scope names the subject: "infra(<Scope>): <Action>", e.g. host_vars/alpha.
	Scope, Action string
	Who           *auth.Identity
	Files         []FileEdit
	// ConfirmSecretScan lets findings that may be false positives through.
	ConfirmSecretScan bool
}

// Outcome is what an edit did or would do.
type Outcome struct {
	Commit  string     `json:"commit,omitempty"` // empty for a preview
	Diffs   []FileDiff `json:"diffs"`
	Issues  []Issue    `json:"issues"`  // errors, confirmations and warnings
	Blocked bool       `json:"blocked"` // a preview only: the checks would refuse it
}

// editable says which files the editors may write.
func editable(p string) bool {
	if p == inventoryFile {
		return true
	}
	dir, name := path.Split(p)
	dir = strings.TrimSuffix(dir, "/")
	// group_vars are not editable: they legitimately hold templating and
	// connection variables, which the checks for edited files refuse
	return dir == hostVarsDir && isYAMLName(name) && hostNameRe.MatchString(strings.TrimSuffix(strings.TrimSuffix(name, ".yml"), ".yaml"))
}

// CanWrite reports whether edits can be committed.
func (r *Repo) CanWrite() bool { return r.mirror.CanWrite() }

// plan is a computed edit, ready to validate and commit.
type plan struct {
	scope, action string
	files         map[string][]byte // new content; nil = removed
	extra         []string          // trailers
	confirm       bool
}

// planner computes a plan against the work tree it is given (reset to the branch tip).
type planner func(ctx context.Context) (*plan, error)

func filesOf(p *plan) []string {
	out := make([]string, 0, len(p.files))
	for f := range p.files {
		out = append(out, f)
	}
	sortStrings(out)
	return out
}

func (p *plan) subject() string {
	return "infra(" + p.scope + "): " + p.action
}

// Apply previews (preview) or commits an edit.
func (r *Repo) Apply(ctx context.Context, e Edit, preview bool) (*Outcome, error) {
	pl := func(ctx context.Context) (*plan, error) { return r.planEdit(ctx, e) }
	return r.run(ctx, e.Who, e.Scope, e.Action, e.ConfirmSecretScan, preview, pl)
}

// Revert restores the files a commit touched to their state before it, as a new commit.
func (r *Repo) Revert(ctx context.Context, commit string, who *auth.Identity, preview bool) (*Outcome, error) {
	pl := func(ctx context.Context) (*plan, error) { return r.planRevert(ctx, commit) }
	return r.run(ctx, who, "revert", "revert "+shortRev(commit), false, preview, pl)
}

func shortRev(h string) string {
	if len(h) > 7 {
		return h[:7]
	}
	return h
}

func (r *Repo) record(who *auth.Identity, p *plan, scope, action, outcome string, files, detail []string) {
	if r.o.Audit == nil {
		return
	}
	id, via := "", ""
	if who != nil {
		id, via = who.ID, who.InfraVia
	}
	act := "infra(" + scope + "): " + action
	if p != nil {
		act = p.subject()
		if files == nil {
			files = filesOf(p)
		}
	}
	r.o.Audit.Record(AuditEntry{Time: r.o.Now().UTC(), Who: id, Action: act, Outcome: outcome, Files: files, Detail: detail, Via: via})
}

func issueCodes(is []Issue) []string {
	var out []string
	for _, i := range is {
		if i.Severity != SevWarning {
			out = append(out, i.Code)
		}
	}
	return out
}

// run is the common flow of every edit.
func (r *Repo) run(ctx context.Context, who *auth.Identity, scope, action string, confirm, preview bool, pl planner) (*Outcome, error) {
	if !r.CanWrite() {
		return nil, ErrReadOnly
	}
	if preview {
		r.mu.RLock()
		defer r.mu.RUnlock()
		p, err := pl(ctx)
		if err != nil {
			return nil, err
		}
		p.confirm = confirm
		out := r.evaluate(p)
		out.Blocked = len(blocking(out.Issues, confirm)) > 0
		return out, nil
	}
	if gitstore.AuthorOf(who).IsZero() {
		return nil, ErrNoAuthor
	}
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		out, retry, err := r.attempt(ctx, who, scope, action, confirm, pl)
		if !retry {
			return out, err
		}
	}
	r.record(who, nil, scope, action, "busy", nil, nil)
	return nil, ErrBusy
}

// attempt fetches, resets to the branch tip, computes the plan, checks it and
// commits and pushes it. retry is true when only the push failed because the
// branch moved.
func (r *Repo) attempt(ctx context.Context, who *auth.Identity, scope, action string, confirm bool, pl planner) (out *Outcome, retry bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.mirror.FetchForWrite(ctx); err != nil {
		return nil, false, fmt.Errorf("fetching the repository: %w", err)
	}
	head, err := r.mirror.Checkout(ctx)
	if err != nil {
		return nil, false, err
	}
	r.head, r.syncedAt, r.syncErr = head, r.o.Now(), ""

	p, err := pl(ctx)
	if err != nil {
		var ce *ConflictError
		switch {
		case errors.As(err, &ce):
			r.record(who, nil, scope, action, "conflict", ce.Files, ce.Later)
		case errors.Is(err, ErrNoChange):
			r.record(who, nil, scope, action, "no_change", nil, nil)
		default:
			var ref *RefusedError
			var ee *EditError
			if errors.As(err, &ref) {
				r.record(who, nil, scope, action, "revert_refused", ref.Files, []string{ref.Code})
			} else if errors.As(err, &ee) {
				r.record(who, nil, scope, action, "edit_failed", nil, nil)
			}
		}
		return nil, false, err
	}
	p.confirm = confirm
	res := r.evaluate(p)
	if bl := blocking(res.Issues, confirm); len(bl) > 0 {
		r.record(who, p, "", "", "validation_failed", nil, issueCodes(bl))
		return nil, false, &ValidationError{Issues: res.Issues}
	}
	extra := append([]string{"Files: " + strings.Join(filesOf(p), ", ")}, p.extra...)
	if confirm && hasConfirm(res.Issues) {
		extra = append(extra, "Secret-scan: confirmed-not-secret")
	}
	msg := gitstore.CommitMessage(p.subject(), who, "rackbook", "", extra...)
	author := gitstore.AuthorOf(who)
	committer := r.o.Committer
	if committer.IsZero() {
		committer = gitstore.DefaultCommitter
	}
	hash, err := r.mirror.CommitChanges(ctx, p.files, msg, author, committer)
	if err != nil {
		_, _ = r.mirror.Checkout(ctx)
		return nil, false, err
	}
	if err := r.mirror.PushCommits(ctx); err != nil {
		_, _ = r.mirror.Checkout(ctx) // drop our commit: the branch is the remote's
		if gitstore.IsPushRejected(err) {
			return nil, true, nil
		}
		r.record(who, p, "", "", "push_failed", nil, nil)
		return nil, false, fmt.Errorf("pushing the commit: %w", err)
	}
	r.head, r.syncedAt = hash, r.o.Now()
	res.Commit = hash
	if r.o.OnCommit != nil {
		r.o.OnCommit(hash, who, scope)
	}
	return res, false, nil
}

func hasConfirm(is []Issue) bool {
	for _, i := range is {
		if i.Severity == SevConfirm {
			return true
		}
	}
	return false
}

// evaluate diffs the plan against the work tree and runs the checks on the
// tree as it would be. The caller holds the lock.
func (r *Repo) evaluate(p *plan) *Outcome {
	cur := dirTree{r}
	out := &Outcome{Diffs: []FileDiff{}}
	for _, f := range filesOf(p) {
		before, _ := cur.Read(f)
		if isSecretsPath(f) {
			out.Diffs = append(out.Diffs, secretsDiff(f, before, p.files[f]))
		} else {
			out.Diffs = append(out.Diffs, unifiedDiff(f, before, p.files[f]))
		}
	}
	before := Validate(cur, r.o.Rules, r.o.Scanner)
	after := Validate(overlay{cur, p.files}, r.o.Rules, r.o.Scanner)
	out.Issues = newIssues(before, after)
	// What is being written must pass every check, whatever state the file was in:
	// an old problem in a file this edit rewrites is not a warning.
	for i := range out.Issues {
		if _, touched := p.files[out.Issues[i].File]; touched {
			for _, a := range after {
				if a.key() == out.Issues[i].key() {
					out.Issues[i].Severity = a.Severity
				}
			}
		}
	}
	// A SOPS file is not scanned for plaintext secrets (every value of it is
	// ciphertext); it must instead be fully encrypted for the right recipients.
	after2 := overlay{cur, p.files}
	for _, f := range filesOf(p) {
		if isSecretsPath(f) && p.files[f] != nil {
			out.Issues = append(out.Issues, secretsFileIssues(after2, f, p.files[f])...)
		}
	}
	return out
}

// planEdit computes the plan of an Edit against the current tree.
func (r *Repo) planEdit(ctx context.Context, e Edit) (*plan, error) {
	if len(e.Files) == 0 {
		return nil, ErrNoChange
	}
	p := &plan{scope: e.Scope, action: e.Action, files: map[string][]byte{}}
	var stale []string
	var diffs []FileDiff
	cur := dirTree{r}
	for _, f := range e.Files {
		if !editable(f.Path) && !isSecretsPath(f.Path) {
			return nil, fmt.Errorf("%s is not a file the editors may change", f.Path)
		}
		blob, err := r.mirror.BlobID(ctx, "HEAD", f.Path)
		if err != nil {
			return nil, err
		}
		old, _ := cur.Read(f.Path)
		next, err := f.Make(old)
		if blob != f.Base {
			stale = append(stale, f.Path)
			if err == nil {
				diffs = append(diffs, unifiedDiff(f.Path, old, next))
			}
			continue
		}
		if err != nil {
			return nil, &EditError{Err: err}
		}
		if string(next) == string(old) && (next == nil) == (old == nil) {
			continue
		}
		p.files[f.Path] = next
	}
	if len(stale) > 0 {
		return nil, &ConflictError{Reason: "changed", Files: stale, Diffs: diffs}
	}
	if len(p.files) == 0 {
		return nil, ErrNoChange
	}
	return p, nil
}

// planRevert computes the plan that restores the files of commit to their state before it.
func (r *Repo) planRevert(ctx context.Context, commit string) (*plan, error) {
	if !gitstore.ValidRev(commit) {
		return nil, fmt.Errorf("not a commit: %q", commit)
	}
	rv, err := r.revertable(ctx, commit)
	if err != nil {
		return nil, err
	}
	p := &plan{scope: rv.scope, action: "revert " + shortRev(commit), files: map[string][]byte{}, extra: []string{"Reverts: " + commit}}
	if subj, err := r.mirror.Subject(ctx, commit); err == nil && subj != "" {
		p.action += " " + subj
		if r := []rune(p.action); len(r) > 120 {
			p.action = string(r[:120])
		}
	}
	cur := dirTree{r}
	for _, c := range rv.changes {
		var content []byte
		if c.Status != "A" {
			content, err = r.mirror.ShowFile(ctx, rv.parent, c.Path)
			if err != nil {
				return nil, err
			}
		}
		old, _ := cur.Read(c.Path)
		if HiddenIn(content) > 0 || HiddenIn(old) > 0 {
			return nil, &EditError{Err: errors.New(c.Path + " holds values that look like secrets and is not reverted here")}
		}
		if string(content) == string(old) && (content == nil) == (old == nil) {
			continue
		}
		p.files[c.Path] = content
	}
	if len(p.files) == 0 {
		return nil, ErrNoChange
	}
	return p, nil
}

type revertInfo struct {
	parent  string
	changes []gitstore.FileChange
	scope   string
}

// revertable checks that a commit can be reverted now: it is on the branch,
// has one parent, touched only files the editors own, and no later commit touched them.
func (r *Repo) revertable(ctx context.Context, commit string) (*revertInfo, error) {
	on, err := r.mirror.OnBranch(ctx, commit)
	if err != nil {
		return nil, err
	}
	if !on {
		return nil, &RefusedError{Code: "not_on_branch"}
	}
	parents, err := r.mirror.Parents(ctx, commit)
	if err != nil {
		return nil, err
	}
	switch len(parents) {
	case 0:
		return nil, &RefusedError{Code: "root"}
	case 1:
	default:
		return nil, &RefusedError{Code: "merge"}
	}
	changes, err := r.mirror.Touched(ctx, commit)
	if err != nil {
		return nil, err
	}
	if len(changes) == 0 {
		return nil, &RefusedError{Code: "empty"}
	}
	paths := make([]string, 0, len(changes))
	for _, c := range changes {
		if !editable(c.Path) {
			return nil, &RefusedError{Code: "not_editable", Files: []string{c.Path}}
		}
		paths = append(paths, c.Path)
	}
	later, err := r.mirror.ChangedSince(ctx, commit, paths)
	if err != nil {
		return nil, err
	}
	if len(later) > 0 {
		return nil, &ConflictError{Reason: "later_commits", Files: paths, Later: later}
	}
	scope := "revert"
	if len(paths) == 1 {
		scope = strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(paths[0], "inventory/"), ".yml"), ".yaml")
	}
	return &revertInfo{parent: parents[0], changes: changes, scope: scope}, nil
}

// RefusedError: the request cannot be done at all (not a conflict that retrying could clear).
type RefusedError struct {
	Code  string // not_on_branch, root, merge, empty, not_editable
	Files []string
}

func (e *RefusedError) Error() string { return "refused: " + e.Code }

// HistoryEntry is a commit of the log with what can be done to it.
type HistoryEntry struct {
	gitstore.MirrorCommit
	Files []string `json:"files"`
	// Revertible: the Revert button works now. Otherwise Reason says why:
	// merge, root, not_editable, later_commits (Later lists them) or empty.
	Revertible bool     `json:"revertible"`
	Reason     string   `json:"reason,omitempty"`
	Later      []string `json:"later,omitempty"`
}

// History returns the newest n commits with their files and whether each can be reverted.
func (r *Repo) History(ctx context.Context, n int) ([]HistoryEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	commits, err := r.mirror.Log(ctx, n)
	if err != nil {
		return nil, err
	}
	out := make([]HistoryEntry, 0, len(commits))
	for _, c := range commits {
		h := HistoryEntry{MirrorCommit: c, Files: []string{}}
		if ch, err := r.mirror.Touched(ctx, c.Hash); err == nil {
			for _, f := range ch {
				h.Files = append(h.Files, f.Path)
			}
		}
		if r.CanWrite() {
			_, err := r.revertable(ctx, c.Hash)
			var ref *RefusedError
			var ce *ConflictError
			switch {
			case err == nil:
				h.Revertible = true
			case errors.As(err, &ref):
				h.Reason = ref.Code
			case errors.As(err, &ce):
				h.Reason, h.Later = ce.Reason, ce.Later
			}
		}
		out = append(out, h)
	}
	return out, nil
}

// EditError: the editor's change could not be made to the file (it is not valid
// YAML, a setting is of the wrong kind, a group does not exist).
type EditError struct{ Err error }

func (e *EditError) Error() string { return e.Err.Error() }
func (e *EditError) Unwrap() error { return e.Err }
