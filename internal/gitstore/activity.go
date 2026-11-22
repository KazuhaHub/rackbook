package gitstore

// The activity view (docs/design-audit.md, section 3.2) lists the commits of a
// repository with the trailers Rackbook writes, and shows what one commit
// changed. It reads with the same guarded git runner as everything else.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/ledger"
)

// MaxActivity is the most commits one Activity call returns.
const MaxActivity = 1000

// How a commit relates to Rackbook's own state directory (.rackbook/).
const (
	StateNone = "none" // touches no file in it
	StateSome = "some" // touches it and ledger files
	StateOnly = "only" // touches nothing else
)

// ActivityQuery selects commits for Activity. Zero fields select everything.
// The caller pages by walk position: Tip pins the commit the walk starts from
// and Skip says how many commits of that walk it has already consumed. Time
// limits are not git options (git stops a time-limited walk at the first old
// commit, which loses commits whose dates are out of order); the caller filters
// on Time.
type ActivityQuery struct {
	// Collection limits to commits that touched the collection's file; with ID
	// to commits with exactly the trailer "Record: <collection>/<id>" (no
	// fallback to the file: a page of the timeline must not change meaning
	// when an older page has no such commit). Commits that git's text search
	// finds but whose trailer is not that exact value are returned with Excluded set.
	Collection, ID string
	// IncludeState lists commits that touch .rackbook/ (passkeys, tokens). Without
	// it they are left out, as in History. Ignored for the infra repository.
	IncludeState bool
	// Tip is the commit the walk is pinned to, as a previous page returned it
	// ("" = the current tip of the tracked branch). It must be on that branch.
	Tip   string
	Skip  int // commits of the walk already consumed
	Limit int // at most MaxActivity, 50 when 0
}

// ActivityPage is what Activity returns: Tip is what to pass on the next call.
type ActivityPage struct {
	Tip     string
	Commits []ActivityCommit
}

// ErrBadTip is returned for an ActivityQuery.Tip that is not a commit of the branch.
var ErrBadTip = errors.New("unusable walk position")

// ActivityCommit is one commit of the activity view.
type ActivityCommit struct {
	Hash      string    `json:"hash"`
	Short     string    `json:"short"`
	Author    string    `json:"author"`
	Email     string    `json:"email"`
	Time      time.Time `json:"time"` // committer date, UTC
	Subject   string    `json:"subject"`
	EditedBy  string    `json:"editedBy,omitempty"`
	EditedVia string    `json:"editedVia,omitempty"`
	Records   []string  `json:"records,omitempty"`
	State     string    `json:"state"` // StateNone, StateSome or StateOnly
	// Excluded: the commit is part of the walk (it counts for Skip) but does not
	// match the record filter exactly.
	Excluded bool `json:"-"`
}

const activityFormat = "--format=%x1d%H%x1f%h%x1f%an%x1f%ae%x1f%cI%x1f%s" +
	"%x1f%(trailers:key=Edited-by,valueonly,separator=%x1e)" +
	"%x1f%(trailers:key=Edited-via,valueonly,separator=%x1e)" +
	"%x1f%(trailers:key=Record,valueonly,separator=%x1e)%x1c"

// parseActivityRecord reads one record of activityFormat plus its file names.
func parseActivityRecord(rec, prefix, record string) (ActivityCommit, error) {
	head, names, ok := strings.Cut(rec, "\x1c")
	f := strings.Split(head, "\x1f")
	if !ok || len(f) != 9 {
		return ActivityCommit{}, errors.New("unreadable commit record")
	}
	c := ActivityCommit{Hash: strings.TrimSpace(f[0]), Short: f[1], Author: f[2], Email: f[3], Subject: f[5],
		EditedBy: firstValue(f[6]), EditedVia: firstValue(f[7]), State: StateNone}
	for _, v := range strings.Split(f[8], "\x1e") {
		if v = strings.TrimSpace(v); v != "" {
			c.Records = append(c.Records, v)
		}
	}
	if record != "" && !contains(c.Records, record) {
		c.Excluded = true
	}
	t, err := time.Parse(time.RFC3339, f[4])
	if err != nil {
		return ActivityCommit{}, fmt.Errorf("unreadable commit date %q", f[4])
	}
	c.Time = t.UTC()
	state, other := 0, 0
	for _, n := range strings.Split(names, "\n") {
		if n = strings.TrimSpace(n); n == "" {
			continue
		}
		if rel := strings.TrimPrefix(n, prefix); config.IsStatePath(rel) {
			state++
		} else {
			other++
		}
	}
	switch {
	case state > 0 && other > 0:
		c.State = StateSome
	case state > 0:
		c.State = StateOnly
	}
	return c, nil
}

// activityLog streams the commits of the walk from tip, after q.Skip of them, to
// each, with one git process that is killed as soon as each returns false (or
// after q.Limit commits when that is set). paths are the pathspecs after "--"
// (none = no limit). record, when set, is the exact Record trailer wanted; git's
// text search narrows the walk and the others are passed on Excluded.
func activityLog(ctx context.Context, r *Repo, tip string, q ActivityQuery, paths []string, record string, each func(ActivityCommit) bool) error {
	args := []string{"log", activityFormat, "--name-only", "--date-order"}
	if q.Skip > 0 {
		args = append(args, "--skip="+strconv.Itoa(q.Skip))
	}
	if q.Limit > 0 {
		args = append(args, "-n", strconv.Itoa(min(q.Limit, MaxActivity)))
	}
	if record != "" {
		// A substring prefilter; --fixed-strings keeps it literal whatever grep.patternType says.
		args = append(args, "--fixed-strings", "--grep=Record: "+record)
	}
	args = append(args, tip)
	if len(paths) > 0 {
		args = append(append(args, "--"), paths...)
	}
	prefix, err := r.git(ctx, "rev-parse", "--show-prefix")
	if err != nil {
		return err
	}
	var acc []byte
	var perr error
	stopped := false
	emit := func(rec []byte) bool {
		c, err := parseActivityRecord(string(rec), prefix, record)
		if err != nil {
			perr = err
			return false
		}
		if !each(c) {
			stopped = true
			return false
		}
		return true
	}
	err = r.runStream(ctx, func(chunk []byte) bool {
		acc = append(acc, chunk...)
		for {
			// records start with 0x1d: one is complete when the next one has begun
			i := bytes.IndexByte(acc, 0x1d)
			if i < 0 {
				return true
			}
			j := bytes.IndexByte(acc[i+1:], 0x1d)
			if j < 0 {
				acc = acc[i:]
				return true
			}
			rec := acc[i+1 : i+1+j]
			acc = acc[i+1+j:]
			if !emit(rec) {
				return false
			}
		}
	}, args...)
	if err != nil {
		if strings.Contains(err.Error(), "does not have any commits") {
			return nil
		}
		return err
	}
	if perr != nil {
		return perr
	}
	if !stopped {
		if i := bytes.IndexByte(acc, 0x1d); i >= 0 {
			emit(acc[i+1:])
			if perr != nil {
				return perr
			}
		}
	}
	return nil
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

func firstValue(s string) string {
	v, _, _ := strings.Cut(s, "\x1e")
	return strings.TrimSpace(v)
}

// pinnedTip resolves the tip a walk starts from: the branch's current tip when
// tip is empty, else the commit the caller was given, which must lead to it.
func pinnedTip(ctx context.Context, r *Repo, branchTip, tip string) (string, error) {
	if tip == "" {
		return branchTip, nil
	}
	if !ValidRev(tip) {
		return "", ErrBadTip
	}
	full, err := r.git(ctx, "rev-parse", "--verify", "--quiet", tip+"^{commit}")
	if err != nil || full == "" {
		return "", ErrBadTip
	}
	if _, err := r.git(ctx, "merge-base", "--is-ancestor", full, branchTip); err != nil {
		return "", ErrBadTip
	}
	return full, nil
}

// activityPlan resolves the query against the data repository: the commit the
// walk starts from, the pathspecs and the exact record wanted.
func (s *Store) activityPlan(ctx context.Context, q ActivityQuery) (tip string, paths []string, record string, ok bool, err error) {
	if !s.git {
		return "", nil, "", false, nil
	}
	branchTip, found := s.trackedTip(ctx)
	if !found {
		return "", nil, "", false, nil
	}
	if q.ID != "" && q.Collection == "" {
		return "", nil, "", false, errors.New("id needs a collection")
	}
	if tip, err = pinnedTip(ctx, s.repo, branchTip, q.Tip); err != nil {
		return "", nil, "", false, err
	}
	if q.Collection != "" {
		c := s.cur.Load().Collection(q.Collection)
		if c == nil {
			return "", nil, "", false, fmt.Errorf("unknown collection %q", q.Collection)
		}
		paths = []string{filepath.FromSlash(c.File)}
		if q.ID != "" {
			record = edit.RecordRef(q.Collection, ledger.SafeID(s.Config(), q.Collection, q.ID))
		}
	} else {
		paths = []string{"."}
		if !q.IncludeState {
			paths = append(paths, ":(exclude)"+config.StateDir)
		}
	}
	return tip, paths, record, true, nil
}

// ActivityWalk streams the commits of the tracked branch in git's --date-order
// walk (children before parents, by committer date otherwise) to each, from
// q.Tip after q.Skip commits, with one git process; each returns false to stop
// it. onStart is told the commit the walk is pinned to before the first commit.
// A repository without Git, or without commits, has none.
func (s *Store) ActivityWalk(ctx context.Context, q ActivityQuery, onStart func(tip string), each func(ActivityCommit) bool) error {
	tip, paths, record, ok, err := s.activityPlan(ctx, q)
	if err != nil || !ok {
		return err
	}
	onStart(tip)
	return activityLog(ctx, s.repo, tip, q, paths, record, each)
}

// Activity is ActivityWalk collected: the next q.Limit commits (50 when 0).
func (s *Store) Activity(ctx context.Context, q ActivityQuery) (ActivityPage, error) {
	return collectWalk(q, func(onStart func(string), each func(ActivityCommit) bool) error {
		return s.ActivityWalk(ctx, q, onStart, each)
	})
}

func collectWalk(q ActivityQuery, walk func(onStart func(string), each func(ActivityCommit) bool) error) (ActivityPage, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	limit = min(limit, MaxActivity)
	pg := ActivityPage{Commits: []ActivityCommit{}}
	err := walk(func(tip string) { pg.Tip = tip }, func(c ActivityCommit) bool {
		pg.Commits = append(pg.Commits, c)
		return len(pg.Commits) < limit
	})
	return pg, err
}

// ActivityWalk is Store.ActivityWalk for the followed branch (the work tree is
// reset to it). The mirror has no state directory.
func (m *Mirror) ActivityWalk(ctx context.Context, q ActivityQuery, onStart func(tip string), each func(ActivityCommit) bool) error {
	r, err := m.check(ctx)
	if err != nil {
		return err
	}
	head, err := r.Head(ctx)
	if err != nil {
		return err
	}
	tip, err := pinnedTip(ctx, r, head, q.Tip)
	if err != nil {
		return err
	}
	onStart(tip)
	return activityLog(ctx, r, tip, q, nil, "", each)
}

// Activity is ActivityWalk collected.
func (m *Mirror) Activity(ctx context.Context, q ActivityQuery) (ActivityPage, error) {
	return collectWalk(q, func(onStart func(string), each func(ActivityCommit) bool) error {
		return m.ActivityWalk(ctx, q, onStart, each)
	})
}

// Diff limits.
const (
	MaxDiffBytes = 256 << 10 // the patches of one commit, together
	MaxDiffFiles = 200       // files listed with a patch
)

// FileDiff is one file of a commit diff. Patch is the unified diff of that
// file (empty when omitted); Truncated says it was cut to fit the limit.
type FileDiff struct {
	Status    string `json:"status"` // A, M, D, T (as git prints it)
	Path      string `json:"path"`
	Patch     string `json:"patch,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	// Hidden says the file's patch is left out on purpose (see the caller).
	Hidden bool `json:"hidden,omitempty"`
}

// CommitDiff is what one commit changed.
type CommitDiff struct {
	Hash  string     `json:"hash"`
	Files []FileDiff `json:"files"`
	// MoreFiles says the commit changed more files than MaxDiffFiles.
	MoreFiles bool `json:"moreFiles,omitempty"`
}

var diffHashRe = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// DiffOptions tell CommitDiff how to treat the files of a commit.
type DiffOptions struct {
	// Include drops the files for which it returns false (nil = all).
	Include func(path string) bool
	// HidePatch lists the files whose patch is left out; the file stays listed
	// as changed, with Hidden set (nil = none).
	HidePatch func(path string) bool
	// Redact rewrites a patch before it is returned (nil = as it is).
	Redact func(patch string) string
}

// diffCommit resolves hash on repo (it must be reachable from tip) and lists
// what the commit changed under the directory the repo runs in. The patches are
// read from one git process whose output is cut at MaxDiffBytes: past that the
// process is killed and the files not read in full are marked Truncated.
func diffCommit(ctx context.Context, r *Repo, tip, hash string, o DiffOptions) (*CommitDiff, error) {
	notFound := fmt.Errorf("%w: %s", ErrNoCommit, hash)
	if !diffHashRe.MatchString(hash) {
		return nil, notFound
	}
	full, err := r.git(ctx, "rev-parse", "--verify", "--quiet", hash+"^{commit}")
	if err != nil || full == "" {
		return nil, notFound
	}
	if _, err := r.git(ctx, "merge-base", "--is-ancestor", full, tip); err != nil {
		return nil, notFound
	}
	prefix, err := r.git(ctx, "rev-parse", "--show-prefix")
	if err != nil {
		return nil, err
	}
	out, err := r.runRaw(ctx, nil, "", "diff-tree", "--no-commit-id", "--name-status", "-r", "-z", "--root", "--no-renames", full, "--", ".")
	if err != nil {
		return nil, err
	}
	f := strings.Split(strings.TrimRight(out, "\x00"), "\x00")
	d := &CommitDiff{Hash: full, Files: []FileDiff{}}
	// the files to read patches of: only they are named, so the arguments stay
	// bounded by MaxDiffFiles however many files the commit changed
	var spec []string
	shown := map[string]int{} // path from the repository root -> index into d.Files
	for i := 0; i+1 < len(f); i += 2 {
		root := f[i+1]
		rel := strings.TrimPrefix(root, prefix)
		if o.Include != nil && !o.Include(rel) {
			continue
		}
		if len(d.Files) >= MaxDiffFiles {
			d.MoreFiles = true
			continue
		}
		fd := FileDiff{Status: f[i], Path: rel}
		if o.HidePatch != nil && o.HidePatch(rel) {
			fd.Hidden = true
		} else {
			shown[root] = len(d.Files)
			spec = append(spec, ":(top,literal)"+root)
		}
		d.Files = append(d.Files, fd)
	}
	if len(spec) == 0 {
		return d, nil
	}
	args := append([]string{"diff-tree", "--patch", "--no-ext-diff", "--no-color", "--no-commit-id", "-r", "--root", "--no-renames", full, "--"}, spec...)
	patch, cut, err := r.runLimited(ctx, MaxDiffBytes, args...)
	if err != nil {
		return nil, err
	}
	// Each section belongs to the file named in its own header (a type change
	// has two sections for one file). A section of no listed file is dropped.
	secs := splitPatch(patch)
	got := map[int]*strings.Builder{}
	last := -1
	for k, sec := range secs {
		i, ok := shown[sectionPath(sec)]
		if !ok {
			continue
		}
		if got[i] == nil {
			got[i] = &strings.Builder{}
		}
		got[i].WriteString(sec)
		if k == len(secs)-1 {
			last = i
		}
	}
	for _, i := range shown {
		fd := &d.Files[i]
		b := got[i]
		if b == nil {
			fd.Truncated = cut // never reached: the output ended first
			continue
		}
		p := b.String()
		if cut && i == last {
			fd.Truncated = true
			p = trimPartialRune(p)
		}
		p = StripHunkContext(p)
		if o.Redact != nil {
			p = o.Redact(p)
		}
		fd.Patch = p
	}
	return d, nil
}

// splitPatch cuts the output of diff-tree --patch into the patches of single files.
func splitPatch(patch string) []string {
	var out []string
	for len(patch) > 0 {
		i := strings.Index(patch, "\ndiff --git ")
		if i < 0 {
			out = append(out, patch)
			break
		}
		out = append(out, patch[:i+1])
		patch = patch[i+1:]
	}
	return out
}

// sectionPath is the path in the "diff --git a/P b/P" line of a section (the
// diff has no renames, so both sides name the same file); "" when it cannot be read.
func sectionPath(sec string) string {
	line, _, _ := strings.Cut(sec, "\n")
	rest, ok := strings.CutPrefix(line, "diff --git ")
	if !ok {
		return ""
	}
	if strings.HasPrefix(rest, `"`) { // a name git quotes (a quote, backslash or control character)
		q, err := strconv.QuotedPrefix(rest)
		if err != nil {
			return ""
		}
		name, err := strconv.Unquote(q)
		if err != nil {
			return ""
		}
		return strings.TrimPrefix(name, "a/")
	}
	n := (len(rest) - len("a/ b/")) / 2
	if n <= 0 || rest != "a/"+rest[2:2+n]+" b/"+rest[2:2+n] {
		return ""
	}
	return rest[2 : 2+n]
}

// StripHunkContext rewrites every hunk header of a unified diff down to
// "@@ -a,b +c,d @@". Git adds the nearest line above the hunk that looks like a
// function (for YAML, a top-level key and its value) after the second "@@";
// that line is not part of the change and can be a secret.
func StripHunkContext(patch string) string {
	if !strings.Contains(patch, "@@") {
		return patch
	}
	lines := strings.Split(patch, "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, "@@ ") {
			continue
		}
		if j := strings.Index(l[2:], "@@"); j >= 0 {
			lines[i] = l[:2+j+2]
		} else {
			lines[i] = "@@" // a header cut short by the limit
		}
	}
	return strings.Join(lines, "\n")
}

// trimPartialRune drops a character the output limit cut in two from the end of s.
func trimPartialRune(s string) string {
	for i := 1; i <= utf8.UTFMax-1 && i <= len(s); i++ {
		if utf8.RuneStart(s[len(s)-i]) {
			if !utf8.FullRuneInString(s[len(s)-i:]) {
				return s[:len(s)-i]
			}
			break
		}
	}
	return s
}

// CommitDiff returns what a commit of the tracked branch changed in the data
// directory. A commit that is not on the tracked branch's accepted history, or
// changed nothing the caller may see, is ErrNoCommit (one error for every
// refusal, so it is no oracle). Without includeState the files under .rackbook/
// are dropped, and a commit that touches only them does not exist.
func (s *Store) CommitDiff(ctx context.Context, hash string, includeState bool) (*CommitDiff, error) {
	if !s.git {
		return nil, errors.New("history needs the data directory to be a repository")
	}
	notFound := fmt.Errorf("%w: %s", ErrNoCommit, hash)
	tip, ok := s.trackedTip(ctx)
	if !ok {
		return nil, notFound
	}
	d, err := diffCommit(ctx, s.repo, tip, hash, DiffOptions{Include: func(p string) bool {
		return includeState || !config.IsStatePath(p)
	}})
	if err != nil {
		return nil, err
	}
	if len(d.Files) == 0 {
		// A commit of state files only (for a caller who may not see them), or one
		// that changed nothing in the data directory: it is not in the activity list.
		return nil, notFound
	}
	return d, nil
}

// CommitDiff is the diff of a commit of the followed branch; opts decides
// which files are shown and how (the infra view hides secrets).
func (m *Mirror) CommitDiff(ctx context.Context, hash string, opts DiffOptions) (*CommitDiff, error) {
	r, err := m.check(ctx)
	if err != nil {
		return nil, err
	}
	return diffCommit(ctx, r, "HEAD", hash, opts)
}
