package gitstore

// The activity view (docs/design-audit.md, section 3.2) lists the commits of a
// repository with the trailers Rackbook writes, and shows what one commit
// changed. It reads with the same guarded git runner as everything else.

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

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
type ActivityQuery struct {
	// Since and Until bound the committer date, both inclusive (to the second).
	Since, Until time.Time
	// Collection limits to commits that touched the collection's file; with ID
	// to commits with exactly the trailer "Record: <collection>/<id>" (no
	// fallback to the file: a page of the timeline must not change meaning
	// when an older page has no such commit).
	Collection, ID string
	// IncludeState lists commits that touch .rackbook/ (passkeys, tokens). Without
	// it they are left out, as in History. Ignored for the infra repository.
	IncludeState bool
	Limit        int // at most MaxActivity, 50 when 0
}

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
}

const activityFormat = "--format=%x1d%H%x1f%h%x1f%an%x1f%ae%x1f%cI%x1f%s" +
	"%x1f%(trailers:key=Edited-by,valueonly,separator=%x1e)" +
	"%x1f%(trailers:key=Edited-via,valueonly,separator=%x1e)" +
	"%x1f%(trailers:key=Record,valueonly,separator=%x1e)"

func gitDate(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// activityLog lists commits reachable from tip. paths are the pathspecs after
// "--" (none = no limit). record, when set, keeps only commits with exactly
// that Record trailer (the limit then applies after the check, as in gitLog).
func activityLog(ctx context.Context, r *Repo, tip string, q ActivityQuery, paths []string, record string) ([]ActivityCommit, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	limit = min(limit, MaxActivity)
	args := []string{"log", activityFormat, "--date-order"}
	if !q.Since.IsZero() {
		args = append(args, "--since="+gitDate(q.Since))
	}
	if !q.Until.IsZero() {
		args = append(args, "--until="+gitDate(q.Until))
	}
	if record == "" {
		args = append(args, "-n", fmt.Sprint(limit))
	} else {
		// A substring prefilter; --fixed-strings keeps it literal whatever grep.patternType says.
		args = append(args, "--fixed-strings", "--grep=Record: "+record)
	}
	args = append(args, tip)
	if len(paths) > 0 {
		args = append(append(args, "--"), paths...)
	}
	out, err := r.git(ctx, args...)
	if err != nil {
		if strings.Contains(err.Error(), "does not have any commits") {
			return []ActivityCommit{}, nil
		}
		return nil, err
	}
	commits := []ActivityCommit{}
	for _, rec := range strings.Split(out, "\x1d") {
		f := strings.Split(rec, "\x1f")
		if len(f) != 9 {
			continue
		}
		c := ActivityCommit{Hash: strings.TrimSpace(f[0]), Short: f[1], Author: f[2], Email: f[3], Subject: f[5],
			EditedBy: firstValue(f[6]), EditedVia: firstValue(f[7]), State: StateNone}
		for _, v := range strings.Split(f[8], "\x1e") {
			if v = strings.TrimSpace(v); v != "" {
				c.Records = append(c.Records, v)
			}
		}
		if record != "" && !contains(c.Records, record) {
			continue
		}
		t, err := time.Parse(time.RFC3339, f[4])
		if err != nil {
			continue
		}
		c.Time = t.UTC()
		commits = append(commits, c)
		if len(commits) == limit {
			break
		}
	}
	return commits, nil
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

// markState sets State on commits: which of them touch .rackbook/, which touch
// anything else. It asks git twice for the window of the page (path-limited
// logs are cheap), not once per commit.
func (s *Store) markState(ctx context.Context, tip string, commits []ActivityCommit) error {
	if len(commits) == 0 {
		return nil
	}
	lo, hi := commits[0].Time, commits[0].Time
	for _, c := range commits {
		if c.Time.Before(lo) {
			lo = c.Time
		}
		if c.Time.After(hi) {
			hi = c.Time
		}
	}
	hashes := func(paths ...string) (map[string]bool, error) {
		args := []string{"log", "--format=%H", "--date-order", "--since=" + gitDate(lo), "--until=" + gitDate(hi), tip, "--"}
		out, err := s.repo.git(ctx, append(args, paths...)...)
		if err != nil {
			return nil, err
		}
		set := map[string]bool{}
		for _, h := range strings.Fields(out) {
			set[h] = true
		}
		return set, nil
	}
	state, err := hashes(config.StateDir)
	if err != nil {
		return err
	}
	other, err := hashes(".", ":(exclude)"+config.StateDir)
	if err != nil {
		return err
	}
	for i := range commits {
		h := commits[i].Hash
		switch {
		case state[h] && other[h]:
			commits[i].State = StateSome
		case state[h]:
			commits[i].State = StateOnly
		}
	}
	return nil
}

// Activity lists the commits of the tracked branch, newest committer date
// first (--date-order; ties in git's order). A repository without Git, or
// without commits, has none.
func (s *Store) Activity(ctx context.Context, q ActivityQuery) ([]ActivityCommit, error) {
	if !s.git {
		return []ActivityCommit{}, nil
	}
	tip, ok := s.trackedTip(ctx)
	if !ok {
		return []ActivityCommit{}, nil
	}
	if q.ID != "" && q.Collection == "" {
		return nil, errors.New("id needs a collection")
	}
	var paths []string
	record := ""
	if q.Collection != "" {
		c := s.cur.Load().Collection(q.Collection)
		if c == nil {
			return nil, fmt.Errorf("unknown collection %q", q.Collection)
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
	commits, err := activityLog(ctx, s.repo, tip, q, paths, record)
	if err != nil {
		return nil, err
	}
	if q.IncludeState {
		if err := s.markState(ctx, tip, commits); err != nil {
			return nil, err
		}
	}
	return commits, nil
}

// Activity lists the newest commits of the followed branch (the work tree is
// reset to it), as Store.Activity does. The mirror has no state directory.
func (m *Mirror) Activity(ctx context.Context, q ActivityQuery) ([]ActivityCommit, error) {
	r, err := m.check(ctx)
	if err != nil {
		return nil, err
	}
	return activityLog(ctx, r, "HEAD", q, nil, "")
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
// what the commit changed under the directory the repo runs in. paths are
// relative to the repository root; prefix is what to strip to show them
// relative to that directory.
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
	budget := MaxDiffBytes
	for i := 0; i+1 < len(f); i += 2 {
		root := f[i+1]
		rel := strings.TrimPrefix(root, prefix)
		if o.Include != nil && !o.Include(rel) {
			continue
		}
		if len(d.Files) >= MaxDiffFiles {
			d.MoreFiles = true
			break
		}
		fd := FileDiff{Status: f[i], Path: rel}
		if o.HidePatch != nil && o.HidePatch(rel) {
			fd.Hidden = true
			d.Files = append(d.Files, fd)
			continue
		}
		patch, err := r.runRaw(ctx, nil, "", "diff-tree", "--patch", "--no-ext-diff", "--no-color", "--no-commit-id", "-r", "--root", "--no-renames", full, "--", ":(top,literal)"+root)
		if err != nil {
			return nil, err
		}
		if o.Redact != nil {
			patch = o.Redact(patch)
		}
		switch {
		case budget <= 0:
			fd.Truncated = true
		case len(patch) > budget:
			fd.Patch, fd.Truncated = cutUTF8(patch, budget), true
			budget = 0
		default:
			fd.Patch = patch
			budget -= len(patch)
		}
		d.Files = append(d.Files, fd)
	}
	return d, nil
}

// cutUTF8 keeps at most n bytes of s, not ending inside a character.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
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
