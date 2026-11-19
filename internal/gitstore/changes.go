package gitstore

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrNoCommit is matched by errors.Is when a revision does not name a commit.
var ErrNoCommit = errors.New("no such commit")

var revRe = regexp.MustCompile(`^[0-9a-fA-F]{4,64}$`)

// FileVersions is one file a commit changed, as it was before and after.
// A nil side means the file did not exist there.
type FileVersions struct {
	Path          string // relative to the data directory
	Before, After []byte
}

// CommitDetail is a commit and the collection files it changed.
type CommitDetail struct {
	Commit Commit
	Files  []FileVersions
}

// CommitChanges reads what the commit rev (an abbreviated or full hash) changed
// in the collections' data files. For a merge commit it compares against the
// first parent. Rackbook's own state files are left out, as in History.
func (s *Store) CommitChanges(ctx context.Context, rev string) (*CommitDetail, error) {
	if !s.git {
		return nil, errors.New("history needs the data directory to be a repository")
	}
	notFound := fmt.Errorf("%w: %s", ErrNoCommit, rev) // one error for every refusal, so it is no oracle
	if !revRe.MatchString(rev) {
		return nil, notFound
	}
	// Resolve against the repository (an ambiguous abbreviation fails), then
	// accept only a commit on the tracked branch's accepted history (trackedTip,
	// not the checkout's HEAD): pull request commits, discarded or left behind
	// at HEAD, and commits dropped by an accepted history rewrite are not on it.
	// It reads refs and objects only, so it never waits for the write lock.
	tip, ok := s.trackedTip(ctx)
	if !ok {
		return nil, notFound
	}
	full, err := s.repo.git(ctx, "rev-parse", "--verify", "--quiet", rev+"^{commit}")
	if err != nil || full == "" {
		return nil, notFound
	}
	if _, err := s.repo.git(ctx, "merge-base", "--is-ancestor", full, tip); err != nil {
		return nil, notFound
	}
	commits, err := s.gitLog(ctx, full, 1, "")
	if err != nil {
		return nil, err
	}
	// The log shows the newest ledger commit at or before full; it must be full
	// itself, or the commit touched no ledger file (a state-only commit).
	if len(commits) != 1 || !strings.HasPrefix(full, commits[0].Hash) {
		return nil, notFound
	}
	d := &CommitDetail{Commit: commits[0]}
	parent := ""
	if p, err := s.repo.git(ctx, "rev-parse", "--verify", "--quiet", full+"^"); err == nil {
		parent = p
	}
	// Only the collections' data files are compared: that is what a record diff
	// is made of, and it needs nothing beyond reading two blobs.
	seen := map[string]bool{}
	for _, c := range s.cur.Load().Collections {
		if seen[c.File] {
			continue
		}
		seen[c.File] = true
		f := FileVersions{Path: c.File}
		if parent != "" {
			if b, err := s.repo.git(ctx, "cat-file", "blob", parent+":./"+c.File); err == nil {
				f.Before = []byte(b)
			}
		}
		if b, err := s.repo.git(ctx, "cat-file", "blob", full+":./"+c.File); err == nil {
			f.After = []byte(b)
		}
		if string(f.Before) != string(f.After) || (f.Before == nil) != (f.After == nil) {
			d.Files = append(d.Files, f)
		}
	}
	return d, nil
}
