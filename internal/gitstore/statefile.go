package gitstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/fsutil"
)

// StateResult is the outcome of MutateStateFile.
type StateResult struct {
	// Commit is the short commit hash, the pull request URL (PullRequest set),
	// or "" when the file did not change or there is no Git.
	Commit      string
	PullRequest bool
}

// StateOption adjusts MutateStateFile.
type StateOption func(*WriteOptions)

// Direct commits the change to the tracked branch even in write.mode pr, for
// state that has to work before a pull request could be merged (passkeys).
func Direct() StateOption { return func(o *WriteOptions) { o.Direct = true } }

// statePath resolves a state file inside .rackbook/ and refuses a symbolic link
// there: one in the data repo could point the write anywhere.
func (s *Store) statePath(rel string) (string, error) {
	clean := filepath.ToSlash(filepath.Clean(rel))
	if filepath.IsAbs(rel) || !config.IsStatePath(clean) || clean == config.StateDir {
		return "", fmt.Errorf("state file %q must be inside %s/", rel, config.StateDir)
	}
	abs := filepath.Join(s.cur.Load().Config.Dir, filepath.FromSlash(clean))
	for _, p := range []string{filepath.Dir(abs), abs} {
		if st, err := os.Lstat(p); err == nil && st.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("state path %q is a symbolic link", filepath.Base(p))
		}
	}
	return abs, nil
}

// MutateStateFile changes one of Rackbook's own state files (.rackbook/*.yml,
// like tokens.yml) through the same Git path as a record edit: sync to origin,
// apply, commit as who, push (replayed on a moved remote), or open a pull
// request in pr mode. mutate receives the file's current content (exists says
// whether it is there) and returns the new content; it runs again on a replay.
// Returning the same bytes, or an error, commits nothing. Without Git the file
// is written in place.
func (s *Store) MutateStateFile(ctx context.Context, rel, subject string, who *auth.Identity, mutate func(old []byte, exists bool) ([]byte, error), options ...StateOption) (*StateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	abs, err := s.statePath(rel)
	if err != nil {
		return nil, err
	}
	rel = filepath.ToSlash(filepath.Clean(rel))
	apply := func() (*change, error) {
		old, err := os.ReadFile(abs)
		exists := err == nil
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		nw, err := mutate(old, exists)
		if err != nil {
			return nil, err
		}
		if exists && bytes.Equal(old, nw) {
			return &change{}, nil
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return nil, err
		}
		tmp := abs + ".tmp"
		if err := os.WriteFile(tmp, nw, 0o644); err != nil {
			return nil, err
		}
		if err := fsutil.Rename(tmp, abs); err != nil {
			_ = os.Remove(tmp)
			return nil, err
		}
		return &change{Files: []string{rel}, Subject: subject}, nil
	}
	if !s.git {
		if _, err := apply(); err != nil {
			return nil, err
		}
		return &StateResult{}, nil
	}
	wo := WriteOptions{BranchPrefix: "rackbook/auth/" + Slug(who.IDOrEmpty())}
	for _, o := range options {
		o(&wo)
	}
	commit, pr, err := s.commitLoop(ctx, who, wo, apply)
	if err != nil {
		return nil, err
	}
	return &StateResult{Commit: commit, PullRequest: pr}, nil
}

// StateSettled reports that no write, pull or replay is in progress and the
// clone is at a loaded commit, so what StateFile reads is the committed truth
// (a file that is missing then really is not there).
func (s *Store) StateSettled() bool {
	if !s.mu.TryLock() {
		return false
	}
	defer s.mu.Unlock()
	return s.ConfigProblem() == "" && s.Alert() == nil
}

// StateFile reads a state file from the checkout ("" content and false when it
// does not exist).
func (s *Store) StateFile(rel string) ([]byte, bool, error) {
	abs, err := s.statePath(rel)
	if err != nil {
		return nil, false, err
	}
	b, err := os.ReadFile(abs)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return b, err == nil, err
}
