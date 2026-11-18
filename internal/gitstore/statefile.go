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
)

// StateResult is the outcome of MutateStateFile.
type StateResult struct {
	// Commit is the short commit hash, the pull request URL (PullRequest set),
	// or "" when the file did not change or there is no Git.
	Commit      string
	PullRequest bool
}

// MutateStateFile changes one of Rackbook's own state files (.rackbook/*.yml,
// like tokens.yml) through the same Git path as a record edit: sync to origin,
// apply, commit as who, push (replayed on a moved remote), or open a pull
// request in pr mode. mutate receives the file's current content (exists says
// whether it is there) and returns the new content; it runs again on a replay.
// Returning the same bytes, or an error, commits nothing. Without Git the file
// is written in place.
func (s *Store) MutateStateFile(ctx context.Context, rel, subject string, who *auth.Identity, mutate func(old []byte, exists bool) ([]byte, error)) (*StateResult, error) {
	rel = filepath.ToSlash(filepath.Clean(rel))
	if !config.IsStatePath(rel) || rel == config.StateDir {
		return nil, fmt.Errorf("%q is not a state file under %s/", rel, config.StateDir)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	apply := func() (*change, error) {
		abs := filepath.Join(s.cur.Load().Config.Dir, filepath.FromSlash(rel))
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
		if err := os.WriteFile(abs, nw, 0o644); err != nil {
			return nil, err
		}
		ch := &change{Files: []string{rel}, Subject: subject}
		if !exists {
			ch.Created = []string{abs}
		}
		return ch, nil
	}
	if !s.git {
		if _, err := apply(); err != nil {
			return nil, err
		}
		return &StateResult{}, nil
	}
	commit, pr, err := s.commitLoop(ctx, who, WriteOptions{BranchPrefix: "rackbook/auth/" + Slug(who.IDOrEmpty())}, apply)
	if err != nil {
		return nil, err
	}
	return &StateResult{Commit: commit, PullRequest: pr}, nil
}

// StateFile reads a state file from the checkout ("" content and false when it
// does not exist).
func (s *Store) StateFile(rel string) ([]byte, bool, error) {
	rel = filepath.ToSlash(filepath.Clean(rel))
	if !config.IsStatePath(rel) {
		return nil, false, fmt.Errorf("%q is not a state file", rel)
	}
	b, err := os.ReadFile(filepath.Join(s.Config().Dir, filepath.FromSlash(rel)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return b, err == nil, err
}
