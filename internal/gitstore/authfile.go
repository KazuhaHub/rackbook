package gitstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
)

// State files (.rackbook/passkeys.yml) are not ledger data: they have no
// collection, no schema and no pull request. UpdateStateFile commits them
// straight to the tracked branch, through the same sync, commit, push and
// replay steps as Write, whatever write.mode says (a passkey that only exists
// after a merge could not be used to log in).

// ReadStateFile returns the content of a state file in the work tree, or
// (nil, nil) when it does not exist. rel is relative to the config directory
// and must be inside .rackbook/.
func (s *Store) ReadStateFile(rel string) ([]byte, error) {
	abs, err := s.statePath(rel)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(abs)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

func (s *Store) statePath(rel string) (string, error) {
	clean := filepath.ToSlash(filepath.Clean(rel))
	if filepath.IsAbs(rel) || clean == config.StateDir || len(clean) <= len(config.StateDir)+1 || clean[:len(config.StateDir)+1] != config.StateDir+"/" {
		return "", fmt.Errorf("state file %q must be inside %s/", rel, config.StateDir)
	}
	abs := filepath.Join(s.cur.Load().Config.Dir, filepath.FromSlash(clean))
	// .rackbook and the file in it must be real: a symlink in the data repo
	// could point the write anywhere.
	for _, p := range []string{filepath.Dir(abs), abs} {
		if st, err := os.Lstat(p); err == nil && st.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("state path %q is a symbolic link", filepath.Base(p))
		}
	}
	return abs, nil
}

// UpdateStateFile replaces a state file with what fn computes from its
// current content (nil when absent) and commits the change as who with
// subject. fn runs again on the new tip when the push is rejected because the
// remote moved. It returns nil, without a commit, when fn returns the same
// bytes. Without Git the file is written in place.
func (s *Store) UpdateStateFile(ctx context.Context, rel string, who *auth.Identity, subject string, fn func(old []byte) ([]byte, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	abs, err := s.statePath(rel)
	if err != nil {
		return err
	}
	read := func() ([]byte, error) {
		b, err := os.ReadFile(abs)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return b, err
	}
	write := func(b []byte) error {
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return err
		}
		tmp := abs + ".tmp"
		if err := os.WriteFile(tmp, b, 0o644); err != nil {
			return err
		}
		return os.Rename(tmp, abs)
	}
	if !s.git {
		old, err := read()
		if err != nil {
			return err
		}
		next, err := fn(old)
		if err != nil || string(next) == string(old) {
			return err
		}
		return write(next)
	}
	author := s.authorFor(ctx, who)
	var lastErr error
	for attempt := 1; attempt <= MaxAttempts; attempt++ {
		if err := s.syncLocked(ctx); err != nil {
			return err
		}
		old, err := read()
		if err != nil {
			return err
		}
		next, err := fn(old)
		if err != nil || string(next) == string(old) {
			return err
		}
		parent, _ := s.repo.Head(ctx)
		if err := write(next); err != nil {
			return err
		}
		cfgRel, _ := filepath.Rel(s.cur.Load().Config.Dir, abs)
		files := []string{filepath.ToSlash(cfgRel)}
		if _, err := s.repo.Commit(ctx, files, CommitMessage(subject, who, s.via, ""), author, s.opts.Committer); err != nil {
			s.discardState(ctx, parent, abs, old != nil, files)
			return err
		}
		if !s.HasRemote() {
			return nil
		}
		if s.beforePush != nil {
			s.beforePush()
		}
		push := s.repo.Push
		if s.pushFn != nil {
			push = s.pushFn
		}
		if err := push(ctx, s.branch); err != nil {
			lastErr = err
			_, ferr := s.repo.git(ctx, "fetch", "--quiet", "origin")
			if ferr == nil {
				if _, aerr := s.repo.git(ctx, "merge-base", "--is-ancestor", "HEAD", "origin/"+s.branch); aerr == nil {
					s.advanceToHead(ctx)
					return nil
				}
			}
			tip, _ := s.repo.git(ctx, "rev-parse", "origin/"+s.branch)
			s.discardState(ctx, parent, abs, old != nil, files)
			if ferr != nil || tip == parent {
				return fmt.Errorf("push failed: %w", err)
			}
			s.log.Info("push rejected, replaying state file change on the new tip", "attempt", attempt)
			continue
		}
		s.advanceToHead(ctx)
		return nil
	}
	return fmt.Errorf("giving up after %d attempts, the remote keeps changing: %w", MaxAttempts, lastErr)
}

// discardState drops our unpushed commit and puts the state file back as it
// was: restored when it existed, removed when our commit created it.
func (s *Store) discardState(ctx context.Context, parent, abs string, existed bool, files []string) {
	if parent == "" {
		return
	}
	if _, err := s.repo.git(ctx, "reset", "--quiet", parent); err != nil {
		s.log.Error("could not reset the index", "err", err)
		return
	}
	if existed {
		if _, err := s.repo.git(ctx, append([]string{"checkout", "--quiet", "--"}, files...)...); err != nil {
			s.log.Error("could not restore the state file", "err", err)
		}
		return
	}
	if err := os.Remove(abs); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.log.Error("could not remove the state file", "err", err)
	}
}
