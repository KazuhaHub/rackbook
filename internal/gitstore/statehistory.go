package gitstore

import (
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/kazuhahub/rackbook/internal/config"
)

// StateVersion is a state file as one commit left it; Content is empty when the commit deleted it.
type StateVersion struct {
	Commit  string
	Content []byte
}

// StateHistory is the commits of the tracked branch that changed one state file.
type StateHistory struct {
	// Tip is the commit the walk ended at: pass it as after the next time.
	Tip string
	// Base is the file as it was at after (nil for a walk from the start).
	Base []byte
	// Versions are the commits after that, oldest first, each with the file it left.
	Versions []StateVersion
	// Restarted says after is no longer an ancestor of the tip (the history was rewritten, or
	// the commit is unknown), so the walk began at the start.
	Restarted bool
}

// StateFileHistory walks the history of a state file (.rackbook/...) on the tracked
// branch, from after (a full commit hash that was Tip of an earlier walk; "" for the start) to
// the tip, oldest first. If after is not an ancestor of the tip it walks from the start and says so.
func (s *Store) StateFileHistory(ctx context.Context, rel, after string) (*StateHistory, error) {
	if !s.git {
		return nil, errors.New("history needs the data directory to be a repository")
	}
	clean := path.Clean(filepath.ToSlash(rel))
	if !config.IsStatePath(clean) || clean == config.StateDir || strings.ContainsAny(clean, "\x00\n\r") || strings.HasPrefix(clean, "..") {
		return nil, fmt.Errorf("state file %q must be inside %s/", rel, config.StateDir)
	}
	tip, ok := s.trackedTip(ctx)
	if !ok {
		return nil, errors.New("the tracked branch has no commit")
	}
	h := &StateHistory{Tip: tip}
	if after != "" {
		if !fullRevRe.MatchString(after) {
			after = ""
		} else if _, err := s.repo.git(ctx, "merge-base", "--is-ancestor", after, tip); err != nil {
			after, h.Restarted = "", true
		}
	}
	if after == tip {
		return h, nil
	}
	args := []string{"log", "--format=%H", "--reverse", tip}
	if after != "" {
		args = append(args, "^"+after)
	}
	args = append(args, "--", clean)
	out, err := s.repo.git(ctx, args...)
	if err != nil {
		return nil, err
	}
	if after != "" {
		if h.Base, _, err = s.repo.fileAt(ctx, after+":./"+clean); err != nil {
			return nil, err
		}
	}
	for _, c := range strings.Fields(out) {
		if !fullRevRe.MatchString(c) {
			return nil, fmt.Errorf("unreadable commit %q", c)
		}
		b, _, err := s.repo.fileAt(ctx, c+":./"+clean)
		if err != nil {
			return nil, err
		}
		h.Versions = append(h.Versions, StateVersion{Commit: c, Content: b})
	}
	return h, nil
}
