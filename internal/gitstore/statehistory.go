package gitstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kazuhahub/rackbook/internal/config"
)

// StateEdge is one parent-to-child step of a state file that was not an append: the file at
// Commit is not the file at Parent with lines added at the end.
type StateEdge struct {
	Commit, Parent string
	Base, Content  []byte
}

// StateCheck is what checking the history of a state file found.
type StateCheck struct {
	// Tip is the commit the check ended at: pass it as after the next time.
	Tip string
	// Violations are the steps that were not appends, one per commit and parent.
	Violations []StateEdge
	// Restarted says after is no longer an ancestor of the tip (the history was rewritten, or
	// the commit is unknown), so everything was checked.
	Restarted bool
	// Commits is how many commits that touch the file were looked at.
	Commits int
}

func cleanStatePath(rel string) (string, error) {
	clean := path.Clean(filepath.ToSlash(rel))
	if !config.IsStatePath(clean) || clean == config.StateDir || strings.ContainsAny(clean, "\x00\n\r") || strings.HasPrefix(clean, "..") {
		return "", fmt.Errorf("state file %q must be inside %s/", rel, config.StateDir)
	}
	return clean, nil
}

// CheckStateFileHistory checks that a state file (.rackbook/...) only ever grew by appended lines
// anywhere in the history of the tracked branch: for every commit that touches it and each of its
// parents, the file at the commit must be the file at the parent (empty when the parent has none)
// with lines added at the end. Every edge is checked, not one line of history: git's default
// history simplification follows one side of a merge, which would let a merge that takes a forged
// side go unseen. With after (a Tip of an earlier check) that is an ancestor of the tip only the
// commits not reachable from it are looked at; otherwise everything is.
func (s *Store) CheckStateFileHistory(ctx context.Context, rel, after string) (*StateCheck, error) {
	if !s.git {
		return nil, errors.New("history needs the data directory to be a repository")
	}
	clean, err := cleanStatePath(rel)
	if err != nil {
		return nil, err
	}
	tip, ok := s.trackedTip(ctx)
	if !ok {
		return nil, errors.New("the tracked branch has no commit")
	}
	return s.repo.checkAppendOnly(ctx, tip, after, clean)
}

// CheckStateFileInClone is CheckStateFileHistory for a clone that no server owns (rackbook audit
// verify --repo): the history of its checked-out HEAD, from the start.
func CheckStateFileInClone(ctx context.Context, dir, rel string) (*StateCheck, error) {
	clean, err := cleanStatePath(rel)
	if err != nil {
		return nil, err
	}
	r := &Repo{Dir: dir, IgnoreUserConfig: true}
	if !r.IsRepo(ctx) {
		return nil, errors.New("not a Git repository")
	}
	tip, err := r.Head(ctx)
	if err != nil || tip == "" {
		return nil, errors.New("the clone has no commit")
	}
	return r.checkAppendOnly(ctx, tip, "", clean)
}

func (r *Repo) checkAppendOnly(ctx context.Context, tip, after, clean string) (*StateCheck, error) {
	c := &StateCheck{Tip: tip}
	if after != "" {
		if !fullRevRe.MatchString(after) {
			after = ""
		} else if _, err := r.git(ctx, "merge-base", "--is-ancestor", after, tip); err != nil {
			after, c.Restarted = "", true
		}
	}
	if after == tip {
		return c, nil
	}
	args := []string{"log", "--full-history", "--format=%H %P", tip}
	if after != "" {
		args = append(args, "^"+after)
	}
	args = append(args, "--", clean)
	out, err := r.git(ctx, args...)
	if err != nil {
		return nil, err
	}
	type node struct {
		commit  string
		parents []string
	}
	var nodes []node
	want := map[string]bool{}
	var specs []string
	need := func(commit string) {
		if !want[commit] {
			want[commit] = true
			specs = append(specs, commit)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		for _, h := range f {
			if !fullRevRe.MatchString(h) {
				return nil, fmt.Errorf("unreadable commit line %q", line)
			}
			need(h)
		}
		nodes = append(nodes, node{f[0], f[1:]})
	}
	c.Commits = len(nodes)
	content, err := r.filesAt(ctx, specs, clean)
	if err != nil {
		return nil, err
	}
	for _, n := range nodes {
		parents := n.parents
		if len(parents) == 0 {
			continue // a root commit adds the file: nothing to be a prefix of
		}
		for _, p := range parents {
			if !bytes.HasPrefix(content[n.commit], content[p]) {
				c.Violations = append(c.Violations, StateEdge{Commit: n.commit, Parent: p, Base: content[p], Content: content[n.commit]})
			}
		}
	}
	return c, nil
}

// filesAt reads the file at each commit with one "git cat-file --batch": a commit without the
// file (or without the object) gives an empty content.
func (r *Repo) filesAt(ctx context.Context, commits []string, clean string) (map[string][]byte, error) {
	out := make(map[string][]byte, len(commits))
	if len(commits) == 0 {
		return out, nil
	}
	var in strings.Builder
	for _, c := range commits {
		in.WriteString(c + ":./" + clean + "\n")
	}
	raw, err := r.runRaw(ctx, nil, in.String(), "cat-file", "--batch")
	if err != nil {
		return nil, err
	}
	b := []byte(raw)
	for _, c := range commits {
		nl := bytes.IndexByte(b, '\n')
		if nl < 0 {
			return nil, errors.New("cat-file --batch ended early")
		}
		header := strings.Fields(string(b[:nl]))
		b = b[nl+1:]
		if len(header) == 3 && header[1] == "blob" {
			size, err := strconv.Atoi(header[2])
			if err != nil || size < 0 || size+1 > len(b) {
				return nil, fmt.Errorf("unreadable cat-file header %q", header)
			}
			out[c] = b[:size:size]
			b = b[size+1:]
			continue
		}
		out[c] = nil // missing, or not a file
	}
	return out, nil
}
