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

// MaxStateFileBytes is the largest version of a checked state file. The size comes with the
// object's header, so a larger one is refused as what it is, not read.
const MaxStateFileBytes = 4 << 20

// Why a step of a state file's history was refused.
const (
	ReasonRewritten  = ""                          // the file is not the parent's with lines appended
	ReasonNotRegular = "not_regular"               // a directory, symbolic link or submodule at the path
	ReasonTooLarge   = "too_large"                 // above MaxStateFileBytes
	maxKeptEdges     = 20                          // violations that keep both versions
	chunkNodes       = 8                           // commits whose blobs are read in one call
	batchLimit       = 4*MaxStateFileBytes + 1<<20 // output of one cat-file --batch call
)

// ErrStateDesync is matched by errors.Is when git's answer was not what was asked for (an object
// other than the one requested, or one that does not fit its header).
var ErrStateDesync = errors.New("git answered with something else than was asked")

// StateEdge is one parent-to-child step of a state file that was refused: the file at Commit is
// not the file at Parent with lines added at the end, or it is no regular file, or it is too large.
// Base and Content are kept for the first violations only (nil afterwards, and for the other reasons).
type StateEdge struct {
	Commit, Parent string
	Reason         string
	Base, Content  []byte
}

// StateCheck is what checking the history of a state file found.
type StateCheck struct {
	// Tip is the commit the check ended at: pass it as after the next time.
	Tip string
	// Violations are the refused steps, at most one per commit.
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
// with lines added at the end, and must be a regular file of at most MaxStateFileBytes. Every edge
// is checked, not one line of history: git's default history simplification follows one side of
// a merge, which would let a merge that takes a forged side go unseen. With after (a Tip of an
// earlier check) that is an ancestor of the tip only the commits not reachable from it are looked
// at; otherwise everything is. On an error the returned check still carries Tip when it is known.
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
// verify --repo): the history of its checked-out HEAD, from the start. ErrNotRepository says the
// directory is no Git repository.
func CheckStateFileInClone(ctx context.Context, dir, rel string) (*StateCheck, error) {
	clean, err := cleanStatePath(rel)
	if err != nil {
		return nil, err
	}
	r := &Repo{Dir: dir, IgnoreUserConfig: true}
	if !r.IsRepo(ctx) {
		return nil, ErrNotRepository
	}
	tip, err := r.Head(ctx)
	if err != nil || tip == "" {
		return nil, errors.New("the clone has no commit")
	}
	return r.checkAppendOnly(ctx, tip, "", clean)
}

// ErrNotRepository is returned by CheckStateFileInClone for a directory that is no repository.
var ErrNotRepository = errors.New("not a Git repository")

// stateEntry is what a commit has at the path.
type stateEntry struct {
	present bool
	regular bool // a blob with mode 100644 or 100755
	oid     string
}

// entryAt asks ls-tree what the commit has at the path (-z: names are NUL-terminated, so a
// newline in a name cannot forge a line).
func (r *Repo) entryAt(ctx context.Context, commit, clean string) (stateEntry, error) {
	raw, err := r.runRaw(ctx, nil, "", "ls-tree", "-z", commit, "--", clean)
	if err != nil {
		return stateEntry{}, err
	}
	for _, ent := range strings.Split(raw, "\x00") {
		meta, name, ok := strings.Cut(ent, "\t")
		if !ok || name != clean {
			continue
		}
		f := strings.Fields(meta)
		if len(f) != 3 || !fullRevRe.MatchString(f[2]) {
			return stateEntry{}, fmt.Errorf("%w: ls-tree line %q", ErrStateDesync, meta)
		}
		return stateEntry{present: true, regular: f[1] == "blob" && (f[0] == "100644" || f[0] == "100755"), oid: f[2]}, nil
	}
	return stateEntry{}, nil
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
		return c, err
	}
	type node struct {
		commit  string
		parents []string
	}
	var nodes []node
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		for _, h := range f {
			if !fullRevRe.MatchString(h) {
				return c, fmt.Errorf("%w: commit line %q", ErrStateDesync, line)
			}
		}
		nodes = append(nodes, node{f[0], f[1:]})
	}
	c.Commits = len(nodes)

	entries := map[string]stateEntry{}
	entry := func(commit string) (stateEntry, error) {
		if e, ok := entries[commit]; ok {
			return e, nil
		}
		e, err := r.entryAt(ctx, commit, clean)
		if err == nil {
			entries[commit] = e
		}
		return e, err
	}
	violate := func(n node, parent, reason string, base, content []byte) {
		e := StateEdge{Commit: n.commit, Parent: parent, Reason: reason}
		if len(c.Violations) < maxKeptEdges {
			e.Base, e.Content = base, content
		}
		c.Violations = append(c.Violations, e)
	}
	for start := 0; start < len(nodes); start += chunkNodes {
		chunk := nodes[start:min(start+chunkNodes, len(nodes))]
		// what each commit of the chunk and its parents have at the path
		var oids []string
		wanted := map[string]bool{}
		for _, n := range chunk {
			for _, h := range append([]string{n.commit}, n.parents...) {
				e, err := entry(h)
				if err != nil {
					return c, err
				}
				if e.present && e.regular && !wanted[e.oid] {
					wanted[e.oid] = true
					oids = append(oids, e.oid)
				}
			}
		}
		blobs, err := r.readBlobs(ctx, oids)
		if err != nil {
			return c, err
		}
		for _, n := range chunk {
			me, _ := entry(n.commit)
			if me.present && !me.regular {
				violate(n, "", ReasonNotRegular, nil, nil)
				continue
			}
			if b, big := blobs[me.oid]; me.present && (big && b == nil) {
				violate(n, "", ReasonTooLarge, nil, nil)
				continue
			}
			var content []byte
			if me.present {
				content = blobs[me.oid]
			}
			for _, p := range n.parents {
				pe, _ := entry(p)
				var base []byte
				if pe.present && pe.regular {
					if b, ok := blobs[pe.oid]; ok && b == nil {
						violate(n, p, ReasonTooLarge, nil, nil)
						break
					}
					base = blobs[pe.oid]
				}
				// a parent that is no regular file has been refused as its own commit; compared as empty
				if !bytes.HasPrefix(content, base) {
					violate(n, p, ReasonRewritten, base, content)
					break
				}
			}
		}
	}
	return c, nil
}

// readBlobs reads blobs by object id with one "git cat-file --batch". Each answer is checked to be
// the object asked for and to be a blob, and exactly its size plus the closing newline is
// consumed, so nothing that is read can shift what comes after it. A blob above MaxStateFileBytes
// is not kept (nil in the map, present as a key) but its body is still consumed.
func (r *Repo) readBlobs(ctx context.Context, oids []string) (map[string][]byte, error) {
	out := make(map[string][]byte, len(oids))
	if len(oids) == 0 {
		return out, nil
	}
	for _, o := range oids {
		if !blobIDRe.MatchString(o) {
			return nil, fmt.Errorf("unusable object id %q", o)
		}
	}
	raw, truncated, err := r.runLimitedStdin(ctx, batchLimit, strings.Join(oids, "\n")+"\n", "cat-file", "--batch")
	if err != nil {
		return nil, err
	}
	if truncated {
		return nil, fmt.Errorf("%w: output above %d bytes", ErrStateDesync, batchLimit)
	}
	b := []byte(raw)
	for _, want := range oids {
		nl := bytes.IndexByte(b, '\n')
		if nl < 0 {
			return nil, fmt.Errorf("%w: output ended early", ErrStateDesync)
		}
		h := strings.Fields(string(b[:nl]))
		b = b[nl+1:]
		if len(h) != 3 || h[0] != want || h[1] != "blob" {
			return nil, fmt.Errorf("%w: asked for %s, got %q", ErrStateDesync, want, h)
		}
		size, err := strconv.Atoi(h[2])
		if err != nil || size < 0 || size+1 > len(b) || b[size] != '\n' {
			return nil, fmt.Errorf("%w: object %s does not fit its header", ErrStateDesync, want)
		}
		if size > MaxStateFileBytes {
			out[want] = nil
		} else {
			out[want] = b[:size:size]
		}
		b = b[size+1:]
	}
	if len(b) != 0 {
		return nil, fmt.Errorf("%w: %d bytes left over", ErrStateDesync, len(b))
	}
	return out, nil
}
