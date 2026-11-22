package gitstore

// Reading files as they were in a commit. A file is named by "<commit>:./<path>"
// to rev-parse, which gives the id of its blob, and the blob is read by id: the
// guarded runner allows cat-file only as "cat-file blob <40 or 64 hex digits>"
// and ls-tree only as "ls-tree -z <commit> -- <paths>" (safegit.go).

import (
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kazuhahub/rackbook/internal/config"
)

var (
	fullRevRe = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	blobIDRe  = fullRevRe
)

// safeHistPath cleans rel (config-relative) for reading at a commit and refuses
// anything that is not a plain relative path inside the data directory, or that
// is in .git/ or .rackbook/.
func safeHistPath(rel string) (string, error) {
	p := path.Clean(filepath.ToSlash(rel))
	if rel == "" || p == "." || p == ".." || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") ||
		strings.ContainsAny(p, "\x00\n\r") || config.IsStatePath(p) || p == ".git" || strings.HasPrefix(p, ".git/") {
		return "", fmt.Errorf("refusing to read %q at a commit", rel)
	}
	return p, nil
}

func isMissing(err error) bool {
	var ge *GitError
	return errors.As(err, &ge) && ge.ExitCode() == 1
}

// blobOf is the id of the blob that spec ("<commit>:./<path>") names; "" when
// there is no such file.
func (r *Repo) blobOf(ctx context.Context, spec string) (string, error) {
	out, err := r.git(ctx, "rev-parse", "--verify", "--quiet", spec)
	if err != nil {
		if isMissing(err) {
			return "", nil
		}
		return "", err
	}
	return out, nil
}

// catBlob reads a blob by its id, at most max bytes: truncated says it is longer.
func (r *Repo) catBlob(ctx context.Context, id string, max int) (data []byte, truncated bool, err error) {
	if !blobIDRe.MatchString(id) {
		return nil, false, fmt.Errorf("unusable object id %q", id)
	}
	out, cut, err := r.runLimited(ctx, max, "cat-file", "blob", id)
	if err != nil {
		return nil, false, err
	}
	return []byte(out), cut, nil
}

// fileAt reads the file spec names ("<commit>:./<path>"); found is false when
// the commit has no such file.
func (r *Repo) fileAt(ctx context.Context, spec string) (data []byte, found bool, err error) {
	id, err := r.blobOf(ctx, spec)
	if err != nil || id == "" {
		return nil, false, err
	}
	data, truncated, err := r.catBlob(ctx, id, 1<<30)
	if err != nil || truncated {
		return nil, false, err
	}
	return data, true, nil
}

// lsTree gives the blob id of each of the files (config-relative, plain paths)
// that the commit (a full hash) has; a file it does not have is not in the map.
func (r *Repo) lsTree(ctx context.Context, commit string, files ...string) (map[string]string, error) {
	if !fullRevRe.MatchString(commit) {
		return nil, fmt.Errorf("%w: %q", ErrNoCommit, commit)
	}
	args := []string{"ls-tree", "-z", commit, "--"}
	seen := map[string]bool{}
	for _, f := range files {
		if f == "" {
			continue
		}
		p, err := safeHistPath(f)
		if err != nil {
			continue // a path that cannot be read is a file the commit does not have
		}
		if !seen[p] {
			seen[p] = true
			args = append(args, p)
		}
	}
	out := map[string]string{}
	if len(args) == 4 {
		return out, nil
	}
	raw, err := r.runRaw(ctx, nil, "", args...)
	if err != nil {
		return nil, err
	}
	for _, ent := range strings.Split(raw, "\x00") {
		meta, name, ok := strings.Cut(ent, "\t")
		f := strings.Fields(meta)
		if ok && len(f) == 3 && f[1] == "blob" && blobIDRe.MatchString(f[2]) {
			out[name] = f[2]
		}
	}
	return out, nil
}
