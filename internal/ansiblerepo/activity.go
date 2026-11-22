package ansiblerepo

import (
	"context"
	"path"
	"strings"

	"github.com/kazuhahub/rackbook/internal/gitstore"
)

// Activity lists the newest commits of the branch for the activity view.
func (r *Repo) Activity(ctx context.Context, q gitstore.ActivityQuery) (gitstore.ActivityPage, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mirror.Activity(ctx, q)
}

// ActivityWalk streams the commits of the branch to each (see gitstore.Mirror.ActivityWalk).
func (r *Repo) ActivityWalk(ctx context.Context, q gitstore.ActivityQuery, onStart func(tip string), each func(gitstore.ActivityCommit) bool) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mirror.ActivityWalk(ctx, q, onStart, each)
}

// CommitDiff shows what a commit of the branch changed, for the activity view.
// A file the repository treats as secret (SOPS files, vault files, anything
// under secrets/) is listed as changed without its patch, and what looks like
// a secret in the other files is hidden the way the edit previews hide it.
func (r *Repo) CommitDiff(ctx context.Context, hash string) (*gitstore.CommitDiff, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mirror.CommitDiff(ctx, hash, gitstore.DiffOptions{HidePatch: IsSecretFile, Redact: redactPatch})
}

// IsSecretFile reports whether the file at p (relative to the repository) holds
// secrets that must not be shown even where they are encrypted: SOPS files,
// vault files and anything under a secrets/ directory. .sops.yaml itself (the
// public recipients) is not one.
func IsSecretFile(p string) bool {
	p = strings.ToLower(p)
	base := path.Base(p)
	if base == ".sops.yaml" || base == ".sops.yml" {
		return false
	}
	if strings.Contains(base, ".sops.") || strings.HasSuffix(base, ".sops") || strings.Contains(base, "vault") {
		return true
	}
	for _, seg := range strings.Split(path.Dir(p), "/") {
		if seg == "secrets" || seg == "vault" {
			return true
		}
	}
	return false
}

// redactPatch hides what looks like a secret in the changed and context lines
// of a unified diff; the file headers and hunk headers stay.
func redactPatch(patch string) string {
	patch = gitstore.StripHunkContext(patch)
	lines := strings.Split(patch, "\n")
	var at []int
	var body []string
	inHunk := false
	for i, l := range lines {
		switch {
		case strings.HasPrefix(l, "diff --git "):
			inHunk = false
		case strings.HasPrefix(l, "@@"):
			inHunk = true
		case inHunk && l != "" && (l[0] == ' ' || l[0] == '+' || l[0] == '-'):
			at, body = append(at, i), append(body, l[1:])
		}
	}
	red := redactLines(body)
	for k, i := range at {
		lines[i] = lines[i][:1] + red[k]
	}
	return strings.Join(lines, "\n")
}
