package gitstore

// The write side of a Mirror: what the infra editors need to commit to the
// followed branch of the clone. Every command still goes through the guarded
// runner (safegit.go): the only push is the fast-forward push of HEAD to the
// branch, and nothing here rewrites history.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// CanWrite reports whether the mirror has a write credential.
func (m *Mirror) CanWrite() bool { return m.WriteAuth != nil }

func (m *Mirror) writeRepo() *Repo {
	return &Repo{Dir: m.Dir, Runner: m.Runner, IgnoreUserConfig: true, Auth: m.WriteAuth}
}

// FetchForWrite fetches origin with the write credential.
func (m *Mirror) FetchForWrite(ctx context.Context) error {
	if !m.CanWrite() {
		return errors.New("the repository has no write credential")
	}
	if _, err := m.check(ctx); err != nil {
		return err
	}
	_, err := m.writeRepo().run(ctx, m.env(), "", "fetch", "--quiet", "origin")
	return err
}

var hexRevRe = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// ValidRev reports whether s is a commit hash (7 to 64 hex digits).
func ValidRev(s string) bool { return hexRevRe.MatchString(s) }

func validRevOrHead(rev string) error {
	if rev != "HEAD" && !ValidRev(rev) {
		return fmt.Errorf("unusable revision %q", rev)
	}
	return nil
}

// BlobID is the object ID of the file at path in rev ("" when the file does not exist there).
func (m *Mirror) BlobID(ctx context.Context, rev, path string) (string, error) {
	if err := safeRel(path); err != nil {
		return "", err
	}
	if err := validRevOrHead(rev); err != nil {
		return "", err
	}
	out, err := m.repo().git(ctx, "rev-parse", "--verify", "--quiet", rev+":"+path)
	if err != nil {
		var ge *GitError
		if errors.As(err, &ge) && ge.ExitCode() == 1 {
			return "", nil
		}
		return "", err
	}
	return out, nil
}

// ShowFile is the content of the file at path in rev (nil, nil when it does not exist there).
func (m *Mirror) ShowFile(ctx context.Context, rev, path string) ([]byte, error) {
	id, err := m.BlobID(ctx, rev, path)
	if err != nil || id == "" {
		return nil, err
	}
	out, err := m.repo().runRaw(ctx, nil, "", "cat-file", "blob", id)
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

// FileChange is one file a commit touched.
type FileChange struct {
	Status string `json:"status"` // A, M or D
	Path   string `json:"path"`
}

// Parents lists the parents of a commit.
func (m *Mirror) Parents(ctx context.Context, commit string) ([]string, error) {
	if !ValidRev(commit) {
		return nil, fmt.Errorf("unusable commit %q", commit)
	}
	out, err := m.repo().git(ctx, "log", "-n", "1", "--format=%P", commit)
	if err != nil {
		return nil, err
	}
	return strings.Fields(out), nil
}

// Subject is the first line of a commit message.
func (m *Mirror) Subject(ctx context.Context, commit string) (string, error) {
	if !ValidRev(commit) {
		return "", fmt.Errorf("unusable commit %q", commit)
	}
	return m.repo().git(ctx, "log", "-n", "1", "--format=%s", commit)
}

// OnBranch reports whether commit is reachable from HEAD.
func (m *Mirror) OnBranch(ctx context.Context, commit string) (bool, error) {
	if !ValidRev(commit) {
		return false, fmt.Errorf("unusable commit %q", commit)
	}
	_, err := m.repo().git(ctx, "merge-base", "--is-ancestor", commit, "HEAD")
	if err == nil {
		return true, nil
	}
	var ge *GitError
	if errors.As(err, &ge) && ge.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

// Touched lists the files a (non-merge) commit changed against its parent.
func (m *Mirror) Touched(ctx context.Context, commit string) ([]FileChange, error) {
	if !ValidRev(commit) {
		return nil, fmt.Errorf("unusable commit %q", commit)
	}
	out, err := m.repo().runRaw(ctx, nil, "", "diff-tree", "--no-commit-id", "--name-status", "-r", "-z", "--root", "--no-renames", commit)
	if err != nil {
		return nil, err
	}
	f := strings.Split(strings.TrimRight(out, "\x00"), "\x00")
	var res []FileChange
	for i := 0; i+1 < len(f); i += 2 {
		res = append(res, FileChange{Status: f[i], Path: f[i+1]})
	}
	return res, nil
}

// ChangedSince lists the commits after `commit` (up to HEAD) that touched any of paths, newest first.
func (m *Mirror) ChangedSince(ctx context.Context, commit string, paths []string) ([]string, error) {
	if !ValidRev(commit) || len(paths) == 0 {
		return nil, fmt.Errorf("unusable commit %q", commit)
	}
	args := []string{"log", "--format=%H", commit + "..HEAD", "--"}
	for _, p := range paths {
		if err := safeRel(p); err != nil {
			return nil, err
		}
		args = append(args, p)
	}
	out, err := m.repo().git(ctx, args...)
	if err != nil {
		return nil, err
	}
	return strings.Fields(out), nil
}

var relRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+/-]*$`)

// safeRel accepts only a plain relative path inside the clone.
func safeRel(p string) error {
	if !relRe.MatchString(p) || len(p) > 300 {
		return fmt.Errorf("unusable path %q", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." || strings.HasPrefix(seg, ".git") {
			return fmt.Errorf("unusable path %q", p)
		}
	}
	return nil
}

// CommitChanges writes the files (a nil value removes the file), commits exactly
// those paths and returns the new commit. It does not push. The clone must be at
// the branch tip with a clean work tree.
func (m *Mirror) CommitChanges(ctx context.Context, files map[string][]byte, message string, author, committer Identity) (string, error) {
	if !m.CanWrite() {
		return "", errors.New("the repository has no write credential")
	}
	r, err := m.check(ctx)
	if err != nil {
		return "", err
	}
	root, err := filepath.EvalSymlinks(m.Dir)
	if err != nil {
		return "", err
	}
	var paths []string
	for rel, content := range files {
		if err := safeRel(rel); err != nil {
			return "", err
		}
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := noSymlinkOnTheWay(root, p); err != nil {
			return "", err
		}
		if content == nil {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				return "", err
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return "", err
			}
			if err := os.WriteFile(p, content, 0o644); err != nil {
				return "", err
			}
		}
		paths = append(paths, rel)
	}
	if _, err := r.Commit(ctx, paths, message, author, committer); err != nil {
		return "", err
	}
	return r.Head(ctx)
}

// noSymlinkOnTheWay refuses a path whose existing parts are symlinks.
func noSymlinkOnTheWay(root, p string) error {
	rel, err := filepath.Rel(root, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("%s leaves the repository", p)
	}
	cur := root
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, seg)
		st, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symbolic link", rel)
		}
	}
	return nil
}

// PushCommits pushes HEAD to the branch (a fast-forward; the remote refuses it
// when the branch moved).
func (m *Mirror) PushCommits(ctx context.Context) error {
	if !m.CanWrite() {
		return errors.New("the repository has no write credential")
	}
	if _, err := m.check(ctx); err != nil {
		return err
	}
	args, err := pushArgs(m.Branch)
	if err != nil {
		return err
	}
	_, err = m.writeRepo().run(ctx, m.env(), "", args...)
	return err
}

// IsPushRejected reports whether err is a push the remote refused because the branch moved.
func IsPushRejected(err error) bool {
	var ge *GitError
	if !errors.As(err, &ge) {
		return false
	}
	s := ge.Stderr
	// "[rejected]" is the remote refusing a non-fast-forward; "[remote rejected]" (a protected branch, a hook) is a refusal retrying cannot fix.
	return strings.Contains(s, "[rejected]") || strings.Contains(s, "non-fast-forward") || strings.Contains(s, "fetch first")
}
