// Package gitstore owns the Git side of rackbook: the server-owned clone,
// the write path (fetch, splice, validate, commit, push, retry), pull
// requests, history, and the no-Git fallback.
package gitstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Identity is a Git author or committer.
type Identity struct {
	Name  string
	Email string
}

func (i Identity) String() string { return i.Name + " <" + i.Email + ">" }

// IsZero reports whether no identity is set.
func (i Identity) IsZero() bool { return i.Name == "" && i.Email == "" }

// ParseIdentity parses "Name <email>" or a bare email address.
func ParseIdentity(s string) (Identity, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Identity{}, nil
	}
	if i := strings.Index(s, "<"); i >= 0 {
		j := strings.Index(s, ">")
		if j < i || strings.TrimSpace(s[j+1:]) != "" {
			return Identity{}, fmt.Errorf("invalid identity %q, want \"Name <email>\"", s)
		}
		id := Identity{Name: strings.TrimSpace(s[:i]), Email: strings.TrimSpace(s[i+1 : j])}
		if id.Email == "" {
			return Identity{}, fmt.Errorf("invalid identity %q: empty email", s)
		}
		if id.Name == "" {
			id.Name = strings.SplitN(id.Email, "@", 2)[0]
		}
		return id, nil
	}
	if !strings.Contains(s, "@") {
		return Identity{}, fmt.Errorf("invalid identity %q, want \"Name <email>\"", s)
	}
	return Identity{Name: strings.SplitN(s, "@", 2)[0], Email: s}, nil
}

// Repo runs git commands in a directory inside a work tree.
type Repo struct{ Dir string }

// GitError is a failed git command.
type GitError struct {
	Args   []string
	Stderr string
	Err    error
}

func (e *GitError) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" {
		msg = e.Err.Error()
	}
	return fmt.Sprintf("git %s: %s", strings.Join(e.Args, " "), msg)
}

func (e *GitError) Unwrap() error { return e.Err }

// run executes git with the given extra environment and stdin.
func (r *Repo) run(ctx context.Context, env []string, stdin string, args ...string) (string, error) {
	full := append([]string{"-C", r.Dir, "-c", "safe.directory=*", "-c", "core.quotepath=off"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	cmd.Env = append(cmd.Env, env...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", &GitError{Args: args, Stderr: errb.String(), Err: err}
	}
	return strings.TrimRight(out.String(), "\n"), nil
}

func (r *Repo) git(ctx context.Context, args ...string) (string, error) {
	return r.run(ctx, nil, "", args...)
}

// IsRepo reports whether Dir is inside a Git work tree and git is installed.
func (r *Repo) IsRepo(ctx context.Context) bool {
	out, err := r.git(ctx, "rev-parse", "--is-inside-work-tree")
	return err == nil && out == "true"
}

// Branch is the checked-out branch ("HEAD" when detached).
func (r *Repo) Branch(ctx context.Context) (string, error) {
	return r.git(ctx, "rev-parse", "--abbrev-ref", "HEAD")
}

// RemoteURL returns the URL of origin, or "" when there is none.
func (r *Repo) RemoteURL(ctx context.Context) string {
	out, err := r.git(ctx, "remote", "get-url", "origin")
	if err != nil {
		return ""
	}
	return out
}

// Head returns the full commit hash of HEAD.
func (r *Repo) Head(ctx context.Context) (string, error) {
	return r.git(ctx, "rev-parse", "HEAD")
}

// Dirty reports uncommitted changes to tracked files.
func (r *Repo) Dirty(ctx context.Context) (bool, error) {
	out, err := r.git(ctx, "status", "--porcelain", "--untracked-files=no")
	return out != "", err
}

// ConfigIdentity reads user.name / user.email from the Git configuration.
func (r *Repo) ConfigIdentity(ctx context.Context) Identity {
	name, _ := r.git(ctx, "config", "user.name")
	email, _ := r.git(ctx, "config", "user.email")
	return Identity{Name: name, Email: email}
}

// CommitMessage builds subject + blank line + trailers.
func CommitMessage(subject string, editor Identity, via string) string {
	var b strings.Builder
	b.WriteString(subject + "\n\n")
	if editor.Email != "" {
		b.WriteString("Edited-by: " + editor.Email + "\n")
	}
	b.WriteString("Edited-via: " + via + "\n")
	return b.String()
}

// Commit stages files and commits only them. author and committer are set
// through the environment; the commit never runs hooks or signing.
func (r *Repo) Commit(ctx context.Context, files []string, message string, author, committer Identity) (string, error) {
	if len(files) == 0 {
		return "", errors.New("nothing to commit")
	}
	if _, err := r.git(ctx, append([]string{"add", "--"}, files...)...); err != nil {
		return "", err
	}
	env := []string{
		"GIT_AUTHOR_NAME=" + author.Name, "GIT_AUTHOR_EMAIL=" + author.Email,
		"GIT_COMMITTER_NAME=" + committer.Name, "GIT_COMMITTER_EMAIL=" + committer.Email,
	}
	args := []string{"-c", "commit.gpgsign=false", "commit", "--quiet", "--no-verify", "-F", "-", "--only", "--"}
	if _, err := r.run(ctx, env, message, append(args, files...)...); err != nil {
		return "", err
	}
	return r.git(ctx, "rev-parse", "--short", "HEAD")
}

// Push pushes HEAD to the branch on origin.
func (r *Repo) Push(ctx context.Context, branch string) error {
	_, err := r.git(ctx, "push", "--quiet", "origin", "HEAD:refs/heads/"+branch)
	return err
}

// CommitFiles commits the given config-relative files in the user's own
// working tree (it does not fetch or reset anything). Author is the Git
// configuration unless editor is set.
func CommitFiles(ctx context.Context, dir string, files []string, subject string, editor Identity, via string) (string, error) {
	r := &Repo{Dir: dir}
	if !r.IsRepo(ctx) {
		return "", errors.New("not inside a Git repository")
	}
	who := editor
	if who.IsZero() {
		who = r.ConfigIdentity(ctx)
	}
	if who.IsZero() {
		return "", errors.New("no git identity: set user.name and user.email")
	}
	return r.Commit(ctx, files, CommitMessage(subject, who, via), who, who)
}

// PushCurrent pushes the checked-out branch to origin.
func PushCurrent(ctx context.Context, dir string) error {
	r := &Repo{Dir: dir}
	br, err := r.Branch(ctx)
	if err != nil {
		return err
	}
	if br == "HEAD" {
		return errors.New("detached HEAD: nothing to push")
	}
	return r.Push(ctx, br)
}
