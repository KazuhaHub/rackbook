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

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/roles"
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

// Repo runs git commands in a directory inside a work tree. Every command
// goes through Runner (nil = the real git), so tests can record them.
type Repo struct {
	Dir    string
	Runner Runner
	// IgnoreUserConfig runs git without the user's global configuration (the
	// server: its behaviour must not depend on whoever's ~/.gitconfig it finds).
	// The CLI keeps it.
	IgnoreUserConfig bool
	// Auth, when set, attaches a GitHub App installation token to fetches and
	// pushes (see gitauth.go).
	Auth *GitAuth
}

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

// ExitCode is git's exit status, or -1 when git did not run to completion.
func (e *GitError) ExitCode() int {
	var ee *exec.ExitError
	if errors.As(e.Err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// Cmd is one git invocation: the arguments after "git" (the runner adds
// "-C Dir" and its fixed -c options), extra environment and stdin.
type Cmd struct {
	Dir   string
	Args  []string
	Env   []string
	Stdin string
	// IgnoreUserConfig sets GIT_CONFIG_GLOBAL to the null device.
	IgnoreUserConfig bool
	// MaxStdout, when positive, limits the output read: past it the process is
	// killed and Run returns what was read with ErrOutputLimit.
	MaxStdout int
}

// Runner runs git. It is the only place in rackbook that starts a git
// process; tests replace it with a recorder.
type Runner interface {
	Run(ctx context.Context, c Cmd) (stdout, stderr string, err error)
}

type execRunner struct{}

// RealRunner is the Runner that runs the real git, with the guards of safegit.go.
// A test wraps it to watch or interfere with the commands.
func RealRunner() Runner { return defaultRunner }

// defaultRunner runs the real git. Tests may replace it.
var defaultRunner Runner = execRunner{}

func (execRunner) Run(ctx context.Context, c Cmd) (string, string, error) {
	if err := refuseDestructive(c.Args); err != nil {
		return "", "", err
	}
	if err := refuseEnv(c.Env); err != nil {
		return "", "", err
	}
	// Hooks never run (not even pre-push). The server (IgnoreUserConfig) also
	// ignores the system and global config and trusts its own directory; the CLI
	// keeps the user's config, so credential helpers keep working.
	full := []string{"-C", c.Dir, "-c", "core.quotepath=off", "-c", "core.hooksPath=/dev/null",
		// Files are committed byte for byte: no CRLF conversion, whatever the
		// platform default is (Git for Windows ships with autocrlf=true).
		"-c", "core.autocrlf=false"}
	if c.IgnoreUserConfig {
		full = append(full, "-c", "safe.directory=*")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append(full, c.Args...)...)
	cmd.Env = append(inheritedEnv(os.Environ()), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	if c.IgnoreUserConfig {
		cmd.Env = append(cmd.Env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	}
	cmd.Env = append(cmd.Env, c.Env...)
	if c.Stdin != "" {
		cmd.Stdin = strings.NewReader(c.Stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stderr = &errb
	if c.MaxStdout > 0 {
		lw := &limitWriter{max: c.MaxStdout, stop: cancel}
		cmd.Stdout = lw
		err := cmd.Run()
		if lw.hit {
			// the process was killed once the limit was passed: that is no failure
			return lw.buf.String(), errb.String(), ErrOutputLimit
		}
		return lw.buf.String(), errb.String(), err
	}
	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), errb.String(), err
}

// ErrOutputLimit is returned by a Runner with Cmd.MaxStdout set when the
// command wrote more than that: it was stopped, and the output returned is the
// first MaxStdout bytes of it.
var ErrOutputLimit = errors.New("git output limit reached")

// limitWriter keeps the first max bytes written to it and, on the first byte
// past them, calls stop (which kills the process).
type limitWriter struct {
	buf  bytes.Buffer
	max  int
	hit  bool
	stop func()
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if room := w.max - w.buf.Len(); len(p) > room {
		w.buf.Write(p[:room])
		w.hit = true
		w.stop()
		return 0, ErrOutputLimit
	}
	return w.buf.Write(p)
}

// runLimited is runRaw with the output cut at max bytes; truncated says it was.
func (r *Repo) runLimited(ctx context.Context, max int, args ...string) (out string, truncated bool, err error) {
	rn := r.Runner
	if rn == nil {
		rn = defaultRunner
	}
	out, errOut, err := rn.Run(ctx, Cmd{Dir: r.Dir, Args: args, IgnoreUserConfig: r.IgnoreUserConfig, MaxStdout: max})
	if errors.Is(err, ErrOutputLimit) {
		return out, true, nil
	}
	if err != nil {
		return "", false, &GitError{Args: args, Stderr: errOut, Err: err}
	}
	return out, false, nil
}

// run executes git with the given extra environment and stdin.
func (r *Repo) run(ctx context.Context, env []string, stdin string, args ...string) (string, error) {
	out, err := r.runRaw(ctx, env, stdin, args...)
	return strings.TrimRight(out, "\n"), err
}

// runRaw is run without trimming the output (file contents).
func (r *Repo) runRaw(ctx context.Context, env []string, stdin string, args ...string) (string, error) {
	rn := r.Runner
	if rn == nil {
		rn = defaultRunner
	}
	if r.Auth != nil && networkCommand(args) {
		remote := r.RemoteURL(ctx)
		aenv, err := r.Auth.env(ctx, remote)
		if err != nil {
			return "", err
		}
		env = append(append([]string{}, env...), aenv...)
	}
	out, errOut, err := rn.Run(ctx, Cmd{Dir: r.Dir, Args: args, Env: env, Stdin: stdin, IgnoreUserConfig: r.IgnoreUserConfig})
	if err != nil {
		return "", &GitError{Args: args, Stderr: errOut, Err: err}
	}
	return out, nil
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

// ConfigIdentity reads user.name / user.email from the Git configuration.
func (r *Repo) ConfigIdentity(ctx context.Context) Identity {
	name, _ := r.git(ctx, "config", "user.name")
	email, _ := r.git(ctx, "config", "user.email")
	return Identity{Name: name, Email: email}
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

// Push pushes HEAD to the branch on origin: a plain fast-forward push, built
// by pushArgs (safegit.go), the only function that builds a push command.
func (r *Repo) Push(ctx context.Context, branch string) error {
	args, err := pushArgs(branch)
	if err != nil {
		return err
	}
	_, err = r.git(ctx, args...)
	return err
}

// CommitFiles commits the given config-relative files in the user's own
// working tree (it does not fetch or reset anything, except a fetch to check
// that the remote history was not rewritten). The author is who; without one
// (nil) it is the Git configuration. record is the "Record:" trailer value
// ("<collection>/<id>").
func CommitFiles(ctx context.Context, dir string, files []string, subject string, who *auth.Identity, record string, extra ...string) (string, error) {
	r := &Repo{Dir: dir}
	if !r.IsRepo(ctx) {
		return "", errors.New("not inside a Git repository")
	}
	if _, err := r.checkRemoteHistory(ctx, false); err != nil {
		return "", err
	}
	if who.Anonymous() {
		cfg := r.ConfigIdentity(ctx)
		if cfg.IsZero() {
			return "", errors.New("no git identity: set user.name and user.email")
		}
		who = &auth.Identity{ID: roles.FoldASCII(cfg.Email), Name: cfg.Name, Email: cfg.Email, Method: auth.MethodCLI}
	}
	author := AuthorOf(who)
	return r.Commit(ctx, files, CommitMessage(subject, who, "rackbook", record, extra...), author, author)
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
	if _, err := r.checkRemoteHistory(ctx, true); err != nil {
		return err
	}
	if err := r.Push(ctx, br); err != nil {
		return err
	}
	// Our pushed commit is the new base, like on the server: a later force push
	// that removes only this commit must look like a rewrite.
	if h, err := r.Head(ctx); err == nil {
		return r.writeLastGood(ctx, br, h)
	}
	return nil
}

// ConfirmedRecords reports, for each Record trailer value, whether the last
// commit that changed the record carries a "Secret-scan: confirmed-not-secret"
// trailer: the editor confirmed that what looks like a secret in it is not one.
// A record changed since by an unconfirmed commit is not in the result as true.
// The error is nil with an empty map outside a Git repository.
func ConfirmedRecords(ctx context.Context, dir string) (map[string]bool, error) {
	r := &Repo{Dir: dir}
	out := map[string]bool{}
	if !r.IsRepo(ctx) {
		return out, nil
	}
	raw, err := r.git(ctx, "log", "--format=%x1e%(trailers:key=Record,valueonly,separator=%x1f)%x1d%(trailers:key=Secret-scan,valueonly)", "--", ".", ":(exclude)"+config.StateDir)
	if err != nil {
		if strings.Contains(err.Error(), "does not have any commits") {
			return out, nil
		}
		return nil, err
	}
	seen := map[string]bool{}
	for _, c := range strings.Split(raw, "\x1e") { // newest first
		parts := strings.SplitN(c, "\x1d", 2)
		if len(parts) != 2 {
			continue
		}
		confirmed := strings.Contains(parts[1], "confirmed-not-secret")
		for _, ref := range strings.Split(strings.TrimSpace(parts[0]), "\x1f") {
			ref = strings.TrimSpace(ref)
			if ref == "" || seen[ref] {
				continue
			}
			seen[ref] = true
			out[ref] = confirmed
		}
	}
	return out, nil
}
