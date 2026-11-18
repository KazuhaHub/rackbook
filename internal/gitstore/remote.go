package gitstore

// Rewritten-history detection. The server remembers the last remote commit it
// accepted, in memory and in .git/rackbook-last-good inside its clone. After
// every fetch it checks that origin/<branch> is a descendant of that commit
// (git merge-base --is-ancestor). If it is not, somebody rewrote the remote
// history (a force push, or a deleted and recreated branch): the store enters
// the "history rewritten" state, keeps serving the last good commit read-only
// without touching the clone, and refuses writes with *HistoryRewrittenError
// until an administrator accepts the new tip (Store.AcceptRemote).

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kazuhahub/rackbook/internal/config"
)

const lastGoodFile = "rackbook-last-good"

// AlertHistoryRewritten is Alert.Kind of a rewritten remote.
const AlertHistoryRewritten = "history_rewritten"

// Alert is a condition the console should show. It is exposed in /api/meta.
type Alert struct {
	Kind     string `json:"kind"`               // AlertHistoryRewritten or AlertConfigError
	LastGood string `json:"lastGood,omitempty"` // history_rewritten: full hash of the last accepted remote commit
	Remote   string `json:"remote,omitempty"`   // history_rewritten: full hash of the remote tip that is not its descendant
	Message  string `json:"message,omitempty"`  // config_error: why rackbook.yml does not load
}

// ErrHistoryRewritten is matched by errors.Is for a *HistoryRewrittenError.
var ErrHistoryRewritten = errors.New("the remote history was rewritten")

// HistoryRewrittenError says writes are paused because origin/<branch> is no
// longer a descendant of the last accepted commit.
type HistoryRewrittenError struct{ LastGood, Remote string }

func (e *HistoryRewrittenError) Error() string {
	return fmt.Sprintf("the remote history was rewritten: origin is at %s, which does not contain the last accepted commit %s; writes are paused until an administrator accepts the new history", short(e.Remote), short(e.LastGood))
}

func (e *HistoryRewrittenError) Is(target error) bool { return target == ErrHistoryRewritten }

func short(h string) string {
	if len(h) > 7 {
		return h[:7]
	}
	return h
}

var hexRe = regexp.MustCompile(`^[0-9a-f]{40,64}$`)

// lastGoodPath returns the file that stores the last good commit of branch:
// .git/rackbook-last-good/<escaped branch>. An older single file at
// .git/rackbook-last-good is migrated into the directory, for the branch that
// is checked out only; asked for any other branch while that file still
// exists, it fails instead of guessing.
func (r *Repo) lastGoodPath(ctx context.Context, branch string) (string, error) {
	d, err := r.git(ctx, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return "", err
	}
	base := filepath.Join(d, lastGoodFile)
	name := url.PathEscape(branch)
	if fi, err := os.Stat(base); err == nil && !fi.IsDir() {
		if cur, _ := r.Branch(ctx); cur != branch {
			return "", fmt.Errorf("the old single last-good file belongs to the checked-out branch %q; not migrating it for %q", cur, branch)
		}
		old, err := os.ReadFile(base)
		if err != nil {
			return "", err
		}
		return filepath.Join(base, name), migrateLastGood(d, base, name, old)
	} else if err == nil {
		return filepath.Join(base, name), nil
	}
	return filepath.Join(base, name), os.MkdirAll(base, 0o755)
}

// migrateLastGood turns the single file at base into a directory holding one
// file for the branch. The new directory with its file is written and synced
// first, and the old file is only removed after that succeeded; any failure
// leaves the old file in place.
func migrateLastGood(gitDir, base, name string, old []byte) error {
	tmp, err := os.MkdirTemp(gitDir, ".tmp-lastgood-")
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			os.RemoveAll(tmp)
		}
	}()
	if h := strings.TrimSpace(string(old)); hexRe.MatchString(h) {
		if err := writeFileSync(filepath.Join(tmp, name), []byte(h+"\n")); err != nil {
			return err
		}
	}
	if err := os.Remove(base); err != nil {
		return err
	}
	if err := os.Rename(tmp, base); err != nil {
		return err
	}
	done = true
	return nil
}

// writeFileSync writes data to path through a temporary file in the same
// directory (named ".tmp-<random>", which no escaped branch name can equal),
// fsyncs it and renames it into place. Every error is returned.
func writeFileSync(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	fail := func(err error) error {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// readLastGood returns the stored commit of branch, or "" when none is stored.
func (r *Repo) readLastGood(ctx context.Context, branch string) string {
	p, err := r.lastGoodPath(ctx, branch)
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	if h := strings.TrimSpace(string(b)); hexRe.MatchString(h) {
		return h
	}
	return ""
}

func (r *Repo) writeLastGood(ctx context.Context, branch, hash string) error {
	p, err := r.lastGoodPath(ctx, branch)
	if err != nil {
		return err
	}
	return writeFileSync(p, []byte(hash+"\n"))
}

// commitOf resolves ref to a full commit hash, or "" when it does not exist.
func (r *Repo) commitOf(ctx context.Context, ref string) string {
	out, err := r.git(ctx, "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	if err != nil {
		return ""
	}
	return out
}

// verifyDescends checks that remote contains lastGood. An empty lastGood or
// the same commit passes. A commit that git cannot find counts as not
// contained: when in doubt, writes stop.
func (r *Repo) verifyDescends(ctx context.Context, lastGood, remote string) (bool, error) {
	if lastGood == "" || lastGood == remote {
		return true, nil
	}
	_, err := r.git(ctx, "merge-base", "--is-ancestor", lastGood, remote)
	if err == nil {
		return true, nil
	}
	var ge *GitError
	if errors.As(err, &ge) && (ge.ExitCode() == 1 || ge.ExitCode() == 128) {
		return false, nil
	}
	return false, err
}

// checkRemoteHistory is the CLI variant (rackbook add --commit/--push in the
// user's own clone): fetch, and fail with *HistoryRewrittenError when
// origin/<branch> does not descend from the last commit seen in this clone.
// Without a remote it does nothing. A failing fetch is an error when strict (a
// push needs the remote anyway); otherwise (--commit only) it is skipped and
// offline is true, so the caller can warn.
func (r *Repo) checkRemoteHistory(ctx context.Context, strict bool) (offline bool, err error) {
	if r.RemoteURL(ctx) == "" {
		return false, nil
	}
	br, err := r.Branch(ctx)
	if err != nil || br == "HEAD" {
		return false, nil
	}
	good := r.readLastGood(ctx, br)
	if good == "" {
		good = r.commitOf(ctx, "origin/"+br)
	}
	if _, err := r.git(ctx, "fetch", "--quiet", "origin"); err != nil {
		if strict {
			return false, fmt.Errorf("cannot check the remote history before pushing: %w", err)
		}
		return true, nil
	}
	remote := r.commitOf(ctx, "origin/"+br)
	if remote == "" {
		return false, nil
	}
	ok, err := r.verifyDescends(ctx, good, remote)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, &HistoryRewrittenError{LastGood: good, Remote: remote}
	}
	return false, r.writeLastGood(ctx, br, remote)
}

// Store side ---------------------------------------------------------------

// AlertConfigError is Alert.Kind when rackbook.yml fails to load.
const AlertConfigError = "config_error"

// Alert returns the condition to show, or nil: a rewritten remote history
// first, else a config that does not load.
func (s *Store) Alert() *Alert {
	if a := s.alert.Load(); a != nil {
		c := *a
		return &c
	}
	if p := s.ConfigProblem(); p != "" {
		return &Alert{Kind: AlertConfigError, Message: p}
	}
	return nil
}

// setAlert raises or clears the alert; the first time a given remote tip is
// seen it is logged as an error.
func (s *Store) setAlert(a *Alert) {
	old := s.alert.Swap(a)
	if a != nil && (old == nil || old.Remote != a.Remote || old.LastGood != a.LastGood) {
		s.log.Error("remote history was rewritten: writes are paused, serving the last good commit read-only",
			"lastGood", a.LastGood, "remote", a.Remote, "branch", s.branch)
	}
	if a == nil && old != nil {
		s.log.Info("remote history is consistent again")
	}
}

// verifyRemote checks origin/<branch> (already fetched) against the last good
// commit and returns the remote tip. It raises the alert and returns a
// *HistoryRewrittenError on a rewrite. Callers hold mu.
func (s *Store) verifyRemote(ctx context.Context) (string, error) {
	remote := s.repo.commitOf(ctx, "origin/"+s.branch)
	if remote == "" {
		return "", fmt.Errorf("origin/%s does not exist", s.branch)
	}
	ok, err := s.repo.verifyDescends(ctx, s.lastGood, remote)
	if err != nil {
		return "", err
	}
	if !ok {
		a := &Alert{Kind: AlertHistoryRewritten, LastGood: s.lastGood, Remote: remote}
		s.setAlert(a)
		return "", &HistoryRewrittenError{LastGood: a.LastGood, Remote: a.Remote}
	}
	s.setAlert(nil)
	return remote, nil
}

// advance records remote as the last accepted commit. Callers hold mu.
func (s *Store) advance(ctx context.Context, remote string) {
	if remote == "" || remote == s.lastGood {
		return
	}
	s.lastGood = remote
	if err := s.repo.writeLastGood(ctx, s.branch, remote); err != nil {
		s.log.Warn("could not store the last good commit", "err", err)
	}
}

// initLastGood loads the stored commit, or seeds it from the remote-tracking
// ref the clone already has (before the first fetch of this process).
func (s *Store) initLastGood(ctx context.Context) {
	s.lastGood = s.repo.readLastGood(ctx, s.branch)
	if s.lastGood == "" {
		s.advance(ctx, s.repo.commitOf(ctx, "origin/"+s.branch))
	}
}

// Errors of accepting a remote tip.
var (
	// ErrNoAlert: there is no rewritten history to accept.
	ErrNoAlert = errors.New("no_alert: the remote history was not rewritten, there is nothing to accept")
	// ErrNotRemoteTip: the commit is not the current tip of the remote branch.
	ErrNotRemoteTip = errors.New("that commit is not the current tip of the remote branch")
	// ErrLocalCommits: the clone has commits that exist nowhere else.
	ErrLocalCommits = errors.New("the clone has local commits that are not on any remote branch and would be lost; push or save them first (nothing was changed)")
)

var hexPrefixRe = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// ErrRepoDirty is declared in store.go. cloneProblem is the one check that the
// server's clone is exactly what Rackbook left there: every file tracked and
// unmodified. Any modified, untracked or ignored file outside .git refuses the
// write, the pull and the accept (nothing is deleted or overwritten); this also
// covers directory-versus-file and case-insensitive collisions without special
// cases. The server clone must contain only tracked files.
func (r *Repo) cloneProblem(ctx context.Context) error {
	out, err := r.git(ctx, "status", "--porcelain", "--untracked-files=all", "--ignored=matching")
	if err != nil {
		return err
	}
	if out != "" {
		return fmt.Errorf("%w: %s", ErrRepoDirty, firstLines(out, 3))
	}
	return nil
}

// acceptTip fetches and checks that commit may be accepted as the new base,
// without touching the work tree: the remote really is not a descendant of
// lastGood (ErrNoAlert), commit is exactly its tip (ErrNotRemoteTip), and the
// config committed at the tip loads (*ConfigError). It returns the tip.
func (r *Repo) acceptTip(ctx context.Context, branch, lastGood, commit, configPath string) (string, error) {
	commit = strings.ToLower(strings.TrimSpace(commit))
	if !hexPrefixRe.MatchString(commit) {
		return "", fmt.Errorf("%w: give the full commit hash (at least 7 hex characters)", ErrNotRemoteTip)
	}
	if _, err := r.git(ctx, "fetch", "--quiet", "origin"); err != nil {
		return "", err
	}
	remote := r.commitOf(ctx, "origin/"+branch)
	if remote == "" {
		return "", fmt.Errorf("origin/%s does not exist", branch)
	}
	if ok, err := r.verifyDescends(ctx, lastGood, remote); err != nil {
		return "", err
	} else if ok {
		return "", ErrNoAlert
	}
	if !strings.HasPrefix(remote, commit) {
		return "", fmt.Errorf("%w (it is %s)", ErrNotRemoteTip, short(remote))
	}
	if err := r.configLoadsAt(ctx, remote, configPath); err != nil {
		return "", &ConfigError{Err: err}
	}
	return remote, nil
}

// AcceptRemote accepts the rewritten remote history after an administrator
// checked it. It refuses, changing nothing, when no rewrite is active
// (ErrNoAlert), when commit (full hash or a prefix of at least 7 characters)
// is not exactly the tip after a fresh fetch, when the clone has any modified,
// untracked or ignored file (ErrRepoDirty), when it has local commits that
// are on no remote branch (ErrLocalCommits), or when the tip's config does not
// load (ErrConfig). Then it resets the clone to the tip and reloads; if the
// reload fails (for example a schema path that is a symlink out of the
// repository) it resets back, keeps the old base and alert and returns the
// config error. It returns the accepted hash.
func (s *Store) AcceptRemote(ctx context.Context, commit string) (string, error) {
	if !s.HasRemote() {
		return "", errors.New("the data repository has no origin remote")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.repo.cloneProblem(ctx); err != nil {
		return "", err
	}
	remote, err := s.repo.acceptTip(ctx, s.branch, s.lastGood, commit, s.opts.ConfigPath)
	if err != nil {
		return "", err
	}
	// The old accepted history is no longer on a remote branch after the
	// rewrite, so it is excluded explicitly; anything else would be lost.
	if n, err := s.repo.git(ctx, "rev-list", "--count", "HEAD", "--not", "--remotes", s.lastGood); err != nil {
		return "", err
	} else if n != "0" {
		return "", fmt.Errorf("%w (%s commit(s))", ErrLocalCommits, n)
	}
	prev, err := s.repo.Head(ctx)
	if err != nil {
		return "", err
	}
	if _, err := s.repo.git(ctx, "reset", "--quiet", "--hard", "origin/"+s.branch); err != nil {
		return "", err
	}
	if err := s.reload(); err != nil {
		if _, rerr := s.repo.git(ctx, "reset", "--quiet", "--hard", prev); rerr != nil {
			s.log.Error("could not move the clone back after a failed accept", "err", rerr)
		}
		_ = s.reload() // the old config loads again; clears the config error
		return "", err
	}
	s.advance(ctx, remote)
	s.setAlert(nil)
	s.log.Warn("remote history accepted by an administrator", "remote", remote)
	return remote, nil
}

// AcceptRemoteInClone is for the user's own clone (rackbook accept-remote): it
// runs the same checks (a rewrite is active, commit is the remote tip, its
// config loads) and then only records the tip as the new base. It never resets
// or changes the work tree: updating the branch is up to the user, with normal
// git. configPath is the clone's rackbook.yml.
func AcceptRemoteInClone(ctx context.Context, configPath, commit string) (string, error) {
	r := &Repo{Dir: filepath.Dir(configPath)}
	if !r.IsRepo(ctx) || r.RemoteURL(ctx) == "" {
		return "", errors.New("not inside a Git repository with an origin remote")
	}
	br, err := r.Branch(ctx)
	if err != nil || br == "HEAD" {
		return "", errors.New("detached HEAD: check out the branch first")
	}
	remote, err := r.acceptTip(ctx, br, r.readLastGood(ctx, br), commit, configPath)
	if err != nil {
		return "", err
	}
	return remote, r.writeLastGood(ctx, br, remote)
}

func firstLines(s string, n int) string {
	l := strings.Split(s, "\n")
	if len(l) > n {
		l = append(l[:n], "...")
	}
	return strings.Join(l, "; ")
}

// configLoadsAt checks that the config file as committed at ref parses and
// validates, without checking anything out.
func (r *Repo) configLoadsAt(ctx context.Context, ref, configPath string) error {
	prefix, err := r.git(ctx, "rev-parse", "--show-prefix")
	if err != nil {
		return err
	}
	data, err := r.git(ctx, "cat-file", "blob", ref+":"+prefix+filepath.Base(configPath))
	if err != nil {
		return fmt.Errorf("the config file is not in the accepted commit: %w", err)
	}
	_, err = config.Parse([]byte(data), configPath)
	return err
}

// CheckRemoteHistory fails with *HistoryRewrittenError when origin's branch no
// longer descends from the last commit seen in the clone at dir. The CLI calls
// it before it edits anything. With strict (--push) a failing fetch is an
// error; without it offline is reported so the caller can warn and go on.
func CheckRemoteHistory(ctx context.Context, dir string, strict bool) (offline bool, err error) {
	r := &Repo{Dir: dir}
	if !r.IsRepo(ctx) {
		return false, nil
	}
	return r.checkRemoteHistory(ctx, strict)
}

// advanceToHead records our own just-pushed commit as the last good one.
// Without this, a force push of "last good + something else" would look like
// a normal fast-forward and not like a rewrite. Callers hold mu.
func (s *Store) advanceToHead(ctx context.Context) {
	if h, err := s.repo.Head(ctx); err == nil {
		s.advance(ctx, h)
	}
}
