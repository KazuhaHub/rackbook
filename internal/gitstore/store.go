package gitstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/githubapp"
	"github.com/kazuhahub/rackbook/internal/ledger"
)

// MaxAttempts bounds how often a write is replayed after a rejected push.
const MaxAttempts = 3

// DefaultCommitter is used when no --committer is given.
var DefaultCommitter = Identity{Name: "Rackbook", Email: "rackbook@localhost"}

// Options configures a Store.
type Options struct {
	ConfigPath   string
	NoGit        bool          // never use git, even inside a repository
	Committer    Identity      // zero = DefaultCommitter
	PullInterval time.Duration // 0 = no periodic pull from Run
	Via          string        // product name in the Edited-via trailer, default "rackbook"
	Runner       Runner        // runs git; nil = the real git

	// GitHubApp, when set, replaces SSH deploy keys and RACKBOOK_GITHUB_TOKEN:
	// git talks https with installation tokens narrowed to this repository
	// (contents: write to fetch and push, pull_requests: write to open pull
	// requests). Needs an https (or ssh, rewritten) GitHub origin.
	GitHubApp   TokenSource
	GitHubToken string       // pr mode: token for the REST API
	GitHubRepo  string       // "owner/repo"; default parsed from the origin URL
	GitHubAPI   string       // REST base URL; default derived from the origin host
	HTTPClient  *http.Client // default http.DefaultClient with a timeout
	Logger      *slog.Logger

	// OnCommit, when set, is called after this server's own commit reached the
	// tracked branch (a pushed commit; not a pull request branch). hash is the
	// full commit hash, who the caller (nil = anonymous) and record the Record
	// trailer value ("" for none). It runs under the write lock: keep it short.
	OnCommit func(hash string, who *auth.Identity, record string)
}

// Commit is one history entry.
type Commit struct {
	Hash    string `json:"hash"`
	Author  string `json:"author"`
	Email   string `json:"email"`
	Date    string `json:"date"`
	Subject string `json:"subject"`
}

// WriteResult is the outcome of Write.
type WriteResult struct {
	*edit.Result
	// Commit is the short commit hash, the pull request URL in pr mode, or ""
	// when nothing was committed (no Git, or nothing changed).
	Commit string
	// PullRequest says Commit is a pull request URL: nothing reached the
	// tracked branch.
	PullRequest bool
}

// Store serves the current ledger and applies writes.
type Store struct {
	opts   Options
	mu     sync.Mutex // serialises writes, pulls and reloads
	cur    atomic.Pointer[ledger.Ledger]
	repo   *Repo
	git    bool
	remote string // origin URL, "" when none
	branch string
	tip    atomic.Pointer[string] // copy of lastGood for lock-free history reads
	log    *slog.Logger
	http   *http.Client
	token  string
	app    TokenSource
	via    string

	ghOwner, ghRepo, ghAPI string
	lastStamp              time.Time
	beforePush             func()                                         // test seam: runs between commit and push
	pushFn                 func(ctx context.Context, branch string) error // test seam: replaces the push

	lastGood string                 // last accepted remote commit; guarded by mu
	alert    atomic.Pointer[Alert]  // set while the remote history is rewritten
	cfgErr   atomic.Pointer[string] // why the latest config failed to load
}

// Open loads the config and ledger and detects Git. Inside a repository with
// an origin it fast-forwards to the remote first (best effort).
func Open(ctx context.Context, o Options) (*Store, error) {
	cfg, err := config.Load(o.ConfigPath)
	if err != nil {
		return nil, err
	}
	s := &Store{opts: o, log: o.Logger, http: o.HTTPClient, token: o.GitHubToken, app: o.GitHubApp, via: o.Via}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.http == nil {
		s.http = &http.Client{Timeout: 30 * time.Second}
	}
	if s.via == "" {
		s.via = "rackbook"
	}
	if s.opts.Committer.IsZero() {
		s.opts.Committer = DefaultCommitter
	}
	if o.GitHubRepo != "" {
		parts := strings.SplitN(o.GitHubRepo, "/", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("github repo %q must be owner/repo", o.GitHubRepo)
		}
		s.ghOwner, s.ghRepo = parts[0], parts[1]
	}
	s.ghAPI = o.GitHubAPI
	s.repo = &Repo{Dir: cfg.Dir, Runner: o.Runner, IgnoreUserConfig: true}
	if o.GitHubApp != nil {
		s.repo.Auth = &GitAuth{Source: o.GitHubApp, Perms: githubapp.Permissions{Contents: "write"}}
	}
	if !o.NoGit && s.repo.IsRepo(ctx) {
		s.git = true
		s.remote = s.repo.RemoteURL(ctx)
		if o.GitHubApp != nil && o.GitHubRepo != "" && s.remote != "" {
			// The App's token and the https rewrite follow the origin URL alone;
			// --github-repo must not point them somewhere else.
			if _, ow, rp, perr := ParseRemote(s.remote); perr == nil && !strings.EqualFold(ow+"/"+rp, o.GitHubRepo) {
				return nil, fmt.Errorf("--github-repo %s does not match the origin %s (%s/%s): with a GitHub App the repository comes from origin; fix one of them", o.GitHubRepo, s.remote, ow, rp)
			}
		}
		s.branch = cfg.Write.Branch
		cur, err := s.repo.Branch(ctx)
		if err != nil {
			return nil, err
		}
		if s.branch == "" {
			s.branch = cur
		}
		if s.branch == "HEAD" {
			return nil, errors.New("the data repository is on a detached HEAD; check out a branch or set write.branch")
		}
		if cur != s.branch {
			if _, err := s.repo.git(ctx, "checkout", "--quiet", s.branch); err != nil {
				return nil, err
			}
		}
	}
	s.cur.Store(ledger.Load(cfg, nil))
	if !cfg.SecretScanner().Enabled() {
		s.log.Warn("secret_scan.enabled is false: nothing checks the records, data types and state files Rackbook writes for secrets, and Rackbook's commits bypass repository pre-commit hooks")
	}
	if s.git && s.remote != "" {
		s.initLastGood(ctx)
		if err := s.Pull(ctx); err != nil && !errors.Is(err, ErrHistoryRewritten) {
			s.log.Warn("initial pull failed", "err", err)
		}
	}
	return s, nil
}

// GitEnabled reports whether writes are committed to Git.
func (s *Store) GitEnabled() bool { return s.git }

// HasRemote reports whether writes are pushed.
func (s *Store) HasRemote() bool { return s.git && s.remote != "" }

// Ledger returns the current ledger. Without Git the files are re-read on
// every call so edits made by hand show up immediately.
func (s *Store) Ledger() *ledger.Ledger {
	if !s.git {
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.reload(); err != nil {
			s.log.Warn("reload failed", "err", err)
		}
	}
	return s.cur.Load()
}

// Config returns the current config (re-read from disk without Git, like Ledger).
func (s *Store) Config() *config.Config { return s.Ledger().Config }

// reload re-reads config and ledger; callers hold mu. On a config error the
// previous ledger stays in place.
func (s *Store) reload() error {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		msg := err.Error()
		if old := s.cfgErr.Swap(&msg); old == nil || *old != msg {
			s.log.Error("rackbook.yml does not load: serving the last good config read-only", "err", err)
		}
		return &ConfigError{Err: err}
	}
	s.cfgErr.Store(nil)
	s.cur.Store(ledger.Load(cfg, nil))
	return nil
}

// ErrConfig is matched by errors.Is for a *ConfigError.
var ErrConfig = errors.New("rackbook.yml does not load")

// ConfigError says the config on disk (after a pull, a reset or a hand edit)
// failed to load. The store keeps serving the last good config and ledger for
// reads and refuses writes until a config loads again.
type ConfigError struct{ Err error }

func (e *ConfigError) Error() string {
	return "the configuration does not load, writes are paused: " + e.Err.Error()
}
func (e *ConfigError) Unwrap() error   { return e.Err }
func (e *ConfigError) Is(t error) bool { return t == ErrConfig }

// ConfigProblem returns why the latest config failed to load, or "".
func (s *Store) ConfigProblem() string {
	if p := s.cfgErr.Load(); p != nil {
		return *p
	}
	return ""
}

// Pull fetches and fast-forwards to origin/<branch>, reloading if HEAD moved.
// If the remote history was rewritten it returns *HistoryRewrittenError and
// leaves the clone alone.
func (s *Store) Pull(ctx context.Context) error {
	if !s.HasRemote() {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	before, _ := s.repo.Head(ctx)
	if _, err := s.repo.git(ctx, "fetch", "--quiet", "origin"); err != nil {
		return err
	}
	remote, err := s.verifyRemote(ctx)
	if err != nil {
		return err
	}
	if err := s.repo.cloneProblem(ctx); err != nil {
		return err
	}
	if _, err := s.repo.git(ctx, "merge", "--quiet", "--ff-only", "origin/"+s.branch); err != nil {
		return err
	}
	s.advance(ctx, remote)
	if after, _ := s.repo.Head(ctx); after != before || before == "" {
		return s.reload()
	}
	return nil
}

// Run pulls every PullInterval until ctx ends.
func (s *Store) Run(ctx context.Context) {
	if !s.HasRemote() || s.opts.PullInterval <= 0 {
		return
	}
	t := time.NewTicker(s.opts.PullInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Pull(ctx); err != nil && !errors.Is(err, ErrHistoryRewritten) {
				s.log.Warn("pull failed", "err", err)
			}
		}
	}
}

// Errors for a server clone that is not in the state the store requires.
var (
	ErrRepoDirty    = errors.New("the server's clone of the data repository has uncommitted, untracked or ignored files (it must contain only tracked files); an administrator must clean it on the server before edits can be saved")
	ErrRepoDiverged = errors.New("the server's clone of the data repository has local commits that are not on the remote; an administrator must fix it on the server before edits can be saved")
)

// syncLocked moves the work tree to origin/<branch>; callers hold mu. It
// refuses to discard uncommitted or unpushed work: the clone is server-owned.
func (s *Store) syncLocked(ctx context.Context) error {
	if err := s.repo.cloneProblem(ctx); err != nil {
		return err
	}
	if !s.HasRemote() {
		return s.reload()
	}
	if _, err := s.repo.git(ctx, "fetch", "--quiet", "origin"); err != nil {
		return err
	}
	remote, err := s.verifyRemote(ctx)
	if err != nil {
		return err
	}
	if n, err := s.repo.git(ctx, "rev-list", "--count", "origin/"+s.branch+"..HEAD"); err == nil && n != "0" {
		return fmt.Errorf("%w (%s commit(s) ahead of origin/%s)", ErrRepoDiverged, n, s.branch)
	}
	if _, err := s.repo.git(ctx, "reset", "--quiet", "--hard", "origin/"+s.branch); err != nil {
		return err
	}
	s.advance(ctx, remote)
	return s.reload()
}

// authorFor picks the commit author: who, else the Git config, else the committer.
func (s *Store) authorFor(ctx context.Context, who *auth.Identity) Identity {
	if a := AuthorOf(who); !a.IsZero() {
		return a
	}
	if id := s.repo.ConfigIdentity(ctx); id.Name != "" && id.Email != "" {
		return id
	}
	return s.opts.Committer
}

// WriteOptions adjusts how one write reaches the repository.
type WriteOptions struct {
	// ForcePR sends this write through a pull request even when write.mode is
	// push. It never turns a pr-mode repository into a push one.
	ForcePR bool
	// BranchPrefix is the pull request branch up to the timestamp, e.g.
	// "rackbook/mcp/alice". Default: "rackbook/<author>".
	BranchPrefix string
	// Direct commits to the tracked branch even when write.mode is pr. It is for
	// state that must work before anyone could merge a pull request (a passkey
	// that only exists after a merge cannot be used to log in).
	Direct bool
}

// Write applies op on behalf of who (nil = anonymous) with the default options;
// see WriteFunc.
func (s *Store) Write(ctx context.Context, op edit.Op, who *auth.Identity) (*WriteResult, error) {
	return s.WriteFunc(ctx, ApplyOp(op), who, WriteOptions{})
}

// ApplyFunc performs one change on the files under cfg.Dir and reports which
// files it wrote and the commit subject and trailer (see edit.Result). It is
// called again on the new tip when a push is rejected, so it must be
// repeatable: it describes the change, not the file positions.
type ApplyFunc func(cfg *config.Config) (*edit.Result, error)

// ApplyOp is the ApplyFunc of a record edit.
func ApplyOp(op edit.Op) ApplyFunc {
	return func(cfg *config.Config) (*edit.Result, error) { return edit.Apply(cfg, op) }
}

// ApplyOpAs is ApplyOp with the modules allow list (ModuleGuard) applied for
// who. The guard reads the config of the checkout the write is applied to, so
// a modules: entry that a pull or a retry just brought in is already in force.
func ApplyOpAs(who *auth.Identity, op edit.Op) ApplyFunc {
	return func(cfg *config.Config) (*edit.Result, error) {
		op, err := ModuleGuard(who, cfg, op)
		if err != nil {
			return nil, err
		}
		return edit.Apply(cfg, op)
	}
}

// WriteFunc is the one write path for any change to the data repository:
// record edits (ApplyOp), data type changes (types.Apply) and the MCP write
// tools all go through it. Without Git the files are changed in place. With Git
// the change is committed (author = who, committer = service identity; message
// built by CommitMessage, with a Record trailer) and pushed; if the push is
// rejected because the remote moved, apply runs again on the new tip, at most
// MaxAttempts times. In pr mode (or with opts.ForcePR) the commit goes to a new
// branch and a pull request is opened instead.
func (s *Store) WriteFunc(ctx context.Context, apply ApplyFunc, who *auth.Identity, opts WriteOptions) (*WriteResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.git {
		if opts.ForcePR {
			return nil, errPRNeedsGit
		}
		if err := s.reload(); err != nil {
			return nil, err
		}
		res, err := apply(s.cur.Load().Config)
		if err != nil {
			return nil, err
		}
		if err := s.reload(); err != nil {
			return nil, err
		}
		return &WriteResult{Result: res}, nil
	}
	var res *edit.Result
	commit, pr, err := s.commitLoop(ctx, who, opts, func() (*change, error) {
		r, err := apply(s.cur.Load().Config)
		if err != nil {
			return nil, err
		}
		res = r
		return &change{Files: r.Files, Subject: r.Subject(), Record: r.Record(), Trailers: r.Trailers}, nil
	})
	if err != nil {
		return nil, err
	}
	return &WriteResult{Result: res, Commit: commit, PullRequest: pr}, nil
}

// DryRunFunc runs apply as WriteFunc would, up to and including the change
// itself, but writes nothing: apply must not write (edit.Op.DryRun). It takes the
// write lock, makes the same checks a write makes first (a clone that is dirty,
// diverged or behind a rewritten remote, a config that does not load, a pull
// request that cannot be opened) and syncs the clone to the remote the same way.
// pr says the real write would be a pull request.
func (s *Store) DryRunFunc(ctx context.Context, apply ApplyFunc, opts WriteOptions) (res *edit.Result, pr bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.git {
		if opts.ForcePR {
			return nil, false, errPRNeedsGit
		}
		if err := s.reload(); err != nil {
			return nil, false, err
		}
		res, err = apply(s.cur.Load().Config)
		return res, false, err
	}
	pr = !opts.Direct && (opts.ForcePR || s.cur.Load().Config.Write.Mode == "pr")
	if pr && !s.canPR() {
		return nil, false, fmt.Errorf("%w: write.mode is pr or this write must be a pull request, but neither a GitHub App nor RACKBOOK_GITHUB_TOKEN is set", ErrPRUnavailable)
	}
	if pr && !s.HasRemote() {
		if opts.ForcePR {
			return nil, false, errPRNeedsGit
		}
		return nil, false, errors.New("write.mode is pr but the repository has no origin remote")
	}
	if err := s.syncLocked(ctx); err != nil {
		return nil, false, err
	}
	res, err = apply(s.cur.Load().Config)
	return res, pr, err
}

// canPR reports whether a credential for opening pull requests is configured.
func (s *Store) canPR() bool { return s.token != "" || s.app != nil }

// ErrPRUnavailable is matched by errors.Is when a write must go through a pull
// request but the server cannot open one (no Git remote, or no GitHub token).
var ErrPRUnavailable = errors.New("pull requests are unavailable")

var errPRNeedsGit = fmt.Errorf("%w: this write must go through a pull request, but the data directory is not a Git repository with an origin remote", ErrPRUnavailable)

// change is what an apply function did to the work tree.
type change struct {
	Files   []string // config-relative files written; empty = nothing changed
	Subject string
	Record  string // Record trailer value, "" for none
	// Trailers are extra trailers after Record (Secret-scan confirmations).
	Trailers []string
}

// commitLoop is the Git write path shared by record edits and state files:
// sync the clone to origin, apply, commit, then push (replaying apply on a
// moved remote) or open a pull request. Callers hold mu and have checked s.git.
// It returns the short commit hash, or the pull request URL with pr set.
func (s *Store) commitLoop(ctx context.Context, who *auth.Identity, opts WriteOptions, apply func() (*change, error)) (commit string, pr bool, err error) {
	pr = !opts.Direct && (opts.ForcePR || s.cur.Load().Config.Write.Mode == "pr")
	if pr && !s.canPR() {
		return "", false, fmt.Errorf("%w: write.mode is pr or this write must be a pull request, but neither a GitHub App nor RACKBOOK_GITHUB_TOKEN is set", ErrPRUnavailable)
	}
	if pr && !s.HasRemote() {
		if opts.ForcePR {
			return "", false, errPRNeedsGit
		}
		return "", false, errors.New("write.mode is pr but the repository has no origin remote")
	}
	author := s.authorFor(ctx, who)
	var lastErr error
	for attempt := 1; attempt <= MaxAttempts; attempt++ {
		if err := s.syncLocked(ctx); err != nil {
			return "", false, err
		}
		ch, err := apply()
		if err != nil {
			return "", false, err
		}
		if len(ch.Files) == 0 {
			return "", false, nil
		}
		parent, _ := s.repo.Head(ctx)
		msg := CommitMessage(ch.Subject, who, s.via, ch.Record, ch.Trailers...)
		short, err := s.repo.Commit(ctx, ch.Files, msg, author, s.opts.Committer)
		if err != nil {
			s.discard(ctx, parent, ch.Files)
			return "", false, err
		}
		full, _ := s.repo.Head(ctx)
		if !s.HasRemote() {
			if err := s.reload(); err != nil {
				return "", false, err
			}
			return short, false, nil
		}
		if pr {
			url, err := s.openPR(ctx, ch.Subject, opts.BranchPrefix, author, msg)
			s.discard(ctx, parent, ch.Files)
			if err != nil {
				return "", false, err
			}
			_ = s.reload()
			return url, true, nil
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
			// The push may have gone through although the client saw an error.
			_, ferr := s.repo.git(ctx, "fetch", "--quiet", "origin")
			if ferr == nil {
				if _, aerr := s.repo.git(ctx, "merge-base", "--is-ancestor", "HEAD", "origin/"+s.branch); aerr == nil {
					s.advanceToHead(ctx)
					s.committed(full, who, ch.Record)
					if err := s.reload(); err != nil {
						return "", false, err
					}
					return short, false, nil
				}
			}
			// A moved remote means replay; anything else is a real failure.
			tip, _ := s.repo.git(ctx, "rev-parse", "origin/"+s.branch)
			s.discard(ctx, parent, ch.Files)
			if ferr != nil || tip == parent {
				return "", false, fmt.Errorf("push failed: %w", err)
			}
			s.log.Info("push rejected, replaying edit on the new tip", "attempt", attempt)
			continue
		}
		s.advanceToHead(ctx)
		s.committed(full, who, ch.Record)
		if err := s.reload(); err != nil {
			return "", false, err
		}
		return short, false, nil
	}
	return "", false, fmt.Errorf("giving up after %d attempts, the remote keeps changing: %w", MaxAttempts, lastErr)
}

// committed tells Options.OnCommit about a commit that reached the branch.
func (s *Store) committed(hash string, who *auth.Identity, record string) {
	if s.opts.OnCommit != nil && hash != "" {
		s.opts.OnCommit(hash, who, record)
	}
}

// discard drops our unpushed commit and restores only the files the edit
// touched; changes the store did not make are never reset. A file the edit
// created (it is not in the parent commit) is removed again.
func (s *Store) discard(ctx context.Context, parent string, files []string) {
	if parent == "" {
		return
	}
	if _, err := s.repo.git(ctx, "reset", "--quiet", parent); err != nil {
		s.log.Error("could not reset the index", "err", err)
		return
	}
	for _, f := range files {
		if _, err := s.repo.git(ctx, "cat-file", "blob", parent+":./"+f); err != nil {
			if msg := err.Error(); !strings.Contains(msg, "Not a valid object name") && !strings.Contains(msg, "does not exist") && !strings.Contains(msg, "but not in") {
				s.log.Error("could not tell whether the edit created the file", "file", f, "err", err)
				continue
			}
			if err := os.Remove(filepath.Join(s.repo.Dir, filepath.FromSlash(f))); err != nil && !errors.Is(err, os.ErrNotExist) {
				s.log.Error("could not remove the created file", "file", f, "err", err)
			}
			continue
		}
		if _, err := s.repo.git(ctx, "checkout", "--quiet", "--", f); err != nil {
			s.log.Error("could not restore the edited file", "file", f, "err", err)
		}
	}
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

// Slug turns a name into a branch-name part: ASCII letters and digits, with
// runs of anything else as a single "-". Empty input gives "user".
func Slug(name string) string {
	out := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if out == "" {
		return "user"
	}
	if len(out) > 40 {
		out = strings.Trim(out[:40], "-")
	}
	return out
}

// openPR pushes HEAD to <prefix>/<timestamp> and opens a pull request. The
// default prefix is rackbook/<author>.
func (s *Store) openPR(ctx context.Context, title, prefix string, author Identity, msg string) (string, error) {
	if prefix == "" {
		user := Slug(strings.SplitN(author.Email, "@", 2)[0])
		if user == "user" {
			user = "editor"
		}
		prefix = "rackbook/" + user
	}
	now := time.Now().UTC().Truncate(time.Second)
	if !now.After(s.lastStamp) {
		now = s.lastStamp.Add(time.Second)
	}
	s.lastStamp = now
	branch := fmt.Sprintf("%s/%s", prefix, now.Format("20060102-150405"))
	if err := s.repo.Push(ctx, branch); err != nil {
		return "", fmt.Errorf("push %s: %w", branch, err)
	}
	body := strings.SplitN(msg, "\n\n", 2)[1]
	return s.createPR(ctx, branch, s.branch, title, body)
}

// History lists recent commits, optionally only those touching a collection's
// file. With collection and id it lists the commits that carry the trailer
// "Record: <collection>/<id>" (per-record history; the value comes from
// edit.RecordRef, the same function that writes it) and falls back to the
// collection's file history when no commit does (records edited before the
// trailer existed, or by hand).
func (s *Store) History(ctx context.Context, limit int, collection, id string) ([]Commit, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	return s.HistoryUpTo(ctx, limit, collection, id)
}

// MaxHistoryScan is the most commits HistoryUpTo returns.
var MaxHistoryScan = 2000

// HistoryUpTo is History for a caller that pages: limit is taken as given, up
// to MaxHistoryScan, instead of falling back to 20 above 200.
func (s *Store) HistoryUpTo(ctx context.Context, limit int, collection, id string) ([]Commit, error) {
	if !s.git {
		return []Commit{}, nil
	}
	limit = max(1, min(limit, MaxHistoryScan))
	tip, ok := s.trackedTip(ctx)
	if !ok {
		return []Commit{}, nil
	}
	if id != "" && collection == "" {
		return nil, errors.New("id needs a collection")
	}
	var file string
	if collection != "" {
		c := s.cur.Load().Collection(collection)
		if c == nil {
			return nil, fmt.Errorf("unknown collection %q", collection)
		}
		file = filepath.FromSlash(c.File)
	}
	if id != "" {
		want := edit.RecordRef(collection, ledger.SafeID(s.Config(), collection, id))
		// --fixed-strings makes the prefilter literal whatever grep.patternType
		// says; it is a substring match, so the exact value is checked below.
		commits, err := s.gitLog(ctx, tip, limit, want, "--fixed-strings", "--grep=Record: "+want)
		if err != nil || len(commits) > 0 {
			return commits, err
		}
	}
	if file != "" {
		return s.gitLog(ctx, tip, limit, "", "--", file)
	}
	return s.gitLog(ctx, tip, limit, "")
}

// gitLog runs git log from tip with extra selection arguments. With record set, only
// commits with exactly that Record trailer are returned (the limit then applies
// after this check, since the git-side filter is a substring match).
func (s *Store) gitLog(ctx context.Context, tip string, limit int, record string, extra ...string) ([]Commit, error) {
	args := []string{"log", "--format=%h%x1f%an%x1f%ae%x1f%aI%x1f%s%x1f%(trailers:key=Record,valueonly,separator=%x1e)"}
	if record == "" {
		args = append(args, "-n", fmt.Sprint(limit))
	}
	args = append(args, tip)
	if !slices.Contains(extra, "--") {
		// Rackbook's own state (passkeys) is not ledger history.
		extra = append(slices.Clone(extra), "--", ".", ":(exclude)"+config.StateDir)
	}
	out, err := s.repo.git(ctx, append(args, extra...)...)
	if err != nil {
		if strings.Contains(err.Error(), "does not have any commits") {
			return []Commit{}, nil
		}
		return nil, err
	}
	commits := []Commit{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\x1f")
		if len(f) != 6 {
			continue
		}
		if record != "" {
			found := false
			for _, v := range strings.Split(f[5], "\x1e") {
				found = found || strings.TrimSpace(v) == record
			}
			if !found {
				continue
			}
		}
		date := f[3]
		if t, err := time.Parse(time.RFC3339, f[3]); err == nil {
			date = t.UTC().Format(time.RFC3339)
		}
		commits = append(commits, Commit{Hash: f[0], Author: f[1], Email: f[2], Date: date, Subject: f[4]})
		if len(commits) == limit {
			break
		}
	}
	return commits, nil
}
