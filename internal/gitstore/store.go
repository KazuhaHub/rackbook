package gitstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
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
	Via          string        // Edited-via trailer value, default "rackbook"

	GitHubToken string       // pr mode: token for the REST API
	GitHubRepo  string       // "owner/repo"; default parsed from the origin URL
	GitHubAPI   string       // REST base URL; default derived from the origin host
	HTTPClient  *http.Client // default http.DefaultClient with a timeout
	Logger      *slog.Logger
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
	log    *slog.Logger
	http   *http.Client
	token  string
	via    string

	ghOwner, ghRepo, ghAPI string
	lastStamp              time.Time
	beforePush             func()                                         // test seam: runs between commit and push
	pushFn                 func(ctx context.Context, branch string) error // test seam: replaces the push
	loadErr                atomic.Value                                   // string, last reload error
}

// Open loads the config and ledger and detects Git. Inside a repository with
// an origin it fast-forwards to the remote first (best effort).
func Open(ctx context.Context, o Options) (*Store, error) {
	cfg, err := config.Load(o.ConfigPath)
	if err != nil {
		return nil, err
	}
	s := &Store{opts: o, log: o.Logger, http: o.HTTPClient, token: o.GitHubToken, via: o.Via}
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
	s.repo = &Repo{Dir: cfg.Dir}
	if !o.NoGit && s.repo.IsRepo(ctx) {
		s.git = true
		s.remote = s.repo.RemoteURL(ctx)
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
	if s.git && s.remote != "" {
		if err := s.Pull(ctx); err != nil {
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

// Config returns the current config.
func (s *Store) Config() *config.Config { return s.cur.Load().Config }

// reload re-reads config and ledger; callers hold mu. On a config error the
// previous ledger stays in place.
func (s *Store) reload() error {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		return err
	}
	s.cur.Store(ledger.Load(cfg, nil))
	return nil
}

// Pull fetches and fast-forwards to origin/<branch>, reloading if HEAD moved.
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
	if _, err := s.repo.git(ctx, "merge", "--quiet", "--ff-only", "origin/"+s.branch); err != nil {
		return err
	}
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
			if err := s.Pull(ctx); err != nil {
				s.log.Warn("pull failed", "err", err)
			}
		}
	}
}

// Errors for a server clone that is not in the state the store requires.
var (
	ErrRepoDirty    = errors.New("the server's clone of the data repository has uncommitted local changes; an administrator must clean it on the server before edits can be saved")
	ErrRepoDiverged = errors.New("the server's clone of the data repository has local commits that are not on the remote; an administrator must fix it on the server before edits can be saved")
)

// syncLocked moves the work tree to origin/<branch>; callers hold mu. It
// refuses to discard uncommitted or unpushed work: the clone is server-owned.
func (s *Store) syncLocked(ctx context.Context) error {
	if dirty, err := s.repo.Dirty(ctx); err != nil {
		return err
	} else if dirty {
		return ErrRepoDirty
	}
	if !s.HasRemote() {
		return s.reload()
	}
	if _, err := s.repo.git(ctx, "fetch", "--quiet", "origin"); err != nil {
		return err
	}
	if n, err := s.repo.git(ctx, "rev-list", "--count", "origin/"+s.branch+"..HEAD"); err == nil && n != "0" {
		return fmt.Errorf("%w (%s commit(s) ahead of origin/%s)", ErrRepoDiverged, n, s.branch)
	}
	if _, err := s.repo.git(ctx, "reset", "--quiet", "--hard", "origin/"+s.branch); err != nil {
		return err
	}
	return s.reload()
}

// editorIdentity picks the commit author: the editor, else the Git config, else the committer.
func (s *Store) editorIdentity(ctx context.Context, editor Identity) Identity {
	if !editor.IsZero() {
		if editor.Name == "" {
			editor.Name = strings.SplitN(editor.Email, "@", 2)[0]
		}
		return editor
	}
	if id := s.repo.ConfigIdentity(ctx); id.Name != "" && id.Email != "" {
		return id
	}
	return s.opts.Committer
}

// Write applies op. Without Git the files are edited in place. With Git the
// edit is committed (author = editor, committer = service identity) and
// pushed; if the push is rejected because the remote moved, the same edit is
// replayed on the new tip, at most MaxAttempts times.
func (s *Store) Write(ctx context.Context, op edit.Op, editor Identity) (*WriteResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.git {
		if err := s.reload(); err != nil {
			return nil, err
		}
		res, err := edit.Apply(s.cur.Load().Config, op)
		if err != nil {
			return nil, err
		}
		if err := s.reload(); err != nil {
			return nil, err
		}
		return &WriteResult{Result: res}, nil
	}
	pr := s.cur.Load().Config.Write.Mode == "pr"
	if pr && s.token == "" {
		return nil, errors.New("write.mode is pr but RACKBOOK_GITHUB_TOKEN is not set")
	}
	if pr && !s.HasRemote() {
		return nil, errors.New("write.mode is pr but the repository has no origin remote")
	}
	author := s.editorIdentity(ctx, editor)
	var lastErr error
	for attempt := 1; attempt <= MaxAttempts; attempt++ {
		if err := s.syncLocked(ctx); err != nil {
			return nil, err
		}
		res, err := edit.Apply(s.cur.Load().Config, op)
		if err != nil {
			return nil, err
		}
		if !res.Changed() {
			return &WriteResult{Result: res}, nil
		}
		parent, _ := s.repo.Head(ctx)
		msg := CommitMessage(res.Subject(), author, s.via)
		short, err := s.repo.Commit(ctx, res.Files, msg, author, s.opts.Committer)
		if err != nil {
			s.discard(ctx, parent, res.Files)
			return nil, err
		}
		if !s.HasRemote() {
			if err := s.reload(); err != nil {
				return nil, err
			}
			return &WriteResult{Result: res, Commit: short}, nil
		}
		if pr {
			url, err := s.openPR(ctx, res, author, msg)
			s.discard(ctx, parent, res.Files)
			if err != nil {
				return nil, err
			}
			_ = s.reload()
			return &WriteResult{Result: res, Commit: url}, nil
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
					if err := s.reload(); err != nil {
						return nil, err
					}
					return &WriteResult{Result: res, Commit: short}, nil
				}
			}
			// A moved remote means replay; anything else is a real failure.
			tip, _ := s.repo.git(ctx, "rev-parse", "origin/"+s.branch)
			s.discard(ctx, parent, res.Files)
			if ferr != nil || tip == parent {
				return nil, fmt.Errorf("push failed: %w", err)
			}
			s.log.Info("push rejected, replaying edit on the new tip", "attempt", attempt)
			continue
		}
		if err := s.reload(); err != nil {
			return nil, err
		}
		return &WriteResult{Result: res, Commit: short}, nil
	}
	return nil, fmt.Errorf("giving up after %d attempts, the remote keeps changing: %w", MaxAttempts, lastErr)
}

// discard drops our unpushed commit and restores only the files the edit
// touched; changes the store did not make are never reset.
func (s *Store) discard(ctx context.Context, parent string, files []string) {
	if parent == "" {
		return
	}
	if _, err := s.repo.git(ctx, "reset", "--quiet", parent); err != nil {
		s.log.Error("could not reset the index", "err", err)
		return
	}
	if len(files) > 0 {
		if _, err := s.repo.git(ctx, append([]string{"checkout", "--quiet", "--"}, files...)...); err != nil {
			s.log.Error("could not restore the edited files", "err", err)
		}
	}
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

// openPR pushes HEAD to rackbook/<user>/<timestamp> and opens a pull request.
func (s *Store) openPR(ctx context.Context, res *edit.Result, author Identity, msg string) (string, error) {
	user := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(strings.SplitN(author.Email, "@", 2)[0]), "-"), "-")
	if user == "" {
		user = "editor"
	}
	now := time.Now().UTC().Truncate(time.Second)
	if !now.After(s.lastStamp) {
		now = s.lastStamp.Add(time.Second)
	}
	s.lastStamp = now
	branch := fmt.Sprintf("rackbook/%s/%s", user, now.Format("20060102-150405"))
	if err := s.repo.Push(ctx, branch); err != nil {
		return "", fmt.Errorf("push %s: %w", branch, err)
	}
	body := strings.SplitN(msg, "\n\n", 2)[1]
	return s.createPR(ctx, branch, s.branch, res.Subject(), body)
}

// History lists recent commits, optionally only those touching a collection's file.
func (s *Store) History(ctx context.Context, limit int, collection string) ([]Commit, error) {
	if !s.git {
		return []Commit{}, nil
	}
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	args := []string{"log", "-n", fmt.Sprint(limit), "--format=%h%x1f%an%x1f%ae%x1f%aI%x1f%s"}
	if collection != "" {
		c := s.cur.Load().Collection(collection)
		if c == nil {
			return nil, fmt.Errorf("unknown collection %q", collection)
		}
		args = append(args, "--", filepath.FromSlash(c.File))
	}
	out, err := s.repo.git(ctx, args...)
	if err != nil {
		if strings.Contains(err.Error(), "does not have any commits") {
			return []Commit{}, nil
		}
		return nil, err
	}
	commits := []Commit{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\x1f")
		if len(f) != 5 {
			continue
		}
		date := f[3]
		if t, err := time.Parse(time.RFC3339, f[3]); err == nil {
			date = t.UTC().Format(time.RFC3339)
		}
		commits = append(commits, Commit{Hash: f[0], Author: f[1], Email: f[2], Date: date, Subject: f[4]})
	}
	return commits, nil
}
