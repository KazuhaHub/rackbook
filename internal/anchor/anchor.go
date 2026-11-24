// Package anchor writes the optional daily audit anchor and checks the anchors
// already there (docs/design-audit.md, 3.1). Once a day, and only if the audit
// log has moved on, the head of the log (seq and the hash of that line) is
// appended to .rackbook/audit-anchors in the data repository and committed
// through the store's normal write path. Rewriting older audit lines then means
// rewriting Git history, which Rackbook already detects. The anchors are
// checked against the log whether or not the setting is on.
package anchor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/gitstore"
)

// Defaults of Run.
const (
	DefaultDelay = 30 * time.Second // the first check after start
	DefaultEvery = time.Hour
)

// Identity is who the anchor commit is made by: Rackbook itself. Its commit
// event in the audit log carries this identity, which is how the next day's check
// knows that event is not activity worth an anchor.
var Identity = &auth.Identity{ID: auth.AnchorIdentity, Name: "Rackbook audit anchor", Email: gitstore.DefaultCommitter.Email, Method: auth.MethodSystem}

func isOwnCommit(e audit.Event) bool {
	return e.Event == "commit" && e.Identity == Identity.ID && e.Method == auth.MethodSystem
}

// Files is the part of *gitstore.Store the anchor uses.
type Files interface {
	Config() *config.Config
	GitEnabled() bool
	StateFile(rel string) ([]byte, bool, error)
	CheckStateFileHistory(ctx context.Context, rel, after string) (*gitstore.StateCheck, error)
	MutateStateFile(ctx context.Context, rel, subject string, who *auth.Identity, mutate func(old []byte, exists bool) ([]byte, error), options ...gitstore.StateOption) (*gitstore.StateResult, error)
}

// Anchorer writes and checks the anchors. The zero value of the optional
// fields is the default.
type Anchorer struct {
	Log    *audit.Log // nil: there is nothing to anchor or to check
	Store  Files
	Logger *slog.Logger
	Now    func() time.Time // default time.Now
	Delay  time.Duration    // Run: before the first check; default DefaultDelay
	Every  time.Duration    // Run: between checks; default DefaultEvery

	mu        sync.Mutex      // guards warned, malformed and checked: Run and the pull hook call in
	checked   string          // the commit the history of the anchor file was last checked up to (memory only)
	warned    map[string]bool // problems with the setup, said once
	malformed string          // the malformed lines last reported
	failures  map[string]int  // checks that failed, by reason and tip: a repeat is recorded
}

func (a *Anchorer) log() *slog.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return slog.New(slog.DiscardHandler)
}

func (a *Anchorer) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

// warnOnce logs a warning about the setup the first time key comes up, and
// clears it when the setup is fine again.
func (a *Anchorer) warnOnce(key, msg string, args ...any) {
	a.mu.Lock()
	first := !a.warned[key]
	if a.warned == nil {
		a.warned = map[string]bool{}
	}
	a.warned[key] = true
	a.mu.Unlock()
	if first {
		a.log().Warn(msg, args...)
	}
}

func (a *Anchorer) clearWarning(key string) {
	a.mu.Lock()
	delete(a.warned, key)
	a.mu.Unlock()
}

// Verify checks the anchors against the audit log, and has a problem that is not in the chain yet
// written into it. It reads the anchor file at the tip of the data repository, and checks every
// commit that touches it, on every side of every merge, to see that each is its parent's file with
// lines appended and a regular file of reasonable size (anchor_rewritten otherwise). full checks
// every anchor and the whole history: at the start. After a pull only the anchors not verified
// before in this process, and the newest that matched, are looked up, and the history is checked
// from the commit it was last checked up to (from the start again when that commit is no longer an
// ancestor of the tip). It does not depend on audit.anchor: an anchor file left behind when the
// setting was switched off still catches tampering.
//
// A check that cannot be done must not pass quietly: it is recorded as anchor_unreadable (reason and
// tip are its fingerprint, so once per tip), and goes through the banner and acknowledgement like any
// other problem. A reason that git or the disk can cause for a moment (a timeout, a failed command)
// only warns the first time; if the same check fails again (whatever the tip is) it is recorded. A
// reason that is no accident (the file is not a regular file, git's answer does not fit what was
// asked, a version is too large) is recorded at once. Problems found in the same pass are recorded
// as well.
func (a *Anchorer) Verify(full bool) {
	if a.Log == nil || a.Store == nil || !a.Store.GitEnabled() {
		return
	}
	var extra []audit.Problem
	var tip string
	a.mu.Lock()
	after := a.checked
	a.mu.Unlock()
	if full {
		after = ""
	}
	checkedOK := false
	h, err := a.Store.CheckStateFileHistory(context.Background(), audit.AnchorsPath, after)
	if h != nil {
		tip = h.Tip
	}
	if err != nil {
		if p, ok := a.failure(err, "history_error", tip, "the history of the anchor file could not be checked"); ok {
			extra = append(extra, p)
		}
	} else {
		checkedOK = true
		a.clearFailure("history_error")
		extra = append(extra, ProblemsOf(h)...)
	}
	b, _, err := a.Store.StateFile(audit.AnchorsPath)
	if err != nil {
		if p, ok := a.failure(err, "read_error", tip, "the anchor file could not be read"); ok {
			extra = append(extra, p)
		}
		b = nil
	} else {
		a.clearFailure("read_error")
	}
	if len(b) == 0 && len(extra) == 0 {
		if checkedOK {
			a.mu.Lock()
			a.checked = tip
			a.mu.Unlock()
		}
		return
	}
	rev, err := a.Log.ReviewAnchors(b, extra, audit.AnchorOptions{Full: full, Now: a.now()})
	if err != nil {
		a.log().Warn("audit anchors: could not check the anchors", "err", err)
		return
	}
	a.mu.Lock()
	if checkedOK {
		a.checked = tip
	}
	m := ""
	if len(rev.Summary.Malformed) > 0 {
		m = fmt.Sprint(rev.Summary.Malformed)
	}
	changed := m != a.malformed
	a.malformed = m
	a.mu.Unlock()
	if changed && m != "" {
		a.log().Warn("audit anchors: lines of the anchor file are not anchors; they are left as they are", "lines", rev.Summary.Malformed)
	}
}

// ProblemsOf turns what a history check refused into problems, one per commit however many of
// its parents differ.
func ProblemsOf(c *gitstore.StateCheck) []audit.Problem {
	var out []audit.Problem
	seen := map[string]bool{}
	for _, v := range c.Violations {
		if seen[v.Commit] {
			continue
		}
		seen[v.Commit] = true
		switch v.Reason {
		case gitstore.ReasonRewritten:
			out = append(out, audit.RewrittenAnchor(v.Commit, v.Base, v.Content))
		case gitstore.ReasonTooLarge:
			out = append(out, audit.UnreadableAnchors("too_large", v.Commit, "commit "+v.Commit+" has a version above the size limit"))
		default:
			out = append(out, audit.RewrittenAnchorBecause(v.Commit, v.Reason))
		}
	}
	return out
}

// failure decides what a failed read or check comes to. A failure that is no accident is returned as
// a problem at once; one that may be an accident only warns, and is returned as a problem when the
// same reason comes again. temporary is the reason code of a failure that may be an accident.
func (a *Anchorer) failure(err error, temporary, tip, what string) (audit.Problem, bool) {
	reason := temporary
	switch {
	case errors.Is(err, gitstore.ErrStateDesync):
		reason = "history_desync"
	case errors.Is(err, gitstore.ErrStateNotRegular):
		reason = "not_regular"
	}
	if reason == "history_desync" || reason == "not_regular" {
		a.log().Error("audit anchors: "+what, "reason", reason, "tip", tip, "err", err)
		return audit.UnreadableAnchors(reason, tip, err.Error()), true
	}
	// consecutive failures of one reason are counted whatever the tip is (the tip moves while git is
	// in trouble); the problem recorded for the second and later ones is fingerprinted by reason and tip
	a.mu.Lock()
	if a.failures == nil {
		a.failures = map[string]int{}
	}
	a.failures[reason]++
	n := a.failures[reason]
	a.mu.Unlock()
	if n < 2 {
		a.log().Warn("audit anchors: "+what+"; it is recorded if it happens again", "reason", reason, "tip", tip, "err", err)
		return audit.Problem{}, false
	}
	a.log().Error("audit anchors: "+what+" again", "reason", reason, "tip", tip, "err", err)
	return audit.UnreadableAnchors(reason, tip, err.Error()), true
}

// clearFailure forgets the failures of a reason once it works again.
func (a *Anchorer) clearFailure(reason string) {
	a.mu.Lock()
	delete(a.failures, reason)
	a.mu.Unlock()
}

// Tick writes today's anchor if audit.anchor is daily (read from the current
// config, so a reload takes effect) and one is due: none yet for this UTC day,
// and the log's head is past the last anchored seq. A failure is returned and
// leaves nothing behind; the next Tick tries again.
func (a *Anchorer) Tick(ctx context.Context) error {
	cfg := a.Store.Config()
	if !cfg.AuditAnchorDaily() {
		a.clearWarning("nolog")
		a.clearWarning("nogit")
		return nil
	}
	switch {
	case cfg.Write.Mode == "pr":
		// config.Load refuses this combination; it cannot be reached, and nothing is written if it is
		a.warnOnce("pr", "audit.anchor: daily is not available with write.mode: pr; no anchor is written")
		return nil
	case a.Log == nil:
		a.warnOnce("nolog", "audit.anchor: daily does nothing without --state-dir: there is no audit log to anchor")
		return nil
	case !a.Store.GitEnabled():
		a.warnOnce("nogit", "audit.anchor: daily does nothing: the data directory is not a Git repository, so there is no history to protect the anchors")
		return nil
	}
	if !a.healthy() {
		// an anchor would vouch for a log that is not intact
		a.warnOnce("unhealthy", "audit anchors: no anchor is written while the audit log has problems that are not acknowledged")
		return nil
	}
	a.clearWarning("unhealthy")
	seq, hash := a.Log.Head()
	if seq == 0 {
		return nil
	}
	now := a.now()
	day := now.Format("2006-01-02")
	b, _, err := a.Store.StateFile(audit.AnchorsPath)
	if err != nil {
		return err
	}
	anchors := audit.ParseAnchors(b)
	// Only an anchor that is valid and passed the check says what is already anchored: a
	// line dated far ahead, or one that does not match the log, must not keep today's anchor away.
	rev, err := a.Log.ReviewAnchors(b, nil, audit.AnchorOptions{Now: now})
	if err != nil {
		return err
	}
	if !a.healthy() {
		a.warnOnce("unhealthy", "audit anchors: no anchor is written while the audit log has problems that are not acknowledged")
		return nil
	}
	if len(rev.Good) != len(anchors.List) {
		a.warnOnce("untrusted", "audit anchors: some lines of the anchor file are not valid or do not match the log; today's anchor is decided without them")
	} else {
		a.clearWarning("untrusted")
	}
	var last audit.Anchor
	haveLast := len(rev.Good) > 0
	if haveLast {
		last = rev.Good[len(rev.Good)-1]
	}
	if haveLast && !due(last, day, seq) {
		return nil
	}
	if haveLast {
		// the anchor's own commit event is after its seq: that alone is no reason for another
		busy, err := a.Log.ActivitySince(last.Seq, isOwnCommit)
		if err != nil || !busy {
			return err
		}
	}
	anchor := audit.Anchor{Day: day, Seq: seq, Hash: hash, At: now.Format(time.RFC3339)}
	_, err = a.Store.MutateStateFile(ctx, audit.AnchorsPath, fmt.Sprintf("audit: anchor seq %d", seq), Identity, func(old []byte, _ bool) ([]byte, error) {
		// the file is read again on a replay after a moved remote: append only, and not twice
		for _, o := range audit.ParseAnchors(old).List {
			if o == anchor {
				return old, nil
			}
		}
		out := slices.Clone(old)
		if len(out) > 0 && !bytes.HasSuffix(out, []byte("\n")) {
			out = append(out, '\n')
		}
		return append(out, anchor.Line()...), nil
	})
	if err != nil {
		return fmt.Errorf("audit anchor for seq %d: %w", seq, err)
	}
	a.log().Info("audit anchor written", "day", day, "seq", seq)
	return nil
}

// healthy says the audit log has no problem nobody has acknowledged, other than anchors that
// cannot be anchors (anchor_invalid): those say nothing about the log, and must not keep today's
// anchor away.
func (a *Anchorer) healthy() bool {
	st := a.Log.Status()
	if st.OK {
		return true
	}
	for _, p := range st.Problems {
		if p.Kind != audit.KindAnchorInvalid {
			return false
		}
	}
	return len(st.Problems) > 0 // no problems listed: the log cannot be written, which is not healthy
}

// due says an anchor for seq is wanted: the newest trusted one is from an earlier UTC day and
// at an earlier seq.
func due(last audit.Anchor, day string, seq int64) bool {
	return last.Day < day && last.Seq < seq
}

// Run calls Tick shortly after the start and then every hour until ctx ends.
// A failed Tick is logged and tried again on the next one. It never blocks
// anything else: a write of the anchor takes the store's write lock for as long
// as any write does, and nothing else waits for it.
func (a *Anchorer) Run(ctx context.Context) {
	delay, every := a.Delay, a.Every
	if delay <= 0 {
		delay = DefaultDelay
	}
	if every <= 0 {
		every = DefaultEvery
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := a.Tick(ctx); err != nil && ctx.Err() == nil {
				a.log().Warn("audit anchor not written; trying again at the next check", "err", err, "next", every.String())
			}
			t.Reset(every)
		}
	}
}
