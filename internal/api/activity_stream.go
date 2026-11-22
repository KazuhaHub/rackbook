package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/roles"
)

// The activity view merges three streams, each read in its own order and each
// resumable from a position that goes into the cursor: a git stream by (pinned
// tip, commits of the walk consumed), the audit stream by the seq it has come
// down to. Time limits and the other filters are applied to what a stream reads;
// they never stop a walk, so no commit is lost to an out-of-order date, and a
// page never repeats an item.

// Work limits, variables for the tests.
var (
	activityChunk = 200     // audit events read at a time
	walkBudget    = 2_000   // commits one git stream walks per request
	auditBudget   = 200_000 // audit lines one stream looks at per request
	// sinceStopRun: with a since filter, a git walk stops once it has seen this
	// many commits in a row dated more than sinceSlack before it. The walk is in
	// --date-order (a commit before its parents, otherwise by date), so older
	// commits come last; this is a heuristic bound, a commit dated more than
	// sinceSlack earlier than the sinceStopRun commits that follow it can be missed.
	sinceStopRun = 200
	// exportWorkBudget bounds the work of one JSONL export (commits walked plus lines looked at).
	exportWorkBudget = 5_000_000
)

const sinceSlack = 24 * time.Hour

type walkEntry struct {
	item  *activityItem
	match bool // false: part of the walk (it counts for the position) but not an item of this view
}

type streamCursor struct {
	Tip    string `json:"t,omitempty"` // git: the commit the walk is pinned to
	N      int    `json:"n,omitempty"` // git: commits of the walk consumed
	Resume int64  `json:"r,omitempty"` // audit: the lines read so far are those with seq >= Resume
	Done   bool   `json:"d,omitempty"`
}

type activityCursor map[string]streamCursor

// Cursors are authenticated: the payload is signed (HMAC-SHA256) with a key the
// server makes at start and keeps in memory, together with the identity of the
// caller. A cursor therefore cannot be forged (it names a pinned commit, which
// would otherwise tell whether any commit exists), cannot be used by another
// person, and does not survive a restart.
var errCursor = errors.New("the cursor is not valid")

func cursorMAC(key []byte, who string, payload []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(who))
	m.Write([]byte{0})
	m.Write(payload)
	return m.Sum(nil)
}

func (s *server) encodeCursor(who string, c activityCursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(cursorMAC(s.cursorKey, who, b))
}

func (s *server) decodeCursor(who, v string) (activityCursor, error) {
	if v == "" {
		return nil, nil
	}
	p, m, ok := strings.Cut(v, ".")
	if !ok {
		return nil, errCursor
	}
	payload, err1 := base64.RawURLEncoding.DecodeString(p)
	mac, err2 := base64.RawURLEncoding.DecodeString(m)
	if err1 != nil || err2 != nil || !hmac.Equal(mac, cursorMAC(s.cursorKey, who, payload)) {
		return nil, errCursor
	}
	var c activityCursor
	if json.Unmarshal(payload, &c) != nil {
		return nil, errCursor
	}
	// a guard in depth: what is signed was made by this server, but a position is never negative
	for _, sc := range c {
		if sc.N < 0 || sc.Resume < 0 || (sc.Tip != "" && !gitstore.ValidRev(sc.Tip)) {
			return nil, errCursor
		}
	}
	return c, nil
}

type activityStream interface {
	// peek is the next item, nil when there is none (finished) or the work
	// budget ran out (stalled).
	peek() (*activityItem, error)
	take()
	finished() bool
	stalled() bool
	cursor() streamCursor
	work() int
	close() // stops what the stream started (the git process)
}

// gitFeed is one git process of a request, read through a channel. It is
// started by the first read and killed (and waited for) by close.
type gitFeed struct {
	ch     chan feedMsg
	cancel context.CancelFunc
}

type feedMsg struct {
	tip string // the commit the walk is pinned to (first message)
	e   walkEntry
	err error
}

func (f *gitFeed) close() {
	f.cancel()
	for range f.ch { // the process is gone and the goroutine ends when the channel closes
	}
}

// gitWalk streams a repository's walk to each (gitstore Store/Repo.ActivityWalk).
type gitWalk func(ctx context.Context, tip string, skip int, onStart func(string), each func(gitstore.ActivityCommit) bool) error

// startFeed runs the walk in a goroutine. Commits are turned into entries in
// small batches (finish looks the batch up in the audit log).
func startFeed(parent context.Context, walk gitWalk, tip string, skip int, convert func([]gitstore.ActivityCommit) []walkEntry) *gitFeed {
	ctx, cancel := context.WithCancel(parent)
	f := &gitFeed{ch: make(chan feedMsg), cancel: cancel}
	send := func(m feedMsg) bool {
		select {
		case f.ch <- m:
			return true
		case <-ctx.Done():
			return false
		}
	}
	go func() {
		defer close(f.ch)
		// a panic in the walk or in turning commits into entries is the request's error, not the server's end
		defer func() {
			if r := recover(); r != nil {
				send(feedMsg{err: fmt.Errorf("activity walk failed: %v", r)})
			}
		}()
		var batch []gitstore.ActivityCommit
		flush := func() bool {
			ents := convert(batch)
			batch = batch[:0]
			for _, e := range ents {
				if !send(feedMsg{e: e}) {
					return false
				}
			}
			return true
		}
		err := walk(ctx, tip, skip, func(t string) { send(feedMsg{tip: t}) }, func(c gitstore.ActivityCommit) bool {
			batch = append(batch, c)
			return len(batch) < 50 || flush()
		})
		if err == nil && ctx.Err() == nil {
			flush()
		}
		if err != nil && ctx.Err() == nil {
			send(feedMsg{err: err})
		}
	}()
	return f
}

// gitStream reads a git walk through one process per request.
type gitStream struct {
	ctx      context.Context
	walk     gitWalk
	convert  func([]gitstore.ActivityCommit) []walkEntry
	since    time.Time // with it, the walk may stop early (see sinceStopRun)
	cur      streamCursor
	consumed int // commits of the walk consumed by this request
	feed     *gitFeed
	head     *walkEntry
	spent    int
	run      int
	stall    bool
}

func (g *gitStream) next() (walkEntry, bool, error) {
	if g.feed == nil {
		g.feed = startFeed(g.ctx, g.walk, g.cur.Tip, g.cur.N, g.convert)
	}
	for m := range g.feed.ch {
		switch {
		case m.err != nil:
			return walkEntry{}, false, m.err
		case m.tip != "":
			g.cur.Tip = m.tip
		default:
			return m.e, true, nil
		}
	}
	return walkEntry{}, false, nil
}

func (g *gitStream) peek() (*activityItem, error) {
	for {
		if g.cur.Done {
			return nil, nil
		}
		if g.head == nil {
			if g.spent >= walkBudget {
				g.stall = true
				return nil, nil
			}
			e, ok, err := g.next()
			if err != nil {
				return nil, err
			}
			if !ok {
				g.cur.Done = true
				return nil, nil
			}
			g.head = &e
			g.spent++
		}
		if g.head.match {
			g.run = 0
			return g.head.item, nil
		}
		// part of the walk, not an item: consumed, and counted for the early stop
		old := !g.since.IsZero() && g.head.item.at.Before(g.since.Add(-sinceSlack))
		g.consumed++
		g.head = nil
		if !old {
			g.run = 0
		} else if g.run++; g.run >= sinceStopRun {
			g.cur.Done = true
			return nil, nil
		}
	}
}

func (g *gitStream) take() {
	g.consumed++
	g.head = nil
}
func (g *gitStream) finished() bool { return g.cur.Done }
func (g *gitStream) stalled() bool  { return g.stall }
func (g *gitStream) work() int      { return g.spent }
func (g *gitStream) close() {
	if g.feed != nil {
		g.feed.close()
	}
}
func (g *gitStream) cursor() streamCursor {
	c := g.cur
	c.N = g.cur.N + g.consumed
	return c
}

// auditStream reads the audit log newest first.
type auditStream struct {
	read   func(before int64, limit, maxScan int) (audit.Page, []*activityItem, error)
	resume int64
	done   bool
	buf    []*activityItem
	pos    int
	more   bool // the last read left older matches
	read1  bool
	spent  int
	stall  bool
}

func (a *auditStream) peek() (*activityItem, error) {
	for {
		if a.done {
			return nil, nil
		}
		if a.pos < len(a.buf) {
			return a.buf[a.pos], nil
		}
		if a.read1 && !a.more {
			a.done = true
			return nil, nil
		}
		if a.spent >= auditBudget {
			a.stall = true
			return nil, nil
		}
		pg, items, err := a.read(a.resume, activityChunk, auditBudget-a.spent)
		if err != nil {
			return nil, err
		}
		a.read1, a.more = true, pg.More
		a.spent += pg.Scanned
		a.buf, a.pos = items, 0
		if len(items) == 0 && pg.More {
			a.resume = pg.Next // the scan budget ran out before a match: go on from there
		}
	}
}

func (a *auditStream) take() {
	a.resume = a.buf[a.pos].Seq
	a.pos++
}
func (a *auditStream) finished() bool { return a.done }
func (a *auditStream) stalled() bool  { return a.stall }
func (a *auditStream) work() int      { return a.spent }
func (a *auditStream) close()         {}
func (a *auditStream) cursor() streamCursor {
	return streamCursor{Resume: a.resume, Done: a.done}
}

// markVerified says for each commit item whether this server made the commit (its
// audit log has the line), and for the ones it did, who made it as the log has it.
// Everything else stays as written in the commit and is unverified.
func (s *server) markVerified(items []*activityItem) {
	keys := make([]audit.CommitKey, len(items))
	for i, it := range items {
		keys[i] = audit.CommitKey{Area: it.Area, Hash: it.Hash}
	}
	refs := s.o.Audit.LookupCommits(keys)
	for i, it := range items {
		ref, ok := refs[keys[i]]
		it.Verified = &ok
		if ok {
			it.Identity, it.Name, it.Method, it.Token = ref.Identity, ref.Name, ref.Method, ref.Token
		}
	}
}

// activityStreams are the sources the caller's filter reads from, resumed from cur.
func (s *server) activityStreams(ctx context.Context, r *http.Request, f *activityFilter, cur activityCursor) (map[string]activityStream, error) {
	out := map[string]activityStream{}
	admin := auth.Can(ctx, roles.Manage)
	inRange := func(it *activityItem) bool {
		return (f.since.IsZero() || !it.at.Before(f.since)) && (f.until.IsZero() || !it.at.After(f.until))
	}
	// commits: who made them from the audit log, then the filters
	finish := func(cs []gitstore.ActivityCommit, area string, src int) []walkEntry {
		ents := commitItems(area, src, cs, admin)
		items := make([]*activityItem, len(ents))
		for i, e := range ents {
			items[i] = e.item
		}
		s.markVerified(items)
		for i := range ents {
			it := ents[i].item
			// the identity filter keeps what the log vouches for: anybody with push
			// access can write any author or trailer
			if f.identity != "" && !(*it.Verified && it.Identity == f.identity) {
				ents[i].match = false
			}
			ents[i].match = ents[i].match && inRange(it)
		}
		return ents
	}
	if f.has(areaLedger) {
		out[areaLedger] = &gitStream{ctx: ctx, cur: cur[areaLedger], since: f.since,
			walk: func(ctx context.Context, tip string, skip int, onStart func(string), each func(gitstore.ActivityCommit) bool) error {
				return s.o.Store.ActivityWalk(ctx, gitstore.ActivityQuery{Collection: f.collection, ID: f.id, IncludeState: s.canSee(r, seeState), Tip: tip, Skip: skip}, onStart, each)
			},
			convert: func(cs []gitstore.ActivityCommit) []walkEntry { return finish(cs, areaLedger, 0) }}
	}
	// An infra commit or an audit event belongs to no collection.
	if f.collection != "" {
		return out, nil
	}
	wantInfra, wantAudit := f.has(areaInfra) && s.canSee(r, seeInfra), f.has(areaAudit) && s.canSee(r, seeAudit)
	if wantInfra {
		out[areaInfra] = &gitStream{ctx: ctx, cur: cur[areaInfra], since: f.since,
			walk: func(ctx context.Context, tip string, skip int, onStart func(string), each func(gitstore.ActivityCommit) bool) error {
				return s.o.Infra.Repo.ActivityWalk(ctx, gitstore.ActivityQuery{Tip: tip, Skip: skip}, onStart, each)
			},
			convert: func(cs []gitstore.ActivityCommit) []walkEntry { return finish(cs, areaInfra, 1) }}
	}
	if s.o.Audit != nil && (wantInfra || wantAudit) {
		q := audit.Query{Since: f.since, Identity: f.identity, Filter: func(e audit.Event) bool {
			switch {
			case e.Event == "commit":
				return false // it only verifies a commit
			case e.Area == areaInfra:
				return wantInfra
			}
			return wantAudit
		}}
		if !f.until.IsZero() {
			q.Until = f.until.Add(time.Second - time.Nanosecond)
		}
		c := cur[areaAudit]
		out[areaAudit] = &auditStream{resume: c.Resume, done: c.Done, read: func(before int64, limit, maxScan int) (audit.Page, []*activityItem, error) {
			qq := q
			qq.Before, qq.Limit, qq.MaxScan = before, limit, maxScan
			pg, err := s.o.Audit.Read(qq)
			return pg, eventItems(pg.Events, admin), err
		}}
	}
	return out, nil
}

// activityPage returns the next limit items after cur (nil = from the newest),
// the cursor for the page after ("" at the end) and the work it took. The
// streams are merged by taking the newest of their heads; each stream is in its
// own order, so under skewed commit dates the result is not perfectly sorted,
// but nothing is lost or repeated. A stream that runs out of work budget ends
// the page early (possibly with no item), and the cursor carries on from there.
func (s *server) activityPage(r *http.Request, who string, f *activityFilter, cur activityCursor, limit int) ([]*activityItem, string, int, error) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	streams, err := s.activityStreams(ctx, r, f, cur)
	if err != nil {
		return nil, "", 0, err
	}
	defer func() {
		for _, st := range streams {
			st.close() // one git process per source: kill and wait for it
		}
	}()
	var items []*activityItem
	stalled := false
	for len(items) < limit && !stalled {
		var best activityStream
		var bestItem *activityItem
		for _, st := range streams {
			it, err := st.peek()
			if err != nil {
				return nil, "", 0, err
			}
			if st.stalled() {
				stalled = true
				break
			}
			if it != nil && (bestItem == nil || newer(it, bestItem)) {
				best, bestItem = st, it
			}
		}
		if stalled || best == nil {
			break
		}
		items = append(items, bestItem)
		best.take()
	}
	more, work := stalled, 0
	next := activityCursor{}
	for name, st := range streams {
		if !more {
			it, err := st.peek()
			if err != nil {
				return nil, "", 0, err
			}
			more = it != nil || st.stalled()
		}
		next[name] = st.cursor()
		work += st.work()
	}
	if !more {
		return items, "", work, nil
	}
	return items, s.encodeCursor(who, next), work, nil
}
