package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
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
	activityChunk = 200     // entries read from a source at a time
	walkBudget    = 20_000  // commits one stream walks per request
	auditBudget   = 200_000 // audit lines one stream looks at per request
	// exportWorkBudget bounds the work of one JSONL export (commits walked plus lines looked at).
	exportWorkBudget = 5_000_000
)

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

func decodeCursor(s string) (activityCursor, error) {
	if s == "" {
		return nil, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var c activityCursor
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return c, nil
}

func (c activityCursor) encode() string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
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
}

// gitStream reads a git walk in chunks.
type gitStream struct {
	fetch func(tip string, skip, n int) (string, []walkEntry, error)
	cur   streamCursor
	buf   []walkEntry
	pos   int
	base  int // walk position of buf[0]
	eof   bool
	spent int
	stall bool
}

func newGitStream(c streamCursor, fetch func(tip string, skip, n int) (string, []walkEntry, error)) *gitStream {
	return &gitStream{fetch: fetch, cur: c, base: c.N}
}

func (g *gitStream) peek() (*activityItem, error) {
	for {
		if g.cur.Done {
			return nil, nil
		}
		for g.pos < len(g.buf) {
			if e := g.buf[g.pos]; e.match {
				return e.item, nil
			}
			g.pos++
		}
		if g.eof {
			g.cur.Done = true
			return nil, nil
		}
		if g.spent >= walkBudget {
			g.stall = true
			return nil, nil
		}
		g.base += len(g.buf)
		g.buf, g.pos = nil, 0
		tip, ents, err := g.fetch(g.cur.Tip, g.base, activityChunk)
		if err != nil {
			return nil, err
		}
		g.cur.Tip = tip
		g.buf = ents
		g.spent += len(ents)
		g.eof = len(ents) < activityChunk
	}
}

func (g *gitStream) take()          { g.pos++ }
func (g *gitStream) finished() bool { return g.cur.Done }
func (g *gitStream) stalled() bool  { return g.stall }
func (g *gitStream) work() int      { return g.spent }
func (g *gitStream) cursor() streamCursor {
	c := g.cur
	c.N = g.base + g.pos
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
func (a *auditStream) cursor() streamCursor {
	return streamCursor{Resume: a.resume, Done: a.done}
}

// activityStreams are the sources the caller's filter reads from, resumed from cur.
func (s *server) activityStreams(r *http.Request, f *activityFilter, cur activityCursor) (map[string]activityStream, error) {
	out := map[string]activityStream{}
	ctx := r.Context()
	admin := auth.Can(ctx, roles.Manage)
	inRange := func(it *activityItem) bool {
		return (f.since.IsZero() || !it.at.Before(f.since)) && (f.until.IsZero() || !it.at.After(f.until))
	}
	// commits: raw entries, then who made them from the audit log, then the filters
	finish := func(ents []walkEntry) []walkEntry {
		keys := make([]audit.CommitKey, len(ents))
		for i, e := range ents {
			keys[i] = audit.CommitKey{Area: e.item.Area, Hash: e.item.Hash}
		}
		refs := s.o.Audit.LookupCommits(keys)
		for i := range ents {
			it := ents[i].item
			ref, ok := refs[keys[i]]
			it.Verified = &ok
			if ok {
				it.Identity, it.Name, it.Method, it.Token = ref.Identity, ref.Name, ref.Method, ref.Token
			}
			// the identity filter keeps what the log vouches for: anybody with push
			// access can write any author or trailer
			if f.identity != "" && !(ok && it.Identity == f.identity) {
				ents[i].match = false
			}
			ents[i].match = ents[i].match && inRange(it)
		}
		return ents
	}
	if f.has(areaLedger) {
		out[areaLedger] = newGitStream(cur[areaLedger], func(tip string, skip, n int) (string, []walkEntry, error) {
			pg, err := s.o.Store.Activity(ctx, gitstore.ActivityQuery{Collection: f.collection, ID: f.id, IncludeState: s.canSee(r, seeState), Tip: tip, Skip: skip, Limit: n})
			if err != nil {
				return "", nil, err
			}
			return pg.Tip, finish(commitItems(areaLedger, 0, pg.Commits, admin)), nil
		})
	}
	// An infra commit or an audit event belongs to no collection.
	if f.collection != "" {
		return out, nil
	}
	wantInfra, wantAudit := f.has(areaInfra) && s.canSee(r, seeInfra), f.has(areaAudit) && s.canSee(r, seeAudit)
	if wantInfra {
		out[areaInfra] = newGitStream(cur[areaInfra], func(tip string, skip, n int) (string, []walkEntry, error) {
			pg, err := s.o.Infra.Repo.Activity(ctx, gitstore.ActivityQuery{Tip: tip, Skip: skip, Limit: n})
			if err != nil {
				return "", nil, err
			}
			return pg.Tip, finish(commitItems(areaInfra, 1, pg.Commits, admin)), nil
		})
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
func (s *server) activityPage(r *http.Request, f *activityFilter, cur activityCursor, limit int) ([]*activityItem, string, int, error) {
	streams, err := s.activityStreams(r, f, cur)
	if err != nil {
		return nil, "", 0, err
	}
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
	return items, next.encode(), work, nil
}
