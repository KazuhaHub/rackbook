package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/roles"
)

// The activity view (docs/design-audit.md, section 3.2): one time-ordered list
// of the commits of the data repository, the commits of the infra repository
// and the audit log, with who may see which part decided in canSee.

func (s *server) activityRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/activity", s.activity)
	mux.HandleFunc("GET /api/activity/commit/{area}/{hash}", s.activityCommit)
	mux.HandleFunc("GET /api/audit/status", s.auditStatus)
	mux.HandleFunc("POST /api/audit/ack", s.auditAck)
}

// Areas of the activity view, and the visibility classes behind them.
const (
	areaLedger = "ledger"
	areaInfra  = "infra"
	areaAudit  = "audit"
)

type visibility int

const (
	seeLedger visibility = iota // ledger commits that touch no state file
	seeState                    // .rackbook/ commits (tokens, passkeys)
	seeAudit                    // audit events about sign-ins and the ledger
	seeInfra                    // infra commits and infra audit events
)

// canSee is the one place that says who may see which kind of activity.
// Today: everybody sees the ledger; administrators see state and audit events;
// the infra administrators (--infra-admins) see infra. The auditor capability
// (design 3.4) will change only this function.
func (s *server) canSee(r *http.Request, v visibility) bool {
	switch v {
	case seeLedger:
		return true
	case seeState, seeAudit:
		return auth.Can(r.Context(), roles.Manage)
	case seeInfra:
		return s.canInfra(r)
	}
	return false
}

// visibleAreas are the areas the caller may name.
func (s *server) visibleAreas(r *http.Request) []string {
	out := []string{areaLedger}
	if s.canSee(r, seeInfra) {
		out = append(out, areaInfra)
	}
	if s.canSee(r, seeAudit) {
		out = append(out, areaAudit)
	}
	return out
}

// activityItem is one row of the timeline.
type activityItem struct {
	Time     string   `json:"time"`
	Area     string   `json:"area"`
	Kind     string   `json:"kind"` // "commit" or the audit event
	Hash     string   `json:"hash,omitempty"`
	Short    string   `json:"short,omitempty"`
	Commit   string   `json:"commit,omitempty"` // the short hash, as in the design
	Identity string   `json:"identity,omitempty"`
	Name     string   `json:"name,omitempty"`
	Method   string   `json:"method,omitempty"`
	Via      string   `json:"via,omitempty"`
	Subject  string   `json:"subject,omitempty"`
	Records  []string `json:"records,omitempty"`
	// Verified says this server made the commit (its audit log has the line).
	Verified *bool  `json:"verified,omitempty"`
	Token    string `json:"token,omitempty"`
	// State: the commit touches .rackbook/ ("only" or "some"); administrators only.
	State string `json:"state,omitempty"`

	// Audit events.
	Seq     int64    `json:"seq,omitempty"`
	Event   string   `json:"event,omitempty"`
	Reason  string   `json:"reason,omitempty"`
	Code    string   `json:"code,omitempty"`
	Role    string   `json:"role,omitempty"`
	Addr    string   `json:"addr,omitempty"` // administrators only
	Outcome string   `json:"outcome,omitempty"`
	Action  string   `json:"action,omitempty"`
	Host    string   `json:"host,omitempty"`
	Files   []string `json:"files,omitempty"`
	Detail  []string `json:"detail,omitempty"`

	at  time.Time // the time, to the second
	src int       // ledger, infra, audit: the tie-break after the time
}

// key names an item for the cursor.
func (it *activityItem) key() string {
	if it.Kind != "commit" {
		return "audit:" + strconv.FormatInt(it.Seq, 10)
	}
	return it.Area + ":" + it.Hash
}

// newer orders items: time, then the source, then audit seq or hash, newest
// first, so that equal times always come out in the same order.
func newer(a, b *activityItem) bool {
	switch {
	case !a.at.Equal(b.at):
		return a.at.After(b.at)
	case a.src != b.src:
		return a.src < b.src
	case a.Seq != b.Seq:
		return a.Seq > b.Seq
	}
	return a.Hash > b.Hash
}

type activityFilter struct {
	since, until time.Time // inclusive, to the second; zero = open
	identity     string
	areas        []string
	collection   string
	id           string
}

func (f *activityFilter) has(area string) bool { return slices.Contains(f.areas, area) }

// activitySource is one of the three places activity comes from.
type activitySource struct {
	// fetch returns up to n raw items in the range (both ends inclusive, to the
	// second), newest first or nearly so.
	fetch func(since, until time.Time, n int) ([]*activityItem, error)
	// finish adds what is known about the raw items and drops those the filter
	// does not match.
	finish func(raw []*activityItem) []*activityItem
}

const (
	// scanCap bounds how many raw items one request looks at per source.
	scanCap = gitstore.MaxActivity
	// tieCap bounds how many items of one second are read to complete a page edge.
	tieCap = 1000
)

type pulled struct {
	items  []*activityItem
	oldest time.Time
	// cut says the source has older items that were not looked at and fewer than
	// asked for matched: nothing older than oldest can be trusted to be complete.
	cut bool
}

func oldestOf(items []*activityItem) time.Time {
	t := items[0].at
	for _, it := range items {
		if it.at.Before(t) {
			t = it.at
		}
	}
	return t
}

// pull reads at least need matching items of one source, or all it has, or as
// many as scanCap allows.
func pull(src activitySource, since, until time.Time, need int) (pulled, error) {
	n := min(need, scanCap)
	for {
		raw, err := src.fetch(since, until, n)
		if err != nil {
			return pulled{}, err
		}
		if len(raw) < n {
			return pulled{items: src.finish(raw)}, nil
		}
		// The oldest second may go on past the page edge: read all of it, so that
		// the order inside it, and the cursor, are exact.
		tmin := oldestOf(raw)
		ties, err := src.fetch(tmin, tmin, tieCap)
		if err != nil {
			return pulled{}, err
		}
		kept := raw[:0:0]
		for _, it := range raw {
			if it.at.After(tmin) {
				kept = append(kept, it)
			}
		}
		raw = append(kept, ties...)
		items := src.finish(raw)
		if len(items) >= need || n >= scanCap {
			return pulled{items: items, oldest: tmin, cut: len(items) < need}, nil
		}
		n = min(n*4, scanCap)
	}
}

// Cursor: the second of the last item of the page and the keys already shown
// in that second.
type activityCursor struct {
	T    int64    `json:"t"`
	Keys []string `json:"k,omitempty"`
}

func decodeCursor(s string) (*activityCursor, error) {
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
	return &c, nil
}

func (c activityCursor) encode() string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

// page returns the next limit items after cur (nil = from the newest) and the
// cursor for the one after, "" at the end.
func (s *server) activityPage(r *http.Request, f *activityFilter, cur *activityCursor, limit int) ([]*activityItem, string, error) {
	until := f.until
	var emitted map[string]bool
	if cur != nil {
		t := time.Unix(cur.T, 0).UTC()
		if until.IsZero() || t.Before(until) {
			until = t
		}
		emitted = map[string]bool{}
		for _, k := range cur.Keys {
			emitted[k] = true
		}
	}
	need := limit + 1
	if cur != nil {
		need += len(cur.Keys)
	}
	var cands []*activityItem
	var horizon time.Time
	for _, src := range s.activitySources(r, f) {
		p, err := pull(src, f.since, until, need)
		if err != nil {
			return nil, "", err
		}
		cands = append(cands, p.items...)
		if p.cut && p.oldest.After(horizon) {
			horizon = p.oldest
		}
	}
	keep := cands[:0]
	for _, it := range cands {
		switch {
		case cur != nil && it.at.Unix() == cur.T && emitted[it.key()]:
		case !horizon.IsZero() && it.at.Before(horizon):
		default:
			keep = append(keep, it)
		}
	}
	cands = keep
	sort.SliceStable(cands, func(i, j int) bool { return newer(cands[i], cands[j]) })
	more := len(cands) > limit || !horizon.IsZero()
	page := cands[:min(limit, len(cands))]
	if !more {
		return page, "", nil
	}
	next := activityCursor{}
	if len(page) > 0 {
		t := page[len(page)-1].at
		next.T = t.Unix()
		for _, it := range page {
			if it.at.Equal(t) {
				next.Keys = append(next.Keys, it.key())
			}
		}
	} else {
		next.T = horizon.Unix()
	}
	if cur != nil && cur.T == next.T {
		next.Keys = append(next.Keys, cur.Keys...)
	}
	return page, next.encode(), nil
}

// activitySources are the places the caller's filter reads from.
func (s *server) activitySources(r *http.Request, f *activityFilter) []activitySource {
	var out []activitySource
	ctx := r.Context()
	admin := auth.Can(ctx, roles.Manage)
	if f.has(areaLedger) {
		out = append(out, activitySource{
			fetch: func(since, until time.Time, n int) ([]*activityItem, error) {
				cs, err := s.o.Store.Activity(ctx, gitstore.ActivityQuery{Since: since, Until: until, Collection: f.collection, ID: f.id,
					IncludeState: s.canSee(r, seeState), Limit: n})
				if err != nil {
					return nil, err
				}
				return commitItems(areaLedger, 0, cs, admin), nil
			},
			finish: func(raw []*activityItem) []*activityItem { return s.verify(raw, f) },
		})
	}
	// An infra commit or an audit event belongs to no collection.
	if f.collection != "" {
		return out
	}
	if f.has(areaInfra) && s.canSee(r, seeInfra) {
		out = append(out, activitySource{
			fetch: func(since, until time.Time, n int) ([]*activityItem, error) {
				cs, err := s.o.Infra.Repo.Activity(ctx, gitstore.ActivityQuery{Since: since, Until: until, Limit: n})
				if err != nil {
					return nil, err
				}
				return commitItems(areaInfra, 1, cs, admin), nil
			},
			finish: func(raw []*activityItem) []*activityItem { return s.verify(raw, f) },
		})
	}
	wantInfra, wantAudit := f.has(areaInfra) && s.canSee(r, seeInfra), f.has(areaAudit) && s.canSee(r, seeAudit)
	if s.o.Audit != nil && (wantInfra || wantAudit) {
		out = append(out, activitySource{
			fetch: func(since, until time.Time, n int) ([]*activityItem, error) {
				q := audit.Query{Since: since, Identity: f.identity, Limit: n, Filter: func(e audit.Event) bool {
					switch {
					case e.Event == "commit":
						return false // it only verifies a commit
					case e.Area == areaInfra:
						return wantInfra
					}
					return wantAudit
				}}
				if !until.IsZero() {
					q.Until = until.Add(time.Second - time.Nanosecond)
				}
				pg, err := s.o.Audit.Read(q)
				if err != nil {
					return nil, err
				}
				return eventItems(pg.Events, admin), nil
			},
			finish: func(raw []*activityItem) []*activityItem { return raw },
		})
	}
	return out
}

func commitItems(area string, src int, cs []gitstore.ActivityCommit, admin bool) []*activityItem {
	out := make([]*activityItem, 0, len(cs))
	for _, c := range cs {
		it := &activityItem{Area: area, Kind: "commit", Hash: c.Hash, Short: c.Short, Commit: c.Short, Subject: c.Subject,
			Records: c.Records, Via: c.EditedVia, at: c.Time.Truncate(time.Second), src: src,
			// as written in the commit: nothing here proves it (see verify)
			Identity: c.EditedBy, Name: c.Author}
		it.Time = it.at.Format(time.RFC3339)
		if admin && (c.State == gitstore.StateOnly || c.State == gitstore.StateSome) {
			it.State = c.State
		}
		out = append(out, it)
	}
	return out
}

func eventItems(es []audit.Event, admin bool) []*activityItem {
	out := make([]*activityItem, 0, len(es))
	for _, e := range es {
		area := areaAudit
		if e.Area == areaInfra {
			area = areaInfra
		}
		it := &activityItem{Area: area, Kind: e.Event, Event: e.Event, Seq: e.Seq, Identity: e.Identity, Name: e.Name, Method: e.Method,
			Reason: e.Reason, Code: e.Code, Role: e.Role, Outcome: e.Outcome, Action: e.Action, Host: e.Host, Files: e.Files,
			at: e.Time.UTC().Truncate(time.Second), src: 2}
		for _, d := range e.Detail {
			if v, ok := strings.CutPrefix(d, "token:"); ok {
				it.Token = v
			} else {
				it.Detail = append(it.Detail, d)
			}
		}
		if admin {
			it.Addr = e.Addr
		}
		it.Time = it.at.Format(time.RFC3339)
		out = append(out, it)
	}
	return out
}

// verify marks the commits this server made (its audit log has a line for the
// hash) and takes who made them from that line. The identity filter keeps only
// those: anybody with push access can write any author or trailer.
func (s *server) verify(raw []*activityItem, f *activityFilter) []*activityItem {
	keys := make([]audit.CommitKey, len(raw))
	for i, it := range raw {
		keys[i] = audit.CommitKey{Area: it.Area, Hash: it.Hash}
	}
	refs := s.o.Audit.LookupCommits(keys)
	out := raw[:0]
	for i, it := range raw {
		ref, ok := refs[keys[i]]
		v := ok
		it.Verified = &v
		if ok {
			it.Identity, it.Name, it.Method, it.Token = ref.Identity, ref.Name, ref.Method, ref.Token
		}
		if f.identity != "" && !(ok && it.Identity == f.identity) {
			continue
		}
		out = append(out, it)
	}
	return out
}

// parseTime reads RFC3339 or YYYY-MM-DD; a date alone is the whole day in UTC.
func parseTime(v string, endOfDay bool) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC().Truncate(time.Second), nil
	}
	t, err := time.Parse("2006-01-02", v)
	if err != nil {
		return time.Time{}, errors.New("dates are RFC 3339 or YYYY-MM-DD")
	}
	if endOfDay {
		t = t.AddDate(0, 0, 1).Add(-time.Second)
	}
	return t, nil
}

// activityFilterOf reads the query string. It answers the request itself on an error.
func (s *server) activityFilterOf(w http.ResponseWriter, r *http.Request) (*activityFilter, bool) {
	q := r.URL.Query()
	bad := func(msg string) (*activityFilter, bool) {
		writeError(w, http.StatusBadRequest, "bad_request", msg)
		return nil, false
	}
	f := &activityFilter{identity: q.Get("identity"), collection: q.Get("collection"), id: q.Get("id")}
	var err error
	if v := q.Get("since"); v != "" {
		if f.since, err = parseTime(v, false); err != nil {
			return bad("since: " + err.Error())
		}
	}
	if v := q.Get("until"); v != "" {
		if f.until, err = parseTime(v, true); err != nil {
			return bad("until: " + err.Error())
		}
	}
	if f.id != "" && f.collection == "" {
		return bad("id needs a collection")
	}
	if f.collection != "" && s.o.Store.Ledger().Collection(f.collection) == nil {
		return bad("unknown collection " + strconv.Quote(f.collection))
	}
	visible := s.visibleAreas(r)
	for _, v := range q["area"] {
		for _, a := range strings.Split(v, ",") {
			switch a = strings.TrimSpace(a); a {
			case "":
			case areaLedger, areaInfra, areaAudit:
				if !slices.Contains(visible, a) {
					writeError(w, http.StatusForbidden, "forbidden", "you may not see the "+a+" activity")
					return nil, false
				}
				if !slices.Contains(f.areas, a) {
					f.areas = append(f.areas, a)
				}
			default:
				return bad("area is ledger, infra or audit")
			}
		}
	}
	if len(f.areas) == 0 {
		f.areas = visible
	}
	return f, true
}

const (
	defaultActivityLimit = 50
	maxActivityLimit     = 200
)

// maxExportItems bounds one JSONL export (a variable for the tests).
var maxExportItems = 50_000

func (s *server) activity(w http.ResponseWriter, r *http.Request) {
	f, ok := s.activityFilterOf(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	switch q.Get("format") {
	case "":
	case "jsonl":
		s.activityExport(w, r, f)
		return
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "format is jsonl")
		return
	}
	limit := defaultActivityLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "bad_request", "limit must be a positive whole number")
			return
		}
		limit = min(n, maxActivityLimit)
	}
	cur, err := decodeCursor(q.Get("cursor"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "unusable cursor")
		return
	}
	items, next, err := s.activityPage(r, f, cur, limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	out := map[string]any{"items": items, "areas": s.visibleAreas(r), "audit": s.o.Audit != nil}
	if items == nil {
		out["items"] = []*activityItem{}
	}
	if next != "" {
		out["cursor"] = next
	}
	writeJSON(w, http.StatusOK, out)
}

// activityExport streams every match, one JSON object per line.
func (s *server) activityExport(w http.ResponseWriter, r *http.Request, f *activityFilter) {
	h := w.Header()
	h.Set("Content-Type", "application/x-ndjson")
	h.Set("Content-Disposition", "attachment; filename=rackbook-activity-"+s.now().UTC().Format("2006-01-02")+".jsonl")
	h.Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	var cur *activityCursor
	sent := 0
	for {
		items, next, err := s.activityPage(r, f, cur, 500)
		if err != nil {
			s.log.Error("activity export failed", "err", err)
			_ = enc.Encode(map[string]any{"error": "internal"})
			return
		}
		for _, it := range items {
			if sent >= maxExportItems {
				_ = enc.Encode(map[string]bool{"truncated": true})
				return
			}
			if err := enc.Encode(it); err != nil {
				return
			}
			sent++
		}
		if next == "" {
			return
		}
		if sent >= maxExportItems {
			_ = enc.Encode(map[string]bool{"truncated": true})
			return
		}
		if cur, err = decodeCursor(next); err != nil {
			return
		}
	}
}

func (s *server) activityCommit(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	notFound := func() { writeError(w, http.StatusNotFound, "not_found", "no such commit") }
	var d *gitstore.CommitDiff
	var err error
	switch r.PathValue("area") {
	case areaLedger:
		d, err = s.o.Store.CommitDiff(r.Context(), hash, s.canSee(r, seeState))
	case areaInfra:
		if s.o.Infra == nil {
			notFound()
			return
		}
		if !s.infraAdmin(w, r) {
			return
		}
		d, err = s.o.Infra.Repo.CommitDiff(r.Context(), hash)
	default:
		notFound()
		return
	}
	if errors.Is(err, gitstore.ErrNoCommit) {
		notFound()
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"area": r.PathValue("area"), "hash": d.Hash, "files": d.Files, "moreFiles": d.MoreFiles})
}

// Audit log status and acknowledgement ---------------------------------------

type auditProblemOut struct {
	Kind       string `json:"kind"`
	Seq        int64  `json:"seq"`
	File       string `json:"file,omitempty"`
	Detail     string `json:"detail,omitempty"`
	RecordedAt int64  `json:"recordedAt,omitempty"`
}

func (s *server) auditAdmin(w http.ResponseWriter, r *http.Request, write bool) bool {
	if write && s.o.ReadOnly {
		writeError(w, http.StatusForbidden, "read_only", "the ledger is read-only")
		return false
	}
	id := s.who(r)
	if id == nil || (write && id.Method == auth.MethodToken) || !s.canSee(r, seeAudit) {
		writeError(w, http.StatusForbidden, "forbidden", "only administrators may see or acknowledge the audit log status")
		return false
	}
	return true
}

func (s *server) auditStatus(w http.ResponseWriter, r *http.Request) {
	if !s.auditAdmin(w, r, false) {
		return
	}
	writeJSON(w, http.StatusOK, s.auditStatusOut())
}

func (s *server) auditStatusOut() map[string]any {
	out := map[string]any{"enabled": s.o.Audit != nil, "ok": true, "problems": []auditProblemOut{}, "lastSeq": 0}
	if s.o.Audit == nil {
		return out
	}
	st := s.o.Audit.Status()
	probs := []auditProblemOut{}
	for _, p := range st.Problems {
		probs = append(probs, auditProblemOut{Kind: p.Kind, Seq: p.Seq, File: p.File, Detail: p.Detail, RecordedAt: p.RecordedAt})
	}
	out["ok"], out["problems"], out["lastSeq"] = st.OK, probs, st.LastSeq
	if !st.OK && len(probs) == 0 {
		// the log cannot be written, which no acknowledgement helps
		out["failed"] = st.Problem
	}
	return out
}

func (s *server) auditAck(w http.ResponseWriter, r *http.Request) {
	if !s.auditAdmin(w, r, true) {
		return
	}
	var b struct {
		Through int64 `json:"through"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&b); err != nil || b.Through < 1 {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be {"through": <seq>}`)
		return
	}
	if s.o.Audit == nil {
		writeError(w, http.StatusConflict, "no_audit_log", "this server keeps no audit log (it needs --state-dir)")
		return
	}
	who := s.who(r)
	switch err := s.o.Audit.Ack(who, b.Through); {
	case err == nil:
		s.log.Warn("audit chain problems acknowledged", "by", who.ID, "through", b.Through)
		writeJSON(w, http.StatusOK, s.auditStatusOut())
	case errors.Is(err, audit.ErrNothingToAck):
		writeError(w, http.StatusConflict, "nothing_to_ack", err.Error())
	case errors.Is(err, audit.ErrBadThrough):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	default:
		s.internal(w, err)
	}
}
