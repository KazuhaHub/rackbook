package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
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

func (s *server) activityRoutes(mux *routeMux) {
	mux.HandleFunc("GET /api/activity", s.activity)
	mux.HandleFunc("GET /api/activity/commit/{area}/{hash}", s.activityCommit)
	mux.HandleFunc("GET /api/audit/status", s.auditStatus)
	mux.HandleFunc("GET /api/audit/identities", s.auditIdentities)
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
	seeExport                   // the JSONL export of everything the caller may see
)

// canSee is the one place that says who may see which kind of activity.
// Everybody sees the ledger. State (.rackbook/ commits), audit events and the
// export are for administrators and auditors (auth.auditors: a capability that
// is separate from the role, design 3.4). Infra is for the infra
// administrators and the infra auditors (--infra-admins, --infra-auditors).
// Seeing is not acknowledging: the acknowledgement is admin-only and does not
// go through here.
func (s *server) canSee(r *http.Request, v visibility) bool {
	switch v {
	case seeLedger:
		return true
	case seeState, seeAudit, seeExport:
		return auth.Can(r.Context(), roles.Manage) || auth.IsAuditor(r.Context())
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
	// RestoredFrom is the commit a restore took the record from (the Restored-from trailer).
	RestoredFrom string `json:"restoredFrom,omitempty"`
	// Verified says this server made the commit (its audit log has the line).
	Verified *bool  `json:"verified,omitempty"`
	Token    string `json:"token,omitempty"`
	// State: the commit touches .rackbook/ ("only" or "some"); administrators and auditors (seeState).
	State string `json:"state,omitempty"`

	// Audit events.
	Seq   int64  `json:"seq,omitempty"`
	Event string `json:"event,omitempty"`
	// Target is the account an administrator or the command line acted on, when that is not the actor
	// ("local:<username>").
	Target  string   `json:"target,omitempty"`
	Reason  string   `json:"reason,omitempty"`
	Code    string   `json:"code,omitempty"`
	Role    string   `json:"role,omitempty"`
	Addr    string   `json:"addr,omitempty"` // administrators and auditors (seeAudit)
	Outcome string   `json:"outcome,omitempty"`
	Action  string   `json:"action,omitempty"`
	Host    string   `json:"host,omitempty"`
	Files   []string `json:"files,omitempty"`
	Detail  []string `json:"detail,omitempty"`
	// sign-in events: the groups or roles claim was cut off ("overage"); the person signed in without the lost values.
	Groups   string `json:"groups,omitempty"`
	AppRoles string `json:"app_roles,omitempty"`
	// how the person was an infra administrator (identity, group or app_role) on a sign-in and on infra events; infra_overage on a
	// sign-in: the claim entry of --infra-admins or --infra-auditors could not be used because its list was cut off (groups, app_roles).
	InfraVia        string `json:"infra_via,omitempty"`
	InfraAuditorVia string `json:"infra_auditor_via,omitempty"`
	InfraOverage    string `json:"infra_overage,omitempty"`
	// role_changed: the role and auditor capability before and after, and why it was seen (sign_in or config).
	From        string `json:"from,omitempty"`
	To          string `json:"to,omitempty"`
	AuditorFrom *bool  `json:"auditor_from,omitempty"`
	AuditorTo   *bool  `json:"auditor_to,omitempty"`
	Cause       string `json:"cause,omitempty"`

	at  time.Time // the time, to the second
	src int       // ledger, infra, audit: the tie-break after the time
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

func commitItems(area string, src int, cs []gitstore.ActivityCommit, showState bool) []walkEntry {
	out := make([]walkEntry, 0, len(cs))
	for _, c := range cs {
		it := &activityItem{Area: area, Kind: "commit", Hash: c.Hash, Short: c.Short, Commit: c.Short, Subject: c.Subject,
			Records: c.Records, Via: c.EditedVia, RestoredFrom: c.RestoredFrom, at: c.Time.Truncate(time.Second), src: src,
			// as written in the commit: nothing here proves it (see markVerified)
			Identity: c.EditedBy, Name: c.Author}
		it.Time = it.at.Format(time.RFC3339)
		if showState && (c.State == gitstore.StateOnly || c.State == gitstore.StateSome) {
			it.State = c.State
		}
		out = append(out, walkEntry{item: it, match: !c.Excluded})
	}
	return out
}

// showInfra says the caller is an infra administrator or auditor: only they may see how anyone is one (infra_via
// and the rest), or the list of infra administrators would reach every ledger administrator and auditor.
func eventItems(es []audit.Event, showAddr, showInfra bool) []*activityItem {
	out := make([]*activityItem, 0, len(es))
	for _, e := range es {
		area := areaAudit
		if e.Area == areaInfra {
			area = areaInfra
		}
		it := &activityItem{Area: area, Kind: e.Event, Event: e.Event, Seq: e.Seq, Identity: e.Identity, Target: e.Target, Name: e.Name, Method: e.Method,
			Reason: e.Reason, Code: e.Code, Role: e.Role, Outcome: e.Outcome, Action: e.Action, Host: e.Host, Files: e.Files,
			Groups: e.Groups, AppRoles: e.AppRoles, From: e.From, To: e.To, AuditorFrom: e.AuditorFrom, AuditorTo: e.AuditorTo, Cause: e.Cause,
			at: e.Time.UTC().Truncate(time.Second), src: 2}
		if showInfra {
			it.InfraVia, it.InfraAuditorVia, it.InfraOverage = e.InfraVia, e.InfraAuditorVia, e.InfraOverage
		}
		for _, d := range e.Detail {
			if v, ok := strings.CutPrefix(d, "token:"); ok {
				it.Token = v
			} else {
				it.Detail = append(it.Detail, d)
			}
		}
		if showAddr {
			it.Addr = e.Addr
		}
		it.Time = it.at.Format(time.RFC3339)
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
		if !s.canSee(r, seeExport) {
			writeError(w, http.StatusForbidden, "forbidden", "only administrators and auditors may export the activity")
			return
		}
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
	cur, err := s.decodeCursor(s.cursorBinding(r, f), q.Get("cursor"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "cursor_invalid", "the cursor is not valid (it does not survive a restart, and is for the person who got it); start again without it")
		return
	}
	items, next, work, err := s.activityPage(r, s.cursorBinding(r, f), f, cur, limit)
	if errors.Is(err, gitstore.ErrBadTip) {
		writeError(w, http.StatusBadRequest, "cursor_invalid", "the cursor no longer fits this history; start again without it")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	out := map[string]any{"items": items, "areas": s.visibleAreas(r), "audit": s.o.Audit != nil, "scanned": work}
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
	var cur activityCursor
	sent, work := 0, 0
	truncated := func() { _ = enc.Encode(map[string]bool{"truncated": true}) }
	for {
		items, next, w1, err := s.activityPage(r, s.cursorBinding(r, f), f, cur, 500)
		if err != nil {
			s.log.Error("activity export failed", "err", err)
			_ = enc.Encode(map[string]any{"error": "internal"})
			return
		}
		work += w1
		for _, it := range items {
			if sent >= maxExportItems {
				truncated()
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
		if sent >= maxExportItems || work >= exportWorkBudget {
			truncated()
			return
		}
		if cur, err = s.decodeCursor(s.cursorBinding(r, f), next); err != nil {
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
		if !s.infraReader(w, r) {
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

// auditAccess admits the audit status (administrators and auditors) and, with
// write, the acknowledgement. The acknowledgement is for administrators only,
// whatever the auditor list says, and never for a token.
func (s *server) auditAccess(w http.ResponseWriter, r *http.Request, write bool) bool {
	if write && s.o.ReadOnly {
		writeError(w, http.StatusForbidden, "read_only", "the ledger is read-only")
		return false
	}
	id := s.who(r)
	switch {
	case id == nil:
	case write:
		if id.Method != auth.MethodToken && auth.Can(r.Context(), roles.Manage) {
			return true
		}
		writeError(w, http.StatusForbidden, "forbidden", "only administrators may acknowledge the audit log status")
		return false
	case s.canSee(r, seeAudit):
		return true
	}
	writeError(w, http.StatusForbidden, "forbidden", "only administrators and auditors may see the audit log status")
	return false
}

func (s *server) auditStatus(w http.ResponseWriter, r *http.Request) {
	if !s.auditAccess(w, r, false) {
		return
	}
	writeJSON(w, http.StatusOK, s.auditStatusOut())
}

// auditIdentities lists audit/identities.json: for each person who signed in, the
// last role and auditor flag Rackbook saw, when and how. It holds no groups and no
// claims. It is part of the audit log's story about sign-ins, so it is visible to
// the same people as the sign-in events: administrators and auditors (seeAudit).
func (s *server) auditIdentities(w http.ResponseWriter, r *http.Request) {
	if !s.canSeeIdentities(w, r) {
		return
	}
	out := []audit.IdentityEntry{}
	if s.o.Audit != nil {
		out = append(out, s.o.Audit.Identities()...)
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": s.o.Audit != nil, "max": audit.MaxIdentities, "identities": out})
}

func (s *server) canSeeIdentities(w http.ResponseWriter, r *http.Request) bool {
	if s.who(r) != nil && s.canSee(r, seeAudit) {
		return true
	}
	writeError(w, http.StatusForbidden, "forbidden", "only administrators and auditors may see the sign-in identities")
	return false
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
	if !s.auditAccess(w, r, true) {
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

// cursorBinding is what a cursor is signed together with: who the caller is, the
// filters in effect and what the caller may see. A cursor used with other
// filters, or after a role change, no longer verifies.
func (s *server) cursorBinding(r *http.Request, f *activityFilter) string {
	who := ""
	if id := s.who(r); id != nil {
		who = id.Method + ":" + id.ID
	}
	areas := slices.Clone(f.areas)
	slices.Sort(areas)
	return strings.Join([]string{who, strings.Join(areas, ","), f.collection, f.id, strconv.FormatInt(f.since.Unix(), 10), strconv.FormatInt(f.until.Unix(), 10), f.identity,
		strconv.FormatBool(s.canSee(r, seeState)), strconv.FormatBool(s.canSee(r, seeInfra)), strconv.FormatBool(s.canSee(r, seeAudit))}, "\x00")
}
