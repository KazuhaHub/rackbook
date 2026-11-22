package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/roles"
)

// A record's version history, restore, and deleted records
// (docs/design-audit.md, section 3.3). Everyone with a role may read the history,
// as for /api/history; restore is a write and has the gates of PUT.

func (s *server) historyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/c/{collection}/{id}/history", s.versions)
	mux.HandleFunc("GET /api/c/{collection}/{id}/history/{commit}", s.version)
	mux.HandleFunc("POST /api/c/{collection}/{id}/restore", s.restore)
	mux.HandleFunc("GET /api/c/{collection}/deleted", s.deleted)
}

const (
	defaultVersionLimit = 20
	maxVersionLimit     = 50
)

// versionOut is one version of a record: the commit as the activity view shows
// it, and what the commit changed in the record.
type versionOut struct {
	*activityItem
	Change      string                 `json:"change"` // created, changed, deleted or renamed
	RenamedFrom string                 `json:"renamedFrom,omitempty"`
	RenamedTo   string                 `json:"renamedTo,omitempty"`
	RecordHash  string                 `json:"recordHash"`
	Changes     []gitstore.FieldChange `json:"changes"`
	MoreChanges bool                   `json:"moreChanges,omitempty"`
	Unreadable  bool                   `json:"unreadable,omitempty"`
	Approximate bool                   `json:"approximate,omitempty"`
}

// commitItem makes the activity item of one commit, verified as in the activity view.
func (s *server) commitItems(r *http.Request, cs []gitstore.ActivityCommit) []*activityItem {
	ents := commitItems(areaLedger, 0, cs, s.canSee(r, seeState))
	items := make([]*activityItem, len(ents))
	for i, e := range ents {
		items[i] = e.item
	}
	s.markVerified(items)
	return items
}

func (s *server) versionBinding(r *http.Request, coll, id string) string {
	who := ""
	if i := s.who(r); i != nil {
		who = i.Method + ":" + i.ID
	}
	return who + "\x00versions\x00" + coll + "\x00" + id
}

func (s *server) versions(w http.ResponseWriter, r *http.Request) {
	_, c := s.collection(w, r)
	if c == nil {
		return
	}
	id := r.PathValue("id")
	q := r.URL.Query()
	limit := defaultVersionLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "bad_request", "limit must be a positive whole number")
			return
		}
		limit = min(n, maxVersionLimit)
	}
	binding := s.versionBinding(r, c.Name, id)
	cur, err := s.decodeCursor(binding, q.Get("cursor"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "cursor_invalid", "the cursor is not valid (it does not survive a restart, and is for the person who got it); start again without it")
		return
	}
	sc := cur["versions"]
	pg, err := s.o.Store.RecordVersions(r.Context(), gitstore.VersionQuery{Collection: c.Name, ID: id, Tip: sc.Tip, Skip: sc.N, Limit: limit})
	if errors.Is(err, gitstore.ErrBadTip) {
		writeError(w, http.StatusBadRequest, "cursor_invalid", "the cursor no longer fits this history; start again without it")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	cs := make([]gitstore.ActivityCommit, len(pg.Versions))
	for i, v := range pg.Versions {
		cs[i] = v.Commit
	}
	items := s.commitItems(r, cs)
	out := make([]versionOut, len(pg.Versions))
	for i, v := range pg.Versions {
		out[i] = versionOut{activityItem: items[i], Change: v.Kind, RenamedFrom: v.RenamedFrom, RenamedTo: v.RenamedTo,
			RecordHash: v.Hash, Changes: v.Changes, MoreChanges: v.MoreChanges, Unreadable: v.Unreadable, Approximate: v.Approximate}
	}
	body := map[string]any{"id": pg.ID, "versions": out, "audit": s.o.Audit != nil}
	if !pg.Done {
		body["cursor"] = s.encodeCursor(binding, activityCursor{"versions": {Tip: pg.Tip, N: pg.Skip}})
	}
	writeJSON(w, http.StatusOK, body)
}

// version is one version of the record with what restoring it would change.
func (s *server) version(w http.ResponseWriter, r *http.Request) {
	_, c := s.collection(w, r)
	if c == nil {
		return
	}
	d, err := s.o.Store.VersionAt(r.Context(), c.Name, r.PathValue("id"), r.PathValue("commit"))
	if errors.Is(err, gitstore.ErrNoCommit) || errors.Is(err, gitstore.ErrNotInCommit) {
		writeError(w, http.StatusNotFound, "not_found", "no such version of this record")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	items := s.commitItems(r, []gitstore.ActivityCommit{d.Commit})
	writeJSON(w, http.StatusOK, map[string]any{"id": d.ID, "commit": items[0], "recordHash": d.Hash, "data": d.Data, "hidden": d.Hidden,
		"exists": d.Exists, "current": d.Current, "changes": d.Changes, "moreChanges": d.MoreChanges})
}

type restoreBody struct {
	Commit           string `json:"commit"`
	Hash             string `json:"hash"`
	ConfirmNotSecret bool   `json:"confirm_not_secret"`
	// ConfirmNotSecretCamel is the same, as written in the design.
	ConfirmNotSecretCamel bool `json:"confirmNotSecret"`
}

// restoreNeedsEdit answers a restore that cannot be done as it is: the old
// content is returned (without the values the secret scan flags) so that the
// console opens it in the editor, to be fixed and saved as an ordinary edit.
func restoreNeedsEdit(w http.ResponseWriter, src *gitstore.RestoreSource, msg string, extra ...any) {
	paths := src.HiddenPaths
	if paths == nil {
		paths = []string{}
	}
	extra = append([]any{"data", src.Visible, "hidden", src.Hidden, "hiddenPaths", paths, "commit", src.Commit}, extra...)
	writeError(w, http.StatusConflict, "restore_needs_edit", msg, extra...)
}

// restore writes the record as it was at a commit as one new commit.
func (s *server) restore(w http.ResponseWriter, r *http.Request) {
	if !s.writable(w, r, roles.Write) {
		return
	}
	_, c := s.collection(w, r)
	if c == nil {
		return
	}
	var b restoreBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return
	}
	if b.Commit == "" {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be {"commit": "<commit>", "hash": "<hash of the current record>"}`)
		return
	}
	if !s.permits(w, r, auth.ActUpdate, c.Name) {
		return
	}
	id := r.PathValue("id")
	cfg := s.o.Store.Config()
	cur := c.Get(id)
	if cur == nil && !s.permits(w, r, auth.ActCreate, c.Name) {
		return // bringing a deleted record back creates it
	}
	if cur != nil && b.Hash == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "hash is required: send the hash of the record you started from (an empty hash is for a record that no longer exists)")
		return
	}
	src, err := s.o.Store.RestoreSourceAt(r.Context(), c.Name, id, b.Commit)
	switch {
	case errors.Is(err, gitstore.ErrNoCommit):
		writeError(w, http.StatusNotFound, "not_found", "no such commit on the tracked branch")
		return
	case errors.Is(err, gitstore.ErrNotInCommit):
		writeError(w, http.StatusNotFound, "not_found", "the record did not exist in that commit")
		return
	case err != nil:
		s.internal(w, err)
		return
	}
	switch {
	case cur != nil && cur.Hash != b.Hash:
		s.writeFailure(w, &edit.ConflictError{Message: c.Name + " " + strconv.Quote(ledger.SafeID(cfg, c.Name, cur.ID)) + " was changed by someone else", Current: cur})
		return
	case cur == nil && b.Hash != "":
		s.writeFailure(w, &edit.ConflictError{Message: c.Name + " " + strconv.Quote(ledger.SafeID(cfg, c.Name, id)) + " no longer exists"})
		return
	case cur != nil && src.Hash == cur.Hash:
		writeError(w, http.StatusConflict, "already_current", "the record already is that version")
		return
	}
	// The key fields give the id; a version whose key fields give another id (they
	// were edited since, or the collection has no key) is an edit, not a restore.
	newID := ledger.ID(c.Collection, 0, src.Data)
	switch {
	case len(c.Key) == 0:
		restoreNeedsEdit(w, src, "this collection has no key, so the record cannot be found in the old version with certainty: check it and save it as an edit")
		return
	case cur != nil && newID != cur.ID, cur == nil && newID != id && ledger.SafeID(cfg, c.Name, newID) != id:
		restoreNeedsEdit(w, src, "the key fields of that version give another id than this record's: check it and save it as an edit")
		return
	}
	op := edit.Op{Kind: edit.Add, Collection: c.Name, Data: src.Data, RestoredFrom: src.Commit}
	if cur != nil {
		op = edit.Op{Kind: edit.Edit, Collection: c.Name, ID: cur.ID, Hash: b.Hash, Data: src.Data, RestoredFrom: src.Commit}
	}
	res, err := s.applyOp(r, s.confirmed(r, op, b.ConfirmNotSecret || b.ConfirmNotSecretCamel))
	var ie *edit.InvalidError
	if errors.As(err, &ie) {
		restoreNeedsEdit(w, src, "that version no longer fits the current schema or references: fix it and save it as an edit", "errors", s.safeIssues(ie.Issues))
		return
	}
	if err != nil {
		s.writeFailure(w, err)
		return
	}
	out := recordResponse(res)
	out["restoredFrom"] = src.Commit
	status := http.StatusOK
	if cur == nil {
		status = http.StatusCreated
	}
	writeJSON(w, status, out)
}

// deletedOut is one deleted record of the list.
type deletedOut struct {
	*activityItem
	// ID is the id as it is shown; Last the commit that still had the record (what
	// Restore takes it from); DeletedAt the time of the deleting commit.
	ID        string                  `json:"id"`
	Last      string                  `json:"last"`
	DeletedAt string                  `json:"deletedAt"`
	Summary   []gitstore.SummaryField `json:"summary"`
}

// deleted lists the records whose last change removed them.
func (s *server) deleted(w http.ResponseWriter, r *http.Request) {
	_, c := s.collection(w, r)
	if c == nil {
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "bad_request", "limit must be a positive whole number")
			return
		}
		limit = min(n, 100)
	}
	res, err := s.o.Store.DeletedRecords(r.Context(), c.Name)
	if err != nil {
		s.internal(w, err)
		return
	}
	more := len(res.Records) > limit
	recs := res.Records[:min(len(res.Records), limit)]
	cs := make([]gitstore.ActivityCommit, len(recs))
	for i, e := range recs {
		cs[i] = e.ActivityCommit()
	}
	items := s.commitItems(r, cs)
	out := make([]deletedOut, len(recs))
	for i, e := range recs {
		fields := e.Fields
		if fields == nil {
			fields = []gitstore.SummaryField{}
		}
		out[i] = deletedOut{activityItem: items[i], ID: e.ID, Last: e.Last, DeletedAt: items[i].Time, Summary: fields}
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": out, "complete": res.Complete, "more": more, "audit": s.o.Audit != nil})
}

// issueOut is a validation problem as a restore reports it: where it is and which rule
// failed, and nothing the validator quoted from the old content (its message and
// params carry values, which may be ones the secret scan hides).
type issueOut struct {
	Collection string         `json:"collection"`
	ID         string         `json:"id,omitempty"`
	Path       string         `json:"path"`
	Rule       string         `json:"rule"`
	Keyword    string         `json:"keyword,omitempty"`
	Message    string         `json:"message"`
	Params     map[string]any `json:"params,omitempty"`
}

// safeParams are the params of an issue that name fields, limits and rules, never a value of the record.
var safeParams = map[string]bool{"missing": true, "format": true, "limit": true, "fields": true, "key": true, "target": true, "side": true, "left": true, "right": true}

func (s *server) safeIssues(in []ledger.Issue) []issueOut {
	cfg := s.o.Store.Config()
	out := make([]issueOut, 0, len(in))
	for _, i := range in {
		o := issueOut{Collection: i.Collection, ID: ledger.SafeID(cfg, i.Collection, i.ID), Path: i.Path, Rule: i.Rule, Keyword: i.Keyword,
			Message: "this version does not pass the current check (" + i.Rule + ")"}
		for k, v := range i.Params {
			if safeParams[k] {
				if o.Params == nil {
					o.Params = map[string]any{}
				}
				o.Params[k] = v
			}
		}
		out = append(out, o)
	}
	return out
}
