package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/ledger"
)

type historyListIn struct {
	Collection string `json:"collection" jsonschema:"collection name"`
	ID         string `json:"id,omitempty" jsonschema:"record id; omit for the history of the whole collection"`
	Cursor     string `json:"cursor,omitempty" jsonschema:"next_cursor of the previous page"`
	Limit      int    `json:"limit,omitempty" jsonschema:"commits per page (default 50, max 100)"`
}

type historyListOut struct {
	Collection string            `json:"collection"`
	ID         string            `json:"id,omitempty"`
	Items      []gitstore.Commit `json:"items" jsonschema:"newest first"`
	NextCursor string            `json:"next_cursor"`
	// ScanLimitReached is true when history_list stopped reading at its scan
	// limit (2000 commits) and there may be older commits it cannot page to.
	ScanLimitReached bool `json:"scan_limit_reached"`
}

type historyDiffIn struct {
	Commit     string `json:"commit" jsonschema:"commit hash from history_list"`
	Collection string `json:"collection,omitempty" jsonschema:"only changes in this collection"`
	ID         string `json:"id,omitempty" jsonschema:"only changes to this record (needs collection)"`
}

type fieldChange struct {
	Field  string `json:"field"`
	Before any    `json:"before,omitempty"`
	After  any    `json:"after,omitempty"`
}

type recordChange struct {
	Collection string        `json:"collection"`
	ID         string        `json:"id"`
	Change     string        `json:"change" jsonschema:"added, updated or removed"`
	Fields     []fieldChange `json:"fields"`
}

type historyDiffOut struct {
	Commit    gitstore.Commit `json:"commit"`
	Total     int             `json:"total" jsonschema:"how many records the commit changed (after the filters)"`
	Changes   []recordChange  `json:"changes"`
	Truncated bool            `json:"truncated" jsonschema:"true when Total exceeds the 500 changes listed"`
}

func (t *tools) addHistoryTools(s *mcp.Server) {
	addTool[historyListIn, historyListOut](t, s, &mcp.Tool{Name: "history_list", Annotations: readAnnotations(),
		Description: "List the commits that changed one record (with id) or one collection, newest first: hash, author, date, subject. For a record it falls back to the collection's file history when the record was edited before per-record history existed. Pass next_cursor back as cursor; at most 100 commits per page."},
		t.historyList)
	addTool[historyDiffIn, historyDiffOut](t, s, &mcp.Tool{Name: "history_diff", Annotations: readAnnotations(),
		Description: "Show what one commit changed, record by record and field by field (before and after), for the commit's ledger files. Take the commit from history_list. Filter with collection and id."},
		t.historyDiff)
}

func (t *tools) historyList(ctx context.Context, _ *mcp.CallToolRequest, in historyListIn) (*mcp.CallToolResult, any, error) {
	if _, _, errRes := t.coll(in.Collection); errRes != nil {
		return errRes, nil, nil
	}
	offset, limit, ok := paging(in.Cursor, in.Limit, defaultLimit, maxHistoryLimit)
	if !ok {
		return errBadCursor, nil, nil
	}
	// One more than the page, to know whether there is a next one.
	commits, err := t.backend.HistoryUpTo(ctx, offset+limit+1, in.Collection, in.ID)
	if err != nil {
		return apiError("internal", "could not read the history: "+err.Error(), nil), nil, nil
	}
	// The scan read at most MaxHistoryScan commits. If it stopped there and the
	// page reaches (or lies past) its end, nothing further can be paged: say so
	// instead of ending the list as if it were complete.
	capped := len(commits) >= gitstore.MaxHistoryScan && offset+limit >= len(commits)
	page, next := pageOf(commits, offset, limit)
	if capped {
		next = ""
	}
	return nil, historyListOut{Collection: in.Collection, ID: in.ID, Items: page, NextCursor: next, ScanLimitReached: capped}, nil
}

func (t *tools) historyDiff(ctx context.Context, _ *mcp.CallToolRequest, in historyDiffIn) (*mcp.CallToolResult, any, error) {
	if in.ID != "" && in.Collection == "" {
		return apiError("invalid", "id needs a collection", nil), nil, nil
	}
	if in.Collection != "" {
		if _, _, errRes := t.coll(in.Collection); errRes != nil {
			return errRes, nil, nil
		}
	}
	d, err := t.backend.CommitChanges(ctx, in.Commit)
	switch {
	case errors.Is(err, gitstore.ErrNoCommit):
		return apiError("not_found", err.Error(), nil), nil, nil
	case err != nil:
		return apiError("invalid", err.Error(), nil), nil, nil
	}
	cfg := t.backend.Config()
	before, after := map[string][]byte{}, map[string][]byte{}
	changed := map[string]bool{}
	for _, f := range d.Files {
		changed[f.Path] = true
		before[f.Path], after[f.Path] = f.Before, f.After
		if before[f.Path] == nil {
			before[f.Path] = []byte{}
		}
		if after[f.Path] == nil {
			after[f.Path] = []byte{}
		}
	}
	lb, la := ledger.Load(cfg, before), ledger.Load(cfg, after)
	var changes []recordChange
	for _, ac := range la.Collections {
		if !changed[ac.File] || (in.Collection != "" && ac.Name != in.Collection) {
			continue
		}
		bc := lb.Collection(ac.Name)
		seen := map[string]bool{}
		for _, r := range ac.Records {
			seen[r.ID] = true
			if in.ID != "" && r.ID != in.ID {
				continue
			}
			var old *ledger.Record
			if bc != nil {
				old = bc.Get(r.ID)
			}
			switch {
			case old == nil:
				changes = append(changes, recordChange{Collection: ac.Name, ID: r.ID, Change: "added", Fields: fieldChanges(nil, r.Data)})
			case old.Hash != r.Hash:
				changes = append(changes, recordChange{Collection: ac.Name, ID: r.ID, Change: "updated", Fields: fieldChanges(old.Data, r.Data)})
			}
		}
		if bc == nil {
			continue
		}
		for _, r := range bc.Records {
			if !seen[r.ID] && (in.ID == "" || r.ID == in.ID) {
				changes = append(changes, recordChange{Collection: ac.Name, ID: r.ID, Change: "removed", Fields: fieldChanges(r.Data, nil)})
			}
		}
	}
	out := historyDiffOut{Commit: d.Commit, Total: len(changes), Changes: []recordChange{}}
	if len(changes) > maxLimit {
		changes, out.Truncated = changes[:maxLimit], true
	}
	out.Changes = append(out.Changes, changes...)
	return nil, out, nil
}

// fieldChanges lists the fields whose value differs between two versions of a
// record, sorted by name. A nil side means the record did not exist.
func fieldChanges(before, after map[string]any) []fieldChange {
	names := map[string]bool{}
	for k := range before {
		names[k] = true
	}
	for k := range after {
		names[k] = true
	}
	out := []fieldChange{}
	for k := range names {
		b, a := before[k], after[k]
		bj, _ := json.Marshal(b)
		aj, _ := json.Marshal(a)
		if string(bj) != string(aj) {
			out = append(out, fieldChange{Field: k, Before: b, After: a})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return slices.Clip(out)
}
