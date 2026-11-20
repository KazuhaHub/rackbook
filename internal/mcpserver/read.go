package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/export"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/labels"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/locale"
	"github.com/kazuhahub/rackbook/internal/validate"
)

// coll finds a collection, or builds the not_found result.
func (t *tools) coll(name string) (*ledger.Ledger, *ledger.Collection, *mcp.CallToolResult) {
	l := t.src()
	c := l.Collection(name)
	if c == nil {
		names := make([]string, len(l.Collections))
		for i, x := range l.Collections {
			names[i] = x.Name
		}
		return nil, nil, apiError("not_found", fmt.Sprintf("unknown collection %q; use collections_list", name), map[string]any{"available": names})
	}
	return l, c, nil
}

type recordItem struct {
	ID   string         `json:"id"`
	Hash string         `json:"hash"`
	Data map[string]any `json:"data"`
}

func item(r *ledger.Record) recordItem { return recordItem{ID: r.ID, Hash: r.Hash, Data: r.Data} }

// collections_list, collections_describe -----------------------------------

type collectionEntry struct {
	Name         string           `json:"name"`
	Title        string           `json:"title"`
	Group        string           `json:"group,omitempty"`
	Description  string           `json:"description,omitempty"`
	Key          []string         `json:"key,omitempty"`
	Fields       []fieldInfo      `json:"fields"`
	References   []ledger.RefInfo `json:"references"`
	ReferencedBy []ledger.BackRef `json:"referenced_by"`
	Records      int              `json:"records"`
}

type collectionsListOut struct {
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Collections []collectionEntry `json:"collections"`
}

func entryOf(l *ledger.Ledger, c *ledger.Collection) collectionEntry {
	req := map[string]bool{}
	for _, r := range c.Schema.Required {
		req[r] = true
	}
	e := collectionEntry{Name: c.Name, Title: c.Title, Group: c.Group, Description: c.Description, Key: c.Key, Fields: []fieldInfo{},
		References: l.Refs(c.Name), ReferencedBy: l.BackRefs(c.Name), Records: len(c.Records)}
	if e.References == nil {
		e.References = []ledger.RefInfo{}
	}
	if e.ReferencedBy == nil {
		e.ReferencedBy = []ledger.BackRef{}
	}
	for _, p := range c.Schema.Props {
		e.Fields = append(e.Fields, fieldInfo{Name: p.Name, Title: p.Title, Type: p.Type, Required: req[p.Name]})
	}
	return e
}

func (t *tools) collectionsListOut() collectionsListOut {
	l := t.src()
	out := collectionsListOut{Title: l.Config.Title, Description: l.Config.Description, Collections: []collectionEntry{}}
	for _, c := range l.Collections {
		out.Collections = append(out.Collections, entryOf(l, c))
	}
	return out
}

type describeIn struct {
	Collection string `json:"collection" jsonschema:"collection name from collections_list"`
}

type noteInfo struct {
	Title string `json:"title"`
	Text  string `json:"text"`
}

type describeOut struct {
	Name         string           `json:"name"`
	Title        string           `json:"title"`
	Group        string           `json:"group,omitempty"`
	Description  string           `json:"description,omitempty"`
	Key          []string         `json:"key,omitempty"`
	Label        string           `json:"label,omitempty" jsonschema:"template that renders a record's display name"`
	Fields       []fieldInfo      `json:"fields"`
	Schema       map[string]any   `json:"schema" jsonschema:"the JSON Schema of one record"`
	References   []ledger.RefInfo `json:"references" jsonschema:"fields of this collection that point at other collections"`
	ReferencedBy []ledger.BackRef `json:"referenced_by" jsonschema:"fields of other collections that point here"`
	Facets       []config.Facet   `json:"facets"`
	Notes        []noteInfo       `json:"notes"`
	Records      int              `json:"records"`
	Documents    bool             `json:"documents" jsonschema:"whether records of this collection can carry documents"`
}

func (t *tools) describe(name string) (describeOut, *mcp.CallToolResult) {
	l, c, errRes := t.coll(name)
	if errRes != nil {
		return describeOut{}, errRes
	}
	if c.SchemaRaw == nil {
		return describeOut{}, apiError("config_error", fmt.Sprintf("collection %s has no readable schema", c.Name), nil)
	}
	e := entryOf(l, c)
	out := describeOut{Name: e.Name, Title: e.Title, Group: e.Group, Description: e.Description, Key: e.Key, Label: c.Label, Fields: e.Fields,
		References: e.References, ReferencedBy: e.ReferencedBy, Facets: c.Facets, Notes: []noteInfo{}, Records: e.Records}
	if out.Facets == nil {
		out.Facets = []config.Facet{}
	}
	if err := json.Unmarshal(c.SchemaRaw, &out.Schema); err != nil {
		return describeOut{}, apiError("config_error", fmt.Sprintf("the schema of %s is not valid JSON", c.Name), nil)
	}
	describeFields(out.Fields, out.Schema)
	for _, n := range l.Notes {
		if n.Collection == c.Name {
			out.Notes = append(out.Notes, noteInfo{Title: n.Title, Text: n.Text})
		}
	}
	return out, nil
}

// describeFields adds what a client needs to read the stored codes: the field
// titles in every language the schema translates, and for each enum-like field
// (an array of them, or a property of a row object) its codes with their labels
// per language. Fields named in rows get their values under the row's field.
func describeFields(fields []fieldInfo, schema map[string]any) {
	props, _ := schema["properties"].(map[string]any)
	for i := range fields {
		prop, _ := props[fields[i].Name].(map[string]any)
		if prop == nil {
			continue
		}
		if t := fieldTitles(prop); t != nil {
			fields[i].Titles = t
		}
		target := prop
		items, _ := prop["items"].(map[string]any)
		if items != nil {
			target = items
		}
		if vs := valuesOf(target); vs != nil {
			fields[i].Values = vs
		}
		// row objects: the enum-like properties inside items.properties
		if rowProps, ok := items["properties"].(map[string]any); ok {
			names := make([]string, 0, len(rowProps))
			for n := range rowProps {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				rp, _ := rowProps[n].(map[string]any)
				if rp == nil {
					continue
				}
				row := rowField{Name: n, Titles: fieldTitles(rp)}
				if s, ok := rp["title"].(string); ok {
					row.Title = s
				}
				row.Values = valuesOf(rp)
				if row.Values == nil && row.Titles == nil {
					continue
				}
				fields[i].Row = append(fields[i].Row, row)
			}
		}
	}
}

func fieldTitles(prop map[string]any) map[string]string {
	if len(labels.Translations(prop)) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, loc := range locale.Supported {
		if s := labels.Text(prop, loc, "title"); s != "" {
			out[loc] = s
		}
	}
	return out
}

func valuesOf(prop map[string]any) []valueInfo {
	en, ok := labels.Parse(prop)
	if !ok {
		return nil
	}
	var out []valueInfo
	for _, it := range en.Items {
		v := valueInfo{Code: it.Code, Labels: map[string]string{}}
		differs := false
		for _, loc := range locale.Supported {
			l := en.Label(loc, it.Code)
			v.Labels[loc] = l
			differs = differs || l != it.Code
		}
		if !differs {
			v.Labels = nil
		}
		out = append(out, v)
	}
	return out
}

func (t *tools) addReadTools(s *mcp.Server) {
	addTool[noArgs, collectionsListOut](t, s, &mcp.Tool{Name: "collections_list", Annotations: readAnnotations(),
		Description: "List every collection in the ledger with its title, description, key fields, fields (name, title, type, required), references to and from other collections and record count. Call this first to learn the collection names and field names used by the other tools."},
		func(context.Context, *mcp.CallToolRequest, noArgs) (*mcp.CallToolResult, any, error) {
			return nil, t.collectionsListOut(), nil
		})
	addTool[describeIn, describeOut](t, s, &mcp.Tool{Name: "collections_describe", Annotations: readAnnotations(),
		Description: "Describe one collection: title, description, key fields, label, the JSON Schema of its records, references in and out, facets, notes, record count and whether it supports documents. For enum-like fields, fields[].values lists the allowed codes with their labels per language: records hold the codes, never the labels. Read it to build valid records for records_create and records_update."},
		func(_ context.Context, _ *mcp.CallToolRequest, in describeIn) (*mcp.CallToolResult, any, error) {
			out, errRes := t.describe(in.Collection)
			if errRes != nil {
				return errRes, nil, nil
			}
			return nil, out, nil
		})
	addTool[queryIn, queryOut](t, s, &mcp.Tool{Name: "records_query", Annotations: readAnnotations(),
		Description: "List the records of one collection (file order unless order_by), filtered by where and search, one page at a time. where maps a field to a value for an exact match (an array field matches when any element equals it), or to {\"contains\": text} or {\"prefix\": text} (case-sensitive, like the console facets); every condition must hold. search is a case-insensitive substring over every field. fields keeps only those fields in each item's data. order_by is a field name, with a leading - for descending. Pass next_cursor back as cursor for the next page. For \"what services run on host X\" use collection=services where={\"device\":\"X\"}, and remember that rows with device \"all\" apply to every host."},
		t.recordsQuery)
	addTool[getIn, getOut](t, s, &mcp.Tool{Name: "records_get", Annotations: readAnnotations(),
		Description: "Get one record by id (the key field values joined with \"/\", with \"/\" and \"%\" inside a value written as %2F and %25): {id, hash, data}. Use the hash as expected_hash when you update or delete it. include adds backrefs (the records of other collections that reference it; for a device its addresses and services, including services declared for device \"all\") and history (the commits that changed it)."},
		t.recordsGet)
	addTool[searchIn2, searchOut2](t, s, &mcp.Tool{Name: "ledger_search", Annotations: readAnnotations(),
		Description: "Case-insensitive substring search over every text, number and boolean field of every record (or of the listed collections), best matches first: an exact field value ranks above a partial one, and a match in a key field above another field. Use it when you do not know the collection, e.g. \"who uses port 10511\", \"which host has IP 198.51.100.20\". Each hit lists the fields that matched. include_docs is accepted for when records carry documents; this server has none yet."},
		t.ledgerSearch)
	addTool[checkIn2, checkOut2](t, s, &mcp.Tool{Name: "ledger_check", Annotations: readAnnotations(),
		Description: "Validate the whole ledger (YAML syntax, JSON Schema, unique keys, references, set rules) and report every error and warning with collection, record id, field path, rule and message, plus any store state that pauses writes (history_rewritten, config_error). Filter with collection or rule. Check before writing, and after."},
		t.ledgerCheck)
	addTool[exportIn, exportOut](t, s, &mcp.Tool{Name: "ledger_export", Annotations: readAnnotations(),
		Description: "Return the ledger (or one collection) as one Markdown document (a table per collection) or as JSON. Limited to 1 MiB; a larger export is refused with too_large and the resource rackbook://export/markdown to read instead. Prefer records_query, records_get or ledger_search for targeted questions."},
		t.ledgerExport)
}

// records_query ----------------------------------------------------------------

type queryIn struct {
	Collection string         `json:"collection" jsonschema:"collection name from collections_list"`
	Where      map[string]any `json:"where,omitempty" jsonschema:"field to value (exact match) or to {contains: text} / {prefix: text}; every condition must hold"`
	Search     string         `json:"search,omitempty" jsonschema:"case-insensitive substring over every field"`
	Fields     []string       `json:"fields,omitempty" jsonschema:"keep only these fields in data"`
	OrderBy    string         `json:"order_by,omitempty" jsonschema:"field name; a leading - sorts descending"`
	Cursor     string         `json:"cursor,omitempty" jsonschema:"next_cursor of the previous page"`
	Limit      int            `json:"limit,omitempty" jsonschema:"items per page (default 50, max 500)"`
}

type queryOut struct {
	Collection string       `json:"collection"`
	Total      int          `json:"total" jsonschema:"how many records match, over all pages"`
	Items      []recordItem `json:"items"`
	NextCursor string       `json:"next_cursor" jsonschema:"pass as cursor for the next page; empty on the last page"`
}

type cond struct {
	field, op, val string
}

// rowValues are the values a record offers to a condition: each element of an
// array, else the value itself.
func rowValues(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		out := make([]string, len(x))
		for i, e := range x {
			out[i] = ledger.Str(e)
		}
		return out
	}
	return []string{ledger.Str(v)}
}

func (c cond) match(v any) bool {
	vals := rowValues(v)
	if len(vals) == 0 && c.op == "eq" {
		vals = []string{""} // an unset field equals ""
	}
	for _, s := range vals {
		switch c.op {
		case "eq":
			if s == c.val {
				return true
			}
		case "contains":
			if strings.Contains(s, c.val) {
				return true
			}
		case "prefix":
			if strings.HasPrefix(s, c.val) {
				return true
			}
		}
	}
	return c.op == "eq" && ledger.Str(v) == c.val // a whole object or array written out
}

func scalarText(v any) (string, bool) {
	switch v.(type) {
	case string, float64, bool, json.Number, int, int64:
		return ledger.Str(v), true
	}
	return "", false
}

func parseWhere(where map[string]any, known map[string]bool) ([]cond, string) {
	keys := make([]string, 0, len(where))
	for k := range where {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var conds []cond
	for _, k := range keys {
		if len(known) > 0 && !known[k] {
			return nil, fmt.Sprintf("where: unknown field %q; fields: %s", k, strings.Join(sortedKeys(known), ", "))
		}
		switch v := where[k].(type) {
		case map[string]any:
			if len(v) == 0 {
				return nil, fmt.Sprintf("where.%s: give contains or prefix", k)
			}
			ops := make([]string, 0, len(v))
			for op := range v {
				ops = append(ops, op)
			}
			sort.Strings(ops)
			for _, op := range ops {
				text, ok := scalarText(v[op])
				if !ok || (op != "contains" && op != "prefix" && op != "eq") {
					return nil, fmt.Sprintf("where.%s.%s: operators are contains and prefix, with a text, number or boolean value", k, op)
				}
				conds = append(conds, cond{k, op, text})
			}
		default:
			text, ok := scalarText(v)
			if !ok {
				return nil, fmt.Sprintf("where.%s: use a text, number or boolean for an exact match, or {contains: …} / {prefix: …}", k)
			}
			conds = append(conds, cond{k, "eq", text})
		}
	}
	return conds, ""
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func propSet(c *ledger.Collection) map[string]bool {
	known := map[string]bool{}
	for _, p := range c.Schema.Props {
		known[p.Name] = true
	}
	return known
}

// matchedFields are the fields of r whose text contains q (lower case), sorted.
func matchedFields(r *ledger.Record, q string) []string {
	var fields []string
	for k, v := range r.Data {
		if strings.Contains(strings.ToLower(flatten(v)), q) {
			fields = append(fields, k)
		}
	}
	sort.Strings(fields)
	return fields
}

func lessValue(a, b any) bool {
	x, y := ledger.Str(a), ledger.Str(b)
	fx, ex := strconv.ParseFloat(x, 64)
	fy, ey := strconv.ParseFloat(y, 64)
	if ex == nil && ey == nil {
		return fx < fy
	}
	return x < y
}

func (t *tools) recordsQuery(_ context.Context, _ *mcp.CallToolRequest, in queryIn) (*mcp.CallToolResult, any, error) {
	_, c, errRes := t.coll(in.Collection)
	if errRes != nil {
		return errRes, nil, nil
	}
	offset, limit, ok := paging(in.Cursor, in.Limit, defaultLimit, maxLimit)
	if !ok {
		return errBadCursor, nil, nil
	}
	known := propSet(c)
	conds, bad := parseWhere(in.Where, known)
	if bad != "" {
		return apiError("invalid", bad, nil), nil, nil
	}
	for _, f := range in.Fields {
		if len(known) > 0 && !known[f] {
			return apiError("invalid", fmt.Sprintf("fields: unknown field %q; fields: %s", f, strings.Join(sortedKeys(known), ", ")), nil), nil, nil
		}
	}
	orderField, desc := strings.TrimPrefix(in.OrderBy, "-"), strings.HasPrefix(in.OrderBy, "-")
	if orderField != "" && len(known) > 0 && !known[orderField] {
		return apiError("invalid", fmt.Sprintf("order_by: unknown field %q; fields: %s", orderField, strings.Join(sortedKeys(known), ", ")), nil), nil, nil
	}
	q := strings.ToLower(strings.TrimSpace(in.Search))
	var hits []*ledger.Record
rows:
	for _, r := range c.Records {
		for _, cd := range conds {
			if !cd.match(r.Data[cd.field]) {
				continue rows
			}
		}
		if q != "" && len(matchedFields(r, q)) == 0 {
			continue
		}
		hits = append(hits, r)
	}
	if orderField != "" {
		sort.SliceStable(hits, func(i, j int) bool {
			a, aok := hits[i].Data[orderField]
			b, bok := hits[j].Data[orderField]
			switch {
			case !aok || !bok:
				return aok && !bok // records without the field go last either way
			case desc:
				return lessValue(b, a)
			}
			return lessValue(a, b)
		})
	}
	page, next := pageOf(hits, offset, limit)
	out := queryOut{Collection: c.Name, Total: len(hits), Items: make([]recordItem, 0, len(page)), NextCursor: next}
	for _, r := range page {
		it := item(r)
		if len(in.Fields) > 0 {
			it.Data = map[string]any{}
			for _, f := range in.Fields {
				if v, ok := r.Data[f]; ok {
					it.Data[f] = v
				}
			}
		}
		out.Items = append(out.Items, it)
	}
	return nil, out, nil
}

// records_get --------------------------------------------------------------------

type getIn struct {
	Collection string   `json:"collection" jsonschema:"collection name"`
	ID         string   `json:"id" jsonschema:"record id: key field values joined with /"`
	Include    []string `json:"include,omitempty" jsonschema:"any of backrefs, doc, history"`
}

type getOut struct {
	Collection string                  `json:"collection"`
	ID         string                  `json:"id"`
	Hash       string                  `json:"hash"`
	Data       map[string]any          `json:"data"`
	Backrefs   map[string][]recordItem `json:"backrefs,omitempty"`
	History    []gitstore.Commit       `json:"history,omitempty"`
}

func (t *tools) recordsGet(ctx context.Context, _ *mcp.CallToolRequest, in getIn) (*mcp.CallToolResult, any, error) {
	l, c, errRes := t.coll(in.Collection)
	if errRes != nil {
		return errRes, nil, nil
	}
	for _, inc := range in.Include {
		if !slices.Contains([]string{"backrefs", "doc", "history"}, inc) {
			return apiError("invalid", fmt.Sprintf("include: unknown value %q; use backrefs, doc or history", inc), nil), nil, nil
		}
	}
	r := c.Get(in.ID)
	if r == nil {
		return apiError("not_found", fmt.Sprintf("no record %q in %s; use records_query or ledger_search to find ids", in.ID, c.Name), nil), nil, nil
	}
	out := getOut{Collection: c.Name, ID: r.ID, Hash: r.Hash, Data: r.Data}
	if slices.Contains(in.Include, "backrefs") {
		out.Backrefs = map[string][]recordItem{}
		for coll, recs := range l.Backrefs(c.Name, r) {
			for _, x := range recs {
				out.Backrefs[coll] = append(out.Backrefs[coll], item(x))
			}
		}
	}
	// "doc" is accepted: no collection supports documents yet, so there is none.
	if slices.Contains(in.Include, "history") && t.backend != nil {
		commits, err := t.backend.History(ctx, 20, c.Name, r.ID)
		if err != nil {
			return apiError("internal", "could not read the history: "+err.Error(), nil), nil, nil
		}
		out.History = commits
	}
	return nil, out, nil
}

// ledger_search ------------------------------------------------------------------

type searchIn2 struct {
	Query       string   `json:"query" jsonschema:"text to find (case-insensitive substring)"`
	Collections []string `json:"collections,omitempty" jsonschema:"limit to these collections"`
	IncludeDocs bool     `json:"include_docs,omitempty" jsonschema:"also search documents (none exist yet)"`
	Cursor      string   `json:"cursor,omitempty" jsonschema:"next_cursor of the previous page"`
	Limit       int      `json:"limit,omitempty" jsonschema:"hits per page (default 50, max 500)"`
}

type hit struct {
	Collection    string         `json:"collection"`
	ID            string         `json:"id"`
	Score         int            `json:"score" jsonschema:"higher is a better match"`
	MatchedFields []string       `json:"matched_fields"`
	Data          map[string]any `json:"data"`
}

type searchOut2 struct {
	Query      string `json:"query"`
	Total      int    `json:"total"`
	Items      []hit  `json:"items"`
	NextCursor string `json:"next_cursor"`
}

func (t *tools) ledgerSearch(_ context.Context, _ *mcp.CallToolRequest, in searchIn2) (*mcp.CallToolResult, any, error) {
	q := strings.ToLower(strings.TrimSpace(in.Query))
	if q == "" {
		return apiError("invalid", "query must not be empty", nil), nil, nil
	}
	offset, limit, ok := paging(in.Cursor, in.Limit, defaultLimit, maxLimit)
	if !ok {
		return errBadCursor, nil, nil
	}
	l := t.src()
	cols := l.Collections
	if len(in.Collections) > 0 {
		cols = nil
		for _, name := range in.Collections {
			_, c, errRes := t.coll(name)
			if errRes != nil {
				return errRes, nil, nil
			}
			cols = append(cols, c)
		}
	}
	var hits []hit
	for _, c := range cols {
		for _, r := range c.Records {
			fields := matchedFields(r, q)
			if len(fields) == 0 {
				continue
			}
			score := 0
			for _, f := range fields {
				score++
				if strings.ToLower(flatten(r.Data[f])) == q {
					score += 3
				}
				if slices.Contains(c.Key, f) {
					score += 2
				}
			}
			hits = append(hits, hit{Collection: c.Name, ID: r.ID, Score: score, MatchedFields: fields, Data: r.Data})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].Score > hits[j].Score })
	page, next := pageOf(hits, offset, limit)
	out := searchOut2{Query: in.Query, Total: len(hits), Items: page, NextCursor: next}
	return nil, out, nil
}

// ledger_check ---------------------------------------------------------------------

type checkIn2 struct {
	Collection string `json:"collection,omitempty" jsonschema:"only problems of this collection"`
	Rule       string `json:"rule,omitempty" jsonschema:"only problems of this rule (schema, unique, ref, same_set, config, secret)"`
	Cursor     string `json:"cursor,omitempty" jsonschema:"next_cursor of the previous page"`
	Limit      int    `json:"limit,omitempty" jsonschema:"problems per page (default 50, max 500)"`
}

type checkOut2 struct {
	OK       bool             `json:"ok" jsonschema:"no errors and nothing pauses writes"`
	Store    []map[string]any `json:"store" jsonschema:"store state that pauses writes: history_rewritten, config_error"`
	Errors   []ledger.Issue   `json:"errors"`
	Warnings []ledger.Issue   `json:"warnings" jsonschema:"heuristic secret findings (confirm tier)"`
	Total    int              `json:"total" jsonschema:"errors and warnings together, over all pages"`
	// NextCursor pages through errors first, then warnings.
	NextCursor string `json:"next_cursor"`
}

func (t *tools) ledgerCheck(_ context.Context, _ *mcp.CallToolRequest, in checkIn2) (*mcp.CallToolResult, any, error) {
	offset, limit, ok := paging(in.Cursor, in.Limit, defaultLimit, maxLimit)
	if !ok {
		return errBadCursor, nil, nil
	}
	if in.Collection != "" {
		if _, _, errRes := t.coll(in.Collection); errRes != nil {
			return errRes, nil, nil
		}
	}
	errs, warns := validate.Split(validate.Run(t.src()))
	keep := func(is ledger.Issue) bool {
		return (in.Collection == "" || is.Collection == in.Collection) && (in.Rule == "" || is.Rule == in.Rule)
	}
	errs, warns = slices.DeleteFunc(errs, func(i ledger.Issue) bool { return !keep(i) }), slices.DeleteFunc(warns, func(i ledger.Issue) bool { return !keep(i) })
	out := checkOut2{Store: t.storeProblems(), Errors: []ledger.Issue{}, Warnings: []ledger.Issue{}, Total: len(errs) + len(warns)}
	out.OK = len(errs) == 0 && len(out.Store) == 0
	all := append(slices.Clone(errs), warns...)
	page, next := pageOf(all, offset, limit)
	for _, is := range page {
		if is.Warning() {
			out.Warnings = append(out.Warnings, is)
		} else {
			out.Errors = append(out.Errors, is)
		}
	}
	out.NextCursor = next
	return nil, out, nil
}

// storeProblems lists what pauses writes (see list_problems).
func (t *tools) storeProblems() []map[string]any {
	store := []map[string]any{}
	if t.backend == nil {
		return store
	}
	if a := t.backend.Alert(); a != nil {
		m := map[string]any{"kind": a.Kind, "writesPaused": true}
		if a.Message != "" {
			m["message"] = a.Message
		}
		if a.Remote != "" {
			m["lastGood"], m["remote"] = a.LastGood, a.Remote
		}
		store = append(store, m)
	} else if p := t.backend.ConfigProblem(); p != "" {
		store = append(store, map[string]any{"kind": gitstore.AlertConfigError, "message": p, "writesPaused": true})
	}
	return store
}

// ledger_export --------------------------------------------------------------------

type exportIn struct {
	Format     string `json:"format,omitempty" jsonschema:"markdown (default) or json"`
	Collection string `json:"collection,omitempty" jsonschema:"export only this collection"`
}

type exportOut struct {
	Format     string `json:"format"`
	Collection string `json:"collection,omitempty"`
	Bytes      int    `json:"bytes"`
	Content    string `json:"content"`
}

func (t *tools) ledgerExport(_ context.Context, _ *mcp.CallToolRequest, in exportIn) (*mcp.CallToolResult, any, error) {
	format := in.Format
	if format == "" {
		format = "markdown"
	}
	if format != "markdown" && format != "json" {
		return apiError("invalid", fmt.Sprintf("format must be markdown or json, not %q", in.Format), nil), nil, nil
	}
	l := t.src()
	if in.Collection != "" {
		_, c, errRes := t.coll(in.Collection)
		if errRes != nil {
			return errRes, nil, nil
		}
		one := *l
		one.Collections = []*ledger.Collection{c}
		one.Notes = nil
		for _, n := range l.Notes {
			if n.Collection == c.Name {
				one.Notes = append(one.Notes, n)
			}
		}
		l = &one
	}
	var content string
	if format == "json" {
		b, err := export.JSON(l)
		if err != nil {
			return apiError("internal", "could not render the export", nil), nil, nil
		}
		content = string(b)
	} else {
		content = export.Markdown(l)
	}
	out := exportOut{Format: format, Collection: in.Collection, Bytes: len(content), Content: content}
	return nil, out, nil
}
