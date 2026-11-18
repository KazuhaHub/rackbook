// Package mcpserver exposes the ledger to AI agents over MCP: read tools
// always, and create_record, update_record and delete_record over HTTP for
// callers whose role and credential allow writing (see write.go).
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kazuhahub/rackbook/internal/export"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/validate"
)

// Source returns the current ledger; it is called for every tool call so
// results follow pulls and writes.
type Source func() *ledger.Ledger

const instructions = `Read-only access to an infrastructure ledger kept as YAML in Git.
Start with list_collections to see what exists. Records are addressed by id (the key fields joined with "/").
- "What runs on host X?": list_records collection=services where={"device":"X"}; services whose device is "all" apply to every host, so also list_records services where={"device":"all"}. get_record on the device returns all of its addresses and services as backrefs in one call.
- "Who uses port N?": search query="N" (substring over every field of every collection), or list_records on ports for the port convention.
- "Is the ledger consistent?": check.
- "What expires soon?": expiry_list (days, collections, include_unknown); items are sorted most overdue first, daysLeft below 0 means already expired, and include_unknown adds records whose date is still to be filled in.`

// New builds a read-only MCP server.
func New(src Source, version string) *mcp.Server {
	return NewWithOptions(Options{Source: src, Version: version})
}

// NewWithOptions builds the MCP server.
func NewWithOptions(o Options) *mcp.Server {
	ins := instructions
	writes := o.Backend != nil && !o.ReadOnly
	if writes {
		ins += writeInstructions
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "rackbook", Version: o.Version}, &mcp.ServerOptions{Instructions: ins})
	t := &tools{src: o.Source, backend: o.Backend, readOnly: o.ReadOnly, log: o.Logger}
	if t.log == nil {
		t.log = slog.New(slog.DiscardHandler)
	}
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true}

	mcp.AddTool(s, &mcp.Tool{Name: "list_collections", Annotations: readOnly,
		Description: "List every collection in the ledger with its title, description, key fields, fields (name, title, type, required), reference links to other collections and record count. Call this first to learn the collection names and field names used by the other tools."},
		t.listCollections)
	mcp.AddTool(s, &mcp.Tool{Name: "list_records", Annotations: readOnly,
		Description: "List the records of one collection in file order, optionally filtered by exact field values (where is an object like {\"device\": \"web-1\", \"managed\": true}; all entries must match; values are compared as text). To answer \"what services run on host X\" use collection=services where={\"device\":\"X\"} and remember that rows with device \"all\" apply to every host."},
		t.listRecords)
	mcp.AddTool(s, &mcp.Tool{Name: "get_record", Annotations: readOnly,
		Description: "Get one record by id (the key field values joined with \"/\", with \"/\" and \"%\" inside a value written as %2F and %25) together with backrefs: the records of other collections that reference it. For a device this returns its addresses and its services (including services declared for device \"all\") in a single call."},
		t.getRecord)
	mcp.AddTool(s, &mcp.Tool{Name: "search", Annotations: readOnly,
		Description: "Case-insensitive substring search over every text, number and boolean field of every record (or one collection). Use it for questions where you do not know the collection, e.g. \"who uses port 10511\" (query=10511), \"where is nginx\", \"which host has IP 198.51.100.20\". Each match lists the fields that matched."},
		t.search)
	mcp.AddTool(s, &mcp.Tool{Name: "get_schema", Annotations: readOnly,
		Description: "Get the JSON Schema of one collection's records: field names, types, titles, descriptions and required fields."},
		t.getSchema)
	mcp.AddTool(s, &mcp.Tool{Name: "check", Annotations: readOnly,
		Description: "Validate the whole ledger (YAML syntax, JSON Schema, unique keys, references, set rules) and return ok plus every error with collection, record id, field path and message."},
		t.check)
	mcp.AddTool(s, &mcp.Tool{Name: "export_markdown", Annotations: readOnly,
		Description: "Return the whole ledger as one Markdown document (a table per collection). Large; prefer list_records, get_record or search for targeted questions."},
		t.exportMarkdown)
	mcp.AddTool(s, &mcp.Tool{Name: "list_problems", Annotations: readOnly,
		Description: "List what is wrong with the ledger: validation errors (collection, record id, field path, message) and any store state that pauses writes (history_rewritten, config_error). Check this before writing, and after."},
		t.listProblems)
	t.addExpiryTools(s)
	if o.Backend != nil {
		mcp.AddTool(s, &mcp.Tool{Name: "record_history", Annotations: readOnly,
			Description: "List the commits that changed one record (newest first: hash, author, date, subject), falling back to the collection's file history for records edited before per-record history existed."},
			t.recordHistory)
	}
	if writes {
		t.addWriteTools(s)
	}
	return s
}

// Handler serves the server over streamable HTTP. The SDK's localhost
// (DNS-rebinding) protection stays on unless authenticated is true: behind a
// tunnel or proxy that rewrites Host, requests arrive on loopback with a public
// Host, and the caller's authentication middleware is what guards the endpoint.
func Handler(s *mcp.Server, authenticated bool) http.Handler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{DisableLocalhostProtection: authenticated})
}

// RunStdio serves one client over stdin/stdout until it disconnects.
func RunStdio(ctx context.Context, s *mcp.Server) error {
	return s.Run(ctx, &mcp.StdioTransport{})
}

type tools struct {
	src      Source
	backend  Backend
	readOnly bool
	log      *slog.Logger
}

func (t *tools) collection(name string) (*ledger.Ledger, *ledger.Collection, error) {
	l := t.src()
	c := l.Collection(name)
	if c == nil {
		names := make([]string, len(l.Collections))
		for i, x := range l.Collections {
			names[i] = x.Name
		}
		return nil, nil, fmt.Errorf("unknown collection %q; available: %s", name, strings.Join(names, ", "))
	}
	return l, c, nil
}

// list_collections ---------------------------------------------------------

type noArgs struct{}

type fieldInfo struct {
	Name     string `json:"name"`
	Title    string `json:"title,omitempty"`
	Type     string `json:"type,omitempty"`
	Required bool   `json:"required,omitempty"`
}

type collectionInfo struct {
	Name         string           `json:"name"`
	Title        string           `json:"title"`
	Group        string           `json:"group,omitempty"`
	Description  string           `json:"description,omitempty"`
	Key          []string         `json:"key,omitempty"`
	Fields       []fieldInfo      `json:"fields"`
	References   []ledger.RefInfo `json:"references,omitempty"`
	ReferencedBy []ledger.BackRef `json:"referencedBy,omitempty"`
	Records      int              `json:"records"`
}

type listCollectionsOut struct {
	Title       string           `json:"title"`
	Description string           `json:"description,omitempty"`
	Collections []collectionInfo `json:"collections"`
}

func (t *tools) listCollections(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, listCollectionsOut, error) {
	l := t.src()
	out := listCollectionsOut{Title: l.Config.Title, Description: l.Config.Description, Collections: []collectionInfo{}}
	for _, c := range l.Collections {
		req := map[string]bool{}
		for _, r := range c.Schema.Required {
			req[r] = true
		}
		info := collectionInfo{Name: c.Name, Title: c.Title, Group: c.Group, Description: c.Description, Key: c.Key,
			Fields: []fieldInfo{}, References: l.Refs(c.Name), ReferencedBy: l.BackRefs(c.Name), Records: len(c.Records)}
		for _, p := range c.Schema.Props {
			info.Fields = append(info.Fields, fieldInfo{Name: p.Name, Title: p.Title, Type: p.Type, Required: req[p.Name]})
		}
		out.Collections = append(out.Collections, info)
	}
	return nil, out, nil
}

// list_records -------------------------------------------------------------

type listRecordsIn struct {
	Collection string         `json:"collection" jsonschema:"collection name from list_collections"`
	Where      map[string]any `json:"where,omitempty" jsonschema:"exact-match filter on fields, e.g. {\"device\":\"web-1\"}"`
}

type recordOut struct {
	ID   string         `json:"id"`
	Data map[string]any `json:"data"`
}

type listRecordsOut struct {
	Collection string      `json:"collection"`
	Count      int         `json:"count"`
	Records    []recordOut `json:"records"`
}

func (t *tools) listRecords(_ context.Context, _ *mcp.CallToolRequest, in listRecordsIn) (*mcp.CallToolResult, listRecordsOut, error) {
	_, c, err := t.collection(in.Collection)
	if err != nil {
		return nil, listRecordsOut{}, err
	}
	where := map[string]string{}
	for k, v := range in.Where {
		where[k] = ledger.Str(v)
	}
	out := listRecordsOut{Collection: c.Name, Records: []recordOut{}}
	for _, r := range c.Records {
		if ledger.Match(r, where) {
			out.Records = append(out.Records, recordOut{ID: r.ID, Data: r.Data})
		}
	}
	out.Count = len(out.Records)
	return nil, out, nil
}

// get_record ---------------------------------------------------------------

type getRecordIn struct {
	Collection string `json:"collection" jsonschema:"collection name"`
	ID         string `json:"id" jsonschema:"record id: key field values joined with /"`
}

type getRecordOut struct {
	Collection string                 `json:"collection"`
	ID         string                 `json:"id"`
	Hash       string                 `json:"hash"`
	Data       map[string]any         `json:"data"`
	Backrefs   map[string][]recordOut `json:"backrefs"`
}

func (t *tools) getRecord(_ context.Context, _ *mcp.CallToolRequest, in getRecordIn) (*mcp.CallToolResult, getRecordOut, error) {
	l, c, err := t.collection(in.Collection)
	if err != nil {
		return nil, getRecordOut{}, err
	}
	r := c.Get(in.ID)
	if r == nil {
		return nil, getRecordOut{}, fmt.Errorf("no record %q in %s; use list_records or search to find ids", in.ID, c.Name)
	}
	out := getRecordOut{Collection: c.Name, ID: r.ID, Hash: r.Hash, Data: r.Data, Backrefs: map[string][]recordOut{}}
	for coll, recs := range l.Backrefs(c.Name, r) {
		for _, x := range recs {
			out.Backrefs[coll] = append(out.Backrefs[coll], recordOut{ID: x.ID, Data: x.Data})
		}
	}
	return nil, out, nil
}

// search -------------------------------------------------------------------

type searchIn struct {
	Query      string `json:"query" jsonschema:"text to find (case-insensitive substring)"`
	Collection string `json:"collection,omitempty" jsonschema:"limit to one collection"`
}

type match struct {
	Collection string         `json:"collection"`
	ID         string         `json:"id"`
	Fields     []string       `json:"matchedFields"`
	Data       map[string]any `json:"data"`
}

type searchOut struct {
	Query   string  `json:"query"`
	Count   int     `json:"count"`
	Matches []match `json:"matches"`
}

func (t *tools) search(_ context.Context, _ *mcp.CallToolRequest, in searchIn) (*mcp.CallToolResult, searchOut, error) {
	q := strings.ToLower(strings.TrimSpace(in.Query))
	if q == "" {
		return nil, searchOut{}, fmt.Errorf("query must not be empty")
	}
	l := t.src()
	cols := l.Collections
	if in.Collection != "" {
		_, c, err := t.collection(in.Collection)
		if err != nil {
			return nil, searchOut{}, err
		}
		cols = []*ledger.Collection{c}
	}
	out := searchOut{Query: in.Query, Matches: []match{}}
	for _, c := range cols {
		for _, r := range c.Records {
			var fields []string
			for k, v := range r.Data {
				if strings.Contains(strings.ToLower(flatten(v)), q) {
					fields = append(fields, k)
				}
			}
			if len(fields) > 0 {
				sort.Strings(fields)
				out.Matches = append(out.Matches, match{Collection: c.Name, ID: r.ID, Fields: fields, Data: r.Data})
			}
		}
	}
	out.Count = len(out.Matches)
	return nil, out, nil
}

func flatten(v any) string {
	switch x := v.(type) {
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = flatten(e)
		}
		return strings.Join(parts, " ")
	case map[string]any:
		b, _ := json.Marshal(x)
		return string(b)
	}
	return ledger.Str(v)
}

// get_schema, check, export_markdown --------------------------------------

type getSchemaIn struct {
	Collection string `json:"collection" jsonschema:"collection name"`
}

func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func (t *tools) getSchema(_ context.Context, _ *mcp.CallToolRequest, in getSchemaIn) (*mcp.CallToolResult, any, error) {
	_, c, err := t.collection(in.Collection)
	if err != nil {
		return nil, nil, err
	}
	if c.SchemaRaw == nil {
		return nil, nil, fmt.Errorf("collection %s has no readable schema", c.Name)
	}
	return text(string(c.SchemaRaw)), nil, nil
}

type checkOut struct {
	OK       bool           `json:"ok"`
	Errors   []ledger.Issue `json:"errors"`
	Warnings []ledger.Issue `json:"warnings"`
}

func (t *tools) check(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, checkOut, error) {
	issues, warnings := validate.Split(validate.Run(t.src()))
	return nil, checkOut{OK: len(issues) == 0, Errors: issues, Warnings: warnings}, nil
}

func (t *tools) exportMarkdown(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
	return text(export.Markdown(t.src())), nil, nil
}
