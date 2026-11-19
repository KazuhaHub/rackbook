package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/roles"
)

// The surface is specified in docs/mcp-surface.md.
const (
	defaultLimit    = 50
	maxLimit        = 500
	maxHistoryLimit = 100
	// maxResultBytes caps one result's structured content (section 8).
	maxResultBytes = 1 << 20

	// removedIn is the release that drops the deprecated v0.2 tool names.
	removedIn = "v0.7.0"

	idempotencyTTL = 24 * time.Hour
)

// replacements maps each deprecated v0.2 tool name to the tool that replaces it.
var replacements = map[string]string{
	"list_collections": "collections_list",
	"get_schema":       "collections_describe",
	"list_records":     "records_query",
	"get_record":       "records_get",
	"search":           "ledger_search",
	"check":            "ledger_check",
	"list_problems":    "ledger_check",
	"export_markdown":  "ledger_export",
	"record_history":   "history_list",
	"create_record":    "records_create",
	"update_record":    "records_update",
	"delete_record":    "records_delete",
}

// writeTools are the tools that change the ledger, with the action the role
// must allow. tools/list hides them from a caller whose role does not.
var writeTools = map[string]roles.Action{
	"records_create": roles.Write, "records_update": roles.Write, "records_delete": roles.Delete,
	"create_record": roles.Write, "update_record": roles.Write, "delete_record": roles.Delete,
}

// writeActions is the token action (create, update, delete) of each write tool.
var writeActions = map[string]string{
	"records_create": auth.ActCreate, "records_update": auth.ActUpdate, "records_delete": auth.ActDelete,
	"create_record": auth.ActCreate, "update_record": auth.ActUpdate, "delete_record": auth.ActDelete,
}

// families lists the tools of each family in the order ledger_info reports them.
var families = []struct {
	name  string
	tools []string
}{
	{"ledger", []string{"ledger_info", "ledger_search", "ledger_check", "ledger_export"}},
	{"collections", []string{"collections_list", "collections_describe"}},
	{"records", []string{"records_query", "records_get", "records_create", "records_update", "records_delete"}},
	{"history", []string{"history_list", "history_diff"}},
	{"expiry", []string{"expiry_list"}},
}

// familyVersion is the surface version of every family (it grows only with
// additive changes to that family).
const familyVersion = 1

func readAnnotations() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{ReadOnlyHint: true, DestructiveHint: new(false), OpenWorldHint: new(false)}
}

// mark records that a tool is registered, for ledger_info and tools/list.
func (t *tools) mark(tool *mcp.Tool) *mcp.Tool {
	t.names[tool.Name] = true
	return tool
}

// legacy registers tool as a deprecated v0.2 name: its description says what
// replaces it and when it goes, and ledger_info lists it. Annotations default to
// read-only; every tool declares all of them.
func (t *tools) legacy(tool *mcp.Tool) *mcp.Tool {
	repl := replacements[tool.Name]
	tool.Description = fmt.Sprintf("Deprecated: use %s; removed in %s. %s", repl, removedIn, tool.Description)
	if tool.Annotations == nil {
		tool.Annotations = readAnnotations()
	}
	t.deprecated = append(t.deprecated, deprecatedInfo{Tool: tool.Name, Replacement: repl, RemovedIn: removedIn})
	return t.mark(tool)
}

// addTool registers a tool of the new surface: its output schema comes from Out
// and the handler returns errors as structured results (see apiError).
func addTool[In, Out any](t *tools, s *mcp.Server, tool *mcp.Tool, h func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error)) {
	schema, err := jsonschema.For[Out](nil)
	if err != nil {
		panic(fmt.Errorf("%s: %w", tool.Name, err)) // the types are fixed
	}
	spellOutAny(schema)
	tool.OutputSchema = schema
	mcp.AddTool(s, t.mark(tool), h)
}

// spellOutAny replaces every empty property schema (a Go `any` field, which marshals as
// the bare boolean `true`) with an anyOf over the JSON types. The set of
// accepted values is the same; the difference is that clients which require a
// schema object (OpenAI strict function schemas, Gemini function declarations)
// no longer reject the tool.
func spellOutAny(s *jsonschema.Schema) {
	if s == nil {
		return
	}
	for _, p := range s.Properties {
		if reflect.DeepEqual(*p, jsonschema.Schema{}) {
			*p = anyValue()
		} else {
			spellOutAny(p)
		}
	}
	spellOutAny(s.Items)
	for _, b := range s.AnyOf {
		spellOutAny(b)
	}
}

func anyValue() jsonschema.Schema {
	return jsonschema.Schema{AnyOf: []*jsonschema.Schema{
		{Type: "string"}, {Type: "number"}, {Type: "boolean"},
		{Type: "object"}, {Type: "array"},
	}}
}

// apiError is a tool error: a result with isError and the structured body
// {error, message, details?} (section 4). The codes are the HTTP API's.
func apiError(code, msg string, details map[string]any) *mcp.CallToolResult {
	body := map[string]any{"error": code, "message": msg}
	if len(details) > 0 {
		body["details"] = details
	}
	b, _ := json.Marshal(body)
	return &mcp.CallToolResult{IsError: true, StructuredContent: json.RawMessage(b), Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}
}

// capResults refuses a result whose structured content is over 1 MiB with
// too_large, naming what to use instead: a resource URI where one carries the
// same content, else a smaller limit with the cursor to continue from. The
// deprecated names keep their v0.2 behaviour and are not capped.
func capResults(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		cr, ok := res.(*mcp.CallToolResult)
		call, isCall := req.(*mcp.CallToolRequest)
		if err != nil || method != "tools/call" || !ok || !isCall || cr.IsError || cr.StructuredContent == nil {
			return res, err
		}
		if _, old := replacements[call.Params.Name]; old {
			return res, err
		}
		b, merr := json.Marshal(cr.StructuredContent)
		if merr != nil || len(b) <= maxResultBytes {
			return res, err
		}
		var content any
		_ = json.Unmarshal(b, &content)
		return tooLarge(call.Params.Name, call.Params.Arguments, content, len(b)), nil
	}
}

// returned counts what a paged result held (its items, or a check's errors
// and warnings), and names the first of them.
func returned(content any) (n int, first map[string]any) {
	m, _ := content.(map[string]any)
	for _, key := range []string{"items", "errors", "warnings"} {
		list, _ := m[key].([]any)
		n += len(list)
		if first == nil && len(list) > 0 {
			first, _ = list[0].(map[string]any)
		}
	}
	return n, first
}

// tooLarge builds the too_large error. content is the oversize structured
// content, so the advice follows what was actually returned: for a paged tool
// a limit strictly below the item count of this page (so following it always
// makes progress), or, when a single item alone is over the cap, the resource
// that carries it.
func tooLarge(tool string, raw json.RawMessage, content any, size int) *mcp.CallToolResult {
	var args struct {
		Collection string `json:"collection"`
		ID         string `json:"id"`
		Cursor     string `json:"cursor"`
		Limit      int    `json:"limit"`
	}
	_ = json.Unmarshal(raw, &args)
	details := map[string]any{"limit_bytes": maxResultBytes, "size_bytes": size}
	hint := "narrow the request"
	switch tool {
	case "ledger_export":
		details["resource"] = "rackbook://export/markdown"
		hint = "read the resource rackbook://export/markdown, or export one collection"
	case "ledger_info":
		details["resource"] = "rackbook://info"
	case "collections_list":
		details["resource"] = "rackbook://collections"
	case "collections_describe":
		details["resource"] = prefixColl + url.PathEscape(args.Collection)
	case "records_get":
		details["resource"] = prefixRecord + url.PathEscape(args.Collection) + "/" + url.PathEscape(args.ID)
		hint = "read the resource, or leave out include"
	case "records_query", "ledger_search", "ledger_check", "history_list", "expiry_list":
		n, first := returned(content)
		details["cursor"] = args.Cursor // continue from the same place
		details["returned"] = n
		switch {
		case n <= 1:
			// One item alone does not fit: no limit helps. A record has a resource.
			coll, id := args.Collection, ""
			if first != nil {
				if c, ok := first["collection"].(string); ok {
					coll = c
				}
				id, _ = first["id"].(string)
			}
			if (tool == "records_query" || tool == "ledger_search") && coll != "" && id != "" {
				details["resource"] = prefixRecord + url.PathEscape(coll) + "/" + url.PathEscape(id)
				hint = "one record alone is over the cap: read it as the resource"
			} else {
				hint = "one item alone is over the cap"
			}
		default:
			// Scale by the page that was really returned, never by the limit asked
			// for (which may have been capped), and always go below it.
			details["suggested_limit"] = max(1, min(n-1, n*(maxResultBytes*9/10)/size))
			hint = "repeat with the cursor and the suggested_limit"
		}
	}
	return apiError("too_large", "the result is larger than 1 MiB; "+hint, details)
}

func encodeCursor(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(offset)))
}

// paging reads cursor and limit. ok is false for a cursor this server did not
// issue.
func paging(cursor string, limit, def, ceiling int) (offset, n int, ok bool) {
	offset, ok = decodeCursor(cursor)
	if limit <= 0 {
		limit = def
	}
	return offset, min(limit, ceiling), ok
}

// pageOf returns the offset..offset+n slice of all and the cursor of the next
// page ("" on the last).
func pageOf[T any](all []T, offset, n int) ([]T, string) {
	if offset >= len(all) {
		return []T{}, ""
	}
	end := min(offset+n, len(all))
	next := ""
	if end < len(all) {
		next = encodeCursor(end)
	}
	return all[offset:end], next
}

var errBadCursor = apiError("invalid", "cursor is not one returned by this tool", nil)

// ledger_info ----------------------------------------------------------------

type deprecatedInfo struct {
	Tool        string `json:"tool"`
	Replacement string `json:"replacement"`
	RemovedIn   string `json:"removed_in"`
}

type familyInfo struct {
	Name    string   `json:"name"`
	Version int      `json:"version"`
	Tools   []string `json:"tools"`
}

type callerInfo struct {
	Authenticated bool     `json:"authenticated"`
	ID            string   `json:"id,omitempty"`
	Name          string   `json:"name,omitempty"`
	Role          string   `json:"role,omitempty"`
	Scopes        []string `json:"scopes"`
	CanWrite      bool     `json:"can_write"`
	CanDelete     bool     `json:"can_delete"`
}

type limitsInfo struct {
	DefaultLimit    int `json:"default_limit"`
	MaxLimit        int `json:"max_limit"`
	MaxHistoryLimit int `json:"max_history_limit"`
	MaxResultBytes  int `json:"max_result_bytes"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type infoOut struct {
	Server          serverInfo       `json:"server"`
	Title           string           `json:"title,omitempty"`
	ProtocolVersion string           `json:"protocol_version" jsonschema:"the MCP revision negotiated for this session"`
	Families        []familyInfo     `json:"families"`
	Caller          callerInfo       `json:"caller"`
	Limits          limitsInfo       `json:"limits"`
	Deprecated      []deprecatedInfo `json:"deprecated"`
}

// visibleTo reports whether tool is offered to id: a write tool only to a
// caller whose role allows it. A caller without an identity (stdio) sees all
// that is registered.
func (t *tools) visibleTo(tool string, id *auth.Identity) bool {
	need, w := writeTools[tool]
	return !w || id == nil || (id.Can(need) && t.mayAny(id, writeActions[tool]))
}

// mayAny says whether the credential's own narrowing (an API token's actions
// and collections) lets it perform action on at least one collection.
func (t *tools) mayAny(id *auth.Identity, action string) bool {
	if id.Allow == nil {
		return true
	}
	for _, c := range t.src().Collections {
		if id.Permits(action, c.Name) {
			return true
		}
	}
	return false
}

func (t *tools) info(req mcp.Request, version string) infoOut {
	id := identityOf(req)
	l := t.src()
	out := infoOut{
		Server:     serverInfo{Name: "rackbook", Version: t.version},
		Title:      l.Config.Title,
		Families:   []familyInfo{},
		Deprecated: slices.Clone(t.deprecated),
		Limits:     limitsInfo{DefaultLimit: defaultLimit, MaxLimit: maxLimit, MaxHistoryLimit: maxHistoryLimit, MaxResultBytes: maxResultBytes},
		Caller:     callerInfo{Scopes: []string{}},
	}
	if out.Deprecated == nil {
		out.Deprecated = []deprecatedInfo{}
	}
	slices.SortFunc(out.Deprecated, func(a, b deprecatedInfo) int { return compareStr(a.Tool, b.Tool) })
	out.ProtocolVersion = version
	for _, f := range families {
		fi := familyInfo{Name: f.name, Version: familyVersion, Tools: []string{}}
		for _, name := range f.tools {
			if t.names[name] && t.visibleTo(name, id) {
				fi.Tools = append(fi.Tools, name)
			}
		}
		if len(fi.Tools) > 0 {
			out.Families = append(out.Families, fi)
		}
	}
	if id != nil {
		out.Caller = callerInfo{Authenticated: true, ID: id.ID, Name: id.Name, Role: id.EffectiveRole().String(), Scopes: slices.Clone(id.Scopes),
			CanWrite:  t.canWrite() && id.Can(roles.Write) && (t.mayAny(id, auth.ActCreate) || t.mayAny(id, auth.ActUpdate)),
			CanDelete: t.canWrite() && id.Can(roles.Delete) && t.mayAny(id, auth.ActDelete)}
		if out.Caller.Scopes == nil {
			out.Caller.Scopes = []string{}
		}
	}
	return out
}

func compareStr(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// canWrite says whether this server offers write tools at all.
func (t *tools) canWrite() bool { return t.backend != nil && !t.readOnly }

type infoIn struct{}

func (t *tools) addInfoTool(s *mcp.Server) {
	addTool[infoIn, infoOut](t, s, &mcp.Tool{Name: "ledger_info", Annotations: readAnnotations(),
		Description: "Feature detection: the server version, the MCP revision negotiated, the tool families this server provides with each family's surface version, who you are (role and effective scopes), the limits, and which tools are deprecated with their replacement and removal version. Call it first."},
		func(_ context.Context, req *mcp.CallToolRequest, _ infoIn) (*mcp.CallToolResult, any, error) {
			return nil, t.info(req, req.ProtocolVersion()), nil
		})
}

// Hiding write tools from a caller that cannot use them -----------------------

// filterTools makes tools/list show a caller only the tools its role allows.
// The call is gated as before; this only keeps the list honest.
func (t *tools) filterTools(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		if err != nil || method != "tools/list" {
			return res, err
		}
		lt, ok := res.(*mcp.ListToolsResult)
		id := identityOf(req)
		if !ok || id == nil {
			return res, err
		}
		lt.Tools = slices.DeleteFunc(lt.Tools, func(tool *mcp.Tool) bool { return !t.visibleTo(tool.Name, id) })
		return lt, nil
	}
}

// Idempotency keys ------------------------------------------------------------

type idemEntry struct {
	at          time.Time
	fingerprint string
	out         writeOut2
}

type idempotency struct {
	mu      sync.Mutex
	entries map[string]idemEntry
	now     func() time.Time
}

func (i *idempotency) prune() {
	cut := i.now().Add(-idempotencyTTL)
	for k, e := range i.entries {
		if e.at.Before(cut) {
			delete(i.entries, k)
		}
	}
}
