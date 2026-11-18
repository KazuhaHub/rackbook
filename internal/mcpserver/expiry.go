package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kazuhahub/rackbook/internal/expiry"
)

const (
	defaultExpiryLimit = 50
	maxExpiryLimit     = 500
)

type expiryListIn struct {
	Days           *int     `json:"days,omitempty" jsonschema:"window in days (default 30, 0 to 3650); records that expire today or within this many days, plus every expired one"`
	Collections    []string `json:"collections,omitempty" jsonschema:"limit to these collections (default: every collection with an expires mark)"`
	IncludeUnknown bool     `json:"include_unknown,omitempty" jsonschema:"also list records whose expiry is not a date (for example 待补), listed last"`
	Cursor         string   `json:"cursor,omitempty" jsonschema:"next_cursor of the previous page"`
	Limit          int      `json:"limit,omitempty" jsonschema:"items per page (default 50, max 500)"`
}

type expiryListOut struct {
	Today      string        `json:"today" jsonschema:"today's date in UTC"`
	Days       int           `json:"days"`
	Items      []expiry.Item `json:"items" jsonschema:"most overdue first; unknown dates last"`
	NextCursor string        `json:"next_cursor" jsonschema:"pass as cursor for the next page; empty on the last page"`
}

// addExpiryTools registers expiry_list. Its output schema is given explicitly,
// so a failure can be returned as a structured {error, message} result.
func (t *tools) addExpiryTools(s *mcp.Server) {
	schema, err := jsonschema.For[expiryListOut](nil)
	if err != nil {
		panic(err) // the type is fixed
	}
	mcp.AddTool(s, &mcp.Tool{Name: "expiry_list", OutputSchema: schema,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(false)},
		Description: "List the records that are expired or expire within N days (default 30), from the collections whose schema marks an expiry field (certificates, secrets, tokens, domains, contracts). Records without a date and revoked records are never listed. Each item has collection, id, label, expires (as written), daysLeft (negative = overdue), status (expired, expiring, unknown) and source (the module that maintains the record; empty = entered by hand)."},
		t.expiryList)
}

func structuredError(code, msg string) *mcp.CallToolResult {
	b, _ := json.Marshal(map[string]string{"error": code, "message": msg})
	return &mcp.CallToolResult{IsError: true, StructuredContent: json.RawMessage(b), Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}
}

func decodeCursor(c string) (int, bool) {
	if c == "" {
		return 0, true
	}
	b, err := base64.RawURLEncoding.DecodeString(c)
	n, err2 := strconv.Atoi(string(b))
	return n, err == nil && err2 == nil && n >= 0
}

func (t *tools) expiryList(_ context.Context, _ *mcp.CallToolRequest, in expiryListIn) (*mcp.CallToolResult, any, error) {
	offset, ok := decodeCursor(in.Cursor)
	if !ok {
		return structuredError("invalid", "cursor is not one returned by this tool"), nil, nil
	}
	limit := in.Limit
	if limit <= 0 {
		limit = defaultExpiryLimit
	}
	limit = min(limit, maxExpiryLimit)
	days := expiry.DefaultDays
	if in.Days != nil {
		days = *in.Days
	}
	res, err := expiry.List(t.src(), expiry.Options{Days: days, Collections: in.Collections, Unknown: in.IncludeUnknown})
	if errors.Is(err, expiry.ErrUnknownCollection) {
		return structuredError("not_found", err.Error()), nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	out := expiryListOut{Today: res.Today, Days: res.Days, Items: []expiry.Item{}}
	if offset < len(res.Items) {
		end := min(offset+limit, len(res.Items))
		out.Items = res.Items[offset:end]
		if end < len(res.Items) {
			out.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(end)))
		}
	}
	return nil, out, nil
}
