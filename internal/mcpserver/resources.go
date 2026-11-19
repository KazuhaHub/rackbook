package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kazuhahub/rackbook/internal/export"
)

const (
	uriInfo        = "rackbook://info"
	uriCollections = "rackbook://collections"
	uriExportMD    = "rackbook://export/markdown"
	uriLLMS        = "rackbook://llms.txt"
	prefixColl     = "rackbook://collections/"
	prefixRecord   = "rackbook://records/"
)

func jsonResource(uri string, v any) (*mcp.ReadResourceResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: "application/json", Text: string(b)}}}, nil
}

func textResource(uri, mime, text string) *mcp.ReadResourceResult {
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: mime, Text: text}}}
}

// addResources registers the resources and resource templates of section 3.
// What they return matches the tools of the same name.
func (t *tools) addResources(s *mcp.Server) {
	s.AddResource(&mcp.Resource{URI: uriInfo, Name: "info", MIMEType: "application/json",
		Description: "What ledger_info returns: server version, families, your role, limits, deprecated tools."},
		func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return jsonResource(uriInfo, t.info(req, req.ProtocolVersion()))
		})
	s.AddResource(&mcp.Resource{URI: uriCollections, Name: "collections", MIMEType: "application/json",
		Description: "What collections_list returns."},
		func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return jsonResource(uriCollections, t.collectionsListOut())
		})
	s.AddResource(&mcp.Resource{URI: uriExportMD, Name: "export-markdown", MIMEType: "text/markdown",
		Description: "The whole ledger as Markdown, a table per collection. Large: read it deliberately."},
		func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return textResource(uriExportMD, "text/markdown", export.Markdown(t.src())), nil
		})
	s.AddResource(&mcp.Resource{URI: uriLLMS, Name: "llms-txt", MIMEType: "text/plain",
		Description: "llms.txt: a summary of the ledger and its collections."},
		func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return textResource(uriLLMS, "text/plain", export.LLMS(t.src(), "")), nil
		})
	s.AddResourceTemplate(&mcp.ResourceTemplate{URITemplate: prefixColl + "{collection}", Name: "collection", MIMEType: "application/json",
		Description: "What collections_describe returns for one collection: description and JSON Schema."},
		func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			name, err := url.PathUnescape(strings.TrimPrefix(req.Params.URI, prefixColl))
			if err != nil {
				return nil, mcp.ResourceNotFoundError(req.Params.URI)
			}
			out, errRes := t.describe(name)
			if errRes != nil {
				return nil, mcp.ResourceNotFoundError(req.Params.URI)
			}
			return jsonResource(req.Params.URI, out)
		})
	s.AddResourceTemplate(&mcp.ResourceTemplate{URITemplate: prefixRecord + "{collection}/{id}", Name: "record", MIMEType: "application/json",
		Description: "One record as records_get returns it. Percent-encode the id (a \"/\" between key parts is %2F)."},
		func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			coll, id, ok := strings.Cut(strings.TrimPrefix(req.Params.URI, prefixRecord), "/")
			coll, err1 := url.PathUnescape(coll)
			id, err2 := url.PathUnescape(id)
			if !ok || err1 != nil || err2 != nil {
				return nil, mcp.ResourceNotFoundError(req.Params.URI)
			}
			l := t.src()
			c := l.Collection(coll)
			if c == nil || c.Get(id) == nil {
				return nil, mcp.ResourceNotFoundError(req.Params.URI)
			}
			r := c.Get(id)
			return jsonResource(req.Params.URI, getOut{Collection: c.Name, ID: r.ID, Hash: r.Hash, Data: r.Data})
		})
}

// Prompts only assemble context and instructions; they never write.

func promptText(text string) *mcp.GetPromptResult {
	return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: text}}}}
}

func (t *tools) addPrompts(s *mcp.Server) {
	s.AddPrompt(&mcp.Prompt{Name: "audit_record",
		Description: "Check one record against its references, history and the ledger's validation, and report inconsistencies.",
		Arguments: []*mcp.PromptArgument{
			{Name: "collection", Description: "collection name", Required: true},
			{Name: "id", Description: "record id", Required: true},
		}},
		func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			coll, id := req.Params.Arguments["collection"], req.Params.Arguments["id"]
			l := t.src()
			c := l.Collection(coll)
			if c == nil || c.Get(id) == nil {
				return nil, fmt.Errorf("no record %q in collection %q", id, coll)
			}
			r := c.Get(id)
			rec, _ := json.MarshalIndent(r.Data, "", "  ")
			refs, _ := json.Marshal(l.ReferencesTo(c.Name, r))
			return promptText(fmt.Sprintf(`Audit the record %s/%s of this ledger and report anything inconsistent. Change nothing.

Record (hash %s):
%s

Records that reference it: %s

Steps: read collections_describe for %s to learn its schema and references; call records_get with include=["backrefs","history"]; follow each reference of the record with records_get and check that the target exists and agrees; run ledger_check with collection=%s; compare the latest history_diff with the current record. Report each problem with the field, what you found and what you expected.`,
				c.Name, r.ID, r.Hash, rec, refs, c.Name, c.Name)), nil
		})
	s.AddPrompt(&mcp.Prompt{Name: "prepare_change",
		Description: "Plan a change to the ledger: find the affected records, dry-run each write and propose one pull request.",
		Arguments:   []*mcp.PromptArgument{{Name: "goal", Description: "what should change, in plain words", Required: true}}},
		func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			goal := req.Params.Arguments["goal"]
			if strings.TrimSpace(goal) == "" {
				return nil, fmt.Errorf("goal must not be empty")
			}
			return promptText(fmt.Sprintf(`Goal: %s

Prepare this change to the ledger. Call collections_list, then find the affected records with ledger_search and records_query. For every record to change, call records_get and note its hash. Then run each records_create, records_update or records_delete with dry_run=true, one at a time, and read the diff and the validation result. Fix any problem before going on. When every dry run is clean, summarise the change (records, fields, before and after) and ask before making the real writes. Writes become pull requests; deletes always do.`, goal)), nil
		})
	s.AddPrompt(&mcp.Prompt{Name: "explain_collection",
		Description: "Summarise a collection's schema and conventions for a new contributor.",
		Arguments:   []*mcp.PromptArgument{{Name: "collection", Description: "collection name", Required: true}}},
		func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			out, errRes := t.describe(req.Params.Arguments["collection"])
			if errRes != nil {
				return nil, fmt.Errorf("unknown collection %q", req.Params.Arguments["collection"])
			}
			b, _ := json.MarshalIndent(out, "", "  ")
			return promptText(fmt.Sprintf(`Explain the collection %q to someone who will edit it for the first time: what a record stands for, the key fields, which fields are required and what values they take, how it refers to other collections, and the conventions in its notes. Use records_query with a small limit to show two or three real examples.

Description of the collection:
%s`, out.Name, b)), nil
		})
}
