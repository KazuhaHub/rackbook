package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kazuhahub/rackbook/internal/apierr"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/mcpauth"
	"github.com/kazuhahub/rackbook/internal/roles"
	"github.com/kazuhahub/rackbook/internal/validate"
)

// Backend is the part of the store the write and history tools use. It is
// *gitstore.Store; the interface keeps the tool handlers independent of how a
// record is stored (v0.3 will keep one file per record).
type Backend interface {
	WriteFunc(ctx context.Context, apply gitstore.ApplyFunc, who *auth.Identity, opts gitstore.WriteOptions) (*gitstore.WriteResult, error)
	History(ctx context.Context, limit int, collection, id string) ([]gitstore.Commit, error)
	Config() *config.Config
	Alert() *gitstore.Alert
	ConfigProblem() string
}

// Options configures the server.
type Options struct {
	Source  Source
	Version string
	// Backend enables record_history and, unless ReadOnly, the write tools.
	// Leave it nil for a read-only server (stdio).
	Backend  Backend
	ReadOnly bool
	Logger   *slog.Logger
}

const writeInstructions = `
Writes (create_record, update_record, delete_record) are validated exactly like the console's. Depending on who you are they either commit directly or open a pull request: the result says which (pullRequest true, url = the PR). Deletes always open a pull request. update_record and delete_record need the "hash" from get_record; a conflict error carries the current record, so re-read and retry. If the ledger reports history_rewritten, config_error or repo_dirty, writes are paused: report it, do not retry.`

type writeIn struct {
	Collection string         `json:"collection" jsonschema:"collection name from list_collections"`
	Data       map[string]any `json:"data" jsonschema:"the full record: every field, as in get_record's data"`
	Confirm    bool           `json:"confirm_not_secret,omitempty" jsonschema:"set true only after a secret_suspected error, when you have checked the value is not a secret"`
}

type updateIn struct {
	Collection string         `json:"collection" jsonschema:"collection name"`
	ID         string         `json:"id" jsonschema:"record id from list_records or get_record"`
	Hash       string         `json:"hash" jsonschema:"the hash from get_record; the write fails with a conflict if the record changed since"`
	Data       map[string]any `json:"data" jsonschema:"the full new record (not a patch): every field"`
	Confirm    bool           `json:"confirm_not_secret,omitempty" jsonschema:"set true only after a secret_suspected error, when you have checked the value is not a secret"`
}

type deleteIn struct {
	Collection string `json:"collection" jsonschema:"collection name"`
	ID         string `json:"id" jsonschema:"record id"`
	Hash       string `json:"hash" jsonschema:"the hash from get_record"`
}

type writeOut struct {
	ID          string         `json:"id"`
	Hash        string         `json:"hash,omitempty"`
	Data        map[string]any `json:"data,omitempty"`
	Commit      string         `json:"commit,omitempty"`
	PullRequest bool           `json:"pullRequest"`
	URL         string         `json:"url,omitempty"`
	Message     string         `json:"message"`
}

func (t *tools) addWriteTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{Name: "create_record",
		Description: "Add a record to a collection. data is the whole record (see get_schema for the fields). Validated like the console; the result tells whether it was committed or opened as a pull request (url)."},
		func(ctx context.Context, req *mcp.CallToolRequest, in writeIn) (*mcp.CallToolResult, any, error) {
			return t.write(ctx, req, auth.ActCreate, roles.Write, in.Collection, edit.Op{Kind: edit.Add, Collection: in.Collection, Data: intify(in.Data), ConfirmNotSecret: in.Confirm})
		})
	mcp.AddTool(s, &mcp.Tool{Name: "update_record",
		Description: "Replace a record. Needs the hash from get_record; data is the whole new record. Fails with a conflict (and the current record) if it changed meanwhile."},
		func(ctx context.Context, req *mcp.CallToolRequest, in updateIn) (*mcp.CallToolResult, any, error) {
			if in.Hash == "" {
				return errText(http.StatusBadRequest, "bad_request", "hash is required: call get_record first", nil), nil, nil
			}
			return t.write(ctx, req, auth.ActUpdate, roles.Write, in.Collection, edit.Op{Kind: edit.Edit, Collection: in.Collection, ID: in.ID, Hash: in.Hash, Data: intify(in.Data), ConfirmNotSecret: in.Confirm})
		})
	mcp.AddTool(s, &mcp.Tool{Name: "delete_record",
		Description: "Delete a record. Needs the hash from get_record. A delete always opens a pull request, even for credentials that may commit directly; it is refused while other records still reference the record."},
		func(ctx context.Context, req *mcp.CallToolRequest, in deleteIn) (*mcp.CallToolResult, any, error) {
			if in.Hash == "" {
				return errText(http.StatusBadRequest, "bad_request", "hash is required: call get_record first", nil), nil, nil
			}
			return t.write(ctx, req, auth.ActDelete, roles.Delete, in.Collection, edit.Op{Kind: edit.Delete, Collection: in.Collection, ID: in.ID, Hash: in.Hash})
		})
}

func identityOf(req *mcp.CallToolRequest) *auth.Identity {
	if x := req.GetExtra(); x != nil {
		return mcpauth.IdentityFrom(x.TokenInfo)
	}
	return nil
}

// errText is a tool error carrying the same JSON as the API's error bodies.
func errText(status int, code, msg string, extra map[string]any) *mcp.CallToolResult {
	body := map[string]any{"error": code, "message": msg, "status": status}
	for k, v := range extra {
		body[k] = v
	}
	b, _ := json.Marshal(body)
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}
}

func (t *tools) write(ctx context.Context, req *mcp.CallToolRequest, action string, need roles.Action, collection string, op edit.Op) (*mcp.CallToolResult, any, error) {
	if t.readOnly {
		return errText(http.StatusForbidden, "read_only", "the ledger is read-only", nil), nil, nil
	}
	id := identityOf(req)
	if id == nil {
		return errText(http.StatusForbidden, "forbidden", "writes need an authenticated HTTP session", nil), nil, nil
	}
	if !id.Can(need) {
		if id.Role.Allows(need) { // the role would allow it: the credential's scope does not
			return errText(http.StatusForbidden, "insufficient_scope", fmt.Sprintf("this credential's scopes do not allow writing (needs %q)", t.backend.Config().Auth.MCP.Scopes.WriteScope()), nil), nil, nil
		}
		return errText(http.StatusForbidden, "forbidden", fmt.Sprintf("your role (%s) may not do this", id.EffectiveRole()), nil), nil, nil
	}
	if !id.Permits(action, collection) {
		return errText(http.StatusForbidden, "forbidden", fmt.Sprintf("this token may not %s records in %s", action, collection), nil), nil, nil
	}
	if op.ConfirmNotSecret {
		// A confirmation is only taken from someone who may give it; otherwise the
		// write is refused as secret_suspected like any other.
		if gitstore.MayConfirm(id, t.backend.Config(), op.Kind, collection) {
			op.ConfirmedBy = id.IDOrEmpty()
		} else {
			op.ConfirmNotSecret = false
		}
	}
	opts := gitstore.WriteOptionsFor(id, t.backend.Config(), op.Kind, collection)
	res, err := t.backend.WriteFunc(ctx, gitstore.ApplyOpAs(id, op), id, opts)
	if err != nil {
		info := apierr.Classify(err)
		if info.Status == http.StatusInternalServerError {
			t.log.Error("mcp write failed", "err", err)
			// A pull request that could not be opened is the caller's to hear about.
			return errText(500, "internal", "the write failed on the server (see its log)", nil), nil, nil
		}
		return errText(info.Status, info.Code, info.Message, info.Extra), nil, nil
	}
	out := writeOut{ID: res.ID, Hash: res.Hash, Data: res.Data, Commit: res.Commit, PullRequest: res.PullRequest}
	switch {
	case res.PullRequest:
		out.URL = res.Commit
		out.Commit = ""
		out.Message = "opened a pull request; the change is not on the tracked branch until it is merged"
	case res.Commit != "":
		out.Message = "committed"
	default:
		out.Message = "nothing changed"
	}
	if op.Kind == edit.Delete {
		out.Hash, out.Data = "", nil
	}
	b, _ := json.Marshal(out)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
}

// intify turns integral float64 values (how JSON numbers arrive) into int64 so
// they are written as integers.
func intify(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = intifyValue(v)
	}
	return out
}

func intifyValue(v any) any {
	switch x := v.(type) {
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1<<53 {
			return int64(x)
		}
	case map[string]any:
		return intify(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = intifyValue(e)
		}
		return out
	}
	return v
}

// Read tools added with the write path ------------------------------------

type historyIn struct {
	Collection string `json:"collection" jsonschema:"collection name"`
	ID         string `json:"id" jsonschema:"record id"`
	Limit      int    `json:"limit,omitempty" jsonschema:"at most this many commits (default 20, max 200)"`
}

type historyOut struct {
	Collection string            `json:"collection"`
	ID         string            `json:"id"`
	Commits    []gitstore.Commit `json:"commits"`
}

func (t *tools) recordHistory(ctx context.Context, _ *mcp.CallToolRequest, in historyIn) (*mcp.CallToolResult, historyOut, error) {
	if _, _, err := t.collection(in.Collection); err != nil {
		return nil, historyOut{}, err
	}
	commits, err := t.backend.History(ctx, in.Limit, in.Collection, in.ID)
	if err != nil {
		return nil, historyOut{}, err
	}
	return nil, historyOut{Collection: in.Collection, ID: in.ID, Commits: commits}, nil
}

type problemsOut struct {
	OK bool `json:"ok"`
	// Store lists what pauses writes: history_rewritten, config_error.
	Store  []map[string]any `json:"store"`
	Errors []ledger.Issue   `json:"errors"`
	// Warnings are heuristic secret findings (confirm tier).
	Warnings []ledger.Issue `json:"warnings"`
}

func (t *tools) listProblems(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, problemsOut, error) {
	issues := validate.Run(t.src())
	issues, warnings := validate.Split(issues)
	out := problemsOut{Store: []map[string]any{}, Errors: issues, Warnings: warnings}
	if t.backend != nil {
		if a := t.backend.Alert(); a != nil {
			m := map[string]any{"kind": a.Kind, "writesPaused": true}
			if a.Message != "" {
				m["message"] = a.Message
			}
			if a.Remote != "" {
				m["lastGood"], m["remote"] = a.LastGood, a.Remote
			}
			out.Store = append(out.Store, m)
		} else if p := t.backend.ConfigProblem(); p != "" {
			out.Store = append(out.Store, map[string]any{"kind": gitstore.AlertConfigError, "message": p, "writesPaused": true})
		}
	}
	out.OK = len(issues) == 0 && len(out.Store) == 0
	return nil, out, nil
}
