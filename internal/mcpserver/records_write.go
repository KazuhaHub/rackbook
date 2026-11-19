package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kazuhahub/rackbook/internal/apierr"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/edit"
	"github.com/kazuhahub/rackbook/internal/gitstore"
	"github.com/kazuhahub/rackbook/internal/ledger"
	"github.com/kazuhahub/rackbook/internal/roles"
	"github.com/kazuhahub/rackbook/internal/types"
)

const writeInstructionsV2 = `
Writes (records_create, records_update, records_delete) are validated exactly like the console's. Depending on who you are they either commit directly or open a pull request: result.change.kind says which (commit or pull_request, url = the PR). Deletes always open a pull request. Pass dry_run=true to see the diff, the validation result and whether it would be a PR, without writing anything. records_update and records_delete need expected_hash from records_get; a conflict error carries the current record in details, so re-read and retry. Send an idempotency_key to make a retry safe. If ledger_check reports history_rewritten, config_error or repo_dirty, writes are paused: report it, do not retry.`

type recordsCreateIn struct {
	Collection     string         `json:"collection" jsonschema:"collection name from collections_list"`
	Data           map[string]any `json:"data" jsonschema:"the full record: every field, as in records_get's data"`
	Confirm        bool           `json:"confirm_not_secret,omitempty" jsonschema:"set true only after a secret_suspected error, when you have checked the value is not a secret"`
	DryRun         bool           `json:"dry_run,omitempty" jsonschema:"validate and show the change without writing it"`
	IdempotencyKey string         `json:"idempotency_key,omitempty" jsonschema:"a repeated call with the same key and arguments within 24 hours returns the first result"`
}

type recordsUpdateIn struct {
	Collection     string         `json:"collection" jsonschema:"collection name"`
	ID             string         `json:"id" jsonschema:"record id from records_query or records_get"`
	ExpectedHash   string         `json:"expected_hash,omitempty" jsonschema:"the hash from records_get; the write fails with a conflict if the record changed since"`
	Data           map[string]any `json:"data" jsonschema:"the full new record (not a patch): every field"`
	Confirm        bool           `json:"confirm_not_secret,omitempty" jsonschema:"set true only after a secret_suspected error, when you have checked the value is not a secret"`
	DryRun         bool           `json:"dry_run,omitempty" jsonschema:"validate and show the change without writing it"`
	IdempotencyKey string         `json:"idempotency_key,omitempty" jsonschema:"a repeated call with the same key and arguments within 24 hours returns the first result"`
}

type recordsDeleteIn struct {
	Collection      string `json:"collection" jsonschema:"collection name"`
	ID              string `json:"id" jsonschema:"record id"`
	ExpectedHash    string `json:"expected_hash,omitempty" jsonschema:"the hash from records_get"`
	ClearReferences bool   `json:"clear_references,omitempty" jsonschema:"also remove the references to this record from the records that hold them, in the same change"`
	DryRun          bool   `json:"dry_run,omitempty" jsonschema:"validate and show the change without writing it"`
	IdempotencyKey  string `json:"idempotency_key,omitempty" jsonschema:"a repeated call with the same key and arguments within 24 hours returns the first result"`
}

type changeOut struct {
	Kind string `json:"kind" jsonschema:"commit or pull_request"`
	ID   string `json:"id" jsonschema:"the short commit hash, or the pull request number"`
	URL  string `json:"url,omitempty" jsonschema:"the pull request"`
}

type fileDiff struct {
	Path   string `json:"path"`
	Status string `json:"status" jsonschema:"added or modified"`
	Diff   string `json:"diff" jsonschema:"unified diff"`
}

type problem struct {
	Code    string         `json:"error"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

type dryRunOut struct {
	Valid   bool       `json:"valid" jsonschema:"the change passes validation and the secret scan"`
	Changed bool       `json:"changed" jsonschema:"false when the write would change nothing"`
	WouldBe string     `json:"would_be,omitempty" jsonschema:"direct_push or pull_request"`
	Files   []fileDiff `json:"files"`
	// Problems are the validation errors or secret findings that make the write fail.
	Problems []problem `json:"problems"`
}

type writeOut2 struct {
	Change   *changeOut         `json:"change,omitempty" jsonschema:"absent when nothing changed or on a dry run"`
	Record   *recordItem        `json:"record,omitempty" jsonschema:"the record as written; absent for a delete"`
	Cleared  []ledger.Reference `json:"cleared,omitempty" jsonschema:"references removed by a delete with clear_references"`
	Message  string             `json:"message"`
	DryRun   *dryRunOut         `json:"dry_run,omitempty"`
	Replayed bool               `json:"replayed,omitempty" jsonschema:"true when this is the first result of the same idempotency_key"`
}

func (t *tools) addRecordWriteTools(s *mcp.Server) {
	write := func(destructive, idempotent bool) *mcp.ToolAnnotations {
		return &mcp.ToolAnnotations{DestructiveHint: &destructive, IdempotentHint: idempotent, OpenWorldHint: new(false)}
	}
	addTool[recordsCreateIn, writeOut2](t, s, &mcp.Tool{Name: "records_create", Annotations: write(false, false),
		Description: "Add a record to a collection. data is the whole record (see collections_describe for the fields). Validated like the console; fails with conflict if the id exists. result.change tells whether it was committed or opened as a pull request (url). dry_run shows the diff without writing."},
		func(ctx context.Context, req *mcp.CallToolRequest, in recordsCreateIn) (*mcp.CallToolResult, any, error) {
			op := edit.Op{Kind: edit.Add, Collection: in.Collection, Data: intify(in.Data), ConfirmNotSecret: in.Confirm}
			return t.recordsWrite(ctx, req, "records_create", auth.ActCreate, roles.Write, op, in.DryRun, in.IdempotencyKey)
		})
	addTool[recordsUpdateIn, writeOut2](t, s, &mcp.Tool{Name: "records_update", Annotations: write(false, true),
		Description: "Replace a record. Needs expected_hash from records_get; data is the whole new record. Fails with conflict (and the current record in details) if it changed meanwhile, so the same call with the same expected_hash never applies twice. dry_run shows the diff without writing."},
		func(ctx context.Context, req *mcp.CallToolRequest, in recordsUpdateIn) (*mcp.CallToolResult, any, error) {
			if in.ExpectedHash == "" {
				return apiError("invalid", "expected_hash is required: call records_get first", nil), nil, nil
			}
			op := edit.Op{Kind: edit.Edit, Collection: in.Collection, ID: in.ID, Hash: in.ExpectedHash, Data: intify(in.Data), ConfirmNotSecret: in.Confirm}
			return t.recordsWrite(ctx, req, "records_update", auth.ActUpdate, roles.Write, op, in.DryRun, in.IdempotencyKey)
		})
	addTool[recordsDeleteIn, writeOut2](t, s, &mcp.Tool{Name: "records_delete", Annotations: write(true, false),
		Description: "Delete a record. Needs expected_hash from records_get. A delete always opens a pull request, even for credentials that may commit directly. It is refused (conflict, details.references) while other records still reference the record, unless clear_references removes those references in the same change. dry_run shows the diff without writing."},
		func(ctx context.Context, req *mcp.CallToolRequest, in recordsDeleteIn) (*mcp.CallToolResult, any, error) {
			if in.ExpectedHash == "" {
				return apiError("invalid", "expected_hash is required: call records_get first", nil), nil, nil
			}
			op := edit.Op{Kind: edit.Delete, Collection: in.Collection, ID: in.ID, Hash: in.ExpectedHash, ClearReferences: in.ClearReferences}
			return t.recordsWrite(ctx, req, "records_delete", auth.ActDelete, roles.Delete, op, in.DryRun, in.IdempotencyKey)
		})
}

// writeError turns a failed write into the structured error result. The codes
// are the API's, folded into the MCP set: a record that is still referenced is a
// conflict (details.references) and a malformed request is invalid.
func (t *tools) writeError(err error) *mcp.CallToolResult {
	info := apierr.Classify(err)
	switch info.Code {
	case "internal":
		t.log.Error("mcp write failed", "err", err)
		return apiError("internal", "the write failed on the server (see its log)", nil)
	case "referenced":
		return apiError("conflict", info.Message, info.Extra)
	case "bad_request":
		return apiError("invalid", info.Message, info.Extra)
	}
	return apiError(info.Code, info.Message, info.Extra)
}

// fingerprint identifies a call's arguments apart from the idempotency key.
func fingerprint(req *mcp.CallToolRequest) string {
	var args map[string]any
	_ = json.Unmarshal(req.Params.Arguments, &args)
	delete(args, "idempotency_key")
	b, _ := json.Marshal(args) // map keys are sorted
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// recordsWrite is the common path of the three record write tools.
func (t *tools) recordsWrite(ctx context.Context, req *mcp.CallToolRequest, tool, action string, need roles.Action, op edit.Op, dryRun bool, key string) (*mcp.CallToolResult, any, error) {
	id, g := t.gate(req, action, need, op.Collection)
	if g != nil {
		return apiError(g.code, g.msg, nil), nil, nil
	}
	if op.Kind == edit.Delete {
		op.MayUpdate = func(coll string) bool { return id.Permits(auth.ActUpdate, coll) && id.Can(roles.Write) }
	}
	if dryRun {
		return t.dryRun(ctx, id, op)
	}
	var idemKey string
	if key != "" {
		idemKey = credentialKey(id) + "\x00" + tool + "\x00" + key
		t.idem.mu.Lock()
		defer t.idem.mu.Unlock()
		t.idem.prune()
		if e, ok := t.idem.entries[idemKey]; ok {
			if e.fingerprint != fingerprint(req) {
				return apiError("conflict", "idempotency_key was already used with different arguments", nil), nil, nil
			}
			out := e.out
			out.Replayed = true
			return nil, out, nil
		}
	}
	res, err := t.commit(ctx, id, op)
	if err != nil {
		return t.writeError(err), nil, nil
	}
	out := writeOut2{Cleared: res.Cleared}
	switch {
	case res.PullRequest:
		out.Change = &changeOut{Kind: "pull_request", ID: pullNumber(res.Commit), URL: res.Commit}
		out.Message = "opened a pull request; the change is not on the tracked branch until it is merged"
	case res.Commit != "":
		out.Change = &changeOut{Kind: "commit", ID: res.Commit}
		out.Message = "committed"
	case res.Changed():
		// No Git: the files were changed in place.
		out.Change = &changeOut{Kind: "commit", ID: ""}
		out.Message = "written in place (the data directory is not a Git repository)"
	default:
		out.Message = "nothing changed"
	}
	if op.Kind != edit.Delete {
		out.Record = &recordItem{ID: res.ID, Hash: res.Hash, Data: res.Data}
	}
	if key != "" {
		t.idem.entries[idemKey] = idemEntry{at: t.idem.now(), fingerprint: fingerprint(req), out: out}
	}
	return nil, out, nil
}

// pullNumber is the number at the end of a pull request URL, else the URL.
func pullNumber(u string) string {
	if parsed, err := url.Parse(u); err == nil {
		if i := strings.LastIndex(parsed.Path, "/"); i >= 0 && i+1 < len(parsed.Path) {
			return parsed.Path[i+1:]
		}
	}
	return u
}

// credentialKey names the credential behind an identity: the same username
// reached with another method, issuer or API token is another credential.
func credentialKey(id *auth.Identity) string {
	return strings.Join([]string{id.Method, id.Issuer, id.ID, id.Token}, "\x00")
}

// dryRun runs the whole write without writing, under the store's write lock and
// after the checks a real write makes first (paused writes, a dirty or diverged
// clone, a pull request that cannot be opened), so it refuses what the write
// would refuse. It returns the same checks (module rules, secret scan,
// validation, conflicts), the files and diffs the write would produce, and
// whether it would be pushed or become a pull request.
func (t *tools) dryRun(ctx context.Context, id *auth.Identity, op edit.Op) (*mcp.CallToolResult, any, error) {
	op = t.confirmFor(id, op)
	op.DryRun = true
	opts := gitstore.WriteOptionsFor(id, t.backend.Config(), op.Kind, op.Collection)
	res, pr, err := t.backend.DryRunFunc(ctx, gitstore.ApplyOpAs(id, op), opts)
	if err != nil {
		info := apierr.Classify(err)
		switch info.Code {
		case "invalid", "secret_detected", "secret_suspected":
			return nil, writeOut2{Message: "the write would fail", DryRun: &dryRunOut{Files: []fileDiff{}, Problems: []problem{{Code: info.Code, Message: info.Message, Details: info.Extra}}}}, nil
		}
		return t.writeError(err), nil, nil
	}
	d := &dryRunOut{Valid: true, Changed: res.Changed(), Files: []fileDiff{}, Problems: []problem{}, WouldBe: "direct_push"}
	if pr {
		d.WouldBe = "pull_request"
	}
	for _, f := range res.Files {
		fd := fileDiff{Path: f, Status: "modified", Diff: types.UnifiedDiff(f, string(res.Before[f]), string(res.After[f]))}
		if len(res.Before[f]) == 0 {
			fd.Status = "added"
		}
		d.Files = append(d.Files, fd)
	}
	out := writeOut2{Cleared: res.Cleared, DryRun: d, Message: "dry run: nothing was written"}
	if op.Kind != edit.Delete && res.Hash != "" {
		out.Record = &recordItem{ID: res.ID, Hash: res.Hash, Data: res.Data}
	}
	return nil, out, nil
}
