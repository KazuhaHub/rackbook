# MCP surface (decision 16)

Status: accepted direction, to be implemented in v0.5.0 (the `expiry` family
already ships in v0.3.0). Tool names, their
arguments and their result shapes are part of Rackbook's SemVer promise (README,
"Versioning and compatibility"), so this document fixes the shape before 1.0.

## 1. Principles

- **Generic, never per collection.** Every tool takes `collection` (and `id`)
  as arguments. Collections, fields, keys and references come from
  `rackbook.yml` and the JSON Schemas, so a new data type never needs a new
  tool. Agents read the schema (`collections_describe`) to build valid records.
- **Families with one naming scheme.** Tool names are
  `<family>_<verb>` in snake_case, for example `records_get` or `docs_put`.
  Dots would read better, but tool names like `records.get` are refused by
  several clients and by the Anthropic API (`^[a-zA-Z0-9_-]{1,64}$`), so the
  underscore is the separator.
- **Tools for actions, resources for reading, prompts for workflows.**
- **Every result is structured.** Each tool declares an `outputSchema` and
  returns `structuredContent`, with a short text rendering for clients that
  don't read structured content.

## 2. Families

| family | tools | since | scope |
|---|---|---|---|
| `ledger` (server-wide) | `ledger_info`, `ledger_search`, `ledger_check`, `ledger_export` | v0.5.0 | read |
| `collections` | `collections_list`, `collections_describe` | v0.5.0 | read |
| `records` | `records_query`, `records_get`, `records_create`, `records_update`, `records_delete` | v0.5.0 | read / write |
| `docs` | `docs_get`, `docs_put`, `docs_delete` | v0.5.0 (decision 15) | read / docs |
| `history` | `history_list`, `history_diff` | v0.5.0 | read |
| `changes` | `changes_list`, `changes_get`, `changes_status`, `changes_comment` | v0.5.0 | read / write |
| `expiry` | `expiry_list` | v0.3.0 (decision 17) | read |
| `facts` | `facts_list`, `facts_get`, later `facts_adopt` | later | read / write |
| `admin` | `admin_types_list`, `admin_types_plan`, `admin_types_apply`, `admin_users_list`, `admin_tokens_list`, … | later | admin |

- `ledger_info` is the feature-detection entry point. It returns the server
  version, the MCP spec revision negotiated, the families this server provides
  with each family's surface version, the caller's identity, role and effective
  scopes, the limits (section 8), and which tools are deprecated with their
  replacement and removal version. It is also available as the resource
  `rackbook://info`.
- **Discovering unknown or future families.** Clients never guess names. They
  read `ledger_info.families` or `tools/list`. A server only lists tools of
  families the caller's role and scopes allow. When those change during a
  session (a role edit in `rackbook.yml`), it sends
  `notifications/tools/list_changed`. A family is added only in a minor
  release and is announced in `ledger_info`.

### Tool details

- `collections_describe(collection)`: title, description, key fields, label,
  JSON Schema, references in and out, facets, notes, record count, document
  support. This replaces `get_schema`.
- `records_query(collection, where?, search?, fields?, order_by?, cursor?, limit?)`:
  - `where` holds exact-match conditions per field, plus `contains` and
    `prefix` operators matching the console facets;
  - `fields` projects the record;
  - the result is `{items:[{id, hash, data}], next_cursor}`.
- `records_get(collection, id, include?)`: `include` can be `backrefs`, `doc`
  or `history`. Returns `{id, hash, data, backrefs?, doc?, history?}`.
- `ledger_search(query, collections?, include_docs?, cursor?, limit?)`:
  substring search over records (and documents), with ranked hits.
- `ledger_check(collection?, rule?, cursor?, limit?)`: validation problems.
  This replaces both `check` and `list_problems`.
- `ledger_export(format: markdown|json, collection?)`: subject to the size cap
  in section 8. Larger exports are offered as resources instead.
- `history_list(collection, id?, cursor?, limit?)` and
  `history_diff(commit, collection?, id?)`: the field-level diff of a record
  change.
- `changes_*`: pull requests and proposals that Rackbook opened (from MCP,
  tokens or the console) as first-class objects. Tools list them, get one with
  its diff and validation status, read CI and review status, and comment. They
  never merge; merging stays a human action in the Git host.

## 3. Resources and prompts

- **Resources**, using resource templates:
  - `rackbook://info`
  - `rackbook://collections`
  - `rackbook://collections/{collection}` (description and schema)
  - `rackbook://records/{collection}/{id}`
  - `rackbook://docs/{collection}/{id}`
  - `rackbook://export/markdown`
  - `rackbook://llms.txt`

  Clients that prefer reading use these; the content matches the corresponding
  tools. Subscriptions (`resources/subscribe`) send an update after a pull
  brings in a change.
- **Prompts:**
  - `audit_record(collection, id)`: check a record against its references,
    documents and recent history, and report inconsistencies;
  - `prepare_change(goal)`: find the affected records, run dry runs, propose
    one PR;
  - `explain_collection(collection)`: summarise the schema and conventions for
    a new contributor.

  Prompts only assemble context and instructions; they never write.

## 4. Spec features

- **Annotations** on every tool:
  - `readOnlyHint` on all read tools;
  - `destructiveHint` on `records_delete`, `docs_delete` and admin writes;
  - `idempotentHint` on `records_update` and `docs_put` (given the same
    `expected_hash`);
  - `openWorldHint: false` everywhere except `changes_*`, which touch the Git
    host.
- **Structured results:** `outputSchema` plus `structuredContent` for every
  tool (section 1).
- **Pagination:** opaque `cursor` / `next_cursor` on every list or search tool,
  with a default and a maximum `limit`.
- **Errors:** tool errors are results with `isError: true` and
  `structuredContent: {error: <code>, message, details?}`. The codes are the
  same as the HTTP API's: `not_found`, `conflict`, `invalid`,
  `secret_detected`, `forbidden`, `insufficient_scope`, `history_rewritten`,
  `config_error`, `repo_dirty`, `pull_request_unavailable`, `rate_limited`,
  `too_large`. Protocol errors (unknown tool, bad arguments) stay JSON-RPC
  errors.
- **Spec revision:** the server tracks the latest revision the Go SDK supports
  and negotiates down to 2025-06-18 at minimum. The SDK in use (v1.8.0)
  supports up to 2026-07-28. Capabilities declared: `tools` (`listChanged`),
  `resources` (`subscribe`, `listChanged`), `prompts`, `logging`, and
  `completions` for `collection` and `id` arguments.

## 5. Safe writes for agents

- Every write tool takes `dry_run: true`. That returns the would-be change:
  the files and unified diff, validation results, secret-scan findings, and
  whether it would be a direct push or a PR. Nothing is written.
- `records_update`, `records_delete`, `docs_put` and `docs_delete` require
  `expected_hash` (optimistic concurrency); a mismatch returns `conflict` with
  the current value. `records_create` fails with `conflict` if the id exists.
- `idempotency_key` (optional, recommended). A repeated call with the same key
  and the same arguments within 24 h returns the first result instead of a
  second change. The keys are kept in memory and are lost on restart, which is
  acceptable because `expected_hash` still prevents double writes.
- Every write returns `{change: {kind: commit|pull_request, id, url?, branch?}, record?}`.
- Policy is unchanged:
  - writes from MCP and tokens are PRs by default, and deletes always are;
  - direct push only as configured in `auth.mcp.direct_push`;
  - the secret scan applies to every write, including documents.

## 6. Authorization per family

| scope | grants (never more than the caller's role) |
|---|---|
| `rackbook:read` | all read tools, resources, prompts |
| `rackbook:write` | `records_*` writes, `changes_comment` |
| `rackbook:docs` | `docs_put`, `docs_delete` |
| `rackbook:admin` | `admin_*` (admin role only) |

- Scopes only narrow the role; a viewer with `rackbook:write` still can't
  write.
- An issuer that sends no scopes gets the role's full rights, as configured
  per issuer in v0.2.
- Every new family states its scope in this table before release. A family
  that needs no new rights reuses `read`/`write`.

## 7. Evolution policy

- **Allowed in a minor release (additive):** new families, new tools, new
  optional arguments, new result fields, new error codes, new resources and
  prompts. Clients must ignore unknown fields.
- **Renames and removals:** the old name keeps working as a deprecated alias
  for at least one minor release. Its description starts with
  `Deprecated: use <new>; removed in <version>`, and `ledger_info` lists it.
  Before 1.0, removal is allowed in the next minor after the deprecation; from
  1.0, only in a major.
- **Changing a result shape or an argument's meaning** counts as a rename: the
  tool gets a new name.
- `ledger_info.families[].version` is a per-family surface version
  (`records: 1`). It increases only on additive changes to that family.

## 8. Limits

- `limit`: default 50 and maximum 500 per page for queries and searches; at
  most 100 history entries per page.
- A single result is capped at 1 MiB of structured content. Beyond that the
  tool returns `too_large` with a cursor or a resource URI to use instead.
  `ledger_export` beyond the cap points to `rackbook://export/markdown`.
- Rate limits per identity: 600 reads and 60 writes per minute by default,
  configurable in `auth.mcp.limits`. Over the limit, the result is
  `rate_limited` with `retry_after`.
- No tool returns the whole ledger in one call. Full exports are resources
  and are read deliberately.

## 9. Contract tests

- `internal/mcpserver/testdata/surface.golden.json` holds the full
  `tools/list` and `resources/templates/list` and `prompts/list`, with
  names, input and output schemas, and annotations.
- A test compares the live surface with it. Additive differences pass only if
  the golden file is updated in the same commit. Removals or changes of
  existing entries fail unless the old entry is still present as a deprecated
  alias.
- CI runs it on every PR. Updating the golden file needs `-update` and shows in
  review.

## 10. v0.2 tools → v0.5.0

The renames ship in **v0.5.0** with deprecated aliases, removed in **v0.6.0**.
They aren't patch-released: aliases would double the tool list in clients,
which costs more than waiting.

| v0.2 tool | v0.5.0 | change |
|---|---|---|
| `list_collections` | `collections_list` | rename |
| `get_schema` | `collections_describe` | rename; result adds keys, refs, facets, notes, counts |
| `list_records` | `records_query` | rename; adds cursor/limit, `fields`, `contains`/`prefix` operators; result becomes `{items, next_cursor}` |
| `get_record` | `records_get` | rename; `include` replaces the always-on backrefs |
| `search` | `ledger_search` | rename; adds collections filter, documents, cursor |
| `check` | `ledger_check` | rename; merges `list_problems` |
| `list_problems` | `ledger_check` | merged |
| `export_markdown` | `ledger_export` | rename; `format` argument, size cap |
| `record_history` | `history_list` | rename; cursor |
| `create_record` | `records_create` | rename; adds `dry_run`, `idempotency_key`; result `{change, record}` |
| `update_record` | `records_update` | rename; `hash` → `expected_hash` (old name accepted on the alias), adds `dry_run`, `idempotency_key` |
| `delete_record` | `records_delete` | rename; same; `clear_references` option |
| — | `ledger_info`, `history_diff`, `docs_*`, `changes_*`, resources, prompts | new |

Other v0.2 → v0.5.0 changes:

- Annotations: add `destructiveHint`, `idempotentHint` and `openWorldHint`
  everywhere. Today only `readOnlyHint` is set.
- `outputSchema` and `structuredContent` on every tool. Today results are text
  or JSON in text.
- Errors move to the shared code set.
- `tools/list` is filtered by scope and role, with `list_changed`.
