# Rackbook HTTP API

All endpoints return JSON (`Content-Type: application/json; charset=utf-8`)
except the export endpoints. Errors always have the shape
`{"error": "<code>", "message": "<human text>", ...}`.

## Identifiers

- **Record id**: the values of the collection's `key` fields, each escaped
  (`%` → `%25`, `/` → `%2F`) and joined with `/`. Example:
  `web-hostco-ashburn-va-us-dc/SSH`. In URL paths the whole id is one path
  segment, so clients pass it through `encodeURIComponent`. A collection
  without `key` uses `#<index>` (0-based position in the list).
- **Record hash**: first 16 hex chars of SHA-256 over the record's canonical
  JSON (keys sorted, no whitespace). Writes send the hash they started from.

## Read

### `GET /api/meta`

```json
{
  "title": "示例网络台账",
  "description": "…",
  "readOnly": false,
  "writeMode": "push",
  "user": {"id": "a@example.com", "email": "a@example.com", "name": "a",
           "role": "editor", "authMethod": "cloudflare-access",
           "canEdit": true, "canAdmin": false},
  "alert": {"kind": "history_rewritten", "lastGood": "<40 hex>", "remote": "<40 hex>"},
  "collections": [
    {
      "name": "services",
      "title": "服务端口",
      "description": "…",
      "group": "",
      "key": ["device", "service"],
      "label": "",
      "list": ["device", "service", "port", "exposure", "managed"],
      "facets": [
        {"field": "device", "match": "exact", "values": []},
        {"field": "exposure", "match": "contains", "values": ["公网", "Tailscale"]}
      ],
      "schema": { "…JSON Schema object…": true },
      "refs": [{"field": "device", "to": "devices", "toField": "name", "allow": ["all"]}],
      "backrefs": [],
      "notes": [{"title": "…", "text": "…"}],
      "count": 12
    }
  ]
}
```

- `user` is always present. `role` is `admin`, `editor` or `viewer` (the role
  after any scope narrowing, from `auth.roles` evaluated on this request).
  `authMethod` is `none`, `cloudflare-access`, `oidc`, `passkey`, `mcphub` or
  `token`. `canEdit` is `role` ≥ editor and the server is not read-only;
  `canAdmin` is `role` = admin. `id` (lowercased identity), `email` and `name`
  are left out when unknown (auth `none` without `--editor`).
- `alert` is present only while the remote Git history was rewritten (see
  [design.md](design.md), section 3): writes return `503` until an
  administrator accepts it with `POST /api/admin/accept-remote`. It can also be
  `{"kind": "config_error", "message": "…"}` when `rackbook.yml` no longer
  loads (writes `503 config_error`, everyone is capped at viewer); a rewritten
  history takes precedence.
- `list` empty → the client shows all schema properties in order.
- `facets[].match`: `exact` (values = distinct field values, computed by
  the client when `values` is empty), `contains` (a record matches a value if
  the field contains it as a substring), `prefix`.
- `refs`: this collection's fields that reference another collection.
- `backrefs`: `[{"collection": "addresses", "field": "device"}]` on
  `devices` — other collections whose field references this one.

### `GET /api/c/{collection}`

```json
{"records": [{"id": "…", "hash": "…", "data": {"device": "…", "service": "…"}}]}
```

Records in file order. No server-side paging or filtering.

### `GET /api/c/{collection}/{id}`

```json
{
  "id": "…", "hash": "…", "data": {…},
  "backrefs": {"addresses": [{"id": "…", "hash": "…", "data": {…}}], "services": […]}
}
```

`backrefs` includes, per back-referencing collection, the records whose
reference field equals this record's referenced field (for `services`, rows
with `device: all` are included too, because `all` is an allowed literal that
applies to every device). 404 `{"error":"not_found"}` if missing.

### `GET /api/check`

```json
{"ok": false, "errors": [
  {"collection": "services", "id": "x/SSH", "path": "/device", "rule": "ref",
   "message": "unknown devices.name \"x\""}
]}
```

`rule` ∈ `yaml`, `schema`, `unique`, `ref`, `same_set`, `config`.
`path` is a JSON pointer inside the record (may be empty).

### `GET /api/history?limit=20[&collection=c[&id=<record id>]]`

```json
{"commits": [{"hash": "abc1234", "author": "a", "email": "a@example.com",
  "date": "2026-11-17T12:00:00Z", "subject": "ledger(services): edit x/SSH"}]}
```

`collection` limits to commits touching that collection's file. With `id` too
(needs `collection`, else 400) the list is that record's history: the commits
carrying the trailer `Record: <collection>/<id>`, falling back to the
collection file's history when none does. Empty list when the data directory
is not a Git checkout.

## Write

All writes: `403 {"error":"read_only"}` in read-only mode and
`403 {"error":"forbidden"}` when the caller's role may not do it (creating and
editing need `editor`, deleting needs `editor`); any request from an
identity without a role gets `403 {"error":"no_role"}`; `422 {"error":"invalid","errors":[…check errors…]}` when the result
would not validate (errors as in `/api/check`, limited to the ones the write
introduced); `409 {"error":"conflict","current":{id,hash,data}|null}` when the
record changed since `hash` (or a record with the new id already exists, or
it was deleted); `415 {"error":"unsupported_media_type"}` when POST/PUT is not
`application/json`; `403 {"error":"cross_site"}` for cross-site requests;
`503 {"error":"history_rewritten","lastGood":"…","remote":"…"}` while the
remote's history is rewritten (full commit hashes; see `alert` above);
`503 {"error":"repo_dirty"|"repo_diverged"}` when the server's clone has local
changes or unpushed commits (an administrator must fix the clone). Other
failures are `500 {"error":"internal","message":"…","requestId":"…"}`; the
details are only in the server log. Success responses carry `commit` (short hash, or `""` when
the server runs without Git).

### `POST /api/c/{collection}`

Body `{"data": {…}}` → `201 {"id","hash","data","commit"}`.

### `PUT /api/c/{collection}/{id}`

Body `{"data": {…}, "hash": "<base hash>"}` → `200 {"id","hash","data","commit"}`.
Changing key fields changes the id (rename).

### `DELETE /api/c/{collection}/{id}?hash=<base hash>`

→ `200 {"commit": "…"}`.

### `POST /api/admin/accept-remote`

Admin only (`403 forbidden` otherwise). Body `{"commit": "<hash>"}`, the
current tip of the remote branch as shown in `alert.remote` (at least 7 hex
characters) → `200 {"ok": true, "lastGood": "<full hash>"}`. The server moves
its clone to that commit and records it as the new base, which clears `alert`.
`409 {"error":"no_alert"}` when no rewrite is active, `409 not_remote_tip` when
the commit is not the tip after a fresh fetch, `409 local_commits` when the
clone has commits that exist nowhere else, `400` without a commit, `503
repo_dirty` if the clone has local changes, `403 read_only` in `--read-only`
mode. A refused request changes nothing.

## Exports

- `GET /export.md` — Markdown (`text/markdown; charset=utf-8`)
- `GET /export.json` — `{"title", "collections": {name: [data…]}, "notes": […]}`
- `GET /llms.txt`, `GET /llms-full.txt` — `text/plain; charset=utf-8`

## MCP

`POST /mcp` (streamable HTTP) — same tools as `rackbook mcp` on stdio.

## Static console

Every other `GET` serves the embedded console (`index.html` for unknown paths,
so client-side routes work).

## Data types (administrators only)

All answers are 403 for anyone below the admin role. Design: `docs/design-v0.2.md` section 3.

| Request | Answer |
|---|---|
| `GET /api/types` | `{types: [{name, title, group, icon, file, path, schemaFile, count, fields, problems}], fieldTypes, formats, dataDir, schemaDir}` |
| `GET /api/types/{name}` | `{type, incoming}`: the collection as the console edits it (fields with console type and options, key, label, list, facets, multi-field unique rules, read-only extras and same_set rules) and the collections that reference it |
| `POST /api/types/{name}/plan` | the dry run. Body `{type, migrations}`; a name that does not exist plans a creation, `{delete: true}` plans the removal. Answer: `{clean, changed, subject, files: [{path, status, diff}], invalid, dangling, other, backrefs, migrations, refusals}` |
| `POST /api/types` | create from `{type}`: one commit with `rackbook.yml`, `schemas/<name>.json` and the empty data file. 201 |
| `PUT /api/types/{name}` | change from `{type, migrations}`: one commit. 422 `refused` with the plan when it is not clean |
| `DELETE /api/types/{name}` | remove an empty, unreferenced collection (its data file stays). 422 `refused` otherwise |

Migrations: `{kind: "remove-field", field}` deletes the field from the records that have it;
`{kind: "fill-default", field, value?}` gives a new required field a value (the field default when `value` is
omitted) in the records that lack it. The plan lists what is on offer (`migrations`) and what it refused
(`refusals`: rename, layout, narrowing, shared-schema, field-in-use, not-empty, referenced, ...).

`DELETE /api/c/{collection}/{id}` answers 409 `referenced` with `references: [{collection, id, field}]` when other
records point at the record; `?clearReferences=true` removes those references in the same commit.
