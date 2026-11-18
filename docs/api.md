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
  "user": {"email": "a@example.com", "name": "a", "canEdit": true},
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

- `user` is `null` when auth is `none` and no editor identity is configured.
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

### `GET /api/history?limit=20[&collection=c]`

```json
{"commits": [{"hash": "abc1234", "author": "a", "email": "a@example.com",
  "date": "2026-11-17T12:00:00Z", "subject": "ledger(services): edit x/SSH"}]}
```

`collection` limits to commits touching that collection's file. Empty list
when the data directory is not a Git checkout.

## Write

All writes: `403 {"error":"read_only"}` in read-only mode or when the user may
not edit; `422 {"error":"invalid","errors":[…check errors…]}` when the result
would not validate (errors as in `/api/check`, limited to the ones the write
introduced); `409 {"error":"conflict","current":{id,hash,data}|null}` when the
record changed since `hash` (or a record with the new id already exists, or
it was deleted); `415 {"error":"unsupported_media_type"}` when POST/PUT is not
`application/json`; `403 {"error":"cross_site"}` for cross-site requests;
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

## Exports

- `GET /export.md` — Markdown (`text/markdown; charset=utf-8`)
- `GET /export.json` — `{"title", "collections": {name: [data…]}, "notes": […]}`
- `GET /llms.txt`, `GET /llms-full.txt` — `text/plain; charset=utf-8`

## MCP

`POST /mcp` (streamable HTTP) — same tools as `rackbook mcp` on stdio.

## Static console

Every other `GET` serves the embedded console (`index.html` for unknown paths,
so client-side routes work).
