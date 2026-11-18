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
identity without a role gets `403 {"error":"no_role"}`; `422 {"error":"secret_detected","findings":[…]}` when a value looks like a secret (see below); `422 {"error":"invalid","errors":[…check errors…]}` when the result
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
the server runs without Git; the pull request URL with `"pullRequest": true`
in pr mode and for writes by API tokens). `503 {"error":"pull_request_unavailable"}`
when a write must be a pull request but the server has no remote or no
`RACKBOOK_GITHUB_TOKEN`. With an API token (`Authorization: Bearer rbk_…`),
`403 forbidden` also means the token's collections/actions do not allow it.

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

### API tokens (admin)

Admin only, and never with a token (`403 forbidden`); `404` unless token support
is on (it is in `rackbook serve`).

- `GET /api/admin/tokens` → `{"tokens": [{name, prefix, scope, collections?, actions?, writeMode?, createdBy, created, expires?, revoked?, status: active|revoked|expired, lastUsed?, creatorRole, warnings: [creator_no_role|limited_by_creator|push_needs_admin]}], "mcpUrl"}`.
- `POST /api/admin/tokens` `{"name", "scope": "read"|"write", "collections": [], "actions": ["create","update","delete"], "writeMode": ""|"pr"|"push", "expiresDays": 0}` → `201 {"token", "secret", "snippet", "claudeCode", "commit", "pullRequest"}`. The secret is shown only here. `400` for invalid input, `409 exists` for a taken name.
- `DELETE /api/admin/tokens/{name}` → `200 {"ok", "commit"}`; `404` for an unknown name.

Bearer tokens are accepted on `/mcp`, `/api/c/…`, `/api/meta`, `/api/check`, `/api/history`, `/export.*` and `/llms*` (`403 forbidden` on any other path); `401
invalid_token` (expired, revoked or unknown) and `429 rate_limited` with
`Retry-After` after repeated failures from one address.

## Login (`--auth oidc`)

Only with the built-in login (see the README and design-v0.2.md section 2).
Without a valid session every API request gets `401
{"error":"login_required","message":…,"login":"/auth/login?return=…"}` (plus
`"reason":"expired"` after a timeout); an identity without a role gets `403
{"error":"no_role"}`. Console pages redirect to `/auth/login` instead.

Public endpoints (no session):

- `GET /auth/login[?return=<path>][&error=<code>]` — the console's login page
  (`error`: `no_role`, `tenant` (both served with status 403), `idp_error`,
  `idp_unavailable`, `expired`, `bad_callback`, `claims`, `logged_out`). With a
  valid session and no `error` it redirects to `return`.
- `GET /auth/config` → `{"oidc": true, "provider": "microsoft"|"oidc", "passkeys": bool}`.
- `GET /auth/oidc/start[?return=<path>]` — redirects to the IdP and sets the
  `__Host-rackbook_login` binding cookie. `return` must be a same-origin path.
- `GET /auth/oidc/callback` — completes the login; always redirects (to `return`
  on success, else to `/auth/login?error=<code>`).
- `POST /auth/logout` (same-origin only) → `200 {"login": "/auth/login?error=logged_out"}`
  when `Accept: application/json`, else `303`.
- `POST /auth/passkey/begin` → `{"ceremony": "<id>", "options": <WebAuthn request options>}`;
  `POST /auth/passkey/finish?ceremony=<id>[&return=<path>]` with the assertion JSON →
  `200 {"return": "<path>"}` and a session, `401 passkey_failed`, `403 no_role`,
  `503 passkey_unavailable`. Only with `auth.passkeys`.

With a session:

- `GET /api/account` → `{"id", "name", "email", "role", "authMethod", "passkeysEnabled",
  "canEnrol", "enrolUntil", "passkeys": [{"id", "name", "created"}], "passkeyError"?}`.
- `POST /api/account/passkeys/begin` `{"name": "MacBook"}` → `{"ceremony", "options": <creation options>}`;
  `POST /api/account/passkeys/finish?ceremony=<id>` with the attestation JSON →
  `201 {"passkeys": […]}`. `403 recent_login_required` unless the session's OIDC
  login is at most 10 minutes old, `403 read_only`. Each add is a Git commit.
- With a passkey session, an unreadable or missing `.rackbook/passkeys.yml` (for example during a pull) answers `503 passkey_unavailable` and keeps the cookie; only a file that loads without the credential ends the session. These endpoints refuse API tokens and OAuth access tokens (`403`).
- `DELETE /api/account/passkeys/{id}` → `200 {"ok": true}` (own passkeys only, `404` otherwise).
- Admin: `GET /api/admin/users` → `{"users": [{"id", "name", "method", "role", "seen",
  "firstSeen", "lastSeen", "passkeys"}], "passkeysEnabled"}` (users seen since the
  server started plus users with passkeys; `role` is the effective role, `none` if
  they have none) and `DELETE /api/admin/passkeys/{id}`.

## Exports

- `GET /export.md` — Markdown (`text/markdown; charset=utf-8`)
- `GET /export.json` — `{"title", "collections": {name: [data…]}, "notes": […]}`
- `GET /llms.txt`, `GET /llms-full.txt` — `text/plain; charset=utf-8`

## MCP

`POST /mcp` (streamable HTTP) — the read tools of `rackbook mcp` on stdio, plus
`record_history` and `list_problems`, and (for callers that may write)
`create_record`, `update_record` and `delete_record`. Auth: the console's mode,
an OAuth access token of a trusted issuer (`auth.mcp`, README), or an API token.
`/.well-known/oauth-protected-resource` (RFC 9728, public) describes the
resource; a missing or invalid token gets `401` with `WWW-Authenticate: Bearer
resource_metadata="…"`, a valid token without a role `403` with
`error="insufficient_scope"`. Write tools fail with the API's error codes in a
tool error: `{"error","message","status",…}`; a successful write returns
`{id, hash, data, commit | url, pullRequest}`.

## Static console

Every other `GET` serves the embedded console (`index.html` for unknown paths,
so client-side routes work).

## Data types (administrators only)

All answers are 403 for anyone below the admin role. Design: `docs/design-v0.2.md` section 3.

| Request | Answer |
|---|---|
| `GET /api/types` | `{types: [{name, title, group, icon, file, path, schemaFile, count, fields, problems}], fieldTypes, formats, dataDir, schemaDir}` |
| `GET /api/types/{name}` | `{type, incoming}`: the collection as the console edits it, with `type.version` (a hash of the schema file and the collection's entry; changing or deleting the type needs it) (fields with console type and options, key, label, list, facets, multi-field unique rules, read-only extras and same_set rules) and the collections that reference it |
| `POST /api/types/{name}/plan` | the dry run. Body `{type, migrations}`; a name that does not exist plans a creation, `{delete: true}` plans the removal. Answer: `{clean, changed, subject, files: [{path, status, diff}], invalid, dangling, other, backrefs, migrations, refusals}` |
| `POST /api/types` | create from `{type}`: one commit with `rackbook.yml`, `schemas/<name>.json` and the empty data file. 201 |
| `PUT /api/types/{name}` | change from `{type, migrations}` (the `type` carries the `version` it was read with, or send `version` beside it; 400 without): one commit. 409 `conflict` with `current` when the type changed since; 422 `refused` with the plan when it is not clean. Removing a field that has values is refused unless the `remove-field` migration is chosen |
| `DELETE /api/types/{name}?version=…` | remove an empty, unreferenced collection (its data file stays). 400 without `version`, 409 `conflict` when stale, 422 `refused` otherwise |

Migrations: `{kind: "remove-field", field}` deletes the field from the records that have it;
`{kind: "fill-default", field, value?}` gives a new required field a value (the field default when `value` is
omitted) in the records that lack it. The plan lists what is on offer (`migrations`) and what it refused
(`refusals`: rename, layout, narrowing, shared-schema, field-in-use, not-empty, referenced, ...).

`DELETE /api/c/{collection}/{id}` answers 409 `referenced` with `references: [{collection, id, field}]` when other
records point at the record; `?clearReferences=true` removes those references in the same commit.

## Secret detection

Every write path scans what it is about to write (records, data types, passkey
and token names) and refuses it with

```json
{"error": "secret_detected", "message": "a possible secret was found; nothing was written",
 "findings": [{"rule": "github-token", "collection": "devices", "id": "web-1",
               "path": "/notes", "excerpt": "ghp_…"}]}
```

status `422`. `path` is the JSON pointer of the field (`in: "key"` is added when
the secret is a field name, and `path` is then its map). `excerpt` is at most the
first 4 characters of the match. The MCP write tools return the same body as a
tool error (`isError`), and the CLI exits 1. `GET /api/check` (and `rackbook
check`) report secrets already in the data as errors with `rule: "secret"`, the
same redaction and the message `possible secret (<rule>): <excerpt>`. Passkey
enrolment with a name that is a secret answers the same `422` before the
ceremony starts. Configure it under `secret_scan` in `rackbook.yml`; see the
README.
