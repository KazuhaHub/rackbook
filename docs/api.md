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
      "count": 12,
      "expiryField": "",
      "revokedField": ""
    }
  ],
  "modules": [
    {"name": "entra", "collection": "credentials",
     "fields": ["kind", "expires", "kid"], "directPush": true}
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
- `branding` is `{"name": string, "logo": bool}`: `branding.name` (empty when unset)
  and whether a custom logo is served at `/branding/logo`.
- `list` empty → the client shows all schema properties in order.
- `facets[].match`: `exact` (values = distinct field values, computed by
  the client when `values` is empty), `contains` (a record matches a value if
  the field contains it as a substring), `prefix`.
- `expiryField` and `revokedField`: the properties marked
  `x-rackbook: {expires: true}` and `{revoked: true}` in the collection's
  schema, or `""` ([modules.md](modules.md), section 1.1).
- `modules`: the `modules:` allow list of `rackbook.yml` (always an array,
  empty without one; token names are never shown).
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

### `GET /api/expiring?days=30[&collection=<name>…][&unknown=true]`

```json
{"today": "2026-11-18", "days": 30,
 "items": [
   {"collection": "credentials", "id": "tls-www", "label": "tls-www",
    "expires": "2026-11-10", "daysLeft": -8, "status": "expired", "source": ""}
 ]}
```

The records of collections with an `expires` mark that are expired or expire
within `days` (default 30, clamped to 0..3650; today is the UTC date; today
counts as `expiring`, 0 days left). `collection` can repeat to limit the
listing. Empty or missing dates and records with a non-empty `revoked` field
are left out; with `unknown=true`, records whose date is not a date (for
example `待补`) are listed too, with `status: "unknown"` and `daysLeft: null`.
`label` is the collection's label field, else the id; `source` is `""` for a
record entered by hand. Sorted by `daysLeft`, unknown last. `400 bad_request`
for a `days` that is not a whole number, `404 not_found` for an unknown
collection. Needs read access; API tokens may call it.

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

Writes with a token listed under `modules:` in `rackbook.yml` follow the
module rules ([modules.md](modules.md), section 2.3): `403 forbidden` for a
write to another collection, any delete, a create whose `source` is not the
module's name, an update of a record whose `source` is not the module's name,
and an update that changes a field outside the module's `fields`. The commit
carries the trailer `Source: <module>`.

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

- `GET /api/admin/tokens` → `{"tokens": [{name, prefix, scope, collections?, actions?, writeMode?, createdBy, created, expires?, revoked?, status: active|revoked|expired, lastUsed?, creatorRole, module?, warnings: [creator_no_role|limited_by_creator|push_needs_admin]}], "mcpUrl"}`; `module` names the module (rackbook.yml `modules:`) that uses the token.
- `POST /api/admin/tokens` `{"name", "scope": "read"|"write", "collections": [], "actions": ["create","update","delete"], "writeMode": ""|"pr"|"push", "expiresDays": 0}` → `201 {"token", "secret", "snippet", "claudeCode", "commit", "pullRequest"}`. The secret is shown only here. `400` for invalid input, `409 exists` for a taken name.
- `DELETE /api/admin/tokens/{name}` → `200 {"ok", "commit"}`; `404` for an unknown name.

Bearer tokens are accepted on `/mcp`, `/api/c/…`, `/api/meta`, `/api/check`, `/api/history`, `/api/expiring`, `/api/modules/…` (only the calls of the modules panel below), `/export.*` and `/llms*` (`403 forbidden` on any other path); `401
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
- `GET /auth/config` → `{"oidc": true, "provider": "oidc", "passkeys": bool, "label": string,
  "name": string, "logo": bool}`. `label` is `auth.oidc.label` (empty when unset),
  `name` is `branding.name` (empty when unset) and `logo` says whether
  `branding.logo` is configured. `provider` is kept for older consoles and is always
  `"oidc"`.
- `GET /branding/logo`, `GET /branding/favicon` — the images of `branding.logo` and
  `branding.favicon` (also public; GET and HEAD only). They carry the exact
  `Content-Type`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-cache`, an
  `ETag` (content hash; `If-None-Match` gets `304`) and
  `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox`.
  Without a configured file `/branding/favicon` serves the console's own favicon and
  `/branding/logo` answers `404` (the console then shows its default mark).
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

## Built-in authorization server

Only with `auth.mcp.builtin_issuer.enabled` (docs/oauth-server.md). `GET /api/meta`
then carries `"oauthServer": true`. Public (no session; the first four answer
cross-origin requests):

- `GET /.well-known/oauth-authorization-server` — RFC 8414 metadata.
- `GET /oauth/jwks` — the public signing key.
- `POST /oauth/register` — RFC 7591 registration, JSON body `{redirect_uris, client_name?, token_endpoint_auth_method?: "none", grant_types?, response_types?}` → `201` (`200` for a repeated registration) `{client_id, client_name, redirect_uris, …}`; `400 invalid_redirect_uri | invalid_client_metadata`, `429` (per client address) or `503` (every stored registration in use), `404` when `dynamic_registration` is off or `allowed_clients` is set.
- `POST /oauth/token` — form body. `grant_type=authorization_code` (`code`, `client_id`, `redirect_uri`, `code_verifier`, optional `resource`) or `grant_type=refresh_token` (`refresh_token`, `client_id`, optional narrower `scope`) → `{access_token, token_type: "Bearer", expires_in: 600, refresh_token, scope}`; errors are RFC 6749 `{error, error_description}` (`invalid_grant`, `invalid_target`, `invalid_scope`, `unsupported_grant_type`, `invalid_client`). Responses are `no-store`.

With a session:

- `GET /oauth/authorize?response_type=code&client_id&redirect_uri&code_challenge&code_challenge_method=S256&resource&scope&state` — checks the request. A client or redirect URI that cannot be trusted gets an HTML error page; other errors redirect to the client with `error`, `state` and `iss`; a good request redirects to `/oauth/consent?req=<id>`.
- `GET /api/oauth/consent?req=<id>` → `{clientName, clientId, redirectUri, redirectHost, scopes, canWrite, user}` (`404` if the request expired or belongs to someone else).
- `POST /api/oauth/consent` `{"req", "approve": true|false}` → `{"redirect": "<client redirect URI with code, state and iss, or error=access_denied>"}`. Same-origin only; the request is decided once.
- `GET /api/account/grants` → `{"grants": [{id, clientId, clientName, scopes, canWrite, created, lastUsed}]}` and `DELETE /api/account/grants/{id}` (own grants; `404` otherwise).
- Admin: `GET /api/admin/grants` (adds `user`, `userName`) and `DELETE /api/admin/grants/{id}`.

Grant endpoints refuse API tokens and OAuth access tokens (`403`). A revoked
grant's access token stops working at once.

## Exports

- `GET /export.md` — Markdown (`text/markdown; charset=utf-8`)
- `GET /export.json` — `{"title", "collections": {name: [data…]}, "notes": […]}`
- `GET /llms.txt`, `GET /llms-full.txt` — `text/plain; charset=utf-8`

## MCP

`POST /mcp` (streamable HTTP) — the tools of `rackbook mcp` on stdio (read
only), plus `history_list` / `history_diff` and, for callers that may write,
`records_create`, `records_update` and `records_delete`. The surface (families,
arguments, result shapes, limits) is specified in `mcp-surface.md`; `ledger_info`
reports what this server offers. Tools: `ledger_info`, `ledger_search`,
`ledger_check`, `ledger_export`, `collections_list`, `collections_describe`,
`records_query`, `records_get`, `records_create`, `records_update`,
`records_delete`, `history_list`, `history_diff`, `expiry_list`; resources
`rackbook://info`, `rackbook://collections`, `rackbook://collections/{collection}`,
`rackbook://records/{collection}/{id}`, `rackbook://export/markdown`,
`rackbook://llms.txt`; prompts `audit_record`, `prepare_change`,
`explain_collection`. Auth: the console's mode,
an OAuth access token of a trusted issuer (`auth.mcp`, README), or an API token.
`/.well-known/oauth-protected-resource` (RFC 9728, public) describes the
resource; a missing or invalid token gets `401` with `WWW-Authenticate: Bearer
resource_metadata="…"` (plus `scope="…"` with the built-in authorization server), a valid token without a role `403` with
`error="insufficient_scope"`. Tools fail with the API's error codes in a tool
error (`isError`) whose `structuredContent` is `{"error","message","details"?}`
(`details` carries `current`, `errors`, `references` or `findings` as the HTTP
body does at top level; a referenced record is `conflict` with
`details.references`). Lists take `cursor` and `limit` and return `next_cursor`
(`""` on the last page). A write returns `{change: {kind: "commit" |
"pull_request", id, url?}, record?, cleared?, message}`; with `dry_run: true` it
returns `{dry_run: {valid, changed, would_be: "direct_push" | "pull_request",
files: [{path, status, diff}], problems: [{error, message, details?}]}, record?}`
and writes nothing. `idempotency_key` makes a retry within 24 hours return the
first result (`replayed: true`).

Deprecated aliases (removed in v0.7.0, same arguments and results as in v0.2):
`list_collections`, `get_schema`, `list_records`, `get_record`, `search`,
`check`, `list_problems`, `export_markdown`, `record_history`, `create_record`,
`update_record` and `delete_record`. Their results keep the v0.2 shapes
(`{count, records}`, `{matches}`, `{commits}`, and for writes the flat
`{id, hash, data, commit | url, pullRequest}` with the flat
`{"error","message","status",…}` errors), and `update_record` / `delete_record`
take `hash` where the new tools take `expected_hash`. Each description starts
with `Deprecated: use <new>; removed in v0.7.0`, and `ledger_info.deprecated`
lists them.

## Static console

Every other `GET` serves the embedded console (`index.html` for unknown paths,
so client-side routes work).

## Modules panel

Design and the rules behind it: [modules.md](modules.md) section 7. Admin calls
need a signed-in administrator and are never answered to a token (`403
forbidden`). A module uses its own token for the three calls marked *module*.
`/api/meta` lists the modules too (`modules: [{name, type?, readOnly, collection, fields, directPush}]`, no token names).

| Request | Who | Answer |
|---|---|---|
| `GET /api/modules` | admin | `{modules: [...], now, writeMode, historyKept}`. Each module: `{name, type, token, tokenStatus: active\|revoked\|expired\|missing, readOnly, collection?, fields, directPush, settings, version, paused, status: ok\|failed\|skipped\|never, lastRun, lastOk, runs, runRequest, schedule: {times, timezone, default}, nextRun, due, keys}`. `settings` holds only the values that are set; `runs` is the last 30, newest first; `nextRun` is the next daily time (null when paused); `due` says it would run at its next hourly check |
| `GET /api/modules/{name}/settings` | module, admin | `{name, type, settings, version, runRequest, lastOk, lastRun, now}`. A module token (or any other non-admin caller) gets `403` for every module name but its own, whether the name exists or not, so names cannot be probed; an administrator gets `404` for an unknown one. `lastOk` is when the last successful run **started** |
| `PUT /api/modules/{name}/settings` | admin | body `{version, settings, confirm_impact?}` (the complete new settings; keys left out are removed; `version` is required). One Git commit: `{name, changed, commit, pullRequest, settings, version}`; nothing is written when nothing changed (`changed: false`). `409 conflict` with `current: {settings, version}` when the settings changed since; `422 refused` (the reason in `message`) for an unknown key or a value that is not valid; `422 confirm_required` with `impact` for a risky change that is not confirmed; `422 no_settings` for a module without a `type`; secret detections as for records; `403 read_only` in `--read-only` mode |
| `POST /api/modules/{name}/preview` | admin | body `{settings}` → `{records: [{id, label, expires, effect: frozen\|maybe_revoked}], risky}`: what the change would do to the module's records; writes nothing |
| `POST /api/modules/{name}/run-request` | admin | stores one pending "run now" request → `{runRequest: {id, requested, by}}`. Asking again returns the same one. `409 paused` while the module is paused |
| `POST /api/modules/{name}/runs` | module | body `{started, finished, status: ok\|failed\|skipped, counts: {created, updated, revoked, sent}, error?, run_request?}` (RFC 3339 times, `finished` more than 24 hours ahead of the server clock is refused; one that is merely ahead (a fast module clock) is accepted and stored exactly as reported, with a log line when more than 10 minutes ahead) → `201 {ok: true}`. Only the module's own token (`403` otherwise, an administrator included); `400` for an invalid body. `error` is cut to 300 characters on one line. A run that carries the pending request's id clears it; consecutive `skipped` runs replace each other. The server keeps the last 30 runs per module in `<state-dir>/modules.json` |
| `GET /api/modules/status` | admin, notify module | `{modules: [{name, type, paused, lastRun}]}`: the last run of every module, for rackbook-notify's digest. `403` for any other token |

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
first 4 characters of the match. The MCP write tools return it as a tool error
(`isError`; the new `records_*` tools carry `findings` in `details`, the
deprecated names return the body above), and the CLI exits 1. `GET /api/check` (and `rackbook
check`) report secrets already in the data as errors with `rule: "secret"`, the
same redaction and the message `possible secret (<rule>): <excerpt>`. Passkey
enrolment with a name that is a secret answers the same `422` before the
ceremony starts. Configure it under `secret_scan` in `rackbook.yml`; see the
README.
