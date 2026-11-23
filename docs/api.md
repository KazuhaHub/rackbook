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
           "canEdit": true, "canAdmin": false, "locale": "en-US"},
  "locale": "zh-CN",
  "defaultLocale": "zh-CN",
  "i18n": {"en-US": {"title": "Example network ledger", "description": "…"}},
  "alert": {"kind": "history_rewritten", "lastGood": "<40 hex>", "remote": "<40 hex>"},
  "collections": [
    {
      "name": "services",
      "title": "服务端口",
      "description": "…",
      "group": "",
      "i18n": {"en-US": {"title": "Services", "description": "…", "group": "…"}},
      "key": ["device", "service"],
      "label": "",
      "list": ["device", "service", "port", "exposure", "managed"],
      "facets": [
        {"field": "device", "match": "exact", "values": []},
        {"field": "exposure", "match": "contains", "values": ["公网", "Tailscale"]}
      ],
      "schema": { "…JSON Schema object…": true },
      "refs": [{"field": "device", "to": "devices", "toField": "name", "allow": ["all"]}],
      "backrefs": [{"collection": "addresses", "field": "device", "title": "地址",
                    "i18n": {"en-US": {"title": "Addresses"}}}],
      "notes": [{"title": "…", "text": "…", "i18n": {"en-US": {"title": "…"}}}],
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

`locale` is the console language for this request: the best match of the
`Accept-Language` header among `zh-CN`, `zh-TW` and `en-US` (`zh-HK`, `zh-Hant` →
`zh-TW`; `zh`, `zh-Hans` → `zh-CN`; any `en-*` → `en-US`), or `defaultLocale` when
nothing matches. `defaultLocale` is `i18n.default` of `rackbook.yml` (`zh-CN` when
unset). `user.locale` is the language the person saved with
`PUT /api/account/preferences`; it is absent until they choose one, and the console
prefers it over `locale`. The response carries `Vary: Accept-Language` and
`Cache-Control: no-store`.

`i18n` carries the configured text in the other languages as raw maps (`{<locale>: {key: text}}`),
so the console resolves by its current language and a language switch needs no new request. The
top level has `title` and `description`, a collection `title`, `description` and `group`, a note
`title`, and a back-reference entry `title` (from `backref_title`). A key is left out when it has no
translation, and the whole `i18n` is left out when there is none. `title`, `description`, `group`
stay the standard text, in `defaultLocale`. A language's text is its entry, else the standard
text. `schema` is the raw schema file, so `x-rackbook-i18n`, `x-rackbook-enum-icons` and `oneOf`
labels reach the console as written (see the README, "Ledger text in several languages"). The
check API's messages are not translated.

### `PUT /api/account/preferences`

`{"locale": "en-US"}` → `200 {"locale": "en-US"}`. The value is normalized the same
way as above (`zh-HK` is stored as `zh-TW`); `{"locale": ""}` clears the preference and
answers `200 {"locale": ""}`. It is stored per identity in `<state-dir>/preferences.json`
(memory only without `--state-dir`), so it follows the person across browsers.

- `400 invalid_locale` for a value that is not supported (nothing is stored), `400 bad_request`
  for a body without `locale`.
- `409 no_identity` when the server does not know who is calling (`--auth none` without
  `--editor`: everyone shares one anonymous identity, which gets no server-side preference;
  the console then keeps the choice in the browser).
- `403 forbidden` for API tokens, OAuth access tokens and MCPHub credentials.
- Same-origin and `Content-Type: application/json` are required, as for every write.
- It works with `--read-only`: that mode protects the ledger, and a preference is
  Rackbook's own state outside the data repository.
- Works in every login mode (`oidc`, passkey sessions, `cloudflare-access`, and `none`
  with `--editor`). The console calls it only for `oidc`, passkey and `cloudflare-access`:
  under `none` everyone shares one identity, so it keeps the choice in the browser.

- `user` is always present. `role` is `admin`, `editor` or `viewer` (the role
  after any scope narrowing, from `auth.roles` evaluated on this request).
  `authMethod` is `none`, `cloudflare-access`, `oidc`, `passkey`, `mcphub` or
  `token`. `canEdit` is `role` ≥ editor and the server is not read-only;
  `canAdmin` is `role` = admin. `auditor: true` appears only for a person (or the token or grant
  of a person) on `auth.auditors`: a capability next to the role, not part of it (an admin has no
  `auditor` unless listed; an auditor with no role has `role` = `viewer`, the floor). `canInfra: true`
  appears for an infra administrator or an infra auditor, and `canInfraWrite: true` only for an
  administrator when the infra editors are on; an infra auditor has `infraAuditor: true` instead (see Infra, below). `id` (lowercased identity), `email` and `name`
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

Each error also carries `keyword` (what failed) and, for the keywords below,
`params` (the values its message is made of), so a client can word it in the
reader's language. `message` stays the English text and is the fallback: show
it for a keyword you do not know or when a param you need is missing.

```json
{"collection": "devices", "id": "gw", "path": "/ipv4_type", "rule": "schema",
 "message": "\"静态\" is not allowed; use code \"static\"",
 "keyword": "enum", "params": {"value": "静态", "use": "static"}}
```

| `keyword` | `params` |
|---|---|
| `type` | `want` (list of types), `got` |
| `required` | `missing` (field names; `path` is the object that lacks them) |
| `dependentRequired`, `dependencies` | `property`, `missing` |
| `enum` (also an enum written as `oneOf` of `const`s) | `allowed` (every code); for a field's own choices also `value`, and `use` instead of `allowed` when the value is one of the labels or a code in other letters (the code to write) |
| `const` | `want` |
| `format` | `value`, `format` |
| `pattern` | `value`, `pattern` |
| `minLength`, `maxLength`, `minItems`, `maxItems`, `minProperties`, `maxProperties` | `limit`, `got` |
| `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `multipleOf` | `limit`, `value` (numbers) |
| `uniqueItems` | `first`, `second` (indexes of two equal items) |
| `additionalProperties` | `properties` (the fields that are not allowed) |
| `unique` | `fields`, `values`, `key` (true when the uniqueness is the collection's key) |
| `ref` | `value`, `target` (`collection.field`), and the rule's own text: `ruleMessage` (rackbook.yml `message`), `ruleMessageI18n` (`{locale: message}`) when set |
| `same_set` | `value`, `side` (`left`: in the collection but not in the file; `right`: the other way), `left` (`collection.field`), `right` (`file path`), `ruleMessage`, `ruleMessageI18n` |

Other schema keywords (`contains`, `propertyNames`, …) carry `keyword` without
`params`; a failed `not` or `false` schema, and `yaml`, `config` and `secret`
errors, carry neither. The same shape is
used wherever check errors appear: the `422 invalid` write error, the type
editor's plan (`invalid`, `dangling`, `other`) and the MCP tools.
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

### Record history, restore and deleted records

Described in the README, section *Record history, restore and deleted records*:
`GET /api/c/{collection}/{id}/history`, `GET /api/c/{collection}/{id}/history/{commit}`,
`POST /api/c/{collection}/{id}/restore` (`{"commit", "hash", "confirm_not_secret"}`; `409 restore_needs_edit`
carries the old content) and `GET /api/c/{collection}/deleted`. Reading is open to every role; restoring has the
gates of `PUT`.

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

- `GET /api/admin/tokens` → `{"tokens": [{name, prefix, scope, collections?, actions?, writeMode?, createdBy, created, expires?, revoked?, status: active|revoked|expired, lastUsed?, creatorRole, creatorAuditor?, module?, warnings: [creator_no_role|limited_by_creator|push_needs_admin]}], "mcpUrl"}`; `module` names the module (rackbook.yml `modules:`) that uses the token. `creatorAuditor: true` says the creator is on `auth.auditors` now; the token then carries the capability (`user.auditor` in its `/api/meta`) for as long as that holds, but it cannot reach the activity or audit routes (it is limited to the paths below).
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
  "name": string, "logo": bool, "locale": string, "defaultLocale": string}`. `locale` is
  the `Accept-Language` match (see `GET /api/meta`) and `defaultLocale` is `i18n.default`;
  the response has `Vary: Accept-Language` and `Cache-Control: no-store`. `label` is `auth.oidc.label` (empty when unset),
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

- `GET /api/account` → `{"id", "name", "email", "role", "auditor", "authMethod", "passkeysEnabled",
  "canEnrol", "enrolUntil", "locale"?, "passkeys": [{"id", "name", "created"}], "passkeyError"?}`.
- `POST /api/account/passkeys/begin` `{"name": "MacBook"}` → `{"ceremony", "options": <creation options>}`;
  `POST /api/account/passkeys/finish?ceremony=<id>` with the attestation JSON →
  `201 {"passkeys": […]}`. `403 recent_login_required` unless the session's OIDC
  login is at most 10 minutes old, `403 read_only`. Each add is a Git commit.
- With a passkey session, an unreadable or missing `.rackbook/passkeys.yml` (for example during a pull) answers `503 passkey_unavailable` and keeps the cookie; only a file that loads without the credential ends the session. These endpoints refuse API tokens and OAuth access tokens (`403`).
- `DELETE /api/account/passkeys/{id}` → `200 {"ok": true}` (own passkeys only, `404` otherwise).
- Admin: `GET /api/admin/users` → `{"users": [{"id", "name", "method", "role", "auditor"?, "seen",
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

- `GET /oauth/authorize?response_type=code&client_id&redirect_uri&code_challenge&code_challenge_method=S256&resource&scope&state` — checks the request. A client or redirect URI that cannot be trusted gets an HTML error page (in the person's saved console language, else the browser's `Accept-Language`, else `i18n.default`); other errors redirect to the client with `error`, `state` and `iss`; a good request redirects to `/oauth/consent?req=<id>`.
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

Deprecated aliases (removed in v0.8.0, same arguments and results as in v0.2):
`list_collections`, `get_schema`, `list_records`, `get_record`, `search`,
`check`, `list_problems`, `export_markdown`, `record_history`, `create_record`,
`update_record` and `delete_record`. Their results keep the v0.2 shapes
(`{count, records}`, `{matches}`, `{commits}`, and for writes the flat
`{id, hash, data, commit | url, pullRequest}` with the flat
`{"error","message","status",…}` errors), and `update_record` / `delete_record`
take `hash` where the new tools take `expected_hash`. Each description starts
with `Deprecated: use <new>; removed in v0.8.0`, and `ledger_info.deprecated`
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

## Activity and the audit log

README, *Activity*. Every role may call `GET /api/activity` and is limited to the areas it may see; who sees which
area is decided in one place (`canSee` in `internal/api/activity.go`):

| Class | Who |
|---|---|
| ledger commits without `.rackbook/` | every role |
| state (`.rackbook/` commits and their diffs), audit events, the client address (`addr`), the JSONL export | admins and auditors (`auth.auditors`, README *Auditors*) |
| infra commits and infra audit events | infra administrators and infra auditors |

- `GET /api/activity?since&until&identity&area&collection&id&limit&cursor` → `{items, cursor?, areas, audit, scanned}`. `areas` lists what the caller may name; another area is `403 forbidden`.
- `GET /api/activity?format=jsonl` → every match as `application/x-ndjson`. Admins and auditors; `403` for everyone else.
- `GET /api/activity/commit/{area}/{hash}` → `{area, hash, files, moreFiles}`. `ledger`: `.rackbook/` files only for admins and auditors. `infra`: infra administrators and infra auditors (secret files are listed without a patch).
- `GET /api/audit/status` → `{enabled, ok, problems, lastSeq, failed?}`. Admins and auditors.
- `POST /api/audit/ack` `{"through": <seq>}` → the status. **Admins only**: an auditor, an editor, a token and a read-only server are `403`; `409 nothing_to_ack | no_audit_log`; `400` for a bad body.

An auditor never gets a success from any write route (`403`), and the only write open to every signed-in person is
`PUT /api/account/preferences` (their own language).

## Infra (`--infra-repo`)

Only with `--infra-repo` (README, *Infrastructure view and editors*); without it every path below is `404`.
Each call needs a person listed in `--infra-admins`, or, for the read class below, in `--infra-auditors`, who signed in with the OIDC login **under the issuer and
client ID pinned by `--infra-oidc-issuer` and `--infra-oidc-client-id`, with the identity claim and tenant of `--infra-oidc-identity-claim` and `--infra-oidc-tenant`**: any other caller, a token of the
listed person included, gets `403 forbidden`. None is on `/mcp`. `/api/meta` tells such a person with
`user.canInfra: true`, and with `user.canInfraWrite: true` when the editors are on (`--infra-write`, not `--read-only`).

Every route is in one of three classes:

- **read**: infra administrators and infra auditors (`--infra-auditors`, the same pinned provider and OIDC sessions only): `GET /api/infra/hosts`, `…/hosts/{name}`, `…/certs`, `…/iplists`, `…/commits`, `…/groups`, `…/features`, `…/write`, and `GET /api/activity/commit/infra/{hash}`. For an infra auditor `GET /api/infra/write` answers `{enabled: false, secrets: false, fresh: false, auditor: true}` and `canRevert` in the commits is false; `user.infraAuditor: true` marks them in `/api/meta`.
- **secret**: infra administrators only; an infra auditor gets `403 forbidden`: `GET …/hosts/{name}/secrets`, `POST …/secrets/reveal|set|unset|reencrypt`, and `GET …/hosts/{name}/vars` (the editor's raw host_vars file; it sends no content when the hide scan finds anything, and is admin-only as defence in depth). The hide scan is the boundary: a plaintext secret it does not recognise reaches an infra auditor through `GET /api/infra/hosts/{name}` (`vars`) and infra commit diffs, as it reaches infra administrators.
- **write**: infra administrators only (with a recent sign-in): every other `POST` (`…/vars`, `…/features/{feature}`, `…/groups`, `…/commits/{hash}/revert`). A refused attempt is audited.

`hub` is `{state: ok|stale|missing|invalid, error?, time?, ageSeconds}`, the state of the hub's
status file. Anything but `ok` means its data is not current: `report` is left out and `certs`
and `lists` are empty. `repo` is `{branch, head?, syncedAt, error?}`: the commit the clone is at
and the last successful and failed refresh.

| Request | Answer |
|---|---|
| `GET /api/infra/hosts` | `{repo, hub, hosts: [{name, groups, hasVars, features, report?, behind}]}`. `features` are the enabled names under `features:`; `report` is the hub's latest `{appliedCommit?, result, message?, time, receivedAt?, features?}`; `behind` is true when the applied commit is not `repo.head` |
| `GET /api/infra/hosts/{name}` | `{repo, hub, host: {name, groups, hasVars, vars?, features: [{name, enabled, settings?}], hidden}, report?, behind}`. `vars` is the host_vars file as YAML with secret-looking values replaced by `(hidden)` (`hidden` counts them). `404` for a name that is not in the inventory |
| `GET /api/infra/certs` | `{hub, certs: [{name, owner, notAfter?, failing, lastError?}]}` |
| `GET /api/infra/iplists` | `{hub, lists: [{name, version?, entries, warnings}]}` |
| `GET /api/infra/commits` | `{repo, canRevert, commits: [{hash, author, time, subject, files, revertible, reason?, later?}]}`: the last 50, newest first. `reason` (when not revertible): `merge`, `root`, `not_editable`, `later_commits` (`later` lists them), `empty`, `not_on_branch` |

### Editors (`--infra-write`)

Each write is one commit on the followed branch (README, *Editing the infra repository*). A write needs
the person above **and** a sign-in no older than `--infra-write-max-age`; otherwise `403`
`{"error": "reauth_required", "maxAgeSeconds": 43200}` and the console offers a new sign-in. With the
editors off or on a `--read-only` server a write is `403 read_only`. Writes are `POST` with
`Content-Type: application/json` from the console's own origin. Every body may carry `"preview": true`: the
answer is then `200` with what would happen and nothing is committed (a preview needs the same
sign-in). `base` is the object ID the `GET` returned for the file; a file that changed since is a conflict.

| Request | Answer |
|---|---|
| `GET /api/infra/write` | `{enabled, secrets, fresh, signedInAt?, maxAgeSeconds}`; `secrets` is true when `--sops-age-key-file` is set |
| `GET /api/infra/features` | `{features: [{name, description?, type?, settings: [{name, type: string\|int\|bool\|enum, description?, enum?, default?, required?, requiredWhen?, secret?, pattern?, min?, max?}]}], invalid: [name]}` |
| `GET /api/infra/hosts/{name}/vars` | `{path, exists, base, content, hidden}`. A file with secret-looking values (`hidden > 0`) comes without `content` |
| `POST /api/infra/hosts/{name}/vars` | `{base, content, preview?, confirmSecretScan?}`: replaces the file. Answer `{commit?, diffs: [{path, status, diff}], issues, blocked}` |
| `POST /api/infra/hosts/{name}/features/{feature}` | `{base, enabled, settings: {name: value}, preview?, confirmSecretScan?}`: `enabled: false` removes `features.<feature>`; otherwise the settings listed (empty or omitted = default) replace those of the feature and nothing else changes. A `secret: true` setting with a non-empty value is stored in the host's SOPS file under `feature_<feature>_<setting>` in the same commit (empty or omitted = keep it; `secretsBase` optionally names the object ID of the SOPS file as the editor saw it); `422 invalid` `feature.secret_unavailable` without `--sops-age-key-file`, `feature.bad_value` for a value its definition refuses. `base` is the one of the host's `vars` |
| `GET /api/infra/groups` | `{base, membership: {groups, hosts, direct: {host: [group]}}}`: who `inventory/hosts.yml` lists directly in each group of `all.children` |
| `POST /api/infra/groups` | `{base, changes: [{host, group, member}], preview?}` |
| `POST /api/infra/commits/{hash}/revert` | `{preview?}`: commits the files that commit touched back to how they were before it |

Errors of a write: `409 conflict` `{reason: changed|later_commits, files, later, diffs}` (diffs: the
current file against the edit); `409 revert_refused` `{reason}`; `409 busy` (the branch moved on three
attempts); `422 invalid` `{issues: [{code, severity: error|confirm|warning, file?, path?, params?, message}]}`
(the checks refused it: `code` and `params` are translated by the console, `message` is English);
`422 no_change`; `422 edit_failed` (the change cannot be made to the file); `403 forbidden` for
anyone else. Issues with severity `confirm` (a heuristic secret finding) are let through when
`confirmSecretScan` is true. Issue codes: `yaml.invalid`, `yaml.multi_document`, `yaml.not_mapping`,
`yaml.duplicate_key`, `inventory.missing`, `inventory.shape`, `inventory.not_managed`,
`inventory.no_host_vars`, `inventory.no_secrets`, `inventory.agent_missing`, `inventory.agent_extra`, `yaml.anchor`, `yaml.tag`, `vars.template`, `vars.ansible_key`,
`feature.unknown`, `feature.not_mapping`, `feature.settings_not_mapping`, `feature.unknown_setting`,
`feature.secret_in_vars`, `feature.secret_unavailable`, `feature.hidden_value`, `feature.bad_value`,
`feature.missing_required`, `secret.found`, `secrets.invalid`, `secrets.no_metadata`, `secrets.not_encrypted`,
`secrets.recipients`, `secrets.no_rule`.

### Secrets (`--sops-age-key-file`)

The secrets of a host's `secrets/<host>.sops.yaml` (README, *Editing secrets*). Same callers as the editors. Without
`--sops-age-key-file` every call but the `GET` is `403 secrets_off`. Reveal, set and unset also need a
sign-in no older than `--infra-write-max-age` (`403 reauth_required`); set and unset need the editors on (`403 read_only`).
A value is never in a listing, a diff, an audit entry or a log; only a successful reveal returns it.

| Request | Answer |
|---|---|
| `GET /api/infra/hosts/{name}/secrets` | `{enabled, canWrite, publicKey, file: {host, path, exists, base, keys: [{name, editable}], recipients, rule, canDecrypt, lastModified?, problem?}}`. Read from the YAML without decrypting. `recipients` are the age recipients of the file, `rule` those of its creation rule in `.sops.yaml` (`null` = no rule), `canDecrypt` whether Rackbook's key is among them, `publicKey` is Rackbook's own age public key (to add as a recipient). `editable` is false for a nested value or a name the editor does not accept. `404` for a host not in the inventory; `422 edit_failed` for a host that is not managed, is named `admin`, or has no rule of its own (`^secrets/<host>\.sops\.yaml$`) in `.sops.yaml`. Without `--sops-age-key-file`: `{enabled: false}` |
| `POST /api/infra/hosts/{name}/secrets/reveal` | `{key}` → `{key, value}` with `Cache-Control: no-store`. `404 no_such_key` (also for a name outside `^[a-z0-9_-]+$`), `429 rate_limited` after 10 a minute, 30 an hour or 100 a day per person, counted in `--state-dir` (`Retry-After`; audited with the limit in `detail`, and logged as a warning), `403 read_only` on a `--read-only` server. The value is exactly the stored bytes, `422 edit_failed` when Rackbook's key is not a recipient of the file. Audited as `infra(secrets/<host>): reveal <key>` with outcome `revealed`, `reveal_failed`, `no_such_key` or `rate_limited` |
| `POST /api/infra/hosts/{name}/secrets/set` | `{base, key, value}`: sets or replaces one key (creates the file from its `.sops.yaml` rule when the host has none; `base` is `""` then). One commit `infra(secrets/<host>): set <key>`; answer `{commit, diffs, issues}` (the diff lists key names only). Values are non-empty UTF-8 text of at most 16 KiB, line breaks kept exactly (a PEM block with BEGIN and END on one line is refused); key names `^[a-z0-9_-]{1,128}$`, not `sops`, not ending in `_unencrypted` (`422 edit_failed`) |
| `POST /api/infra/hosts/{name}/secrets/unset` | `{base, key}`: deletes one key, one commit `infra(secrets/<host>): delete <key>` |

The checks after an edit refuse (`422 invalid`) a SOPS file that is not fully encrypted or whose recipients differ from its
creation rule: `secrets.invalid`, `secrets.no_metadata`, `secrets.not_encrypted` (`params.name`), `secrets.recipients`,
`secrets.no_rule`. Conflicts and `409 busy` are as for the other editors.

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

Shapes of `type` (the console's view of a collection), beyond the fields named above:

- `type.i18n`: `{<locale>: {title?, description?, group?}}`, the collection's `i18n` entry in `rackbook.yml`.
- `field.i18n`: `{<locale>: {title?, description?}}`, the property's `x-rackbook-i18n` (the standard `title` and
  `description` are in the default language).
- Leaving `type.i18n`, `field.i18n` or `field.ref.i18n` out of a request keeps what is stored; `{}` clears it.
  (Enum `labels` are part of the items and are replaced with them.)
- `field.enum[]`: `{value, color?, icon?, label?, labels?: {<locale>: text}}`. `value` is the stored code, `color` goes to
  `x-rackbook-enum-colors`, `icon` (a lucide name in kebab-case) to `x-rackbook-enum-icons`, `label` is the
  default-language label (the `oneOf` title) and `labels` the other languages (`x-rackbook-i18n.<locale>.enum`).
  When any item has a `label` or `labels` the field is written as `oneOf` (`{const, title?}` entries), otherwise as a
  plain `enum`; the other keyword is removed.
- `field.ref.i18n`: `{<locale>: {message?, backref_title?}}`, the translations of the reference rule.
- `fieldTypes` has `country` and `subdivision` after `hostname`; `formats` lists their formats too.

A plan is refused (`refusals`, code `invalid`) for an unsupported language, a key a block does not take
(`field.i18n` has no `enum`; give enum labels on the items), an empty enum code, and an icon name that is not
lowercase letters, digits and single hyphens (at most 64 characters), a label used for two codes of a field in one
language or equal to another code of the field, and any translation sent for a field whose stored `x-rackbook-i18n` the
console cannot read (fix it in the schema file). Empty text is dropped, not refused. Keys the console does not know
inside an existing `x-rackbook-i18n` language (and languages it does not have) are kept.

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
