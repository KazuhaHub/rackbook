# Rackbook

Git-native infrastructure ledger: schema-checked YAML as the source of truth,
with a web console, CLI and MCP server for humans and AI.

[中文说明](#中文说明)

Rackbook keeps the facts about your infrastructure — devices, addresses,
service ports, network plans, sites, conventions, to-dos — as plain YAML
files in a Git repository. It gives you:

- **`rackbook check`** — JSON Schema validation of every record plus
  cross-collection rules (unique keys, references, "this set equals that
  inventory group"), all declared in config. Run it in CI.
- **`rackbook serve`** — a web console (search, filter, sort, per-record
  detail pages with everything that references the record in tabs, rows you
  can open with the keyboard, in-place editing of enum / boolean / date cells,
  schema-driven create/edit/delete forms with searchable selects, tags and
  suggestions; see [docs/design.md](docs/design.md) section 6). Every save is a Git commit with the editor's
  identity, pushed to your repository. The server never holds state of its
  own.
- **`rackbook mcp`** — an MCP server so AI agents can read the ledger
  (list, get, search, schema, check).
- **`rackbook export`** — Markdown, `llms.txt` and JSON.
- **`rackbook list/get/add/set/rm`** — scriptable edits from the terminal.

Edits touch only the lines of the record that changed: comments, blank lines
and formatting in your YAML stay exactly as you wrote them, so diffs stay
reviewable.

The console UI is in Simplified Chinese. Field labels come from the `title`
of each schema property, so they are whatever language your schemas use.

## Quick start

```bash
# binary from the releases page, or:
go install github.com/kazuhahub/rackbook/cmd/rackbook@latest   # API + CLI (console not embedded)

git clone https://github.com/KazuhaHub/rackbook && cd rackbook
rackbook check  --config examples/homelab/rackbook.yml
rackbook list   --config examples/homelab/rackbook.yml services --where device=web-hostco-ashburn-va-us-dc
rackbook export --config examples/homelab/rackbook.yml --format markdown
rackbook serve  --config examples/homelab/rackbook.yml --no-git   # http://127.0.0.1:8080
```

With Docker:

```bash
docker run --rm -p 127.0.0.1:8080:8080 \
  -v "$PWD/examples/homelab:/data" ghcr.io/kazuhahub/rackbook:latest \
  serve --listen 0.0.0.0:8080 --config /data/rackbook.yml --no-git --insecure-no-auth
```

Inside a container Rackbook listens on all interfaces, so it refuses to run
without authentication unless you pass `--insecure-no-auth` — only do that for
a local demo published on `127.0.0.1` as above.

`go install` builds without the web console (it is compiled from `web/` by
`make build`); release binaries and images include it.

## Your own ledger

A data repository needs a `rackbook.yml`, one JSON Schema per collection and
your YAML files, in any layout. `examples/homelab/` is a complete template:

```yaml
title: My ledger
collections:
  devices:
    title: Devices
    file: ledger/devices.yml        # a top-level YAML list…
    schema: schemas/device.json
    key: [name]                     # record id + uniqueness
    facets: [category, site]
  tailscale_ranges:
    file: ledger/networks.yml
    path: tailscale                 # …or a list under a key path
    schema: schemas/network-range.json
    key: [range]
rules:
  - ref: {from: services.device, to: devices.name, allow: [all]}
  - same_set:
      left:  {collection: devices, field: name, where: {managed: true}}
      right: {file: inventory/hosts.yml, path: all.children.managed.hosts, take: keys}
write:
  mode: push      # or: pr (opens a GitHub pull request per edit)
  branch: main
```

See [docs/design.md](docs/design.md) for every option and
[docs/api.md](docs/api.md) for the HTTP API.

## Deployment

Rackbook runs on a host you control, in its own clone of the data repository,
and pushes every edit. People sign in with any OpenID Connect identity provider
(Microsoft Entra ID, Keycloak, Authentik, Google, ...); a reverse proxy or
Cloudflare in front provides TLS.

1. **Deploy key.** Create an SSH key and add it to the data repository as a
   deploy key *with write access*. Clone the repository on the server with
   that key into a directory the container can write, e.g. `/srv/rackbook/repo`.
2. **Register the app with your IdP** as a confidential web client. The redirect
   URI is `<base-url>/auth/oidc/callback`, e.g.
   `https://ledger.example.com/auth/oidc/callback`. Note the issuer URL, the
   client ID and the client secret (Entra walkthrough: see
   [Built-in login](#built-in-login-oidc-passkeys)).
3. **Configure `rackbook.yml`** in the data repository: the issuer, the client
   ID and **roles**. Nobody who matches no role gets in.

   ```yaml
   auth:
     mode: oidc
     oidc:
       issuer: https://keycloak.example.com/realms/home
       client_id: rackbook
       identity_claim: email            # must be controlled by the IdP, see below
     roles:
       admin:  [owner@example.com]
       editor: ["*@example.com"]
   ```

   The identity claim (default `preferred_username`) names the person in roles
   and in Git commits, so **it must be controlled by the IdP**, never editable
   by users or by tenants you do not trust: whoever can set it to someone
   else's address becomes that person. `email` is accepted only with
   `email_verified: true`. If your IdP cannot guarantee that, use
   `identity: subject` and match `oidc:<sub>` role entries instead.
4. **Run it.**

   ```yaml
   # compose.yaml
   services:
     rackbook:
       image: ghcr.io/kazuhahub/rackbook:1
       restart: unless-stopped
       command: >
         serve --listen 0.0.0.0:8080 --config /data/repo/rackbook.yml
         --trusted-proxy 172.16.0.0/12
       environment:
         RACKBOOK_AUTH: oidc
         RACKBOOK_BASE_URL: https://ledger.example.com
         RACKBOOK_OIDC_CLIENT_SECRET: ${RACKBOOK_OIDC_CLIENT_SECRET}  # from .env, never the repo
         RACKBOOK_SESSION_KEY: ${RACKBOOK_SESSION_KEY}                # openssl rand -base64 32
         RACKBOOK_COMMITTER: "Rackbook <rackbook@example.com>"
         GIT_SSH_COMMAND: ssh -i /data/deploy_key -o IdentitiesOnly=yes
       volumes:
         - /srv/rackbook:/data
       ports:
         - "127.0.0.1:8080:8080"
   ```

   Point your reverse proxy (Caddy, nginx, Traefik) or Cloudflare Tunnel at
   `127.0.0.1:8080` and terminate TLS there. `RACKBOOK_BASE_URL` is the public
   `https` URL: it is the base of the IdP redirect, the host of the session
   cookies and the passkey relying-party ID, and it is used in `llms.txt`.
   `--trusted-proxy` lists the CIDRs of the proxy as the container sees it, so
   login and token rate limits use the real client address (the
   `CF-Connecting-IP` header) instead of the proxy's. Sessions are signed
   cookies (`RACKBOOK_SESSION_KEY`); the server keeps no state of its own.
5. **Passkeys (optional).** `auth.passkeys: true` lets signed-in users register
   a passkey for later logins; see [Built-in login](#built-in-login-oidc-passkeys).
6. **AI agents.** `/mcp` and `/.well-known/oauth-protected-resource*`
   authenticate with their own bearer tokens (API tokens or OAuth access tokens,
   below); no proxy login is needed in front of them. Or run `rackbook mcp`
   locally against a clone.

### Alternative: Cloudflare Access

Optional. If you would rather have Cloudflare Access authenticate people, set
`auth.mode: cloudflare-access` (or `RACKBOOK_AUTH=cloudflare-access`).

1. In Cloudflare Zero Trust create a self-hosted application for the hostname
   with a policy for the people allowed in. Note your team name
   (`<team>.cloudflareaccess.com`) and the application's **AUD tag**.
2. Run the same compose service with `RACKBOOK_AUTH: cloudflare-access`,
   `RACKBOOK_CF_TEAM` and `RACKBOOK_CF_AUD` instead of the OIDC variables.
   Rackbook verifies the `Cf-Access-Jwt-Assertion` header on every request
   (signature, issuer, audience, expiry), so a request that bypasses Access is
   rejected, and uses the `email` claim as the Git author. Restrict who may edit
   with `auth.editors` or `auth.roles` (below); everyone else Access lets in can read.
3. Access login must not sit in front of the bearer-token endpoints: add an
   Access **Bypass** policy for exactly `/mcp`, `/.well-known/oauth-protected-resource`
   and `/.well-known/oauth-protected-resource/mcp` (the rest stays protected).
   Or give an agent an Access service token and send `CF-Access-Client-Id` /
   `CF-Access-Client-Secret` with its MCP requests.

Rackbook fetches the remote every minute, so changes pushed from elsewhere
appear without a restart. If someone changed the same record in the meantime,
the console shows a conflict instead of overwriting it.

### Roles

```yaml
# rackbook.yml
auth:
  roles:
    admin:  [owner@example.com]
    editor: ["*@example.com", "mcphub:alice"]
    viewer: ["*"]
```

Entries are exact identities, `*@domain`, `mcphub:<username>`, `group:<id>` or
`*` (anyone authenticated), matched case-insensitively; the highest role wins.
Viewers read, editors also create, edit and delete records, admins also do
administrative actions. Without a `roles` block every authenticated identity
is an editor, and `auth.editors` keeps working. Matching folds ASCII case only.
MCPHub users match only `mcphub:<username>` entries (or `mcphub:*`), plus
exact/`*@domain` entries only for a *verified* e-mail address (the token's `email` with `email_verified: true`, or an issuer marked `emails_verified: true`) if `auth.mcp.match_email: true`; a username that merely looks like an address never matches. Roles are read from the
current config on every request, so a change pulled from Git applies at once.
`/api/meta` reports `user.role`, `user.canEdit` and `user.canAdmin`.

### Any OAuth provider: MCP and MCPHub

`/mcp` is an OAuth 2.0 **protected resource** (RFC 9728). Users sign in to an
authorization server you already run (or to Rackbook's own, see
[below](#built-in-authorization-server-no-external-issuer)); Rackbook never sees a
password. It verifies the access tokens the server issues, offline, and applies
the same `auth.roles` as the console. Tokens are
accepted **only on `/mcp`** (never as a console login, never on `/api`).

```yaml
# rackbook.yml
auth:
  roles:
    admin:  [owner@example.com]
    editor: ["mcphub:alice", "oauth:entra:bob@example.com"]
    viewer: ["mcphub:*"]
  mcp:
    resource: https://ledger.example.com/mcp      # the public URL of /mcp
    trusted_issuers:
      - issuer: https://mcp.example.com            # MCPHub
        kind: mcphub                               # alias defaults to "mcphub"
      - issuer: https://login.microsoftonline.com/<tenant-id>/v2.0   # Entra ID
        alias: entra
        audience: api://<application-id>           # Entra's aud; default: resource
        require_typ_at_jwt: false                  # Entra access tokens have typ JWT
        username_claim: preferred_username
      - issuer: https://sso.example.com/realms/ledger                # Keycloak
        alias: keycloak
        username_claim: preferred_username
    scopes: {write: "rackbook:write"}              # default; read: "" = no scope needed
    match_email: false
    direct_push: []                                # see "What agents may write"
```

Per issuer: `algorithms` (default ES256, RS256, PS256, EdDSA; `HS*` and `none` are
a config error), `require_typ_at_jwt` (default true: RFC 9068 `typ: at+jwt`;
with false `typ: JWT` or none is accepted too, but an ID token is still
refused: its `aud` is not the configured audience, it has neither `scope` nor
`scp`, or it has `at_hash`, `c_hash`, `nonce` or `auth_time` and no scope),
`emails_verified` (the issuer only puts verified addresses in `email`), `audience`, `username_claim` (default `sub`), `scope_claim` (default:
`scope`, then `scp`, as a space-separated string or an array), `jwks_url`
(default: `jwks_uri` from the issuer's metadata).

**Verification.** `iss` and `aud` must match exactly (`aud` may be an array
that contains it), `exp` and `sub` are required, `iat`/`nbf` are honoured with 60 s
of skew. The issuer's metadata is fetched from RFC 8414
`/.well-known/oauth-authorization-server`, then OIDC
`/.well-known/openid-configuration` (path rules for issuers with a path like
`/v2.0` or `/realms/x` are followed), over HTTPS (plain HTTP only for
localhost); its `issuer` must equal the configured one. Keys are cached and
refetched at most once a minute, on an unknown `kid`.

**Opaque tokens (RFC 7662 introspection)** are supported per issuer:

```yaml
        introspection: {client_id: rackbook, client_secret_env: RACKBOOK_INTROSPECTION_SECRET}
```

(`endpoint` defaults to `introspection_endpoint` from the metadata.) The token
must be `active` with matching `iss`, `aud`, `exp`; answers are cached for 60 s
(refusals for 10 s, in a bounded cache). An opaque token is sent to one issuer
only: the one whose `introspection.token_prefix` it starts with, or the single
introspecting issuer. With several introspecting issuers every one needs a
`token_prefix`. Failed attempts are rate-limited per client like API tokens.

**Roles.** The user is the `username_claim` (folded to ASCII lower case) and is
matched like a console identity, with entries that name the issuer:
`mcphub:<user>` for `kind: mcphub`, `oauth:<alias>:<user>` for others (`*`
matches anyone of that issuer). Plain e-mail and `*@domain` entries match
these users only with `match_email: true` and a verified e-mail (see above). A scope can only narrow the role:
without the write scope the write tools are refused; viewers never write.
`/mcp` also still accepts a console login (the session cookie) as before.

**Responses.** A missing or invalid token gets `401` with
`WWW-Authenticate: Bearer resource_metadata="https://ledger.example.com/.well-known/oauth-protected-resource"`;
a valid token that grants no role gets `403` with `error="insufficient_scope"`.
The metadata (`/.well-known/oauth-protected-resource`, also under `/mcp`
as RFC 9728 asks) lists the resource, the issuers, the scopes and
`bearer_methods_supported: ["header"]`.

#### MCPHub

1. In MCPHub add the Rackbook URL to `systemConfig.oauthServer.externalResources`:
   `{"resource": "https://ledger.example.com/mcp", "name": "Rackbook", "allowedClients": []}`
   (empty `allowedClients` = any registered client).
2. Set MCPHub's public base URL (`install.baseUrl` / `INSTALL_BASE_URL`); it
   issues tokens only then, because that is the `iss` Rackbook checks.
3. Register Rackbook as an upstream: type `streamable-http`, URL
   `https://ledger.example.com/mcp`, OAuth with `identityMode: personal`, so every
   user calls Rackbook with their own token.
4. Put users in `auth.roles` as `mcphub:<username>`.

**Network.** `/mcp` and `/.well-known/oauth-protected-resource*` validate bearer
tokens themselves, so no proxy login is needed in front of them. MCPHub can call
Rackbook over the public URL, the local network or Tailscale.

#### Entra ID and Keycloak

Entra: register an API (Expose an API, application ID URI `api://<id>`, scope
`rackbook.write`), set `accessTokenAcceptedVersion` to 2 in the manifest, and
use the issuer `https://login.microsoftonline.com/<tenant>/v2.0`, `audience:
api://<id>` and `scopes: {write: rackbook.write}`. Keycloak: use the realm URL
as issuer, add an audience mapper for the resource and a client scope
`rackbook:write`.

#### Connecting clients

Clients discover the authorization server from the protected resource
metadata, so they need only the URL. They must support OAuth for MCP with
dynamic client registration or a pre-registered client at your issuer.

```sh
# Claude Code
claude mcp add --transport http rackbook https://ledger.example.com/mcp
# then /mcp inside Claude Code to sign in

# MCP Inspector
npx @modelcontextprotocol/inspector
#   Transport: Streamable HTTP, URL: https://ledger.example.com/mcp, then "Open Auth Settings"
```

#### Built-in authorization server (no external issuer)

If you have no MCPHub, Entra or Keycloak, Rackbook can be the authorization
server itself. People approve each MCP client once in the console; the client
then keeps working across restarts, until the grant is revoked, the person loses
their role, or it goes 90 days unused. It works with the same `auth.roles` as
the console. How it works, with a plain-language paragraph per mechanism (PKCE,
resource binding, client metadata documents, registration, refresh rotation, the
state file and lock, the signing key): [docs/oauth-server.md](docs/oauth-server.md).

```yaml
# rackbook.yml
auth:
  mcp:
    resource: https://ledger.example.com/mcp
    builtin_issuer: {enabled: true}      # defaults: idle_expiry 90d, refresh_reuse_grace 60s,
                                         # dynamic_registration true, allowed_clients []
```

```sh
rackbook serve --state-dir /var/lib/rackbook --base-url https://ledger.example.com ...
```

`--state-dir` keeps `oauth-grants.json` and the generated signing key
(`oauth-signing-key.pem`, replace it and restart to rotate); `--base-url` is the
issuer. Both are required, and one server at a time may use a state directory
(a lock). Behind Cloudflare Access, bypass `/mcp`,
`/.well-known/oauth-protected-resource*`, `/.well-known/oauth-authorization-server`,
`/oauth/token`, `/oauth/register` and `/oauth/jwks`, and keep the rest behind the
login. Connect a client by giving it the `/mcp` URL; it finds the rest itself
and opens the console's consent page in the browser:

```sh
# Claude Code
claude mcp add --transport http rackbook https://ledger.example.com/mcp
# then /mcp inside Claude Code and choose "Authenticate"

# MCP Inspector
npx @modelcontextprotocol/inspector
#   Transport: Streamable HTTP, URL: https://ledger.example.com/mcp, then "Open Auth Settings"
```

```jsonc
// VS Code: .vscode/mcp.json (or "MCP: Add Server" > HTTP)
{ "servers": { "rackbook": { "type": "http", "url": "https://ledger.example.com/mcp" } } }

// Cursor: ~/.cursor/mcp.json (or the project's .cursor/mcp.json)
{ "mcpServers": { "rackbook": { "url": "https://ledger.example.com/mcp" } } }
```

VS Code and Cursor ask you to sign in when the server starts. The grants are
listed on **My account** (yours) and on the **Authorized clients** admin page
(everyone's), each with a revoke button. Writes through MCP follow the same
rules as before: pull requests by default.

#### What agents may write

#### MCP tools

Tool names are `<family>_<verb>`; the full surface is specified in
`docs/mcp-surface.md`. Start with `ledger_info` (server version, families, who
you are, limits, deprecated tools).

| family | tools |
|---|---|
| `ledger` | `ledger_info`, `ledger_search`, `ledger_check`, `ledger_export` |
| `collections` | `collections_list`, `collections_describe` |
| `records` | `records_query`, `records_get`, `records_create`, `records_update`, `records_delete` |
| `history` | `history_list`, `history_diff` |
| `expiry` | `expiry_list` |

Lists and searches are paged with `cursor` / `next_cursor` (default 50, at most
500 per page, 100 for history). Tool errors are results with `isError` and
`{error, message, details?}`, using the HTTP API's codes. The server also offers
the resources `rackbook://info`, `rackbook://collections`,
`rackbook://collections/{collection}`, `rackbook://records/{collection}/{id}`
(percent-encode the id), `rackbook://export/markdown` and `rackbook://llms.txt`,
and the prompts `audit_record`, `prepare_change` and `explain_collection`.

The v0.2 tool names still work in v0.6.0 as deprecated aliases with their old
arguments and result shapes, and are removed in **v0.7.0**:

| deprecated | use |
|---|---|
| `list_collections` | `collections_list` |
| `get_schema` | `collections_describe` |
| `list_records` | `records_query` |
| `get_record` | `records_get` (`include` replaces the always-on backrefs) |
| `search` | `ledger_search` |
| `check`, `list_problems` | `ledger_check` (one tool for both) |
| `export_markdown` | `ledger_export` |
| `record_history` | `history_list` |
| `create_record`, `update_record`, `delete_record` | `records_create`, `records_update` (`hash` is now `expected_hash`), `records_delete` |

Each alias's description starts with `Deprecated: use <new>; removed in v0.7.0`,
and `ledger_info.deprecated` lists them. `tools/list` shows the write tools only
to callers whose role and scopes allow them.

#### What agents may write

MCP offers `records_create`, `records_update` and `records_delete` (same
validation and conflict rules as the API, `expected_hash` from `records_get`).
Each takes `dry_run: true` (the diff, the validation result and whether it would
be a direct push or a pull request, writing nothing) and an optional
`idempotency_key` (a repeat with the same key and arguments within 24 hours
returns the first result; kept in memory, lost on restart). `records_delete`
takes `clear_references`. A write returns `{change: {kind: commit|pull_request,
id, url?}, record?}`; the read tools `history_list` and `history_diff` show what
changed, and `ledger_check` reports what pauses writes. Writes by an OAuth user or an
API token are **contributor level**: each one opens its own pull request from
`rackbook/mcp/<user>/<yyyymmdd-hhmmss>` (needs `RACKBOOK_GITHUB_TOKEN` with
pull-request permission), and the commit carries `Edited-by: <user>` and
`Edited-via: mcp (MCPHub, client <client_id>)` (`mcp (<alias>, client ...)`
for other issuers). **Deletes are always pull requests.** Create and update can
go straight to the tracked branch only where an admin allows it:

```yaml
auth:
  mcp:
    direct_push:
      - {users: ["mcphub:alice", "oauth:entra:bob@example.com"], collections: [todo]}
      - {roles: [admin], collections: ["*"]}
```

`direct_push` users are method-gated: `mcphub:<user>` matches only MCPHub
users, `oauth:<alias>:<user>` only that issuer's, and a plain e-mail address
only with `match_email` and a verified e-mail; a bare username is a config
error.

If the server is in `history_rewritten`, `config_error` or dirty state, the
tools return the API's errors and writes are paused.

### API tokens

For scripts that do not use an OAuth provider, admins create tokens in the
console (**令牌**) or with `POST /api/admin/tokens`. A token is `rbk_` and 43
random base62 characters, shown once; `.rackbook/tokens.yml` in the data repo keeps
only its SHA-256 (committed as `rackbook(auth): create token <name>` /
`revoke token <name>`). Send it as `Authorization: Bearer rbk_...` to `/api/*`,
`/mcp`, `/export.*` and `/llms*`; it is never a console login.

- Scope `read`, or `write` (create/update/delete, optionally narrowed to
  `collections` and `actions`). A token never exceeds its **creator's current
  role**: if the creator is demoted the token shrinks, if the creator loses
  every role it stops working (the token list warns). Tokens never manage tokens,
  data types or users.
- Writes by a token are pull requests (`rackbook/token/<name>/<time>`) and
  deletes always are. An admin may give a token `write_mode: push` for
  create and update on named collections; it only counts while the creator is
  still an admin. Trailers: `Edited-by: <creator>`, `Edited-via: rackbook
  (token:<name>)` (`mcp (token:<name>)` over `/mcp`).
- API tokens reach only `/mcp`, record and collection reads and writes
  (`/api/c/…`, `/api/meta`, `/api/check`, `/api/history`, `/api/expiring`), exports and
  `/llms*`. Account, passkey, user, token and type endpoints refuse them.
- Failed attempts are rate-limited per client IP (10 per minute, then `429`);
  the console login endpoints use the same client address, IPv6 counted per
  /64. The IP is the connecting address; `CF-Connecting-IP` is believed only
  from proxies listed in `--trusted-proxy` (CIDRs).
- `rackbook token list` and `rackbook token revoke <name> [--commit|--push]`
  work on the file directly. "Last used" is kept in memory, or across restarts
  in `<state-dir>/token-use.json` when `serve --state-dir` (`RACKBOOK_STATE_DIR`)
  names a writable directory outside the data repository (e.g. `/data/state`).

### Rackbook never force-pushes

Rackbook never runs `git push --force`, `--force-with-lease`, a `+refspec`,
`--mirror` or a branch/tag deletion, and never resets anything on the remote.
Every push is a plain fast-forward of one branch; if the remote moved, the edit
is re-applied on the new tip, and if that keeps failing you get a conflict
error. Tests enforce this on every git command the code runs.

It also notices when somebody else rewrites the remote's history. The server
remembers the last remote commit it accepted (`.git/rackbook-last-good` in its
clone). If `origin/<branch>` stops being a descendant of it, Rackbook pauses
all writes (HTTP `503 history_rewritten`, also for the CLI and MCP), keeps
serving the last good commit read-only without touching its clone, logs an
error and shows a red banner in the console. After checking the new history, an
administrator resumes with the banner's confirm button
(`POST /api/admin/accept-remote`) or
`rackbook serve --accept-remote <commit-of-the-current-remote-tip>`; in a plain
clone use `rackbook accept-remote <commit>` (it only records the base and never
touches your work tree). Accepting is refused unless a rewrite is active and the
new tip's config loads. The server's clone must contain only tracked files:
anything else makes writes fail with `repo_dirty` rather than risk overwriting it.

## Built-in login (OIDC, passkeys)

Rackbook logs people in itself with OpenID Connect (the primary way to deploy
it; tested with Microsoft Entra ID, and any standards-compliant IdP such as
Keycloak, Authentik or Google works the same way), optionally with passkeys. It keeps no
database: sessions are signed cookies, roles live in `rackbook.yml`, and passkey
public keys are committed to `.rackbook/passkeys.yml` in the data repository.

```yaml
# rackbook.yml
auth:
  mode: oidc                          # oidc | cloudflare-access | none
  oidc:
    issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
    client_id: 00000000-0000-0000-0000-000000000000
    scopes: [openid, profile, email]
    identity_claim: preferred_username   # default; Entra: the UPN
    identity: claim                      # or subject: iss|sub, matched by oidc:<sub> role entries
    name_claim: name                     # default
    allowed_tenants: [<tenant-id>]       # checked against the tid claim
  passkeys: true                         # or {user_verification: required}
  session: {idle: 12h, absolute: 7d}     # defaults
  roles:
    admin:  [owner@example.com]
    editor: ["*@example.com"]
```

```sh
export RACKBOOK_OIDC_CLIENT_SECRET='…'     # only ever from the environment
export RACKBOOK_SESSION_KEY="$(openssl rand -base64 32)"   # or --session-key-file
rackbook serve --base-url https://ledger.example.com
```

`--auth`, `RACKBOOK_AUTH` and the other flags still override the file, so v0.1
deployments keep working unchanged. `--base-url` is required and must be
`https`: the IdP redirects to `<base-url>/auth/oidc/callback`, session cookies are
`__Host-` cookies, and the passkey relying-party ID is the host of the base URL.
Behind a reverse proxy this is just the public URL. For local testing, serve
HTTPS directly with `--tls-cert` and `--tls-key` and use `https://localhost:<port>`
(see `examples/homelab-login/`); `--oidc-ca-file` adds a private CA for the IdP.

**Entra app registration.**

1. Microsoft Entra admin center, App registrations, New registration. Name it,
   choose "Accounts in this organizational directory only".
2. Redirect URI: platform **Web**, value `https://<your host>/auth/oidc/callback`.
3. Certificates & secrets: new client secret. Its *value* goes into
   `RACKBOOK_OIDC_CLIENT_SECRET`.
4. Token configuration: add the optional ID-token claims **email** and
   **preferred_username**. The `profile` scope delivers `name`, and `tid` is always
   present. (`preferred_username` is the UPN; `email` is often empty, which is
   why it is not the default identity. If you do set `identity_claim: email`, the
   login is refused unless the token has `email_verified: true`, which Entra does
   not send.)
   **The identity claim must be controlled by the identity provider**, never
   editable by users or by tenants you do not trust: whoever can set it to
   another person's address becomes that person. `preferred_username`/`upn` with
   `allowed_tenants`, or a verified `email`, are fine; anything else logs a
   warning at startup. `identity: subject` names logins by `iss|sub`
   (`oidc:<sub>` in `auth.roles`; it matches only such entries, not `*`, domains
   or groups, and does not combine with passkeys). The ID token's `groups`
   claim (bounded to what fits the cookie) serves `group:<id>` entries.
5. Copy the Directory (tenant) ID into the issuer and into `allowed_tenants`, and the
   Application (client) ID into `client_id`.

**What a login does.** `/auth/login` shows the console's login page; "sign in" goes
through `/auth/oidc/start` (state, nonce and PKCE are created and kept in memory for
10 minutes, bound to the browser by the `__Host-rackbook_login` cookie) and returns to
`/auth/oidc/callback`. The callback refuses duplicate or missing parameters, an
unknown, expired or replayed state, a different browser, a wrong `tid`, an identity
claim that is not a string, and an identity with no role (a 403 page; logged). The
identity is the claim lowercased (ASCII only). The browser then goes back to the page
it came from; only same-origin paths are followed, so there is no open redirect.
`POST /auth/logout` ends the Rackbook session only, not the Microsoft one, so the next
login may need no password.

**Sessions.** The cookie `__Host-rackbook_session` (`Secure`, `HttpOnly`,
`SameSite=Lax`) holds `{identity, method, issued, last_seen}` signed with
HMAC-SHA256; the server stores nothing. It expires after `idle` without activity (the
cookie is refreshed at most every 5 minutes) and after `absolute` in any case. It does
not contain the role: roles are evaluated from `auth.roles` on every request, so
removing someone from Git locks them out within one pull interval. Rotating
`RACKBOOK_SESSION_KEY` logs everyone out. API calls without a session get
`401 {"error":"login_required","login":"/auth/login?return=…"}`; console pages redirect
to the login page. Users with no role are refused (a tenant-wide Entra app does not
open the ledger to the whole tenant), so configure `auth.roles`; without it every
authenticated user is an editor, and Rackbook logs a warning at startup.

**Passkeys.** With `passkeys: true` the login page also offers "sign in with a
passkey" (discoverable credentials: no username). Add one on the **My account** page
(**我的账户**), which requires an OIDC login within the last 10 minutes; passkeys
are an alternative to OIDC, not a second factor, and the role is evaluated exactly as
for OIDC, so a passkey never outlives a removal from `roles`; deleting a passkey also
ends the sessions that were opened with it. Credentials are committed
to `.rackbook/passkeys.yml` (`rackbook(auth): add passkey for <id>` /
`remove passkey`, authored by the user) straight to the tracked branch even when
`write.mode` is `pr`. Sign counters are not stored, so there is no clone detection
(synced passkeys report 0 anyway). Admins see users and passkeys on **用户** and can
delete passkeys. `.rackbook/` is not a collection: it is hidden from the console,
exports and MCP, and cannot be configured as a data file. If nobody can log in,
edit `rackbook.yml` or `.rackbook/passkeys.yml` in Git.

Logins, refusals and logouts go to the server log (stdout). Starting a login or a
passkey ceremony is rate limited per client (the first `CF-Connecting-IP` /
`X-Forwarded-For` address when the request comes from a loopback or private proxy).

## Expiry tracking and modules

Rackbook can list what is about to expire (certificates, client secrets, API
tokens, domains, contracts). Design and module contract: [docs/modules.md](docs/modules.md).

- A collection opts in by marking schema properties: `"x-rackbook": {"expires": true}`
  on the date field, and optionally `{"revoked": true}` on a field whose
  non-empty value retires a record. A date is `YYYY-MM-DD` or an RFC 3339
  time; empty means never expires; any other value (for example `待补`) is
  an unknown date, listed only on request.
- `GET /api/expiring?days=30`, the MCP tool `expiry_list` and the console page
  **到期** list the expired and expiring records; `/api/meta` shows each
  collection's `expiryField` and `revokedField`.
- Modules are separate programs (`rackbook-entra` reads Microsoft Entra ID,
  `rackbook-notify` sends reminders) that use only the public API with an API
  token; the server contains no code for any upstream system.
- `rackbook-notify` greets the mail server with this host's name (or
  `smtp.helo`), because some relays offer no STARTTLS to a client that says
  `localhost`, and it never sends mail without STARTTLS.
- The optional `modules:` block in `rackbook.yml` is an allow list: a token
  named there may only create and update records of one collection, every record
  it writes must carry `source: <module name>`, it may only update records
  that already have that source and only the listed `fields`, and it can never
  delete. The server enforces this on every write.
- `direct_push: true` lets that module's creates and updates commit straight to
  the branch instead of opening a pull request per run; it counts only while the
  token's creator is an admin, like a token's `write_mode: push`.

```yaml
# rackbook.yml
modules:
  entra:
    type: entra
    token: entra-sync
    collection: credentials
    fields: [kind, self_signed, purpose, expires, not_before, kid, ids, revoked]
    direct_push: true
```

- Administrators manage the modules in the console (**模块**): last run and
  failures, pause, "run now", and the settings that are safe to edit in a
  browser (send and sync times, thresholds, recipients, excluded apps, record
  naming). Each save is one Git commit that changes `modules.<name>.settings`
  in `rackbook.yml`. The modules ask the server for their settings and report
  every run, so start them **every hour** (a systemd timer with
  `OnCalendar=hourly`); they act only when a configured time has passed. Run
  history is kept in `--state-dir`. See [docs/modules.md](docs/modules.md),
  section 7.

## Branding and the sign-in button

By default the sign-in page says "使用单点登录" and shows the Rackbook mark; it never names
an identity provider. To use your own wording and logo, add two optional blocks to
`rackbook.yml`:

```yaml
branding:
  name: Kazuha Hub              # product name: sign-in page, header, tab title (default: Rackbook)
  logo: branding/logo.svg       # sign-in page and header
  favicon: branding/favicon.svg # browser tab icon (default: the Rackbook icon)
auth:
  oidc:
    label: 使用 Kazuha Hub SSO 登录   # text of the sign-in button
```

Put the image files in your data repository (for example in `branding/`) and give their
paths relative to the folder that holds `rackbook.yml`, like the schema files. A logo is
`.svg` or `.png`; a favicon is `.svg`, `.png` or `.ico`. Each file must be at most 256 KiB,
must really be that type (a PNG starts with the PNG signature, an SVG is XML whose root
element is `<svg>`), and must be inside the repository: absolute paths, `..` and symbolic
links that lead out are refused. A bad file is a config error, reported by `rackbook check`
and when the server loads or pulls the config. The files are read when the config loads
and served from memory at `/branding/logo` and `/branding/favicon` (also before sign-in,
GET only, revalidated with an `ETag`). `examples/homelab-login/` shows all of it.

**Why an SVG logo is safe.** The console only ever shows the logo through an `<img>` tag,
and browsers never run scripts inside an SVG loaded that way. If someone opens the image
address directly, the response is served with its exact content type,
`X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src 'none';
sandbox`, so the page can still not run script or load anything. Only people who can
write to the data repository can change these files.

## Secret scanning

Rackbook runs Git with hooks disabled, so a pre-commit hook in your data
repository (gitleaks and the like) never sees its commits. Without a check of
its own, a password pasted into a record would be committed and pushed into
history. Rackbook therefore scans what it is about to write, before anything
touches the disk or Git. It is on by default, deterministic, and never runs
anything from the data repository.

It covers every write path: records created or updated through the console and
API, the MCP write tools and `rackbook add` / `set`; data type changes (defaults,
examples, constants, enum values, titles and descriptions in schemas, and the
rackbook.yml entry written for the type); the names and labels in the passkey and
token state files (public keys, ids and hashes are exempt); and the edits made
when a delete clears references. Every string in a record is scanned, including
nested values and field names. `rackbook check` and `/api/check` report what is
already in the repository, so CI catches hand-committed secrets.

**In plain words.** Before Rackbook saves anything, it reads the text for
things that look like passwords and keys. If it finds a real key or a known kind
of token (an SSH private key, a GitHub token, a password inside a URL and so
on), it refuses to save, and nothing you type can override that. The rule is one
sentence: **block-tier formats are refused in every string, always; schema
annotations, placeholders and `confirm_not_secret` only silence the confirm
tier.** If it only
*suspects* a password, for example a line like `root密码：...` or a field called
`password`, it stops and asks you to confirm that it is not one; your name is
recorded in the commit when you do. It cannot catch a secret that has no
recognisable shape and no label ("Hunter2Hunter2 is what we use"), so it does not
replace a scanner in CI. If it flags something harmless, either tick the
confirmation, mark a public field (such as an SSH public key) in the schema, or
add an `allow` entry in `rackbook.yml`; the sections below show how.

### Two tiers

| tier | what | what happens |
|---|---|---|
| **block** (deterministic) | key material and known token formats: PEM and OpenSSH private keys (also base64-encoded, as in a kubeconfig `client-key-data`), `AGE-SECRET-KEY`, GitHub, GitLab, npm, Hugging Face, Tailscale, SendGrid, Slack, AWS, Google, Stripe, OpenAI and Anthropic tokens, JWTs, URLs with a password, key-bearing URL query parameters (`?api_key=...`), private JWKs, and your `extra_patterns` | always refused; only the allow list (by value hash) overrides it |
| **confirm** (heuristic) | a keyword assignment in any language, `key:` / `privkey:` plus 32 or more hex characters (`hex-key`: it could as well be a node key, fingerprint or hash), the whole value of a secret-named field, `Bearer` tokens and high-entropy tokens in free text | refused until the editor confirms it is not a secret; `rackbook check` reports it as a warning |

A block-tier refusal is `422 {"error":"secret_detected","findings":[...]}`, an
MCP tool error with the same findings, or exit code 1 from the CLI. A confirm-tier
hit is `422 {"error":"secret_suspected","findings":[...]}`:

- **Console:** the save is held with "这看起来像密钥/密码", and the editor must tick
  "不是密钥" to save.
- **API and MCP:** retry the same request with `"confirm_not_secret": true`. It is
  accepted for editor and admin sessions and for OAuth/MCP identities with write
  rights, but never for a write that becomes a pull request from an API token,
  and never for a block-tier finding.
- **CLI:** repeat the command with `--confirm-not-secret`.
- Every confirmation is recorded as a commit trailer, `Secret-scan:
  confirmed-not-secret by <user> (<rule ids>)`. `rackbook check` leaves out the
  warnings of a record whose last commit carries that trailer, so a confirmed
  value stops warning until the record changes again.
- Data types and state files have no confirmation flow: only block-tier findings
  refuse there, and heuristic ones show up as warnings in `check`.

A finding gives the rule, tier, collection, record id, the JSON pointer of the
field and at most the first 4 characters of the match; never the secret.

### Rules

`private-key`, `private-key-base64`, `age-secret-key`, `github-token`,
`github-pat`, `gitlab-token`, `npm-token`, `huggingface-token`,
`tailscale-key`, `sendgrid-key`, `slack-token`, `aws-access-key-id`,
`google-api-key`, `stripe-live-key`, `openai-api-key`, `azure-account-key`,
`jwt`, `url-credentials`, `url-query-secret`, `private-jwk` (block);
`secret-assignment`, `hex-key`, `bearer-token`, `high-entropy` (confirm). The IDs are stable.

Text is normalised before it is matched: NFKC (so full-width `：` `＝` and
letters match as `:` `=` and ASCII) and zero-width characters removed. The
assignment keywords are `password`, `passwd`, `pwd`, `pass`, `secret`, `token`,
`api key`, `private key`, `passphrase`, `psk`, `密码`, `口令`, `密钥`, `令牌`,
`秘钥`, `凭据`, `凭证`, `授权码`, `パスワード`, `비밀번호` and a few more. The
separators are `:`, `=`, `is`, `was`, `是`, `为`, `為`, `→`, with up to three plain
words in between ("the root password for the db is X"). The value is the next
token when it is at least 8 characters long and is not a placeholder, a path, or
a reference (`op://...`, `vault:...`, `env:NAME`, `${NAME}`, `secrets/x#key`);
after a word separator or in-between words it must also look like a credential
(a digit, a symbol, or inner capitals). A reference is scanned again after its
prefix, so `op://ghp_...` is still caught. High-entropy tokens are free-text
tokens of 20 or more characters with at least three character classes and
Shannon entropy of at least 4.0 bits per character.

```yaml
# rackbook.yml
secret_scan:
  enabled: true                 # default; false logs a startup warning
  extra_patterns:               # your own block-tier rules; group 1, if any, is the secret
    - {id: corp-token, pattern: 'corp_(tok_[a-z0-9]{12,})', description: internal token}
  allow:                        # a known false positive, as precisely as you can
    - rule: secret-assignment
      collection: devices
      field: /notes             # JSON pointer, covers everything below it
      value_sha256: 3b4c...     # sha256 of the matched value (see below)
  disable_rules: [hex-key]
```

An `allow` entry needs a `rule` and at least one of `collection`, `field` or
`value_sha256`; `value_sha256` must come with a `collection` (a value-only entry
would let the same secret in everywhere). A private key is matched and hashed as
the whole `BEGIN` to `END` block. The matched value is the whole match, except for
the keyword rules (the value after the separator), `hex-key` (the text after the
`:` or `=`), `url-credentials` (`user:password`) and extra patterns with a capture
group (group 1); quotes and a trailing `,` or `;` are not part of it, and it is
the normalised text. Compute it with `printf %s 'the value' | shasum -a 256`. An
invalid pattern or an unknown rule ID is a config error.

### Public fields, placeholders and free text

Free text has no exemptions: notes, descriptions and any other unannotated string
are scanned in full, with no "near a fingerprint" or "stored in 1Password"
leniency. The only ways out are:

1. **A schema annotation** on a property that is public by design:

   ```json
   "ssh_key": {"type": "string", "x-rackbook": {"public": "ssh_public_key"}}
   ```

   Kinds: `ssh_public_key` (`ssh-ed25519 AAAA...` and the other OpenSSH public
   key algorithms), `fingerprint` (SHA256 or MD5), `nodekey` (`nodekey:`,
   `machinekey:` or `discokey:` plus 64 hex), `age_recipient` (`age1...`),
   `pem_public_key`, `jwk_public` (no private members; its other members are
   scanned), `hex_id`, `uuid` (a standard UUID, alone or as `<label>=<uuid>`
   such as `entra_app_id=…`, where the label must not be named like a secret)
   and `secret_reference` (`op://...`, `vault:...`,
   `env:NAME`, `${NAME}` or a path without spaces). Only an annotated field whose
   whole value has the strict format of its kind is exempt from the confirm tier;
   any other value in it is scanned as text, and block-tier formats are refused
   in it as anywhere else. On an array, or on its `items`, every item is checked.
   `hex_id` and `fingerprint` cannot tell a 32-byte key from an id, so a field
   named like a secret may only be annotated `secret_reference`; any other kind
   on it is a config error (reported by `check`, refused by a type change).
2. **Exact placeholders** (`待补`, `TBD`, `-`, `***`, `n/a`, `none`, or an empty
   string), matched as the whole value.
3. **The allow list** above.

A field named like a secret (`password`, `passphrase`, `secret_key`, `api_key`,
`client_secret`, `signing_key`, `private_token`, `access_token`, `密码`, anything
ending in `_secret`, `_password` or `_token`, ...) counts its whole value, spaces
included, and so does every string, number, boolean and map key inside it
(`wifi_password: 98765432` is caught), unless it is an exact placeholder or an
annotated `secret_reference` (only `env:NAME` and `${NAME}` are environment
reference shapes; `$HUNTER2` is not special).

### Limits

This is a safety net, not a guarantee. It is pattern based: a natural-language
secret with no keyword at all ("Hunter2Hunter2 is what we use") is out of scope,
and it is no replacement for an entropy-based scanner such as gitleaks or
trufflehog over the whole repository in CI. Known false positives: `api_key=${API_KEY}`
and similar placeholders in free text, `nodekey` / host-key hex in unannotated
fields, public keys in notes, long camel-case identifiers, and `sk-` hostnames;
annotate the field, add an allow entry, or confirm. A record id built from a
secret is shown redacted everywhere (findings, check output, commit subjects,
`Record:` trailers) as 4 characters and 8 hex digits of a hash; the hash only
tells ids apart and is not secure.

## Windows

Release archives for Windows (amd64 and arm64) are zips containing
`rackbook.exe`. The test suite and a smoke test of the built binary run natively
on Windows Server (amd64) and Windows 11 (arm64) for every change, and every
command works there: `check`, `export`, `list`, `get`, `add`, `set`, `rm`,
`token`, `mcp` and `serve` (console, API, MCP, Git-backed writes and pull
requests).

- Git for Windows must be on `PATH` for anything that uses Git (`serve` with a
  repository, `--commit` / `--push`). Rackbook runs Git with
  `core.autocrlf=false` so files are committed byte for byte.
- Put `* text=auto eol=lf` in a `.gitattributes` at the root of your data
  repository (or clone with `core.autocrlf=false`). Otherwise a Windows clone
  checks files out with CRLF and the server reports the clone as modified.
  Note that this attribute normalises line endings on commit: a file that was
  committed with CRLF is stored as LF after its next edit. Use it only for data
  repositories whose files are LF already (the usual case).
- Paths in `rackbook.yml` are relative, with `/` or `\`; drive letters, UNC
  paths, rooted paths and `:` in a name are refused.
- Not exercised on Windows (skipped in the tests, with a message): committing
  symbolic links, and directory permission bits (`chmod`), which Windows does
  not have. The race detector is not available on Windows arm64, so the tests
  there run without `-race`.

## Development

```bash
make build        # web console (npm) + Go binary with the console embedded
make test         # go test ./...
npm --prefix web run dev:mock   # console against a mock API built from the example
```

## Versioning and compatibility

Rackbook follows [Semantic Versioning](https://semver.org/).

- While the version is 0.x, a minor release (0.y → 0.y+1) may contain
  breaking changes.
- From 1.0 on, breaking changes happen only in a major release.

A change is **breaking** if it is incompatible for any of:

- the `rackbook.yml` format;
- the HTTP API;
- MCP tool names, arguments or result shapes (a rename keeps the old name as a
  deprecated alias for one minor release);
- the on-disk data layout.

Every breaking release ships migration notes in its release notes.

Release plan (details in `docs/design-v0.2.md`, "Versioning"):

- **v0.5.0**: the modules panel. Merged to `main`, not tagged yet.
- **v0.6.0**: the built-in authorization server (`docs/oauth-server.md`) and
  the MCP surface (`docs/mcp-surface.md`).
- **v0.6.1** (proposal): GitHub App authentication and record documents. Both
  were planned for v0.6.0 and move to a later version.
- **v0.7.0**: one record per file storage; the deprecated MCP tool names are
  removed.

## Verifying releases

Every release archive, `checksums.txt` and the container image carries a
signed build provenance attestation (GitHub Artifact Attestations), and the
image is also signed with cosign (keyless, by digest). Both are tied to this
repository's release workflow.

```sh
# Release archives (tar.gz, zip) and checksums.txt
gh attestation verify rackbook_0.2.3_linux_amd64.tar.gz --repo KazuhaHub/rackbook \
  --signer-workflow KazuhaHub/rackbook/.github/workflows/release.yml
sha256sum --check --ignore-missing checksums.txt

# Container image: provenance attestation
gh attestation verify oci://ghcr.io/kazuhahub/rackbook:0.2.3 --repo KazuhaHub/rackbook \
  --signer-workflow KazuhaHub/rackbook/.github/workflows/release.yml

# Container image: cosign signature (cosign v3 or later; v2 reports
# "no signatures found" for this signature format)
cosign verify ghcr.io/kazuhahub/rackbook:0.2.3 \
  --certificate-identity-regexp '^https://github\.com/KazuhaHub/rackbook/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Verify by digest (`ghcr.io/kazuhahub/rackbook@sha256:...`) when you pin the
image. A release is published only after the test suite passed natively on
Linux, macOS and Windows (amd64 and arm64 each).

Releases are immutable. GoReleaser creates a **draft** release with every
archive. The image is pushed only after that, and a final job publishes the
draft once the archives and the image are attested and signed. If any step
fails, the release stays a draft (not visible as a release) and can be
re-run. A published release's assets can never change.

## License

[Apache-2.0](LICENSE)

---

## 中文说明

Rackbook 是一个以 Git 为核心的基础设施台账：设备、内网地址、服务端口、网段规划、
站点、端口规范、待办等，以 YAML 文件的形式放在 Git 仓库里，作为唯一的真实来源。

- `rackbook check`：按 JSON Schema 校验每条记录，并检查配置里声明的跨表规则
  （主键唯一、引用存在、与 inventory 分组一致等），适合放进 CI。
- `rackbook serve`：中文网页控制台，可搜索、筛选、排序；设备详情页用标签页列出它的内网地址和
  服务端口等相关记录（带数量、搜索、分页，适用于所有记录的“通用”条目单独一页）；列表里的枚举、
  布尔、日期、标签单元格可直接修改；新增 / 编辑 / 删除表单按 Schema 校验（可搜索下拉、标签多选、
  已有值提示、端口列表），保存即提交到 Git（作者为编辑者）并推送。
- `rackbook mcp`：MCP 服务，让 AI 读取台账。工具名统一为 `<族>_<动作>`（`ledger_info`、`collections_list`、
  `records_query`、`records_get`、`history_list` 等；`serve` 下有写权限的调用方另有 `records_create`、
  `records_update`、`records_delete`，均支持 `dry_run` 与 `idempotency_key`）。v0.2 的旧工具名（`list_records`、
  `get_record`、`search`、`create_record` 等）在 v0.6.0 作为已弃用别名继续可用，v0.7.0 移除。
- `rackbook export`：导出 Markdown、`llms.txt`、JSON。

写入时只替换被修改的那一条记录所在的行，注释、空行和原有格式保持不变，Git diff 一目了然。

快速试用：

```bash
rackbook check --config examples/homelab/rackbook.yml
rackbook serve --config examples/homelab/rackbook.yml --no-git   # 打开 http://127.0.0.1:8080
```

部署：推荐使用 `auth.mode: oidc`，对接任意 OIDC 身份提供方（Microsoft Entra ID、Keycloak、
Authentik、Google 等）。在 IdP 注册应用，重定向地址为 `<base-url>/auth/oidc/callback`；
`RACKBOOK_BASE_URL`（公网 https 地址）、`RACKBOOK_OIDC_CLIENT_SECRET`、`RACKBOOK_SESSION_KEY`
都从环境变量读取；角色写在 `rackbook.yml` 的 `auth.roles`（admin / editor / viewer，可按身份、
`*@域名`、`group:<id>`、`*` 匹配），没有匹配角色的人无法进入。`identity_claim` 必须由 IdP 控制
（不能由用户自行修改），否则改用 `identity: subject`。服务器用带写权限的 deploy key 克隆数据仓库，
前面放反向代理或 Cloudflare 终结 TLS，并用 `--trusted-proxy` 指明代理地址；compose 示例见上文 “Deployment”。
`/mcp` 与 `/.well-known/oauth-protected-resource*` 使用各自的 Bearer 令牌，不需要在前面加登录。

没有 MCPHub、Entra、Keycloak 时，Rackbook 可以自己当授权服务器（`auth.mcp.builtin_issuer`，v0.6.0）：
符合 MCP 授权规范（OAuth 2.1，PKCE S256，`resource` 绑定，客户端元数据文档或动态注册，刷新令牌每次轮换）。
用户在控制台里对每个 MCP 客户端授权一次，之后客户端一直可用（包括 Rackbook 重启后），直到被撤销、用户失去角色，
或 90 天没有使用。必须同时给 `--state-dir`（保存授权记录 `oauth-grants.json` 和自动生成的签名密钥，
同一目录只能有一个服务器在用）和 `--base-url`（令牌的签发者）。每个机制的大白话说明见
[docs/oauth-server.md](docs/oauth-server.md)；Claude Code、MCP Inspector、VS Code、Cursor 的连接方法见上文
“Built-in authorization server”。授权记录在“我的账户”和管理员的“已授权客户端”页，可随时撤销，立即生效。

可选：Cloudflare Access（`auth.mode: cloudflare-access`，见上文 “Alternative: Cloudflare Access”），
Rackbook 校验 `Cf-Access-Jwt-Assertion` 并用其中的邮箱作为提交作者；此时才需要为 `/mcp` 配置 Access 的 Bypass 策略。

会话是 HMAC 签名的 Cookie，不存数据库；角色每次请求都按 `auth.roles` 重新计算，没有角色的账号会被拒绝（403）。
可选通行密钥（`auth.passkeys`），凭据提交到数据仓库的 `.rackbook/passkeys.yml`。

登录页不会出现任何身份提供方的名字。可在 `rackbook.yml` 里用 `auth.oidc.label`（按钮文字，如“使用 Kazuha Hub SSO 登录”）
和 `branding.name` / `branding.logo` / `branding.favicon`（图片放在数据仓库里，SVG 或 PNG，不超过 256 KiB）定制，见上文 “Branding and the sign-in button”。

Rackbook 永远不会 force push，也不会改写或删除远端分支和标签。若发现远端历史被他人改写，
会暂停所有写入（返回 503 `history_rewritten`）、继续只读提供最后一个可信提交，并在控制台显示红色横幅；
管理员确认后用横幅按钮或 `rackbook serve --accept-remote <提交>` 恢复。

到期跟踪：在集合的 Schema 里给日期字段加 `"x-rackbook": {"expires": true}`（可选再给“已吊销”字段加
`{"revoked": true}`），Rackbook 就能列出已过期和即将到期的记录：`GET /api/expiring`、MCP 工具
`expiry_list`、控制台“到期”页。日期格式 `YYYY-MM-DD`，留空表示永不过期，`待补` 之类视为日期未知。
自动录入由独立的模块程序完成（`rackbook-entra` 读取 Entra ID，`rackbook-notify` 发送提醒），
它们只通过公开 API 和 API 令牌工作。`rackbook.yml` 的 `modules:` 是白名单：列出的令牌只能在指定集合里
新建记录并更新自己的记录，每条记录必须带 `source: <模块名>`，只能改 `fields` 里列出的字段，且不能删除；
服务器在每次写入时强制检查。`direct_push: true` 让模块的新增和更新直接提交到分支而不是每次开一个 PR
（同样要求令牌创建者仍是管理员）。管理员在控制台“模块”页查看每个模块的运行情况和失败、暂停、立即运行，
并修改发送/同步时间、阈值、收件人、排除的应用等设置；每次保存是一次 Git 提交，写入 `rackbook.yml` 的
`modules.<名称>.settings`。模块每小时由定时器启动一次，向服务器取设置，到点才运行，所以定时器要改成
`OnCalendar=hourly`。运行记录保存在 `--state-dir`。详见 [docs/modules.md](docs/modules.md) 第 7 节。
