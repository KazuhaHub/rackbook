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
   (Or use a [GitHub App](#github-app-instead-of-deploy-keys) from v0.7.2 on.)
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

The v0.2 tool names still work, from v0.6.0 until v0.8.0, as deprecated aliases with their old
arguments and result shapes, and are removed in **v0.8.0**:

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

Each alias's description starts with `Deprecated: use <new>; removed in v0.8.0`,
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
  The same directory keeps `preferences.json` (each person's console language).

### GitHub App instead of deploy keys

Instead of SSH deploy keys (and `RACKBOOK_GITHUB_TOKEN`), one GitHub App can
serve both repositories Rackbook uses: the data repository and, with
`--infra-repo`, the infra repository. Rackbook then fetches and pushes over
HTTPS with short-lived installation tokens, each requested for one repository
and the permissions that use needs (`contents: write` to push the ledger,
`pull_requests: write` only to open a pull request, `contents: read` for the
infra clone, which Rackbook only reads; `contents: write` for it only when the
[infra editors](#infrastructure-view-and-editors) are switched on with `--infra-write`).
Without the flags below nothing changes.

| Flag / environment | Meaning |
|---|---|
| `--github-app-id`, `RACKBOOK_GITHUB_APP_ID` | The App ID (a number, on the App's settings page) |
| `--github-app-key-file` | The App's private key (PEM). Instead: `RACKBOOK_GITHUB_APP_KEY` holds the PEM itself, or a systemd credential named `github-app-key` (`LoadCredential=github-app-key:/path/key.pem`). Never put the key in a flag value, in `rackbook.yml` or in Git |
| `--github-api` | REST base URL, only for GitHub Enterprise Server (default `https://api.github.com`; must be https). Tokens go only to `origin` URLs on that API's host (`github.com` for the default); `--github-repo` must match `origin` when an App is used |

The installation id is looked up from each repository and cached; tokens live in
memory only and are renewed 5 minutes before they expire. The token reaches git
through the environment of that one command, never in a command line, a log, the
remote URL or `.git/config`. An ssh-style `origin` is used over https for these
commands only. In compose, mount the key read-only and drop `GIT_SSH_COMMAND`:

```yaml
    command: >
      serve --listen 0.0.0.0:8080 --config /data/repo/rackbook.yml
      --github-app-id 1234567 --github-app-key-file /run/secrets/rackbook_app.pem
    secrets: [rackbook_app]
```

`--infra-ssh-key` and an App are two ways to fetch the infra clone; give only one.

#### Creating the GitHub App

1. In the organization: **Settings → Developer settings → GitHub Apps → New
   GitHub App**.
2. **GitHub App name**: e.g. `rackbook-<org>` (names are global). **Homepage
   URL**: any page you control, e.g. the repository URL.
3. **Webhook**: untick *Active*. Rackbook needs no webhook. Leave the callback
   URL and user authorization options empty.
4. **Repository permissions**: **Contents: Read & write**. Add **Pull requests:
   Read & write** only if you use pull-request mode (`write.mode: pr`) or
   contributor-level MCP writes. *Metadata: Read* is added automatically. No
   organization or account permissions.
5. **Where can this GitHub App be installed?** *Only on this account*.
6. Create it, note the **App ID**, then **Generate a private key**: a `.pem`
   file downloads once. Store it with mode `0600` (or as a secret), never in a
   repository.
7. **Install App** on the organization, choose **Only select repositories** and
   pick the ledger repository and the infra repository, nothing else.
8. Start Rackbook with `--github-app-id <App ID>` and the key. Remove the old
   deploy keys from both repositories once it works.

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

## Infrastructure view and editors

Rackbook can also show a repository of Ansible code with SOPS-encrypted secrets, and the status
of the infra hub that applies it, on its own pages under `/infra`. With `--infra-write` the same
people can also edit parts of that repository from the console (see *Editing the infra
repository* below). It is off unless `--infra-repo` is given.

```
rackbook serve --auth oidc … \
  --infra-repo /data/infra --infra-branch main \
  --infra-admins me@example.org \
  --infra-oidc-issuer https://login.microsoftonline.com/<tenant>/v2.0 \
  --infra-oidc-client-id <the console's application ID> \
  --infra-oidc-tenant <the Entra tenant ID> \
  --hub-status-file /run/hub/status.json
```

| Flag | Meaning |
|---|---|
| `--infra-repo` | A git clone of the repository, made once by you (Rackbook does not clone). Every `--pull-interval` Rackbook runs `git fetch` and resets the clone to `origin/<branch>`; local changes in it are discarded. It pushes only with `--infra-write`, and then only commits made by the editors. It must not be, or sit inside, the ledger clone |
| `--infra-branch` | The branch followed, and the branch the editors commit to (default `main`) |
| `--infra-ssh-key` | (Or use the [GitHub App](#github-app-instead-of-deploy-keys): its token for this clone is `contents: read`, and `contents: write` only for an edit.) The private key (give it a read-only deploy key) used to fetch this clone, and only this clone. It cannot be combined with `--infra-write`. It reaches git in `GIT_SSH_COMMAND` in the environment of the git process, not on a command line; a `known_hosts` file beside the key is used with strict host key checking when it exists |
| `--infra-admins` | Comma-separated exact identities (no wildcards) who may use `/infra`. This is **not** `auth.roles`, and it is never read from `rackbook.yml`, so nobody can grant it by editing the ledger. Needs `--auth oidc`: only a person who signed in with the console's OIDC login counts. API tokens (also the token of a listed person), MCP clients, OAuth access tokens, passkey and Cloudflare Access identities are answered `403 forbidden` |
| `--infra-oidc-issuer`, `--infra-oidc-client-id` | **Required** with `--infra-repo`. The identity provider (issuer URL) and the application (client ID) that infra administrators sign in with. A session counts only if it was issued under exactly this issuer **and** this client ID (and the claim and tenant below); anything else is `403`, however it was obtained. See *Why the identity provider is pinned* |
| `--infra-oidc-identity-claim` | The ID token claim the administrators' identities are taken from (default `preferred_username`; `sub` for subject identities, which are then listed as `oidc:<sub>`). A session whose identity came from another claim is refused, so `auth.oidc.identity_claim` in the ledger cannot change who counts as an administrator |
| `--infra-oidc-tenant` | The tenant (the `tid` claim) the administrators sign in from. **Required for an Entra issuer**, and a tenant GUID in `--infra-oidc-issuer` must equal it; optional for other providers (then a session without a tenant is expected). A session from another tenant is refused; `allowed_tenants` in the ledger is not trusted |
| `--infra-write` | Turn on the editors. Needs `--github-app-id` (the App must have `Contents: read and write` on the infra repository) and cannot be combined with `--infra-ssh-key`; on a `--read-only` server the editors stay off |
| `--sops-age-key-file` | The age identity file Rackbook edits the infra repository's SOPS secrets with (see *Editing secrets*); empty = the secrets editor is off. Needs `--infra-write`, `--state-dir` (the reveal limits are kept there) and the `sops` and `age-keygen` binaries (the container image has them, pinned and checksummed). Mount the file read-only; it is Rackbook's own key, generated on the host, never an administrator's key. Rackbook shows its public key on the secrets page, to be added as a recipient of every **host** rule in `.sops.yaml` (never the `secrets/admin.sops.yaml` rule) |
| `--infra-write-max-age` | How recent a person's sign-in must be for a write (default `12h`). An older session can still read; a write answers `403 reauth_required` and the console offers *Sign in again* |
| `--infra-managed-group`, `--infra-agent-group` | The inventory group whose hosts must each have host_vars and a SOPS file and that must contain every host of every group (default `managed`), and the group that must list exactly the managed hosts (default `infra_agent`). A group the inventory does not have switches its rule off; `""` disables the rule |
| `--hub-status-file` | The hub's `infra-hub status -o json` document (`apiVersion: v1`), rewritten by a timer on the same machine; mount it read-only into the container |

What the pages show:

- **Hosts**: the hosts of `inventory/hosts.yml` with their groups (also through parent groups) and
  whether `inventory/host_vars/<host>.yml` exists, joined with the hub's latest report per host
  (result, applied commit, time, message). A host whose applied commit is not the commit of the
  followed branch is marked *Behind main*. A host page adds that host's `host_vars` file, copied
  as read-only YAML (comments kept; values under secret-looking keys such as `token` or
  `password`, and private keys, are replaced by `(hidden)`; SOPS files are never opened), and the
  switches under `features:`.
- **Certificates** and **IP lists**: the hub's certificate names (owner, expiry, failing, last error) and
  lists (version, entry count, warnings).
- **Commits**: the last 50 commits of the followed branch (with *Revert* when editing is on).

The status file's own `time` tells how old it is. When it is missing, unreadable or older than
three minutes the pages say *Status unavailable* with the reason and show none of its data, so a
stale report is never read as current. The repository's last sync time and error are shown too.
`/infra` is not part of the ledger and is never offered on `/mcp`. The API is under `/api/infra`
(docs/api.md). The Git runner is the ledger's guarded one (see *Rackbook never force-pushes*).

### Why the identity provider is pinned

Who a person *is* comes from the OIDC sign-in, whose settings (`auth.oidc`: issuer, client ID,
`identity_claim`, `allowed_tenants`) live in `rackbook.yml` in the ledger repository. Anyone who can
edit the ledger could therefore point the sign-in at an identity provider they control and present
a listed identity. For `/infra` that is not acceptable, so the provider is not taken from the
ledger: the issuer, client ID, identity claim and tenant (`--infra-oidc-issuer`,
`--infra-oidc-client-id`, `--infra-oidc-identity-claim`, `--infra-oidc-tenant`) come from the command
line, and every session records what it was issued under: the issuer, the client ID, the claim the
identity was taken from, and the ID token's tenant. A session issued under anything else (for example
after `auth.oidc` was edited and Rackbook restarted) is refused with `403` on every `/infra` path, and
Rackbook logs a warning at start when the ledger's settings do not match. Keep the values equal to the
console's own `auth.oidc` (`issuer`, `client_id`, `identity_claim`, `allowed_tenants`). Sessions
made by an older version carry no client ID and need one new sign-in after the upgrade.

### Editing the infra repository

With `--infra-write`, infra administrators get four editors under `/infra`. Every save is **one
commit straight to the followed branch** (no pull request): the branch is applied to the machines,
so Rackbook checks the change itself first (below). No CI gate is assumed.

- **Variables**: the raw YAML of `inventory/host_vars/<host>.yml`, with a diff to review before
  anything is committed. A file that holds secret-looking values is never shown or edited here.
- **Feature switches**: a form generated from `features/<name>/feature.yml` (setting types, enum
  values, patterns, ranges, defaults, `required` and `required_when`; the format is the infra
  repository's `docs/feature-spec.md`). Saving a feature rewrites only its `features.<name>` entry; the
  rest of the file, comments and blank lines included, is byte for byte what it was. Settings marked
  `secret: true` are written to the host's SOPS file (see *Editing secrets*), never to `host_vars`;
  without `--sops-age-key-file` they are refused.
- **Groups**: a host × group table that adds or removes hosts under `all.children.<group>.hosts` in
  `inventory/hosts.yml`, again changing only those lines.
- **History**: each commit that only touched files these editors own gets a *Revert* button, which
  commits those files back to how they were before it. It is refused (`409`) when a later commit
  touched any of the same files, for merge and first commits, and for commits that touched anything else.

Only `inventory/hosts.yml`, `inventory/host_vars/*.yml` and (with `--sops-age-key-file`) `secrets/<host>.sops.yaml` can be written. `group_vars` are shown but never
edited here: they legitimately hold templating and connection variables (`ansible_connection`), which the
rules below refuse in a file Rackbook writes.

Who may write: the same people as the pages, plus a recent sign-in (`--infra-write-max-age`). The
Rackbook role in the ledger is irrelevant, and an API token, OAuth or MCP credential is always
refused, even of a listed person. Writes use a GitHub App token narrowed to the infra repository
with `contents: write`; reads keep using `contents: read`. The org is expected to enforce MFA in the
identity provider: a fresh sign-in is the second factor.

#### Editing secrets

With `--sops-age-key-file` the infra administrators also get a **Secrets** page per host
(`/infra/hosts/<host>/secrets`), which edits `secrets/<host>.sops.yaml` with SOPS. Rackbook has **its own
age key**, generated on the host and mounted read-only; it is not the administrators' key. The
coordinator adds the public key (shown on the page, and logged at start) as a recipient of every
**host** rule of `.sops.yaml` and runs `sops updatekeys` on those files. It never goes into the
`secrets/admin.sops.yaml` rule: that file (the CI signing key backup) is admin-only, and Rackbook refuses
the name `admin` outright; until then the page says the file cannot be
decrypted and offers nothing but the key names.

- **Which files.** Only `secrets/<host>.sops.yaml` of a host that is in the inventory **and** in the managed
  group, and only when `.sops.yaml` has a rule of its own for it (`path_regex: ^secrets/<host>\.sops\.yaml$`,
  the first rule that matches the path). Any other path, a broader rule only, and the host name `admin` are refused.
- **The list** shows key names only. It is read from the YAML itself and decrypts nothing.
- **Reveal** is a separate request for one key, answered with `Cache-Control: no-store`. It needs a recent
  sign-in like every write, is limited per person to 10 a minute, 30 an hour and 100 a day (counted in `--state-dir`, so a restart does
  not reset them; a refusal is audited and logged as a warning with the identity), is refused on a `--read-only` server, and is recorded in the audit log (who,
  which key, when; never the value). The value is returned exactly as stored, trailing newline included. The page shows it for 30 seconds and keeps it out of any cache.
- **Set / replace** and **delete** are one commit each, through the same write path as the other
  editors (conflict rules, author, trailers). The value is sent in the request body and reaches `sops
  set --value-stdin` on its standard input, never as an argument; the commit subject names the key,
  never the value. Key names are `^[a-z0-9_-]+$` (not `sops`, not ending in `_unencrypted`), values
  non-empty UTF-8 text of at most 16 KiB, entered in a multi-line box with line breaks kept exactly; a
  PEM block whose BEGIN and END are on one line (lost line breaks) is refused.
- **Re-encrypt** (`POST /api/infra/hosts/<host>/secrets/reencrypt`, body `{base}`) is one commit that
  re-encrypts the file for exactly the recipients of its creation rule in `.sops.yaml` and gives it a new
  data key (`sops rotate --add-age/--rm-age`: every value and the MAC change; a removed recipient can no
  longer decrypt the new file). Use it after a host is reinstalled (new host key) or a key is rotated and
  the rule changed; the page offers it prominently when the file's recipients differ from the rule, and as a
  secondary action otherwise (it still makes a new data key). It needs a recent sign-in like every write.
  The rule in `.sops.yaml` is the authority: if a commit removes the escrow key from a rule, re-encrypting removes it from the file. It is refused when the file does not exist, when the rule has more than one `key_groups` entry, when no rule lists age recipients, when the rule does not
  list Rackbook's own public key (Rackbook would lock itself out), and when the file has non-age
  recipients (pgp, kms, ...). A file Rackbook's key cannot decrypt cannot be re-encrypted here: another
  key holder must add the key (`sops updatekeys`) first. The request is audited (`reencrypt`: who, file,
  outcome `reencrypted`; failures are recorded by the shared write path under the commit subject) and the commit subject is `infra(secrets/<host>): re-encrypt for the .sops.yaml recipients (new data key)`.
- **Feature secrets**: a `secret: true` setting of a feature is stored under the key
  `feature_<feature>_<setting>` in the host's SOPS file, in the same commit as the feature's other
  settings. Leaving its box empty keeps the stored value.
- **Checks.** The plaintext secret scan does not apply to `secrets/*.sops.yaml`; instead, after every edit
  the file must have SOPS metadata, every value `ENC[...]`, and exactly the recipients of its
  creation rule in `.sops.yaml`, or nothing is committed. A host with no file yet gets one made from the rule.
- **No plaintext on disk.** `sops` and `age-keygen` are started only by `internal/sops`, only for
  `decrypt --extract`, `set --value-stdin`, `unset`, `encrypt` (new file, from standard input), `rotate` and
  `age-keygen -y`, with an empty environment but the key file and a scratch `HOME`. The files they get are
  ciphertext, in a 0700 directory (`/dev/shm` when there is one) removed afterwards.

Never on `/mcp` and never for an API or OAuth token, like every infra write. Reverting a commit that
touched a SOPS file is refused (`not_editable`).

**The commit.** Subject `infra(<path>): <action>` (for example `infra(host_vars/alpha): enable beszel-agent`),
author the signed-in person (name and e-mail from the sign-in), committer `--committer`, and trailers:

```
Edited-by: me@example.org
Edited-via: rackbook (oidc)
Files: inventory/host_vars/alpha.yml
```

(`Reverts: <hash>` on a revert, `Secret-scan: confirmed-not-secret` after a confirmation.)

**Checks before the commit** (native, from the repository's own files; a failure is shown in the
console in the current language and nothing is committed):

- every YAML file parses, has one document, no duplicate keys, and `host_vars` / `group_vars` are mappings;
- the inventory has the shape `all.children.<group>.hosts.<host>`;
- every host in a group is also in the managed group (`--infra-managed-group`);
- if the inventory has an `infra_agent` group, it equals the managed group;
- every managed host has a `host_vars` file and `secrets/<host>.sops.yaml`;
- **host_vars are evaluated by Ansible as root on every machine, so**: no key or string value at any depth
  (block scalars included) contains `{{`, `{%` or `{#`, and no top-level key starts with `ansible_`
  (connection, privilege and interpreter variables);
- no anchors, aliases, merge keys (`<<`) or explicit YAML tags in a file Rackbook writes (they would hide
  values from the checks below);
- each `features.<name>` entry exists in `features/` and its settings fit `feature.yml`: known keys,
  types, enum values, whole-string patterns, `min`/`max`, 512 characters at most, no control
  characters, no `{{`, `{%` or `{#`, required settings (also `required_when`), no secret settings;
- Rackbook's secret scan on `host_vars` and `group_vars` (a heuristic finding may be confirmed by the editor).

What an edit writes must pass every check, whatever state the file was in. Problems the repository
already had in files the edit does not write are shown as warnings and do not block it. Diffs and revert
previews hide secret-looking values and whole PEM blocks, and a revert is refused for files that hold such values.

**Conflicts.** The editor sends the version of each file it loaded. Rackbook fetches, resets its
clone to the branch, and refuses the edit with `409 conflict` and a diff when a file changed since.
When only the push is rejected because the branch moved, the edit is replayed on the new tip (up to
three times) if the files it touches did not change, never by rewriting history: a push is always the
plain fast-forward push of the ledger's guarded Git runner (see *Rackbook never force-pushes*).

**Audit.** Actions that did not end in a commit (checks failed, conflicts, a push that failed, a refused
revert, a write refused for a stale sign-in or for the wrong person, a secret revealed) are logged and, with
`--state-dir`, written to the [audit log](#audit-log) (issue codes, never values). Commits are their own
record in Git; the audit log also holds one `commit` line for each commit Rackbook pushed.

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

Logins, refusals and logouts go to the server log (stdout) and, with `--state-dir`, to the
[audit log](#audit-log). Starting a login or a
passkey ceremony is rate limited per client (the first `CF-Connecting-IP` /
`X-Forwarded-For` address when the request comes from a loopback or private proxy).

## Audit log

With `--state-dir`, Rackbook keeps an append-only audit log in `<state-dir>/audit/`: one file per month
(`audit-2026-11.jsonl`, UTC), one JSON object per line, mode 0600, and `head.json` beside them. Without
`--state-dir` there is no audit file: the same events only go to the server log, as before.

**What is recorded.**

- Sign-ins: `login` and `logout` (identity, name, method, the effective role at sign-in, client address), and
  `login_refused` with a `reason`: `no_role`, `tenant`, `claims` or `passkey_failed`.
- Writes that did not end in a commit on `/infra`: `write_refused` (with the `area` and a `code` such as
  `conflict`, `forbidden`, `validation_failed`).
- Secrets: `secret_revealed`, `secret_reveal_refused` and `reencrypted`: who, which host and file, never a value.
- `commit`: written after Rackbook's own push to the data repository (`area: ledger`) or the infra repository
  (`area: infra`) succeeded. It holds the full commit hash, the repository name, the record and who made the
  change (for an API token, the token's name is in `detail`). A write that opens a pull request, or fails, is not
  a commit line.

A successful write is not copied into the log: the commit is the record, and the `commit` line only says who
made it. The client address comes from the same rules as the rate limits (`--trusted-proxy`), not from the
proxy's address.

| Flag | Meaning |
|---|---|
| `--audit-addr` | How much of the client address is kept: `truncate` (default: IPv4 without the last octet, IPv6 only the first 48 bits), `full` or `none`. `full` still keeps an IPv6 client as its /64, because the same function that rate-limits clients groups it that way. |
| `--audit-retention-months` | Delete month files older than this many whole months before the current one. `0` (default) keeps everything. The current month is never deleted. |

Both are server flags, not `rackbook.yml` keys: the data repository can be edited by people who must not be
able to shorten the retention or widen the addresses, so the deployment decides.

**The chain.** Every line carries `seq` (1, 2, 3, ...) and `prev`, the SHA-256 of the line before it, and
`head.json` holds the `seq` and hash of the last line. Take out, change or reorder a line and the next one no
longer fits; cut lines from the end and `head.json` no longer matches; a new month starts from the last line of
the month before. Anyone who edits a line without rebuilding everything after it, and `head.json`, is caught.
This does not protect against someone with root on the host: they can rewrite all the files and `head.json`
together. It makes quiet edits visible; it does not make them impossible.

**Crashes.** Each line is written with one `write` and then `fsync`. A crash can leave a last line without its
newline (the server moves it to `audit/torn-<seq>.jsonl` and continues from the last complete line) or
`head.json` one line behind (the server brings it up to date). Both are repaired at start and are not
tampering. Any other mismatch is logged as an error; the server still starts and keeps appending, and
repairs nothing. The first thing it appends is a `chain_problem` event for each problem (the kind in `code`, the
broken `seq` and what `head.json` said before, in `detail`), so the evidence is inside the chain before
`head.json` moves on. The problem stays listed, and the server reports the log as not OK, until an
administrator acknowledges it (see [Activity](#activity)).
A last line cut short while `head.json` does not show a crash is set aside in `torn-<seq>.jsonl` too, and recorded
as a `chain_problem` event (code `edited`, with the file name); auditing continues. Only if the partial line cannot
be set aside, or a failed write cannot be undone, does the server write nothing more: it logs an error and reports
the log as failed, because appending would glue a line onto a partial one.

**Checking.** `rackbook audit verify --state-dir <dir>` reads the log and prints what it found: the number of
lines and files, and each problem (`edited`, `missing`, `reordered`, `cut_from_end`, `head_mismatch`) with the
`seq` it starts at. A problem the server already wrote down is listed as `recorded at seq N` and still counts;
once acknowledged it is also listed as `acknowledged at seq N`, and still counts. It never changes a file. It exits 1 on any problem, and 0 when the chain is intact; a torn
last line or a `head.json` one line behind alone are warnings and exit 0. `--json` prints the report as JSON.

**Retention.** With `--audit-retention-months`, old month files are deleted at start and once a day. Before a
file goes, `head.json` records the first file kept and the `prev` of its first line, so `verify` starts there and
does not report the deleted months as missing. Nothing is deleted while the chain has a problem that is not yet recorded in it. After a recorded chain
problem, retention keeps the month that holds the `chain_problem` event and every later month until an
administrator acknowledges the problem on the Activity page (older months are still deleted); once it is
acknowledged, that month is deleted like any other when its turn comes. The acknowledgement is a
`chain_problem_ack` line in the chain itself (`detail: through:<seq>`), so it can be audited too. Each skipped
run logs a warning with the reason. If a start or crash left months behind that `head.json` already says are gone,
they are not a problem, and the next retention run deletes them.

**Migration.** Earlier versions wrote the `/infra` audit to `infra-audit.jsonl` in `--state-dir`. At the first
start with the audit log, its entries are copied into the log with their original times (`audit/migrated` marks it
done). If a start is cut short in the middle, the next start finishes the copy without repeating lines. The old
file stays where it is and is no longer written to.

## Activity

The **Activity** page (`/activity`) is one timeline of everything that changed: the commits of the data
repository, the commits of the `--infra-repo` repository and the audit log. Each row says when, who, what, and
whether Rackbook can vouch for it; a commit opens its diff. The filters (person, area, collection, record, from,
to) are in the URL, so a link reproduces the view; "Load more" pages through older entries.

**Who may see what.** Every request needs a role; what a role shows is decided in one place
(`canSee` in `internal/api/activity.go`):

| Area | What it holds | Who sees it |
|---|---|---|
| `ledger` | commits of the data repository that touch ledger files | every role |
| `ledger`, state | commits that touch `.rackbook/` (tokens, passkeys) | admins |
| `audit` | sign-ins, refusals, `write_refused`, acknowledgements, chain problems | admins |
| `infra` | commits of the infra repository and the infra audit events (secret reveals, re-encryption) | `--infra-admins`, signed in with the console login |

Without `area`, a request returns every area its caller may see. Naming an area the caller may not see is a `403`.
The client address of an audit event is shown to admins only.

**Verified.** Anybody with push access can write any author and any `Edited-by` trailer, so a commit's
trailers prove nothing. A commit is **verified** only when Rackbook itself made it: after its own push it writes a
`commit` line, with the full hash and the signed-in identity, to the audit log. For verified commits the person comes
from that line (and the API token's name, if one was used). Every other commit shows the Git author and trailers as
written, marked **unverified**, and the `identity` filter never matches it. Without `--state-dir` there is no audit
log, so every commit is unverified. `commit` lines are not rows of their own; they only verify a commit. A cache of
them, `audit/index.json`, is updated as the log grows; it can be deleted at any time and is rebuilt from the chain.

**API.**

| Request | Meaning |
|---|---|
| `GET /api/activity` | `since`, `until` (RFC 3339 or `YYYY-MM-DD`; a date for `until` includes that whole day, UTC), `identity`, `area` (`ledger`, `infra`, `audit`; repeat it or separate with commas), `collection`, `id` (needs `collection`; commits with that exact `Record` trailer), `limit` (default 50, at most 200), `cursor`. Answers `{"items": [...], "cursor": "...", "areas": [...], "audit": true}`; `cursor` is absent on the last page. `collection` leaves out infra and audit rows, which belong to no collection. |
| `GET /api/activity?format=jsonl` | Admins only. The same filters, no cursor: every match, one JSON object per line, as `application/x-ndjson` with `Content-Disposition: attachment`. It stops at 50 000 rows, or when its work budget is spent, with a last line `{"truncated":true}`. |
| `GET /api/activity/commit/{area}/{hash}` | What a commit changed (`ledger` or `infra`): the files with status and unified patch. The patches together are capped at 256 KiB (a file that crosses it says `truncated`), at most 200 files. Files under `.rackbook/` are left out for non-admins, and a commit with nothing else is a `404`. In the infra repository SOPS and vault files, and anything under `secrets/`, are listed as changed without a patch, and values that look like secrets are hidden in the others. |
| `GET /api/audit/status` | Admins: `{"enabled", "ok", "problems": [...], "lastSeq"}`: the recorded chain problems nobody has acknowledged. |
| `POST /api/audit/ack` | Admins, signed in (not with an API token), not on a read-only server: `{"through": <seq>}` acknowledges the recorded problems whose `chain_problem` line has that seq or a lower one. `409` when there is no audit log or nothing waits to be acknowledged. |

**Paging.** The three sources (data repository, infra repository, audit log) are read as three streams, each in
its own order, and merged by taking the newest of their heads. The cursor holds, per stream, where it has got to:
for a repository the commit its walk is pinned to and how many commits of the walk were consumed (so pages stay
stable while new commits land, and a commit whose committer date is older than its parent's is not lost); for the
audit log the seq it has come down to. The `since`, `until`, person and record filters are applied to what a stream
reads, never as limits on the walk. Each source is read by one git process per request, streamed and killed once the page is full. Every request
has a work budget per stream (2 000 commits; `scanned` in the answer says how much was looked at); when it runs
out, the page ends (it can hold no row at all) and the cursor carries on from there, so keep following `cursor`
until it is absent. The console goes on by itself for three empty pages in a row and then asks ("keep searching").
With `since`, a git walk may stop early: git's `--date-order` puts a commit before its parents and otherwise
orders by date, so once a walk has seen 200 commits in a row dated more than a day before `since`, it gives up.
This is a heuristic bound: a commit dated more than a day earlier than the 200 commits that follow it in the
walk can be missed by a `since` filter. Without `since` there is no early stop. The
result is ordered by time, newest first, except where a repository's commit dates go backwards along its history or
audit lines were written with an old explicit time: such a row comes at its position in its stream, not at its
date. Nothing is lost or shown twice. Cursors are signed (HMAC-SHA256 with a key the server makes at start, bound to the signed-in person), so they
cannot be made up, used by somebody else, or told apart from a commit lookup; they do not survive a restart. One that
fails the check, or from before a history rewrite was accepted, is `400` with `"error": "cursor_invalid"`; the
console then starts again from the first page with a notice.

**Acknowledging a chain problem.** While the audit log has a recorded problem nobody has acknowledged, admins see a
red banner on every page, with the kinds of problem and the first affected line. *I have checked — acknowledge*
(after a confirmation) records a `chain_problem_ack` line by the admin. The problem stays in the log and in
`rackbook audit verify` (marked acknowledged, and verify still exits 1); it stops showing the banner and stops
keeping its month from the retention.

## Record history, restore and deleted records

On a record page, **History** is the version timeline of that record: one entry for each commit that changed
it, newest first, with the time, the person, the commit subject, and the change **field by field** against the
commit's parent: fields added, removed and changed, with the old and the new value (nested fields are named by
path, such as `ports[2].proto`; a long value is collapsed). A commit that created the record, deleted it or renamed it
(its key fields changed, so its id did) says so. Who made a commit is shown as in [Activity](#activity), **Verified** or
**Unverified**, and a commit made by a restore says *Restored from* and the commit it came from (the Activity page
shows that too).

**What is read, and from where.** A version is read from the collection file *as it was at that commit*, with the
collection's file path, key and type definition of that commit, not today's, so a collection file that moved or a key
that changed does not break the older versions. The commits are those with the exact `Record: <collection>/<id>`
trailer; a record that no commit names (edited by hand, or before the trailer existed) falls back to the commits that
touched the collection's file, and those in which the record did not change are left out. Reading follows the paging
model of Activity: the first page pins the current tip, the cursor holds the commit the walk is pinned to and how many
commits of it were consumed, a request walks at most 400 commits (a page can be short or empty while the cursor
goes on) and returns at most 50 versions. Nothing hidden elsewhere is shown here: ids that hold a secret are shown
redacted, `.rackbook/` is never read, and a value that the secret scan flags (as it would for the record today, with
the type definition of that commit) is not returned, neither in the timeline nor in what *Restore* sends back to the
editor: it is shown as `(hidden)` and a change between two hidden values is still a change. The old values are read
with `git cat-file blob <commit>:./<path>` only (the guarded runner allows exactly one blob argument, never an option).

**Restore this version** (editors; not on the current version) is done by the server: it reads the record at the
commit itself (the browser never gets the hidden values) and writes it as **one new commit** through the ordinary
edit path, so the current schema, references and the secret scan check it exactly as for a `PUT`. The commit has the
subject `ledger(<collection>): restore <id>`, the usual trailers, `Record:` and `Restored-from: <full commit hash>`; it
is a Rackbook commit like any other, so the audit log vouches for it. History is never rewritten. The console asks
first and shows what would change from the current record to that version. If the old version needs the secret-scan
confirmation, the editor is asked again, as for any write. If the old content no longer fits the current schema or
references, or its key fields give another id than the record's, nothing is written: the server answers `409
restore_needs_edit` with the old content and the console opens it in the editor, to be fixed and saved as an ordinary
edit. A collection without a key always needs this step (ids are positions there). `hash` is the current record's
hash, so a change made in the meantime is the usual conflict.

**Deleted records.** On a collection's page, *Deleted records* lists the records whose last change removed them: the
id (redacted if needed), when, by whom (verified or not), a few fields of the last version, and *Restore*, which
brings the record back as an add with `Restored-from`. A record that was deleted and added again is not listed; a
rename is not a deletion. Finding them reads the collection file's whole history, so the result is kept: with
`--state-dir` in `<state-dir>/history/deleted-<collection>.json` (`0600`), without it in memory. The cache is keyed by
the commit the history was read to and extended from there with only the new commits; if that commit is no longer an
ancestor of the tip (the history was rewritten) it is built again, and deleting the file is always safe. A first build is
spread over requests, 200 commits each: until it is finished the answer says `"complete": false` with what is known,
and the console asks again. The cache holds commit hashes, times, ids (redacted where needed) and the author and subject of the deleting commit, never record values.

| Request | Meaning |
|---|---|
| `GET /api/c/{collection}/{id}/history` | `limit` (default 20, at most 50), `cursor`. `{"id", "versions": [...], "cursor"?, "audit"}`. A version has the fields of an Activity row (`time`, `hash`, `short`, `subject`, `identity`, `name`, `via`, `verified`, `token`, `restoredFrom`) and `change` (`created`, `changed`, `deleted`, `renamed`), `renamedFrom`/`renamedTo`, `recordHash` (the record's hash at that commit, `""` when deleted) and `changes`: `[{"path", "op": "added"\|"removed"\|"changed", "old", "new", "hidden"?, "truncated"?}]` (at most 200 per version, a value is cut at 8 KiB). Every role may read it. Cursors are signed like Activity's, bound to the record and the person; `400 cursor_invalid` when one no longer fits. |
| `GET /api/c/{collection}/{id}/history/{commit}` | One version: `{"id", "commit", "recordHash", "data", "hidden", "exists", "current", "changes"}`; `changes` go from today's record to that version (what a restore would change). `404` when the commit is not on the tracked branch or the record did not exist in it. |
| `POST /api/c/{collection}/{id}/restore` | `{"commit": "<hash, 7 or more digits>", "hash": "<current record hash>", "confirm_not_secret": false}` (`confirmNotSecret` is accepted too). Editors, with the gates of `PUT` (read-only mode, role, token narrowing, same-origin, PR write mode). `200` as a `PUT` plus `"restoredFrom"`. `hash: ""` is for a record that does not exist now and makes it a `201` add (it needs create permission too); `400` for an empty hash when the record exists, `409 conflict` for a hash that does not match. `404` for a commit that is not on the tracked branch, or in which the record did not exist; `409 already_current`; `409 restore_needs_edit` `{"data", "hidden", "commit", "errors"}`; `422 secret_suspected` / `secret_detected` as for any write. |
| `GET /api/c/{collection}/deleted` | `limit` (default 50, at most 200). `{"records": [{...commit fields of the deleting commit..., "id", "last", "deletedAt", "summary": [{"field", "value"}]}], "complete", "more"}`; `last` is the commit that still had the record (pass it to restore). A record whose id is `deleted` cannot be fetched with `GET /api/c/{collection}/deleted`, which is this list. |

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

## Console language

The console speaks `zh-CN`, `zh-TW` and `en-US`; switch it from the user menu (or the language
button on the sign-in page). A person's language is, in order: the one they saved while signed in
(kept per identity in `<state-dir>/preferences.json`), the one chosen in this browser (kept in its
local storage), the best match of the browser's `Accept-Language`, then `i18n.default`:

```yaml
i18n:
  default: zh-CN   # zh-CN (default), zh-TW or en-US; used when the browser matches none
```

The block is optional; an unsupported value is a config error. Without `--state-dir` saved choices
live in memory until a restart. With `--auth none` everyone shares one identity (or none), so the
console keeps the choice in each browser and does not save it on the server. Saving a language also works with `--read-only`.
If `preferences.json` does not parse, it is logged and treated as empty; the file is moved to
`preferences.json.corrupt` before the next save.

The console's own words are translated by Rackbook. What the ledger says is yours to translate,
as described next; record values you type (names, notes) are shown as written.

To add a language: copy `web/src/i18n/en-US.ts` to `web/src/i18n/<tag>.ts` and translate it (the
compiler rejects a missing or extra key, `npm run check:i18n` a key of the wrong kind), then list
the tag in `LOCALES`, `LOCALE_NAMES` and the loaders in `web/src/i18n/index.ts` and in `Supported`
in `internal/locale`, so that `Accept-Language` can match it. Server-side text has its own short tables:
the authorization error page (`pageLangs` in `internal/oauthserver/errorpage.go`) and
`rackbook-notify` (`langs` in `cmd/rackbook-notify/message.go`, `NotifyLanguages` in `modsettings`,
the list in `web/src/components/modules/SettingsForm.tsx`). `npm run check:i18n-dom` loads every
page in each language, switches, and fails on text left in the old one.

### Ledger text in several languages

Stored values stay stable English codes (`static`, `TCP 443`, `US`). Only what people read changes
with the viewer's language. The text in the usual places (`title`, `description`, a oneOf entry's
`title`, the `title` of a collection in `rackbook.yml`) is in the default language (`i18n.default`).
Other languages go next to it, under `i18n`. A reader gets the entry for their language, else the
standard text, so nothing is ever empty. Old files with no translations work as before.

```yaml
# rackbook.yml
title: Kazuha Hub 网络台账
i18n:
  default: zh-CN
  en-US: {title: Kazuha Hub network ledger, description: Devices, addresses and services}
  zh-TW: {title: Kazuha Hub 網路台帳}
collections:
  devices:
    title: 设备
    group: 网段规划
    file: ledger/devices.yml
    schema: schemas/device.json
    i18n:
      en-US: {title: Devices, description: All devices, group: Network plans}
notes:
  - title: Docker 地址池规则
    file: ledger/networks.yml
    path: docker.rule
    i18n: {en-US: {title: Docker pool rule}}   # the note text itself comes from the file and is not translated
rules:
  - ref: {from: services.device, to: devices.name, message: 设备不存在, backref_title: 服务,
          i18n: {en-US: {message: Unknown device, backref_title: Services}}}
  - same_set: {left: {...}, right: {...}, message: 设备与清单不一致, i18n: {en-US: {message: Devices differ from the inventory}}}
```

| Where | Keys under each language |
|---|---|
| top level `i18n` | `title`, `description` |
| `collections.<name>.i18n` | `title`, `description`, `group` |
| `notes[].i18n` | `title` |
| `ref` rule `i18n` | `message`, `backref_title` |
| `same_set` rule `i18n` | `message` |

The languages are `zh-CN`, `zh-TW` and `en-US` (the tag exactly). An unsupported language or an
unknown key is a config error. Facet `values` hold codes; their display names come from the schema.

In a schema, a field's choices can carry labels, other languages and icons:

```json
"ipv4_type": {
  "type": "string",
  "title": "IPv4 类型",
  "oneOf": [
    {"const": "static", "title": "静态"},
    {"const": "dynamic", "title": "动态"}
  ],
  "x-rackbook-i18n": {
    "en-US": {"title": "IPv4 type", "description": "…", "enum": {"static": "Static", "dynamic": "Dynamic"}},
    "zh-TW": {"title": "IPv4 類型", "enum": {"static": "靜態"}}
  },
  "x-rackbook-enum-icons": {"static": "pin", "dynamic": "refresh-cw"},
  "x-rackbook-enum-colors": {"static": "green"}
}
```

- A choice list is either a plain `enum` of strings (still valid) or a `oneOf` where every entry
  has a string `const`, an optional string `title` (the default-language label) and nothing else.
  They mean the same; the `oneOf` form carries the labels. It works on a string property, on the
  `items` of an array of strings and on the properties of row objects.
- `x-rackbook-i18n` is keyed by language. Each entry may have `title`, `description` and `enum`
  (code → label). It is allowed on any property and, with `title` and `description`, on the schema
  root. A language Rackbook does not have, or a label for a code that is not in the list, is ignored
  when reading.
- The label of code C in language L is `x-rackbook-i18n[L].enum[C]`, else the `oneOf` title of C,
  else C itself.
- `x-rackbook-enum-icons` maps a code to a lucide icon name in kebab-case (`circle-check`, `clock`).
  The console shows the icon next to the label, never instead of it, and shows nothing for a name it
  does not know.
- The type editor writes the `oneOf` form as soon as a choice has a label in any language, and the
  plain `enum` when none has. Switching removes the other keyword; keys it does not know stay.

Two more field types: `country` (format `country`, an ISO 3166-1 alpha-2 code in capitals such as
`US`, `CN`, `SG`) and `subdivision` (format `subdivision`, ISO 3166-2 shape `US-CA`, `CN-GD`). Both
also accept the placeholder `tbd` for "not known yet"; the console shows it as 待补 / 待補 / TBD.

When a value is refused because it is not one of the choices, the message says what to do. If
the value is a label in any language, or a code in other letters, it reads
`"静态" is not allowed; use code "static"`; otherwise `"xyz" is not one of: static, dynamic, nat`.
`rackbook check` prints that message; the console words it in the viewer's language. Labels, translated text and icon names are
scanned for secrets like titles and descriptions; the language tags and codes that key them are not.

### Text the server writes

- **Validation problems** (`/api/check`, a refused write, the type editor's plan) carry a `keyword`
  and its `params` next to the English `message`; the console words them in the viewer's language
  and names fields and codes by their labels. Other clients can do the same or show `message`
  (docs/api.md, `GET /api/check`).
- **The authorization error page** of the built-in OAuth server (an unknown client, a redirect URI
  it did not register) is in the person's saved language, else the browser's, else `i18n.default`.
- **Reminder mail and webhooks** from `rackbook-notify` use the module's own `language` setting
  (`zh-CN`, `zh-TW` or `en-US`; the older `en` and `zh` still work; default `en-US`), never the
  reader's: one message goes to every recipient. A stored `en` or `zh` is kept as written, so an older
  `rackbook-notify` still reads it; upgrade the module before picking one of the new tags in the console.
- Protocol errors meant for programs (OAuth `error_description`, the API's `message`) stay English.

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
  deprecated alias for at least one minor release);
- the on-disk data layout.

Every breaking release ships migration notes in its release notes.

Release plan (details in `docs/design-v0.2.md`, "Versioning"):

- **v0.5.0**: the modules panel. Merged to `main`, not tagged yet.
- **v0.6.0**: the built-in authorization server (`docs/oauth-server.md`) and
  the MCP surface (`docs/mcp-surface.md`).
- **v0.6.1**: record documents. It and GitHub App authentication were
  planned for v0.6.0 and moved here (owner, 2026-11-18); the App moved on to v0.7.2.
- **v0.7.0**: the console, configured text and server-side text in zh-CN, zh-TW and
  en-US, with English codes in the data.
- **v0.7.1**: read-only `/infra` pages for an Ansible + SOPS repository and its
  infra hub status (`--infra-*` flags, OIDC admins only, never on MCP).
- **v0.7.2**: GitHub App authentication for the ledger and the infra repository
  (`--github-app-id`, `--github-app-key-file`; replaces the SSH deploy keys, which
  keep working when no App is configured).
- **v0.7.3**: the infra editors (host_vars, feature switches, groups, history with revert),
  one commit per edit straight to the infra branch, behind a pinned identity provider
  (`--infra-oidc-issuer`, `--infra-oidc-client-id`, required from this version) and a recent sign-in
  (`--infra-write`, `--infra-write-max-age`). Secrets editing (SOPS) is a later phase.
- **v0.7.4**: the secrets editor (decision 25): key names, audited reveal, set and delete of the
  hosts' SOPS values and secret feature settings, with Rackbook's own age key
  (`--sops-age-key-file`); `sops` and `age` in the container image.
- **v0.8.0**: one record per file storage; the deprecated MCP tool names are
  removed. Both were planned for v0.7.0 and moved here (owner, 2026-11-20).

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
  `get_record`、`search`、`create_record` 等）从 v0.6.0 起作为已弃用别名继续可用，v0.8.0 移除。
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

基础设施视图与编辑（v0.7.3）：给 `serve` 加 `--infra-repo`（一个 Ansible + SOPS 仓库的 git 克隆）后，管理员可在 `/infra`
查看主机清单与各机器的 host_vars、功能开关、基础设施中心（infra-hub）上报的应用状态、证书、IP 列表和最近
50 个提交。能用 `/infra` 的人由 `--infra-admins` 指定（不是 `auth.roles`，也不来自台账里的 `rackbook.yml`），
必须是用控制台 OIDC 登录的会话，并且登录所用的身份提供方必须正是 `--infra-oidc-issuer` 与 `--infra-oidc-client-id`
固定的那一个（签发方、客户端 ID、身份声明 `--infra-oidc-identity-claim` 和租户 `--infra-oidc-tenant` 都来自命令行，不来自台账里可被改动的 `auth.oidc`）；API 令牌、MCP、OAuth 令牌一律 `403`。
加上 `--infra-write` 后，管理员还能编辑 host_vars、按 `feature.yml` 生成的功能开关表单和主机分组，并在提交历史里还原某次提交：
每次保存就是一个直接提交到主分支的提交（作者是登录的人，带 `Edited-by`、`Edited-via`、`Files` 尾注），提交前由
Rackbook 自己检查（YAML、重复键、清单形状、受管主机的 host_vars 与 SOPS 文件、功能设置、密钥扫描；host_vars 里不许有模板语法和 `ansible_*` 变量，不许有锚点、别名、合并键；group_vars 不可编辑），写入需要最近
`--infra-write-max-age`（默认 12 小时）内登录过。密钥（SOPS）的编辑见 v0.7.4：加上 `--sops-age-key-file`（Rackbook 自己的 age 密钥，镜像里自带固定版本的 `sops` 与 `age`）后，每台主机多一个“密钥”页，只列键名；“查看”单独请求、不缓存、限速并写审计（不含值）；设置、删除各是一次提交；功能里 `secret: true` 的设置写入 `feature_<功能>_<设置>`。状态文件（`--hub-status-file`）超过 3 分钟
没更新时显示“状态不可用”。详见上面的 *Infrastructure view and editors*。
