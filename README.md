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
  detail pages with everything that references the record, schema-driven
  create/edit/delete forms). Every save is a Git commit with the editor's
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

## Deployment behind Cloudflare Access

Rackbook is designed to run on a private host behind Cloudflare Access
(Cloudflare Tunnel or a reverse proxy in front). It works in its own clone of
the data repository and pushes every edit.

1. **Deploy key.** Create an SSH key and add it to the data repository as a
   deploy key *with write access*. Clone the repository on the server with
   that key into a directory the container can write, e.g. `/srv/rackbook/repo`.
2. **Access application.** In Cloudflare Zero Trust create a self-hosted
   application for the hostname, with a policy for the people allowed in.
   Note your team name (`<team>.cloudflareaccess.com`) and the application's
   **AUD tag**.
3. **Run it.**

   ```yaml
   # compose.yaml
   services:
     rackbook:
       image: ghcr.io/kazuhahub/rackbook:1
       restart: unless-stopped
       command: serve --listen 0.0.0.0:8080 --config /data/repo/rackbook.yml
       environment:
         RACKBOOK_AUTH: cloudflare-access
         RACKBOOK_CF_TEAM: your-team
         RACKBOOK_CF_AUD: your-aud-tag
         RACKBOOK_BASE_URL: https://ledger.example.com
         RACKBOOK_COMMITTER: "Rackbook <rackbook@example.com>"
         GIT_SSH_COMMAND: ssh -i /data/deploy_key -o IdentitiesOnly=yes
       volumes:
         - /srv/rackbook:/data
       ports:
         - "127.0.0.1:8080:8080"
   ```

   Point the tunnel / reverse proxy at `127.0.0.1:8080`. `RACKBOOK_BASE_URL` is
   the public URL: it is used in `llms.txt` and accepted as the browser origin
   for writes when your proxy rewrites the `Host` header. Rackbook verifies
   the `Cf-Access-Jwt-Assertion` header on every request (signature, issuer,
   audience, expiry) — a request that bypasses Access is rejected — and uses
   the `email` claim as the Git author of edits. Restrict who may edit with
   `auth.editors` in `rackbook.yml`, or assign roles with `auth.roles` (below);
   everyone else Access lets in can read.
4. **AI agents.** Give an agent an Access service token and point its MCP
   client at `https://<host>/mcp`, sending `CF-Access-Client-Id` /
   `CF-Access-Client-Secret`. Or run `rackbook mcp` locally against a clone. To
   let people and agents sign in through an OAuth provider (MCPHub, Entra ID,
   Keycloak, ...) see [Any OAuth provider](#any-oauth-provider-mcp-and-mcphub).

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
authorization server you already run; Rackbook never sees a password and has no
authorization server of its own. It verifies the access tokens the server
issues, offline, and applies the same `auth.roles` as the console. Tokens are
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
`/mcp` still accepts console users (Cloudflare Access) as before.

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

**Network.** `/mcp` validates tokens itself, so it must not sit behind
Cloudflare Access login. Add an Access **Bypass** policy for exactly `/mcp`,
`/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp`
(the rest stays protected), or have MCPHub call Rackbook over the local
network or Tailscale and keep Access in front of everything else.

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

#### What agents may write

MCP offers `create_record`, `update_record` and `delete_record` (same
validation and conflict rules as the API, `hash` from `get_record`), plus the
read tools `record_history` and `list_problems`. Writes by an OAuth user or an
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
  (`/api/c/…`, `/api/meta`, `/api/check`, `/api/history`), exports and
  `/llms*`. Account, passkey, user, token and type endpoints refuse them.
- Failed attempts are rate-limited per client IP (10 per minute, then `429`);
  the console login endpoints use the same client address, IPv6 counted per
  /64. The IP is the connecting address; `CF-Connecting-IP` is believed only
  from proxies listed in `--trusted-proxy` (CIDRs).
- `rackbook token list` and `rackbook token revoke <name> [--commit|--push]`
  work on the file directly; "last used" is kept in memory only.

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

Instead of Cloudflare Access, Rackbook can log people in itself with OpenID
Connect (tested with Microsoft Entra ID), optionally with passkeys. It keeps no
database: sessions are signed cookies, roles live in `rackbook.yml`, and passkey
public keys are committed to `.rackbook/passkeys.yml` in the data repository.

```yaml
# rackbook.yml
auth:
  mode: oidc                          # none | cloudflare-access | oidc
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

## Secret scanning

Rackbook runs Git with hooks disabled, so a pre-commit hook in your data
repository (gitleaks and the like) never sees its commits. Without a check of
its own, a password pasted into a record would be committed and pushed into
history. Rackbook therefore scans what it is about to write, before anything
touches the disk or Git. It is on by default.

It covers every write path: records created or updated through the console and
API, the MCP write tools and `rackbook add` / `set`; data type changes (the
defaults, examples, constants and enum values in schemas); the names and labels
in the passkey and token state files (public keys, ids and hashes are exempt);
and the edits made when a delete clears references. Every string in a record is
scanned, including nested values and field names. The rule set also covers GitLab, npm, Hugging Face, Tailscale, SendGrid and Azure
keys and `Bearer` tokens. Titles and descriptions in types and schemas are
scanned, and `rackbook check` scans the names in `.rackbook/` state files.
A refused write returns
`422 {"error":"secret_detected","findings":[...]}` (the console shows it on the
field), an MCP tool error with the same findings, or exit code 1 from the CLI.
A finding gives the rule, collection, record id, the JSON pointer of the field
and the first few characters of the match; never the secret. Secrets already in
the repository are reported by `rackbook check` and `/api/check` as issues with
rule `secret`, so CI catches hand-committed ones.

The rules: PEM private keys, age secret keys, GitHub tokens, OpenAI and
Anthropic style keys, Slack tokens, AWS access key IDs, Google API keys, Stripe
live keys, JWTs, `password:` / `secret=` / `token:` style assignments (also a
field named `password`), long hex strings assigned to `key:`, and URLs with a
password in them. The rule IDs (`private-key`, `age-secret-key`,
`github-token`, `github-pat`, `openai-api-key`, `slack-token`,
`aws-access-key-id`, `google-api-key`, `stripe-live-key`, `jwt`,
`secret-assignment`, `hex-key`, `url-credentials`) are stable.

```yaml
# rackbook.yml
secret_scan:
  enabled: true                 # default; false logs a startup warning
  extra_patterns:               # your own rules; group 1, if any, is the secret
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
the whole `BEGIN` to `END` block. A field named like a secret (`password`,
`passphrase`, `token`, `api_key`, ...) counts its whole value, spaces included,
and so does everything inside it. The matched value is the whole match, except for
`secret-assignment` and `hex-key` (the text after the `:` or `=`),
`url-credentials` (`user:password`) and extra patterns with a capture group
(group 1); quotes and a trailing `,` or `;` are not part of it. Compute it with
`printf %s 'the value' | shasum -a 256`. An invalid pattern or an unknown rule
ID is a config error.

#### Public fields, placeholders and free text

Free text has no exemptions. Notes, descriptions and any other unannotated
string are scanned in full, with no "near a fingerprint" or "stored in
1Password" leniency, after being split into tokens so that a leading `*`, `/`,
quote or bracket never hides a match. The only ways out are:

1. **A schema annotation** on a property that is public by design:

   ```json
   "ssh_key": {"type": "string", "x-rackbook": {"public": "ssh_public_key"}}
   ```

   Kinds: `ssh_public_key` (`ssh-ed25519 AAAA...` and the other OpenSSH public
   key algorithms), `fingerprint` (SHA256 or MD5), `nodekey` (`nodekey:`,
   `machinekey:` or `discokey:` plus 64 hex), `age_recipient` (`age1...`),
   `pem_public_key`, `jwk_public` (no private members), `hex_id` and
   `secret_reference` (`op://...`, `vault:...`, `env:NAME`, `${NAME}` or a path
   without spaces). Only an annotated field whose whole value has the strict
   format of its kind is exempt; any other value in it is scanned as text. On an
   array, or on its `items`, every item is checked. Remember that `$HUNTER2`
   has the shape of an environment variable reference.
2. **Exact placeholders** (`待补`, `TBD`, `-`, `***`, `n/a`, `none`, or an empty
   string), matched as the whole value.
3. **The allow list** above.

A field named like a secret (`password`, `passphrase`, `secret_key`,
`api_key`, `client_secret`, `signing_key`, `private_token`, `access_token`,
anything ending in `_secret`, `_password` or `_token`, ...) counts its whole
value, spaces included, and so does every string and map key inside it, unless
it is an exact placeholder or an annotated `secret_reference`. Expect some false
positives in notes; that is intended.

This is pattern based. It catches secrets with a recognisable shape or a
telltale label, not arbitrary high-entropy strings, and it is not a replacement
for an entropy-based scanner such as gitleaks or trufflehog in CI over the
whole repository. Known false-positive risks: free text such as
`password: required-for-ssh` after a keyword, hostnames that start with `sk-`,
and long hex values assigned to a name ending in `key` that are not secret;
annotate the field or add an allow entry. A record id built from a secret is
shown redacted (4 characters and a short hash) in findings, check output, commit
subjects and `Record:` trailers.

## Development

```bash
make build        # web console (npm) + Go binary with the console embedded
make test         # go test ./...
npm --prefix web run dev:mock   # console against a mock API built from the example
```

## License

[Apache-2.0](LICENSE)

---

## 中文说明

Rackbook 是一个以 Git 为核心的基础设施台账：设备、内网地址、服务端口、网段规划、
站点、端口规范、待办等，以 YAML 文件的形式放在 Git 仓库里，作为唯一的真实来源。

- `rackbook check`：按 JSON Schema 校验每条记录，并检查配置里声明的跨表规则
  （主键唯一、引用存在、与 inventory 分组一致等），适合放进 CI。
- `rackbook serve`：中文网页控制台，可搜索、筛选、排序；设备详情页列出它的内网地址和
  服务端口；新增 / 编辑 / 删除表单按 Schema 校验，保存即提交到 Git（作者为编辑者）并推送。
- `rackbook mcp`：MCP 服务，让 AI 读取台账。
- `rackbook export`：导出 Markdown、`llms.txt`、JSON。

写入时只替换被修改的那一条记录所在的行，注释、空行和原有格式保持不变，Git diff 一目了然。

快速试用：

```bash
rackbook check --config examples/homelab/rackbook.yml
rackbook serve --config examples/homelab/rackbook.yml --no-git   # 打开 http://127.0.0.1:8080
```

部署：放在 Cloudflare Access 后面（见上文 “Deployment behind Cloudflare Access”）。
服务器用带写权限的 deploy key 克隆数据仓库；Rackbook 校验每个请求的
`Cf-Access-Jwt-Assertion`，用其中的邮箱作为提交作者；`auth.editors` 可限定谁能编辑，
`auth.roles`（admin / editor / viewer）可按身份、`*@域名`、`mcphub:用户名`、`*` 分配角色。

内置登录：`auth.mode: oidc`（Microsoft Entra ID 等 OIDC，见上文 “Built-in login”）。
会话是 HMAC 签名的 Cookie（`RACKBOOK_SESSION_KEY`），不存数据库；客户端密钥只从
`RACKBOOK_OIDC_CLIENT_SECRET` 读取；角色每次请求都按 `auth.roles` 重新计算，没有角色的账号会被拒绝（403）。
可选通行密钥（`auth.passkeys`），凭据提交到数据仓库的 `.rackbook/passkeys.yml`。

Rackbook 永远不会 force push，也不会改写或删除远端分支和标签。若发现远端历史被他人改写，
会暂停所有写入（返回 503 `history_rewritten`）、继续只读提供最后一个可信提交，并在控制台显示红色横幅；
管理员确认后用横幅按钮或 `rackbook serve --accept-remote <提交>` 恢复。
