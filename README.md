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
exact/`*@domain` entries for e-mail usernames if `auth.mcp.match_email: true`. Roles are read from the
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
refused: its `aud` is not the configured audience, or it has a `nonce` and no
scope), `audience`, `username_claim` (default `sub`), `scope_claim` (default:
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
must be `active` with matching `iss`, `aud`, `exp`; answers are cached for 60 s.

**Roles.** The user is the `username_claim` (folded to ASCII lower case) and is
matched like a console identity, with entries that name the issuer:
`mcphub:<user>` for `kind: mcphub`, `oauth:<alias>:<user>` for others (`*`
matches anyone of that issuer). Plain e-mail and `*@domain` entries match
these users only with `match_email: true`. A scope can only narrow the role:
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
      - {users: ["mcphub:alice"], collections: [todo]}
      - {roles: [admin], collections: ["*"]}
```

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
- Failed attempts are rate-limited per client IP (10 per minute, then `429`).
  The IP is the connecting address; `CF-Connecting-IP` is believed only from
  proxies listed in `--trusted-proxy` (CIDRs).
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

Rackbook 永远不会 force push，也不会改写或删除远端分支和标签。若发现远端历史被他人改写，
会暂停所有写入（返回 503 `history_rewritten`）、继续只读提供最后一个可信提交，并在控制台显示红色横幅；
管理员确认后用横幅按钮或 `rackbook serve --accept-remote <提交>` 恢复。
