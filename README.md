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
   `CF-Access-Client-Secret`. Or run `rackbook mcp` locally against a clone.

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
