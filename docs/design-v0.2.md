# Rackbook v0.2 design

Status: draft for the owner's review — nothing in sections 1–6 is built yet.
Builds on [design.md](design.md) (v0.1). Section 7 lists what needs the owner's
decision.

v0.2 has four parts:

1. Console polish and motion (in progress, needs no design).
2. Built-in login: OIDC (Microsoft Entra ID), optional passkeys, sessions and
   roles. Cloudflare Access stays as an alternative.
3. Data types and relations managed from the console.
4. API tokens so MCPHub can call `/mcp`, plus MCP write tools.

Plus what these pull in: Git-backed auth files, per-record history, an account page, and documentation for Entra and MCPHub.

---

## 1. No database: Git plus memory

Decided with the owner: Rackbook stays database-free. Everything durable lives
in the data repository; what cannot go to Git is short-lived and kept in
memory.

| what | where | notes |
|---|---|---|
| roles | `rackbook.yml` (`auth.roles`) | reviewed Git changes |
| passkey credentials | `.rackbook/passkeys.yml` in the data repo | public key, credential id, user handle, identity, name, created; committed on enrol/delete. Public keys are not secrets. |
| API tokens | `.rackbook/tokens.yml` | name, prefix, SHA-256 of the secret, scope, created by/at, expiry, revoked; committed on create/revoke. The hash of a 32-byte random token reveals nothing usable. |
| pending OIDC logins, passkey ceremony challenges | memory (bounded, 10 min / 5 min TTL) | a restart only makes someone mid-login click again; a replayed state fails because it is gone |
| session signing key | `RACKBOOK_SESSION_KEY` env (or `--session-key-file`) | refused at startup if missing when a login mode is on |
| token "last used", failed-login counters | memory | reset on restart |
| audit (logins, failures, logouts) | structured server log (stdout → docker / journald) | data, type, passkey and token changes are already Git commits |

- `.rackbook/` files are ordinary YAML read with the same loader, validated by
  built-in schemas, and written with the same line-splicing Git path; their
  commits use the subject `rackbook(auth): …` and the acting user as author.
  They are hidden from collections, exports and MCP.
- Consequences accepted by the owner: no signature-counter clone detection for
  passkeys (synced iCloud/Google passkeys report 0 anyway, and go-webauthn's
  check is skipped when the stored counter is not advanced); token "last used"
  only since the last restart; "log out everywhere" = rotate the session key
  (logs out all users).
- Recovery when nobody can log in: edit `rackbook.yml` / `.rackbook/*.yml` in
  Git like any other file.

## 2. Login

### 2.1 Modes

```yaml
# rackbook.yml
auth:
  mode: oidc                 # none | cloudflare-access | oidc
  oidc:
    issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
    client_id: 00000000-0000-0000-0000-000000000000
    # secret only from the environment: RACKBOOK_OIDC_CLIENT_SECRET
    scopes: [openid, profile, email]
    identity_claim: preferred_username   # Entra: UPN; "email" is often empty
    name_claim: name
    allowed_tenants: [<tenant-id>]       # Entra: check the tid claim
  passkeys: true             # optional, only with mode: oidc
  session:
    idle: 12h
    absolute: 7d
  roles: …                   # 2.4
```

- Flags and env vars (`--auth`, `RACKBOOK_AUTH`, …) still override config, as
  in v0.1, so existing v0.1 deployments keep working unchanged.
- `cloudflare-access` is unchanged; it gains the same `roles`. Access in front
  of `oidc` also works (two layers).
- `none` stays for local use on loopback only (v0.1 rule).

### 2.2 OIDC flow

- Library: `github.com/KazuhaHub/authcore/oidc` (see section 7, decision 1).
  It handles discovery, state, nonce, PKCE S256, ID-token verification and
  token exchange. Rackbook adds what the package leaves to the application.
- `GET /auth/login?return=/c/devices` shows the login page: a "使用 Microsoft
  登录" button, plus "使用通行密钥登录" when passkeys are enabled.
- `GET /auth/oidc/start` calls `Begin`, stores `State` in the in-memory pending
  store keyed by a random id, sets a short-lived `__Host-rackbook_login` cookie holding
  that id (the browser binding), and redirects to the IdP.
- `GET /auth/oidc/callback` does the following:
  1. rejects duplicate or missing `state`/`code`, and an IdP `error`, with a
     friendly page;
  2. checks the cookie binding, then atomically takes the state, so a second
     callback for the same state fails;
  3. calls `Complete` and decodes the claims with an explicit schema;
  4. checks `tid` against `allowed_tenants`;
  5. maps the identity (claim from `identity_claim`, lowercased);
  6. evaluates roles, and refuses with a 403 page (logged) if no
     role matches;
  7. issues the session and redirects to `return`. Only same-origin relative
     paths are allowed, so there is no open redirect.
- `POST /auth/logout` (CSRF guarded) clears the session. It does not log out
  of Entra, so a later login may go through without a prompt; the page says so.
- Redirect URL = `--base-url` + `/auth/oidc/callback`. authcore requires
  **HTTPS** for it, so OIDC needs a public HTTPS URL, or `https://localhost`
  for local testing (section 6).

### 2.3 Sessions

- Cookie `__Host-rackbook_session` (`Secure`, `HttpOnly`, `SameSite=Lax`,
  `Path=/`). Its value is an HMAC-SHA256-signed payload
  `{identity, method (oidc|passkey), issued, last_seen}`. The server keeps no
  session rows.
- Idle timeout 12 h, refreshed at most once every 5 min; absolute 7 d. Both are
  configurable.
- Logging out clears the cookie. Logging everyone out = rotating
  `RACKBOOK_SESSION_KEY`. Removing someone from `roles` locks them out at once
  (roles are checked on every request).
- The role is **not** stored in the cookie; it is evaluated from config on
  every request, so changing `roles` in Git takes effect within one pull
  interval.
- The existing write guard (Sec-Fetch-Site / Origin) and JSON content-type
  checks stay; `SameSite=Lax` adds a second layer.

### 2.4 Roles

```yaml
auth:
  roles:
    admin:  [kazuha@kazuha.org]       # everything below + data types, tokens, users
    editor: ["*@kazuha.org"]          # create/edit/delete records
    viewer: [guest@example.com]       # read only
```

- Entries are exact identities or `*@domain`. Matching is case-insensitive.
  The highest matching role wins.
- Entra group object IDs are an option (`group:<object-id>`, read from the
  `groups` claim when the app registration emits it). Not needed at first.
- No `roles` block means every authenticated user is an editor (v0.1
  behaviour); `auth.editors` from v0.1 is still read as `roles.editor`.
- No match means no access. A tenant-wide Entra app therefore does not open
  the ledger to the whole tenant.
- Roles live in `rackbook.yml`, so changing them is a reviewed Git change. v0.2
  has no role-editing UI (that would let an admin promote themselves without
  review). The **用户** page (admin) lists users seen, their effective role and
  passkeys (from `.rackbook/passkeys.yml`), with delete.

### 2.5 Passkeys

- Library: `github.com/KazuhaHub/authcore/passkey` at the tag pinned with oidc.
  Rackbook implements its `CredentialStore` on `.rackbook/passkeys.yml` (one Git
  commit per enrol/delete; sign-count updates are not persisted) and uses the
  package's bounded in-memory `SessionStore`.
- **Enrolment** is from **我的账户** after an OIDC login, so the identity is
  already proven. Users can name, list and delete their passkeys. Enrolment
  needs a login within the last 10 minutes; otherwise the page asks to log in
  again.
- **Login** is discoverable (no username): the credential resolves the user
  handle, which resolves the identity. The role is then evaluated exactly as
  for OIDC, so a passkey never outlives removal from `roles`.
- Sign counters are not persisted (section 1), so there is no clone warning.
- RP ID = host of `--base-url`; `--base-url` is required when passkeys are on.
  User verification is `preferred`, configurable to `required`.
- Passkeys are an alternative to OIDC, not a second factor. A user who loses
  every passkey just logs in with OIDC.

### 2.6 What changes elsewhere

- The commit author is the session identity and display name:
  `Name <identity>`; `Edited-by:` and a new `Edited-via: rackbook (oidc|passkey|token:<name>)`.
- `/api/meta` `user` gains `role`, `authMethod` and `canAdmin`; the console
  hides edit and admin controls by role, and the server enforces them anyway.
- `rackbook check`, `export`, `list` and `mcp` (stdio) are local and unaffected.

## 3. Data types and relations in the console

### 3.1 Pages (admin only)

**数据类型** lists collections (icon, title, group, record count, file,
schema). Opening one shows:

- **基本**: name (immutable once created), title, description, group, icon,
  data file and path (creation only), key fields, label field.
- **字段**: an ordered table — name, title, type, required, unique, list column,
  facet — with add/edit/remove/reorder. Field names are immutable once data
  exists (no rename in v0.2).
- **关系**: outgoing references, with incoming ones shown read-only.
- **校验规则**: rules involving this collection (`ref`, `unique`,
  `same_set`). `same_set` can only be edited by hand in YAML in v0.2 and shows
  read-only.
- **预览**: the JSON Schema and the `rackbook.yml` diff that will be committed.

### 3.2 Field types

| type | JSON Schema written | options |
|---|---|---|
| 文本 | `string` | min/max length, regex pattern, examples (suggestions) |
| 长文本 | `string`, `format: textarea` | |
| 整数 / 数字 | `integer` / `number` | min/max |
| IP 地址 | `string`, `format: ip` / `ipv4` / `ipv6` | |
| 网段 (CIDR) | `string`, `format: cidr` | IPv4/IPv6 |
| 端口 | `integer`, 1–65535 | |
| 端口 + 协议 | `string`, `format: port-spec` | e.g. `TCP 443`, `UDP 41641` (free-text ports in the current ledger stay 文本) |
| 域名 | `string`, `format: hostname` | |
| URL | `string`, `format: uri` | |
| 枚举 | `string` + `enum` | values, optional colours for badges |
| 布尔 | `boolean` | default |
| 日期 | `string`, `format: date` | |
| 引用 | `string` (or `array` of strings when multiple) + a `ref` rule | target collection and field, allowed literals (e.g. `all`), single/multiple |

- The console type is stored as `x-rackbook-type` on the property, so it can
  be shown again exactly; standard keywords carry the meaning. Hand-written
  schemas with other keywords are preserved, and the editor marks those fields
  "高级（在 YAML 中编辑）".
- Formats `ip`, `cidr`, `port-spec`, `textarea` and `date` are registered in
  the Go validator and the console's ajv, so both validate identically.
- **unique** adds a `unique` rule in `rackbook.yml`; required goes in schema
  `required`.

### 3.3 References (relations)

- A reference field picks a target collection and target field (default: its
  key). Forms show a searchable picker of target records; detail pages show
  incoming references as tables (as `devices` does in v0.1).
- Each back-reference section can get a title (`backref_title`) and list
  columns.
- Deleting a record that others reference is refused with the list of
  referencing records. Optionally, with a confirm dialog, those references are
  cleared in the same commit; this is per-record, not configured.

### 3.4 Saving a type change

- One commit through the existing Git write path: fetch, apply, validate
  everything, commit as the admin
  (`ledger(types): edit services — add field "owner"`), push, with the same
  replay and conflict rules.
- The schema JSON is rewritten with 2-space indentation and the existing key
  order kept. The collection's entry under `collections:` in `rackbook.yml` is
  spliced like a record (the rest of the file, comments included, untouched);
  rules are added or removed the same way. New collections also create their
  data file (default `docs/ledger/<name>.yml`, a top-level list) and schema
  file (`schemas/<name>.json`).
- Every save is preceded by a **dry run**: `POST /api/types/{name}/plan`
  returns an impact report with the commit preview (files and diff), records
  that would become invalid (linked), references that would dangle, and
  back-references that would appear or disappear. "保存" stays disabled until
  the plan is clean, or until the chosen migrations make it clean.
- Changes that would make existing data invalid are **refused**, except where
  one of these migrations, applied in the same commit, fixes them:
  - removing a field that has values → also delete it from the N records;
  - adding a required field → fill a default into the N records;
  - narrowing a type (e.g. 文本 → IP 地址) → refused, with the N records that
    don't fit listed; fix them first, then retry.
- Removing a collection is allowed only when it has no records and no
  incoming references. Its config entry and schema are removed; the empty data
  file is left in place.
- Renaming fields or collections is out of scope for v0.2 and is refused
  with a message.

## 4. API tokens and MCP

### 4.1 Tokens

- **令牌** page (admin): create (name, scope, expiry: none / 30 / 90 / 365
  days), list (name, scope, prefix, created by/at, expiry, last used), revoke.
  The secret is shown once, with a copy button and a ready MCPHub config
  snippet.
- Format `rbk_` + 32 random bytes (base62), about 47 characters; the first 8
  characters after `rbk_` are a visible prefix for identification. Stored as
  SHA-256 and compared in constant time. A fast hash is the standard choice
  for high-entropy tokens; no plaintext is kept.
- Scopes:
  - `read` (default): every GET under `/api`, every MCP read tool, the exports.
  - `write`: also record create/edit/delete through the API and the MCP write
    tools. The commit author is `token:<name>` on behalf of `<creator>`, and
    the trailer is `Edited-via: rackbook (token:<name>)`.
  - Tokens can never manage data types, tokens or users.
- Accepted as `Authorization: Bearer rbk_…`, only on `/api/*`, `/mcp`,
  `/export.*` and `/llms*`; never as a console login.
- `last used` is kept in memory (since the last restart). Expired or revoked
  tokens get 401, and failures are rate-limited per client IP (`CF-Connecting-IP` when it
  comes from a trusted proxy, else the remote address).
- When a token's creator is no longer an admin, the token keeps working until
  revoked. The token list shows a warning on such tokens. (Alternative:
  auto-disable; see section 7.)

### 4.2 MCP

- Read tools as in v0.1; descriptions get examples.
- New write tools, only for `write` tokens and editor+ sessions:
  `create_record`, `update_record` (requires `hash` from `get_record`) and
  `delete_record` (requires `hash`). They follow the same validation and
  conflict rules as the API, and return the commit.
- New read tools: `record_history(collection, id)` and `list_problems`.

### 4.3 MCPHub registration (goes into the README)

```json
{ "name": "rackbook",
  "config": { "type": "streamable-http",
              "url": "https://ledger.example.com/mcp",
              "headers": { "Authorization": "Bearer rbk_…" } } }
```

Behind Cloudflare Access, MCPHub's request must get through Access first.
Either add a **Bypass** policy for the path `/mcp` (Rackbook's token then
authorises), or keep Access and add an Access service token to the headers
(`CF-Access-Client-Id` / `-Secret`) next to the bearer token. The README
documents both; the second keeps two layers.

## 5. Supporting features

- **Per-record history.** Every Rackbook commit gets a `Record:
  <collection>/<id>` trailer. The detail page's "最近修改" then shows that
  record's commits (author, time, subject, a field-level diff from the YAML
  splice), falling back to the file's history for commits made elsewhere.
- **Audit**: logins, failures and logouts go to the structured server log;
  everything else (data, types, passkeys, tokens) is a Git commit.
- **Account page** (我的账户): identity, role, login method, own passkeys.
- **Login and error pages** in Chinese: 403 no role, expired session and IdP
  error.
- **Security headers.** The CSP keeps `'unsafe-eval'` (ajv, as in v0.1). WebAuthn
  needs no CSP change.
- **Docs.** README sections for Entra app registration (redirect URI, client
  secret, ID-token claims, `tid`), passkeys, roles, tokens/MCPHub, state
  backup, and v0.1 → v0.2 upgrade (no breaking changes).

## 6. Testing, review, demo

- Unit and integration tests: `.rackbook/` stores and their Git commits;
  session sign/expiry/key rotation; the
  OIDC callback against an in-process HTTPS test IdP (httptest TLS, signed
  RS256 ID tokens), covering replayed state, wrong cookie, wrong tenant, no
  role and open-redirect attempts; passkey ceremonies with go-webauthn's
  virtual authenticator helpers; tokens (hash, scope, expiry, revoke, rate
  limit); type planner (each migration, every refusal path); MCP write tools.
- Opus adversarial review before every commit, as in v0.1.
- **Demo before every merge or tag** (owner's rule): `rackbook serve` on a
  copy of the example in the browser pane, with screenshots and the URL, and a
  wait for the owner's OK. For login, the demo needs HTTPS and a real IdP:
  `rackbook serve --tls-cert/--tls-key` with a local certificate for
  `https://localhost:18443` and a test Entra app registration (redirect
  `https://localhost:18443/auth/oidc/callback`). See section 7, decision 2.

Order: (1) polish → demo → merge. (2) state store + OIDC + sessions + roles +
account page → demo. (3) passkeys → demo. (4) tokens + MCP write tools +
MCPHub docs → demo. (5) data types + relations + history → demo. Then tag
v0.2.0 after the owner's OK. Each step is its own PR.

## 7. Decisions

Agreed with the owner on 2026-11-18:

1. Use `authcore/oidc`. Develop against authcore `main`; before login merges,
   the authcore side verifies and tags a release that includes `oidc`
   (e.g. v0.7.0), and Rackbook pins that tag. Passkeys from the same tag.
2. Demo login with a test Entra app registration (redirect
   `https://localhost:18443/auth/oidc/callback`); the owner keeps the client
   secret in an environment variable.
3. A token whose creator is no longer an admin keeps working, with a warning
   in the token list.
4. No database: roles in `rackbook.yml`, passkeys and token hashes in
   `.rackbook/` in the data repo, short-lived state in memory (section 1).

### Decisions, round 2 (2026-11-18)

5. **AI agents may write through MCP**, with the same validation and Git path
   as the console.
   - MCP write tools: `create_record`, `update_record` (needs `hash`) and
     `delete_record` (needs `hash`).
   - Commits carry `Edited-via: mcp (token:<name>)` and
     `Edited-by: <token creator>`.
   - **Token writes land as a pull request by default**, not on the tracked
     branch. Each call opens its own PR from `rackbook/token/<name>/<timestamp>`,
     so token writes are contributor-level.
   - **Deletes through MCP or a token always go through a PR**, even for a
     token that is allowed to push directly.
   - A token may be granted direct push (`write_mode: push`) only by an admin,
     and only for create and update.
   - PR mode needs `RACKBOOK_GITHUB_TOKEN` on the server, with pull-request
     permission on the data repo.
   - **A token can never exceed the permissions of the user who created it**:
     - it is evaluated against the creator's *current* role on every request;
     - it is optionally narrowed per collection and per action
       (`collections: [services, addresses]`, `actions: [create, update]`);
     - if the creator loses a role, the token shrinks with it; if the creator
       has no role, it stops working.
   - This replaces decision 3 ("keeps working with a warning") for anything
     beyond what the creator still holds. The token list warns when a token is
     limited by its creator's role.
6. **Never force push or rewrite history.**
   - Rackbook never runs `push --force`, `--force-with-lease` or a `+refspec`.
     It never deletes or rewrites remote branches or tags, and never resets
     anything on the remote.
   - Every push is fast-forward only (`git push origin HEAD:refs/heads/<branch>`).
   - If the remote moved, Rackbook fetches, re-applies the semantic edit on the
     new tip, re-validates and pushes again (at most 3 attempts). If that still
     fails, the user or agent gets a clear conflict error.
   - The only resets are on the server's own local clone, to the remote tip.
     They happen only after the ancestry check below.
   - A test runs every git invocation through a recorder and fails if any push
     carries a force flag or a `+` refspec, or if any `branch -D`, `push
     --delete` or `push :ref` appears. `git` is wrapped so that one function
     builds every push command line.
   - **Rewritten-history detection.** The server remembers the last remote
     commit it accepted (in memory, and in `.git/rackbook-last-good` inside its
     clone). On every fetch, at startup and before each write, it checks that the
     new `origin/<branch>` is a descendant of that commit
     (`git merge-base --is-ancestor`). If it is not:
     - Rackbook stops writing: API and MCP writes return
       `503 history_rewritten`;
     - it keeps serving read-only from the last good commit, without resetting
       the clone;
     - it logs an error and shows a red banner in the console ("远端历史被改写，
       已暂停写入"), with both commit ids.
     - An admin clears it by acknowledging after checking. The CLI command is
       `rackbook serve --accept-remote <commit>`, or the same action on an
       admin-only page; either records the new base.
   - Documented in the README and in design.md's Git section.
