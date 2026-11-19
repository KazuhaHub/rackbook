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
| token "last used" | memory, or `--state-dir`/token-use.json | reset on restart without a state dir |
| failed-login counters | memory | reset on restart |
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

> Superseded for MCPHub by decision 7 below. MCPHub does not use Rackbook
> tokens: Rackbook trusts the access tokens MCPHub issues. Rackbook's own API
> tokens remain an optional feature for scripts that don't go through MCPHub.

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
- `last used` is kept in memory (since the last restart), or in
  `<state-dir>/token-use.json` with `serve --state-dir` (written at most once a minute per token). Expired or revoked
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

### Decisions, round 3 (2026-11-18): one credential system for MCP

7. **Users log in only to MCPHub; Rackbook trusts the identities MCPHub
   issues.** There is no separate token flow for MCPHub.
   - **MCPHub side** (owner's fork, ADR 0014/0015). MCPHub is an OAuth 2.1
     authorization server. For each configured external resource
     (`systemConfig.oauthServer.externalResources: [{resource, name,
     allowedClients?}]`) it issues RFC 9068 JWT access tokens:
     - header: `alg: ES256`, `kid`, `typ: at+jwt`;
     - claims: `iss` (exactly the issuer from
       `/.well-known/oauth-authorization-server`), `aud` (the resource URL, a
       string), `sub` (MCPHub username), `client_id`, `scope` (space
       separated, may be empty), `iat`, `exp` (default 15 min) and `jti`;
     - keys are published at `jwks_uri`, and tokens are issued only when
       MCPHub's public base URL is set.

     Rackbook is registered as an upstream with `identityMode: personal`, so
     each user calls Rackbook with their own token.
   - **Rackbook `/mcp` is an OAuth protected resource.**

     ```yaml
     auth:
       mcp:
         resource: https://ledger.kazuha.private.kazuhahub.com/mcp
         trusted_issuers:
           - issuer: https://mcp.kazuhahub.com
             audience: https://ledger.kazuha.private.kazuhahub.com/mcp   # default: resource
             jwks_url: ""            # default: jwks_uri from the issuer's metadata
             username_claim: sub
             scopes: {read: "", write: "rackbook:write"}   # see authorisation below
     ```

     - It serves `/.well-known/oauth-protected-resource` (RFC 9728), naming
       the resource and the trusted issuer(s).
     - A missing or invalid token gets
       `401` + `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource"`.
       A valid token without the needed permission gets `403` with
       `error="insufficient_scope"`.
   - **Verification is offline and strict.**
     - Libraries: `go-jose/v4` for parsing, `go-oidc`'s remote key set for the
       JWKS (cached; refetched on an unknown `kid`, at most once a minute).
     - Header: only `ES256` is allowed (no `HS*`, no `none`), and `typ` must
       be `at+jwt`.
     - Claims: `iss` and `aud` must match exactly (`aud` may be a string or an
       array containing the audience). `exp` is required, `iat` and `nbf` are
       honoured, and 60 s of clock skew is allowed. `sub` is required.
     - Each issuer's metadata is fetched over HTTPS. Its `issuer` must equal the
       configured one, and its `jwks_uri` must be HTTPS. An http issuer is
       allowed only for localhost, for the demo.
     - These tokens are accepted only on `/mcp`, never as a console session
       and never on `/api/*`.
   - **Authorisation uses the same roles as the console.**
     - The token's username (`sub`) is matched against `auth.roles` exactly
       like a console identity. A username that is an email matches email and
       `*@domain` entries; others can be listed as `mcphub:<username>`.
     - `scope` can only narrow the role, never widen it. Without the
       configured write scope the write tools are refused; viewers can never
       write.
     - Writes follow decision 5. They become a pull request by default (direct
       push only for roles/collections an admin configures via
       `auth.mcp.direct_push`), and deletes are always PRs.
     - The commit author is the user (`<user>`), with trailers
       `Edited-by: <user>` and `Edited-via: mcp (MCPHub, client <client_id>)`.
   - **Network.** `/mcp` must not sit behind Cloudflare Access, because it
     validates MCPHub tokens itself. The README documents both an Access
     **Bypass** policy for exactly the path `/mcp` (plus
     `/.well-known/oauth-protected-resource`) and calling Rackbook from MCPHub
     over the local network or Tailscale.
   - **Rackbook API tokens** (section 4.1) stay as an optional feature for
     scripts that don't use MCPHub. They are bounded by their creator's role
     (decision 5).
   - **Docs** cover the MCPHub side:
     1. add the Rackbook `/mcp` URL to `oauthServer.externalResources`, with a
        name and optional `allowedClients`;
     2. set MCPHub's public base URL;
     3. register Rackbook as a `streamable-http` upstream with OAuth
        `identityMode: personal`.
   - **Tests** use an in-process ES256 issuer (metadata + JWKS) and cover: a
     good token; a wrong alg / HS256 with the public key as secret / `none`;
     wrong `typ`; wrong `iss` or `aud`; expired; future `nbf`; unknown `kid`
     with a refetch (rate limited); key rotation; a scope that narrows; a role
     miss (403); metadata whose issuer doesn't match.
   - Order of work: this replaces step 4. Token-free MCP auth comes first,
     because it needs no new state; optional API tokens come later.

### Decisions, round 4 (2026-11-18): standard MCP authorization, any OAuth provider

8. **`/mcp` works with any OAuth provider, not only MCPHub** (building now, part of v0.2).
   Each `trusted_issuers` entry has the following options:
   - `algorithms`: default ES256, RS256, PS256, EdDSA. `HS*` and `none` are
     refused at config load.
   - `require_typ_at_jwt`: default true. Set it to false for Entra/Keycloak,
     which send `typ: JWT`. An ID token presented as an access token is still
     refused.
   - `scope_claim`: reads `scope` (a string) or `scp` (a string or array).
   - `username_claim`.
   - Discovery: RFC 8414 first, then OIDC discovery, with path-insertion rules
     for issuers that have a path.
   - `kind: mcphub | oauth`. Generic identities match role entries
     `oauth:<alias>:<user>`.
   - RFC 7662 introspection for opaque tokens if it's cheap; otherwise the
     README says it isn't supported.
   - Roles, scope narrowing and PR-by-default writes are unchanged.

   The README covers MCPHub, Entra and Keycloak, and how to connect MCP
   Inspector and Claude Code.
9. **Static API tokens** (section 4.1) stay, for clients that can only send a
   fixed header.
10. **Built-in authorization server**, so standalone users without MCPHub can
    add Rackbook directly to Claude, Cursor, VS Code or MCP Inspector. It is
    proposed for **v0.6.0** (renumbered four times, see the versioning note below), before the storage work (now v0.7.0).
    **Not started: it waits for the owner's OK on placement and cost.**
    - Spec: the MCP authorization spec — OAuth 2.1 + PKCE S256, RFC 8707
      resource indicators (`aud` = the `/mcp` URL), RFC 8414 metadata, and
      client identification. Use Client ID Metadata Documents where the current
      spec revision prefers them, and RFC 7591 dynamic registration for older
      clients. The exact revision is checked against the spec text before
      building.
    - Login: through Rackbook's own OIDC or passkey login, with a consent page.
    - Tokens: ES256 JWT access tokens (10 min); rotating, one-time refresh
      tokens with reuse detection.
    - Storage: the signing key comes from a file, an environment variable or
      systemd `LoadCredential`, never Git. Grants, refresh tokens and dynamic
      registrations live in memory (section 1), so a restart makes clients sign
      in again through the browser. Persisting them would need a database or
      per-login Git churn, which the owner already ruled out.
    - Cost: about 2,500–3,500 lines of Go and TypeScript. It adds the largest
      security surface in Rackbook (authorize, token, registration and consent
      endpoints) and so needs at least two adversarial review rounds. Testing
      covers MCP Inspector and Claude Code against both the built-in server and
      an external issuer.
11. **Real-client verification in the demo**: MCP Inspector and Claude Code
    (`claude mcp add --transport http`) against an external issuer in v0.2,
    and against the built-in authorization server in v0.6.0.

### Decisions, round 5 (2026-11-18): built-in authorization server approved (ships in v0.6.0)

12. **Approved; ships in v0.6.0.** An MCP client authorizes
    **once** and never has to sign in again, including across restarts,
    upgrades and ansible redeploys.
    - **State file: the one exception to "no database".** Authorization-server
      grants live in a small state file, `<state-dir>/oauth-grants.json`. The
      default state dir is systemd `StateDirectory` (`/var/lib/rackbook`); in
      Docker it is a volume. The file holds:
      - registered clients;
      - grants: user, client, scopes, resource, created, last used;
      - **SHA-256 hashes** of refresh tokens.

      Writes are atomic (temp file, fsync, rename, directory fsync), the file
      is 0600 and the directory 0700, and one process holds a lock on it. If the
      file is lost, clients simply sign in again. Git remains the only source of
      ledger truth.
    - **Refresh tokens** are opaque random values (not JWTs) and are checked
      against the stored hashes.
      - They rotate on every use. Reusing an already-rotated token revokes the
        whole grant and is logged.
      - Expiry is sliding only: a grant unused for 90 days (configurable) is
        revoked. There is **no absolute lifetime**.
      - Access tokens are ES256 JWTs that last 10 minutes.
    - **A grant ends only** when:
      - the user or an admin revokes it. Grants are listed on the account page
        and on the admin page, with client name, created and last used;
      - the user no longer matches any role. The role is re-evaluated from the
        current config on every refresh and every request, and the check fails
        closed;
      - it goes 90 days unused.
    - **Signing key** comes from a file, an environment variable or systemd
      `LoadCredential`, never Git. JWKS publishes the current and previous key
      so access tokens stay valid during a rotation. Rotating the key **does
      not** invalidate refresh tokens, because they are not signed.
    - **Reviews and demo.** Two adversarial review rounds. The demo shows MCP
      Inspector and Claude Code against the built-in server and against an
      external issuer, and **restarts the server to show the client keeps
      working without a browser prompt**.

### Versioning (2026-11-18)

Rackbook uses SemVer (Go modules require SemVer tags). Release plan:

- **v0.2.1** — the release pipeline only: Windows builds, a native test
  matrix on six runners, SHA-pinned actions, build provenance attestations,
  and cosign signing. No feature changes.
- **v0.2.2** — security fix: the built-in secret scan on every write (see
  "v0.2.2 security fix" below).
- **v0.2.3** — Go 1.27.4 for standard library security fixes.
- **v0.3.0** — expiry tracking and modules (decision 17): the `expires` and
  `revoked` schema marks, `/api/expiring`, the `expiry_list` MCP tool, the
  到期 page, the `modules:` allow list, and the `rackbook-entra` and
  `rackbook-notify` modules.
  The v0.3.0 tag exists but was never released: the release matrix found two
  Windows-only test failures in `rackbook-notify`. Its content, plus the fix
  (and the configurable sign-in button and branding), shipped as **v0.3.1**.
  The tag stays as it is; pushed tags are never moved.
- **v0.4.0** — console usability: backref sections as URL-hash tabs with
  search and paging, general (`allow` literal) records in their own tab,
  clickable and keyboard-navigable rows, in-place editing of enum / boolean /
  date / tag cells, searchable selects, tags, suggestions and port lists in the
  forms, readable record ids (design: `design.md` section 6.1 and 6.2).
- **v0.5.0** — modules panel: an admin page (模块) that lists the modules,
  shows their runs (reported by each module with its own token, last 30 kept
  in `<state-dir>/modules.json`), pauses them, asks for a run now, and edits
  their settings under `modules.<name>.settings` in `rackbook.yml` (a Git
  commit per change, with a version check). Modules read their settings at
  start and are run every hour by a timer; they act only when a configured
  time has passed or a run was requested. Rackbook still never connects to a
  module. The settings are typed once in the shared package `modsettings`
  (outside `internal/`, because modules may not import `internal/` and the
  server may not import `modules/`). Details: `modules.md` section 7.
- **v0.6.0** — the built-in authorization server (decision 12), GitHub App
  authentication (decision 14), record documents (decision 15) and the MCP
  surface renames (decision 16). Planned as v0.4.0, then v0.5.0, until console
  usability and the modules panel took those numbers; nothing in them changed.
- **v0.7.0** — storage: one record per file (design in
  `design-v0.4-storage.md`; the file keeps its name).
- **1.0** — once the storage layout, config format and API are stable.

See README, "Versioning and compatibility".

### Decisions, round 6 (2026-11-18): separate ledger repository, GitHub App credentials (v0.6.0)

13. **Rackbook writes only to a dedicated data repository** (for the owner:
    KazuhaHub/ledger), never to an infrastructure repo. In the owner's setup
    the infra repo's `main` is applied as root on every host, so a write
    credential for it would amount to root. Infra may *read* the ledger;
    Rackbook never holds a credential for infra.
14. **GitHub App authentication (v0.6.0)**, as an alternative to deploy key +
    PAT. One credential replaces both.
    - An org-owned GitHub App, installed **only** on the data repository, with
      repository permissions `contents: write` and `pull_requests: write`.
      Nothing else.
    - Configuration:
      `write.github_app: {app_id, installation_id (optional, looked up from
      the repo), private_key_file}`. The key can also come from env
      `RACKBOOK_GITHUB_APP_KEY` or a systemd `LoadCredential` path. It never
      goes into Git.
    - Token flow: an RS256 app JWT (≤ 10 min) is exchanged for an installation
      access token. That token is narrowed in the request to the data repository
      and the two permissions, and lasts about 1 h. It is cached in memory only,
      refreshed 5 min before expiry, and never logged.
    - Git over **HTTPS** with the installation token. The token is passed to git
      through the environment (`GIT_CONFIG_COUNT`/`KEY`/`VALUE` for an
      `http.<url>.extraheader`), never on the command line, in the remote URL,
      or in `.git/config`. The git runner's allow-lists gain exactly this, and
      the never-force rules are unchanged.
    - PR mode uses the same token for the REST API. `RACKBOOK_GITHUB_TOKEN`
      stays supported for non-App setups.
    - Commit authorship is unchanged (author = the user; committer = the
      configured identity).
    - Tests: a fake GitHub API issues installation tokens. They cover expiry and
      refresh, a token that must not appear in argv or logs, push over HTTPS to
      a local smart-HTTP test server, and PRs.

### Decision 15 (2026-11-18): record documents (v0.6.0)

15. **A Markdown document per record**, for runbooks, history and anything
    else that doesn't fit fields. Generic for every collection.
    - **Location:** `docs/<collection>/<key>.md` in the data repo, linked by
      record key with no field needed. The root is configurable
      (`documents.root`, default `docs`) and so is the per-collection
      directory. A composite key uses the record id with its usual escaping,
      and the file name is made safe for every OS: Windows reserved names and
      characters are escaped. Owner's first real example: KazuhaHub/ledger
      `docs/devices/development-ovh-hillsboro-or-us-dc.md`.
    - **Lifecycle:**
      - renaming a record (a key change) moves its document in the same commit
        (`git mv` semantics);
      - deleting a record whose document exists asks whether to delete the
        document too or keep it as an orphan; nothing is removed silently;
      - `rackbook check` reports orphaned documents.
    - **Rendering:** on the record page, CommonMark + GFM tables and task lists.
      **No raw HTML** (stripped, not rendered). Links are limited to
      `http(s)`, `mailto` and relative links (relative links resolve to
      records or documents). Images come only from relative paths in the data
      repo or `https`; there are no `javascript:` or `data:` URLs.
      - Server side: the API returns the Markdown source, and the console
        renders it with a sanitizing renderer (react-markdown + rehype-sanitize
        with a strict schema).
      - Exports and MCP get the source.
    - **Editing:** in the console, with the same roles as record edits
      (editor+). Commits go through the same Git write path with the never-force
      rules, history detection and identity trailers. Commit subject:
      `ledger(<collection>): edit document <id>`.
    - **Secret scan:** covers documents too, as whole-text scanning with the
      same rules and allow-list keyed on the document path.
    - **Search and AI:**
      - full-text search covers documents;
      - `export markdown` and `llms-full.txt` include each document under its
        record;
      - `llms.txt` links to them;
      - MCP read tool `get_document(collection, id)`;
      - MCP write tool `put_document(collection, id, markdown, base_hash)`,
        which follows the PR-by-default rule (deletes always a PR).
    - **Concurrency:** writes carry the document's content hash. A mismatch is
      a 409 with the current text, as for records.
    - **Documentation:** a README section for open-source users (layout,
      config, safety rules).

### Decision 16 (2026-11-18): MCP surface design

16. **The MCP surface is designed as a whole before 1.0**, because tool names,
    arguments and result shapes are covered by the SemVer promise. The full
    design is in [mcp-surface.md](mcp-surface.md):
    - generic tools named `<family>_<verb>`;
    - families: ledger, collections, records, docs, history, changes, and
      later facts and admin;
    - `ledger_info` for feature detection;
    - resources and prompts;
    - full annotations, structured output, cursors and shared error codes;
    - `dry_run`, `expected_hash` and idempotency keys on writes;
    - scopes per family, limits, a deprecation policy and golden-file
      contract tests.

    The renames of the v0.2 tools ship in v0.6.0, with deprecated aliases that
    are removed in v0.7.0.

### Decision 17 (2026-11-18): expiry tracking and modules (v0.3.0)

17. **Credential expiry is tracked in the core; automation lives in modules.**
    The owner wants automatic and manual entry, room for more automations
    later, and the Entra collector as a separate program, rewritten in Go. The
    full design is in [modules.md](modules.md).
    - **Core, generic and small.** A schema mark
      `x-rackbook: {expires: true}` names a collection's expiry field
      (`YYYY-MM-DD`; `待补` = unknown; empty = never), and
      `x-rackbook: {revoked: true}` a field that retires a record. The core
      lists what is expired or expiring within N days: `GET /api/expiring`,
      the MCP tool `expiry_list` (a new family under decision 16's rules, read
      scope) and the console page 到期. Manual entry is unchanged. The core has
      no upstream-specific code and sends no mail.
    - **Modules are separate executables** (`cmd/rackbook-entra`,
      `cmd/rackbook-notify`, shared client `modules/rbclient`). They use only
      the public HTTP API with an API token; a test fails if the `rackbook`
      binary imports module code or a module imports `internal/`. They ship in
      the same release archives and image, with the same signing and
      attestations.
    - **Writing contract.** Records carry `source: <module>`, are upserted
      idempotently by a stable upstream id, manual records are never
      overwritten or deleted, and upstream items that vanish are marked
      revoked, never deleted.
    - **Allow list `modules:` in rackbook.yml** binds a module name to its
      token, one collection and the fields it owns. The server enforces the
      contract for those tokens: only create and update in that collection,
      `source` must be the module's name, updates only on its own records and
      only to its own fields, no deletes. `direct_push: true` lets the module's
      creates and updates skip the per-write PR (decision 5), on the same
      condition as a token's `write_mode: push` (the creator is an admin).
      This keeps decision 13: the writes still go only to the data repository
      through Rackbook's own write path; the module never holds a Git
      credential.
    - **Console.** The record page shows the source, and editing a
      module-maintained record warns which fields the next sync overwrites.
    - **Why not a plugin API inside the server:** a separate process with a
      scoped token is the smallest trust boundary. A bug or a compromised
      upstream credential in a module can at most write wrong metadata into
      one collection, through validation and the secret scan.

## v0.2.2 security fix: built-in secret scan

Rackbook runs Git without hooks (decision above), so a repository's
pre-commit scanners never see its commits, and a secret typed into a record
would be committed and pushed. v0.2.2 closes that with a deterministic,
pattern-based scan (`internal/secretscan`, on by default, configured under
`secret_scan` in `rackbook.yml`) that runs before anything touches the disk or
Git, on every write path: `edit.Apply` (API, MCP and CLI record writes, and the
edits made by `clearReferences`), `types.Apply` (schemas and the rackbook.yml
entry) and `MutateStateFile` (names and labels in passkey and token files;
public keys, ids and hashes are exempt). Nothing from the data repository is
ever executed. The scan is a safety net, not a guarantee: a secret with no
keyword and no known shape ("Hunter2Hunter2 is what we use") is out of scope.

Two tiers:

- **Block (deterministic):** key material and known token formats (PEM and
  OpenSSH, also base64-encoded; AGE-SECRET-KEY; GitHub, GitLab, npm, Hugging
  Face, Tailscale, SendGrid, Slack, AWS, Google, Stripe, OpenAI and Anthropic
  tokens; JWT; URL userinfo; key-bearing query
  parameters; private JWK). Always refused (`422 secret_detected`); only the
  allow list by value hash overrides it.
- **Confirm (heuristic):** keyword assignments in any language (after NFKC
  normalisation and zero-width stripping), the whole value of secret-named
  fields (numbers and booleans included), `key`/`privkey` plus hex (`hex-key`:
  ambiguous with node keys, fingerprints and hashes) and high-entropy tokens in
  free text.
  Refused with `422 secret_suspected` until the editor confirms: the console
  holds the write behind a "不是密钥" tick, API and MCP retry with
  `confirm_not_secret: true` (editor and admin sessions, OAuth/MCP identities
  with write rights; never for a token write that becomes a pull request, never
  for block-tier findings), the CLI takes `--confirm-not-secret`. Every
  confirmation is committed as `Secret-scan: confirmed-not-secret by <user>
  (<rule ids>)`. `rackbook check` reports confirm-tier hits as warnings, and
  not at all for a record whose last commit carries that trailer.

One rule: block-tier formats are refused in every string, always; schema
annotations, placeholders and `confirm_not_secret` only silence the confirm
tier. An exempt value is still run, whole, through the block-tier rules. The
confirm-tier exemptions come only from structure: a schema annotation
`x-rackbook: {public: <kind>}` whose whole value has the kind's strict format,
and the exact placeholders. The allow list (by value hash) is the one override
for the block tier. Free text has none. A secret-named
field may only be annotated `secret_reference`. Record ids that carry a secret are
shown as 4 characters plus 8 hex digits of a hash (not a secure hash; it only tells ids apart).
