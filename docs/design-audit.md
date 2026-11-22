# Audit history and roles from the identity provider

Status: design, agreed 2026-11-22. Phase 1 pieces 1 and 2 are built (3.5); the rest is not. Phase 2
starts with the light version (2a); SCIM (2b) comes later. Phase 3 is accepted. The owner's decisions of
2026-11-22 are in section 7; local accounts beside SSO, and the sign-in security settings, have their own
design, [design-local-accounts.md](design-local-accounts.md).

The team is growing. Two things are needed:

1. **One place to see every change.** Who changed what, when and from where, for the ledger, for infra and
   for the actions that leave no commit (sign-ins, refused writes, secrets revealed). Each record gets a
   version history like a shared document's: a timeline, what changed in each version, and restoring an
   old version.
2. **Roles from the identity provider.** Who may read, edit or administer comes from Entra ID (or any
   OIDC provider) without editing a list by hand for every person. Teams without SSO can still assign
   roles by hand.

The rules from [design-v0.2.md](design-v0.2.md) still hold. There is no database: Git, plus files in
`--state-dir`. Git history is never rewritten. Secret values never appear in a diff, a log or the audit
log. The ledger never decides who may use `/infra`. Security mechanisms stay standard and get a
plain-language explanation (section 8).

---

## 1. What already exists

**Changes.**

- Every ledger change is a Git commit in the data repository, authored by the signed-in person, with the
  trailers `Edited-by`, `Edited-via` and `Record: <collection>/<id>` (`internal/gitstore/commit.go`).
  `GET /api/history` lists commits per collection or per record. A record's history is the commits
  carrying its `Record:` trailer, and falls back to the collection file's history when there are none.
  `/api/history` leaves out `.rackbook/`, so token, passkey and other auth-file commits are not listed
  there.
- Every infra change made in Rackbook is a commit in the infra repository, with the same trailers. Rackbook
  keeps a full local clone (`internal/gitstore/mirror.go`). The infra Commits page shows them, with
  *Revert*.
- Infra actions that did not end in a commit go to `infra-audit.jsonl` in `--state-dir`
  (`internal/ansiblerepo/audit.go`): who, action, outcome, files and issue codes. This covers failed
  checks, conflicts, refused writes, secret reveals and re-encryption. It records no client address and
  never a value. The console does not show it.
- Sign-in and sign-out are only lines in the structured server log (`login`, `logout`, with identity,
  method and `r.RemoteAddr`).
- If the remote's history is rewritten, writes stop (`503 history_rewritten`) and the console shows a red
  banner.

**Roles.**

- `auth.roles` in `rackbook.yml` (viewer < editor < admin; the highest match wins, `internal/roles`).
  Entries can be exact identities, `*@domain`, `group:<id>`, `mcphub:`, `oauth:`, `oidc:` or `*`. Roles are
  evaluated on every request, so a change to `rackbook.yml` applies as soon as the server has pulled it.
  Removing a person *by name* takes effect then, unless a `*@domain` or `group:` entry still matches them.
- `group:<id>` matches the ID token's `groups` claim. It works for OIDC sessions only. The claim is read
  **at sign-in** and kept in the signed session cookie. The server keeps no session rows. Only the first 40
  groups, at most 700 bytes, are kept (`internal/login/session.go`), which is about 19 Entra group IDs. The
  cookie lives up to 12 h idle and 7 days absolute by default (`internal/config/login.go`).
- Passkey sign-in does not involve the identity provider at all (`internal/login/passkeys.go`). A passkey
  session has no groups.
- An API token's creator is evaluated by identity only, without groups. A creator whose role comes only
  from `group:` gives the token no role (`creator_no_role`).
- `/infra` is gated by `--infra-admins`, a server flag set in the infra deployment
  (`inventory/group_vars/rackbook.yml`), together with the pinned issuer, client, tenant and identity
  claim. This is deliberate: editing the ledger must not be able to make someone an infra admin.

## 2. Gaps

1. The history is in four places: two Git repositories, `infra-audit.jsonl` and the server log. There is
   no single timeline, and no way to filter it by person.
2. A record's history lists commits, but it does not show *what changed in the record* field by field,
   and it cannot restore an old version or a deleted record.
3. Sign-ins and role changes leave no record that the console can show.
4. Nothing shows whether an audit file was edited after the fact.
5. Someone disabled in Entra, or removed from a group, keeps their access until their cookie expires (up to
   7 days). With a passkey they can keep signing in, because a passkey sign-in never asks Entra (closed
   by switching passkey sign-in off under SSO, section 4).
6. Group roles break for people in more than about 19 groups, and do not reach their API tokens.
7. There is no read-only role for someone who must see the history but change nothing.
8. Every new `/infra` admin is a change to infra and a production deploy (phase 3).

---

## 3. Phase 1: one history

### 3.1 The audit log

One file per month, `--state-dir/audit/audit-YYYY-MM.jsonl`, append-only, one JSON object per line, mode
0600. Every line is written with a single `write` and then `fsync`.

```json
{"seq": 1842, "time": "2026-11-22T10:15:03Z", "event": "login", "identity": "oidc:…",
 "name": "Example Person", "method": "oidc", "role": "editor", "addr": "203.0.113.7", "prev": "sha256:…"}
```

Times are stored in UTC; the console shows them in the viewer's time zone. `addr` comes from
`internal/clientip` (the trusted-proxy rules), not from `r.RemoteAddr`.

Events (each with `time`, `identity`, `method` and `addr` where known):

| Event | Extra fields |
|---|---|
| `login`, `logout` | `role` (the effective role at sign-in or sign-out); `groups: overage` when the token's groups were cut off (3.1 below and 4; phase 2a) |
| `login_refused` | `reason`: `no_role`, `tenant`, `claims`, `passkey_failed` (local accounts add their own reasons, [design-local-accounts.md](design-local-accounts.md), section 10) |
| `role_changed` | `from`, `to`, `because`: `config` (a `rackbook.yml` commit) or `claims` (different groups or app roles) |
| `write_refused` | `area` (ledger / infra), `code` (`conflict`, `stale_login`, `forbidden`, `checks_failed`, …) |
| `secret_revealed`, `secret_reveal_refused`, `reencrypted` | `host`, `key` (never the value) |
| `accept_remote`, `history_rewritten` | the commits involved |
| `commit` | `area`, `repo`, `hash`, `record` (written after Rackbook's own push succeeds; this is what makes a commit *verified*, 3.2) |

A successful write is otherwise not copied into the log: the `commit` line holds only the hash and who; the
content is the commit. The activity view (3.2)
reads both. The existing `login` and `logout` server-log lines stay, so a log collector keeps working.

**Tamper evidence.** Each line carries `prev`, the SHA-256 of the previous line, and a running `seq`. A
separate file, `audit/head.json`, holds the `seq` and hash of the last line, rewritten (write, `fsync`,
rename) after every append. `rackbook audit verify` and the server at start check that:

- each line's `prev` matches the line before it (an edited, removed or reordered line breaks this);
- the last line matches `head.json` (lines cut from the end break this);
- a new month's first `prev` is the previous month's last hash.

Two crash cases are not tampering, and are repaired without a banner:

- a last line without a newline (a write cut short): reported as **truncated**, set aside in
  `audit/torn-<seq>.jsonl`, and the chain continues from the last complete line;
- `head.json` exactly one line behind, with that line correctly chained (a crash between the line's
  `fsync` and the rename of `head.json`): `head.json` is brought up to date.

Any other mismatch shows a banner to admins and is reported by `rackbook audit verify` with the first
broken `seq`.

What this does **not** protect against: someone with root on the host can rewrite the files and
`head.json` together. The optional **daily anchor** narrows that: `audit.anchor: daily` commits the head
(`seq` and hash) to `.rackbook/audit-anchors` in the data repository once a day. Rewriting anything older
than the last anchor then means rewriting Git history, which Rackbook already detects. The last day stays
open. The anchor is only available with direct push; in pull-request write mode it would open a PR every
day, so it is refused there.

**Migration.** On the first start, the existing `infra-audit.jsonl` is copied into the new log: `who` →
`identity`, `outcome` → `event` (`write_refused`, `secret_revealed`, …), and the free-text `action`,
`files` and `detail` kept as fields of their own. `audit/migrated` is written so the copy happens once. The
old file stays where it is.

**Retention and privacy.** `--audit-retention-months` (default: keep everything) deletes month files older than
the given number of months. It does not depend on the anchor. `audit/head.json` also records the first
kept file and the `prev` its first line points to, so `verify` starts the chain there instead of reporting
the deleted months as missing. With local accounts, retention does not delete the month that holds the account
store's last change; a monthly checkpoint keeps that pin to at most about one month past the configured
retention, and a delayed prune is logged ([design-local-accounts.md](design-local-accounts.md), section 4.6).
`--audit-addr full|truncate|none` (default
`truncate`: the last octet of IPv4, the last 80 bits of IPv6) controls how much of the client address is
kept. `full` still keeps an IPv6 client as its /64, because `clientip.Of`, which the rate limits share,
buckets it that way. Names are kept as the provider sent them. Both are server flags, not `rackbook.yml` keys:
`rackbook.yml` lives in the data repository, so an admin who can edit it could otherwise shorten the
retention and delete the log. The deployment decides.

**Export.** `GET /api/activity?format=jsonl` (admin, auditor) streams the same items as the activity view,
so the log can be fed to a SIEM or archived elsewhere.

### 3.2 The activity view

`GET /api/activity?since=&until=&identity=&area=ledger|infra|audit&collection=&id=&cursor=` returns one
time-ordered list from three sources: commits of the data repository, commits of the infra repository
(only with `--infra-repo`; it is a full local clone), and the audit log.

```json
{"items": [{"time": "…", "area": "ledger", "kind": "commit", "commit": "abc1234",
            "identity": "…", "name": "…", "via": "rackbook", "record": "services/ssh",
            "subject": "ledger(services): edit ssh", "verified": true},
           {"time": "…", "area": "audit", "kind": "login", "identity": "…", "role": "editor"}],
 "cursor": "…"}
```

- **Who did it.** Anyone with push access can write any author and any trailer, so neither proves who
  made a commit. A commit is **verified** only if this server made it: when Rackbook pushes a commit it
  writes the hash and the signed-in identity to the audit log (a `commit` line, part of the chain; not the
  index, which may be deleted). Without `--state-dir` there is no audit log, so every commit shows as
  unverified. For verified commits the identity comes from that record. Every other commit shows
  its Git author and trailers as written, marked **unverified**, and is not matched by the `identity`
  filter.
- **Order.** Commits are ordered by committer date, audit lines by `time`.
- **Git.** The guarded Git runner (`safegit`) allows only `log -n`, `--format` and `--grep` today. The
  activity view needs `--since`, `--until` and path limits; they are added to the allow-list explicitly.
  An index in `audit/index.json` caches what was already read. Deleting it is always safe.

Console page **Activity** (`/activity`): one timeline, filters for person, area, collection and date; each
commit opens its diff. Who may see which area:

| Area | Who |
|---|---|
| ledger commits, without `.rackbook/` | everyone with a role (as `/api/history` today) |
| `.rackbook/` commits (tokens, passkeys, anchors) and audit events about the ledger and sign-ins | admin, auditor |
| infra commits and infra audit events | `--infra-admins` and `--infra-auditors` (3.4) |

### 3.3 A record's version history

On a record page, **History** shows a timeline of the commits that changed the record:

- **What changed, field by field.** The record is read from its collection file *at that commit*. The
  file path and the type definition are also read at that commit, not today's. It is compared with the
  same record at the commit's parent: fields added, removed and changed, with old and new value. Commits
  found through the collection-file fallback in which this record did not change are left out. Values the
  secret scan hides stay hidden.
- **Who, when, from where.** As in the activity view, including **unverified**.
- **Restore this version** (editor) is done by the server, not by sending the old content from the
  browser, because the browser never receives hidden values.
  `POST /api/c/{collection}/{id}/restore {commit, hash}` reads the record at `commit` and writes it as
  **one new commit** with the trailer `Restored-from: <commit>`. History is never rewritten. The usual
  rules apply:
  - the current schema, references and the secret scan check the old content. If the old version needs a
    secret-scan confirmation, the editor is asked again, as for any write;
  - if the old content no longer fits the current schema, or its key fields would give it a different id,
    nothing is written: the old content opens in the editor, to be fixed and saved as an ordinary edit;
  - `hash` is the current version's hash, so a change made in the meantime is a conflict, as usual.

**Deleted records** per collection lists records whose last commit removed them, with the last version and
*Restore*. Finding them means reading the collection file's whole history, so this list comes from the
index.

### 3.4 The auditor capability

The roles are an ordered scale (viewer < editor < admin, the highest wins), so auditing is not a fourth
step on it. It is a **separate capability**, granted by its own list:

```yaml
auth:
  auditors: ["group:<entra-group-id>", "app-role:Rackbook.Auditor"]
```

Being an auditor includes viewer access to records, plus reading and exporting the audit areas of the
activity view. Nothing more: an auditor cannot reveal secrets and is never shown *Restore* unless their
role is editor or higher. An admin is not automatically an auditor.

Older servers ignore keys they do not know (`rackbook.yml` is not decoded strictly), so on an older server
`auth.auditors` simply grants nothing. Bumping the Rackbook version in the ledger's CI first is advised, so
that CI checks the new key, but not required.

For `/infra`, auditors are a second deploy flag, `--infra-auditors`, with the same pinned issuer, client,
tenant and identity claim as `--infra-admins`, and OIDC sessions only. The reason is the same: the ledger
must not decide who sees infra.

### 3.5 Pieces (one PR each)

1. The audit log: chain, `head.json`, `rackbook audit verify`, migration, sign-in and refusal events,
   `clientip`, retention and address settings. **Done.**
2. `GET /api/activity` (with `format=jsonl`) and the Activity page. **Done** (README, "Activity"). As built:
   - Acknowledging a chain problem is part of this piece: `POST /api/audit/ack` records a
     `chain_problem_ack` event, and retention stops keeping the month of an acknowledged problem. It is for
     admins, refused on a read-only server and for API tokens. A `chain_problem` event carries a fingerprint of
     the evidence (the lines involved, or head.json and where the files end), and an acknowledgement covers only
     the fingerprints it saw: the same old break stays acknowledged, a line rewritten later or a new garbage
     head.json or a new cut is recorded again and shows the banner.
   - `audit/index.json` is a map to the `commit` lines (file and offset), not a source of truth: every hit is
     checked against the chain (the line is a `commit` event with that area, hash and identity, and the next
     line's `prev`, or head.json, vouches for it), and a hit that fails rebuilds the index.
   - The `canSee` function in `internal/api/activity.go` is the one place that decides who sees which area;
     piece 4 (auditors) only changes it. Until then the audit areas are admin-only.
   - Audit events are shown under the area `audit`, except the infra ones, which are shown under `infra`.
     The `ledger` area holds commits only, so `write_refused` for the ledger is an `audit` row.
   - Paging model. Each source is a stream with its own resume position, and the cursor holds all of them: for
     a repository, the commit the walk is pinned to (the first page pins the current tip, so new commits do not
     shift later pages) and the number of commits of that `git log --date-order` walk already consumed
     (`--skip=N -n M`); for the audit log, the seq it has come down to. The time, person, record and state
     filters are applied in Go to what a stream reads and never as git options, because git stops a
     time-limited walk at the first old commit, which loses commits whose committer dates are out of order. The
     merge takes the newest head of the three streams. Each git source is one streaming `git log` process per
     request (started by the first read, killed and waited for when the request ends), not one process per
     chunk. Each request has a work budget per stream (2 000 commits, 200 000 audit lines); when it is spent the
     page ends, possibly without a row, and the cursor resumes there; the console follows an empty page three
     times and then asks. With `since` a walk stops after 200 commits in a row dated more than 24 hours before
     it. That is a heuristic bound and is a deviation from "never lose a commit": a commit dated more than a day
     earlier than the 200 that follow it in the walk can be missed by a `since` filter; without `since` there
     is no early stop. The cursor is signed with a key made at start (HMAC-SHA256, bound to the caller), so it
     cannot be forged or replayed by another person and does not survive a restart (`400 cursor_invalid`; the
     console starts again from the top). The audit reader keeps a sparse in-memory seq-to-offset index per month
     file (one mark per 512 lines) so a deep read seeks instead of parsing every newer line. A commit line that
     the chain does not vouch for (a break follows it) is reported unverified without rebuilding the index; the
     index is rebuilt only when it contradicts the files. So the output is complete and has no repeats, but it is sorted only as far as each stream
     is: a repository whose dates go backwards along its history, or audit lines written with an old explicit
     time (the copy of the old infra audit file), show at their position in the stream. The JSONL export walks
     the same pages up to 50 000 rows or its work budget, then ends with `{"truncated":true}`.
   - `format=jsonl` is for admins (design 3.1); `canSee` has a `seeExport` class so piece 4 only adds the
     auditors. The list itself is open to every role, limited by area.
   - A `collection` or `id` filter leaves out infra and audit rows. `id` matches the exact `Record` trailer; it
     does not fall back to the collection's file history as the record page's History does, because a page of the
     timeline must not change meaning when an older page has no such commit.
   - The patch of a commit comes from one `git diff-tree --patch` process whose output is cut at 256 KiB (the
     process is killed there; the files not read in full are marked truncated), 200 files at most, and the
     patches are matched to files by the path in each `diff --git` header (a type change has two sections), with
     only the shown files named in the arguments. Every hunk
     header is rewritten to `@@ -a,b +c,d @@`, because git appends the nearest line above the hunk (for YAML, a
     top-level key and value) and that line can be a secret. `.rackbook/` files are shown to admins in full
     (they hold public keys, ids and hashes by design), secret files of the infra repository are listed as
     changed without a patch.
   - `/api/meta` carries `auditAlert` for admins while recorded problems are not acknowledged; the console's red
     banner (on every page, so also on Activity) reads it.
   - Not done here: the CLI and MCP do not read the audit log.
3. Field-level record history, the restore endpoint, deleted records.
4. `auth.auditors` and `--infra-auditors`.
5. The optional daily anchor.

Each UI piece gets a demo with example data in three languages before merge.

---

## 4. Phase 2a: roles from the provider's claims (the light version)

This builds on what exists: the role is computed from the identity and the claims at sign-in.

- **App roles.** A new entry kind, `app-role:<value>`, matches the ID token's `roles` claim. App roles have
  readable names and avoid the group limits. Per provider:
  - Entra: *App roles* on the app registration, assigned to users (any plan) or to groups (Entra ID P1 or
    higher; nested groups are not expanded);
  - Keycloak: client roles arrive under `resource_access.<client>.roles` unless a mapper puts them in a
    top-level `roles` claim in the ID token, which Rackbook then needs;
  - Authentik: a scope mapping that adds a `roles` claim.
- **Too many groups.** Rackbook keeps only the first 40 groups (700 bytes). Entra also sends no groups at
  all past 200 (the token carries `_claim_names.groups`, or `hasgroups`). In both cases the sign-in
  succeeds without group roles, and the `login` event says `groups: overage`. The docs recommend app
  roles, or Entra's *groups assigned to the application* filter, which sends only the groups the app uses.
- **No passkey sign-in for SSO identities** (changed 2026-11-22). A passkey session never asks the
  provider, so it cannot see a disabled account. Instead of limiting passkeys with
  `auth.passkeys_oidc_max_age`, as first planned, Rackbook offers SSO identities no passkey sign-in and no
  TOTP: their second factor is the provider's (Entra supports passkeys itself). `auth.passkeys_oidc_max_age`,
  the `passkey_needs_oidc` refusal and `last_oidc` are dropped, and `auth.passkeys` with SSO is ignored with a
  warning. Passkeys were never enabled in this deployment, so there is nothing to migrate. Passkeys remain, as
  a second factor, for local accounts, as the owner confirmed
  ([design-local-accounts.md](design-local-accounts.md), sections 2.2 and 14).
- **How fast a removal takes effect.** Claims are read only at sign-in. `auth.session.claims_absolute`
  (default 24 h) shortens the absolute lifetime of a session whose role came from claims. Removing someone
  by name in `rackbook.yml` still applies at the next pull, unless a domain or group entry also matches.
- **Role changes are recorded.** At each sign-in, the effective role is compared with the role stored for
  that identity in `audit/identities.json` (identity, name, last role, last sign-in and its method;
  mode 0600, admin-only API, no groups or claims kept). A difference writes `role_changed`. After a `rackbook.yml` commit,
  `role_changed` is written lazily: at each person's next request, the newly computed role is compared
  with the stored one. People who never come back are not recomputed, because their claims are not kept.
- **Tokens.** A token keeps working only through a role its creator holds *by identity*: an exact entry,
  `*@domain` or `oidc:` (token creators are evaluated with their sign-in method, so `oauth:` and `mcphub:`
  entries never match them). Creating a token is refused, with a clear message,
  when the creator's role comes only from groups or app roles. Otherwise the token would silently have no
  role.
- **Editing roles in the console** (admin, **Users → Roles**): the lists in `auth.roles` and
  `auth.auditors`, with a diff preview. Saving is a commit to `rackbook.yml` through `yamledit`, so comments
  and layout are kept and every change by hand is in the history. It refuses to remove the last admin, and
  refuses to remove the editing admin's own admin entry.
- **Local accounts beside SSO** (username, password and a mandatory second factor), designed in
  [design-local-accounts.md](design-local-accounts.md). As in the owner's other products, a deployment can
  offer both: `auth.login.mode` decides what the sign-in page shows and `auth.login.sso_only` what the local
  endpoint accepts (admins are always exempt, as the break-glass path). Local identities are
  `local:<username>`, assigned in `auth.roles` beside SSO entries and edited with the same role editor;
  section 7 of that design says how the editor treats them. The same console gets a **Sign-in & security**
  page whose settings are `auth.*` keys in `rackbook.yml`, saved as commits like role edits.

## 5. Phase 2b: SCIM (later)

SCIM 2.0 is the standard way for a provider to push users and groups into an application, and to disable
them. Entra, Okta and JumpCloud support it as provisioning clients. Authentik supports it as an outbound
provider. Keycloak needs an extension.

- `/scim/v2/Users` and `/scim/v2/Groups`, with a bearer token per provider.
- A disabled or deleted user goes into `audit/disabled.json` (mode 0600). Every request checks it, so
  their sessions stop at once although the cookie is stateless. Their API tokens stop too.
- Group membership pushed by SCIM replaces the claims at sign-in for that provider, so a change takes
  effect within the provider's sync cycle (Entra: about 40 minutes) instead of at the next sign-in. The
  same applies to token creators.
- Every change SCIM makes is written to the audit log (`scim_user`, `scim_group`).

Phase 2b gets its own design note before it is built.

---

## 6. Phase 3: `/infra` admins by group (accepted 2026-11-22)

Today `--infra-admins` is a list of exact identities in the infra deployment. The proposal: also accept
**one** group or app role, pinned together with the issuer, client and tenant that are already pinned.
Adding an infra admin is then a change in Entra, not a deploy.

The trade-off, plainly: whoever can change that Entra group or app-role assignment (Entra admins, group
owners) can make anyone an infra admin, and an infra admin is root on every host. Today only a change to
the infra repository can do that. The owner accepted this trade-off on 2026-11-22. `/infra` stays OIDC-only:
local accounts never reach it.

## 7. Decisions (2026-11-22)

The open questions of the first draft, as the owner decided them:

1. **Phase 3** (section 6): accepted. `/infra` admins may also come from one Entra group or app role, pinned
   with the issuer, client and tenant.
2. **Sign-in without an OIDC provider:** local accounts are wanted, for teams without SSO. Only when no OIDC
   provider is configured, so a deployment is either SSO or local. An admin creates an account with a
   single-use, expiring invite link; on first use the person sets a password and must enrol a second factor
   (TOTP or a passkey). Passwords are stored as argon2id, in the state dir, encrypted, never in Git.
   Per-account and per-address limits, lockout with backoff. No e-mail: a forgotten password or a lost second
   factor is an admin-issued one-time reset link. Every sign-in, failure, lockout, reset and invite is in the
   audit log.
3. **Passkeys under SSO:** passkey sign-in is disabled when SSO is configured, which makes
   `auth.passkeys_oidc_max_age` moot; it is dropped (section 4).
4. **Daily anchor** (3.1): stays off.
5. **Defaults:** this deployment runs with `--audit-addr full` (an IPv6 client is still kept as its /64);
   the default of the flag stays `truncate`.
   Audit retention is forever (`--audit-retention-months 0`, the default), and stays configurable through that
   flag. `claims_absolute: 24h` stays.

**Later the same day (2026-11-22).** The owner then asked that Rackbook match their own products,
Passwall-Sub-Panel and Report Portal, and answered the open questions of the local-accounts design. This changes
items 2 and 3 above as follows; the rest stands.

6. **Local accounts beside SSO** (changes item 2): not only without SSO. As in Passwall-Sub-Panel and Report
   Portal (and GitLab, Gitea, Grafana, Mattermost), a deployment can offer both, with a login mode (`dual`,
   `sso_first`, `sso_redirect`, `local_only`) and an `sso_only` switch, both failing safe without a provider, and
   with admins always exempt. TOTP and passkey are both allowed as second factors; no recovery codes; a single
   admin may issue a full reset; usernames are never reused.
7. **Item 3 still applies to SSO identities**: Rackbook offers people who sign in through SSO no passkey sign-in
   and no TOTP; their second factor is the provider's. Passkeys were never enabled in this deployment, so nothing is
   migrated. Whether local accounts beside SSO may keep a passkey as their second factor is our reading of the
   owner's rule, not the owner's own words; it is listed for confirmation in
   [design-local-accounts.md](design-local-accounts.md), section 14.
8. **Sign-in security settings in the console**, switchable without a restart: the CAPTCHA (image, Turnstile,
   reCAPTCHA or hCaptcha, off until enabled), the throttle (always on), the lock (off by default) and the 2FA
   limits, all admin-editable. The NIST SP 800-63B cap of 100 consecutive failures is a ceiling admins can lower
   (down to 10) but not raise. Non-secret settings are `rackbook.yml` keys; secrets are kept encrypted in the
   state dir and never returned. Passwordless passkey sign-in is an option, off by default; device-bound passkeys
   are not required.
9. **`/infra`** stays OIDC-only and pinned by deployment flags; nothing on the new settings page reaches it.
   Outside OAuth issuers are trusted only when configured explicitly, in any mode.
10. **The CLI** behaves the same on Linux, macOS and Windows (a Unix socket or a named pipe, with the same
    authenticated and encrypted protocol).
11. **authcore/captcha** is used whole, as Report Portal uses it, not split.

Design: [design-local-accounts.md](design-local-accounts.md).

**The last open points (2026-11-22), answered by the owner as proposed:**

12. **Lock scope:** `ip_account` by default.
13. **CAPTCHA:** `image` is the default when enabled; this deployment uses Cloudflare Turnstile.
14. **`sso_redirect`:** admins reach the local form at `/auth/login?local=1`.
15. **Passkeys for local accounts beside SSO:** allowed as a second factor, which settles the reading noted under
    item 7; the rule of item 3 applies to SSO identities.
16. **Turnstile `cdata`:** authcore exposes `action` and `cdata` as additive fields on `Result`, in a separate
    change; Rackbook validates both server-side as an extra check beside the sealed attempt token.

Nothing is open.

## 8. In plain words

- **Every change is already a Git commit.** Phase 1 adds one page that shows all of them together with
  sign-ins and refused attempts, and lets you put a record back the way it was. Putting it back is a new
  change, so the history itself never changes. Only changes Rackbook itself made count as verified; anything
  pushed to Git another way shows up marked "unverified", whatever name it carries.
- **The audit log is a chain.** Each line includes a fingerprint of the line before it, and a small
  separate file remembers the last line. If someone edits, deletes or cuts off lines, Rackbook says so.
  Someone with full control of the server could rebuild everything; the optional daily anchor writes the
  latest fingerprint into Git, where rewriting is detected, so only the last day stays open.
- **Roles come from Entra.** You put people in an app role or a group in Entra, and Rackbook reads it when
  they sign in. Taking someone out takes effect at their next sign-in, and at the latest after 24 hours.
  People who sign in through Entra get no Rackbook passkey or code: Entra is their only way in (and can use
  passkeys itself), so a disabled Entra account cannot start a new session, and existing sessions end within 24 hours
  for roles that come from Entra, and within 7 days at most otherwise.
  With SCIM (later), Entra tells Rackbook directly, and a disabled account stops at once.
- **Local accounts sit beside SSO.** An admin sends an invite link, the person picks a password and adds a
  passkey or an authenticator app. Admins decide on one settings page whether the sign-in page shows both,
  SSO first, or only one, and can make SSO compulsory for everyone but admins, who keep a local way in if the
  provider breaks. Passwords are never in Git; they sit encrypted on the server, and a forgotten password is a
  new link from an admin, which still asks for the person's passkey or authenticator app. Repeated wrong
  guesses are slowed down, can be answered with a CAPTCHA, and after at most 100 in a row the account only
  accepts its owner from a network they used recently, or with a passkey.
