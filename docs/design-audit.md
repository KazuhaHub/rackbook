# Audit history and roles from the identity provider

Status: design, agreed 2026-11-22. Phase 1 (pieces 1 to 5) is built (3.5). Phase 2a is built except the
console role editor (section 4, "As built, part 1" below); SCIM (2b) comes later. Phase 3 is accepted. The owner's decisions of
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
| `role_changed` | `from`, `to`, `auditor_from`, `auditor_to`, `cause`: `config` (seen at the person's next request after a `rackbook.yml` commit) or `sign_in` (seen at sign-in, which is when different groups or app roles show; section 4, as built) |
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
     piece 4 (auditors) changed only it and the inputs it reads (see piece 4 below).
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
   - `format=jsonl` is for admins and, since piece 4, auditors (design 3.1); `canSee` has a `seeExport` class. The list itself is open to every role, limited by area.
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
3. Field-level record history, the restore endpoint, deleted records. **Done** (README, "Record history, restore and
   deleted records"). As built, and where it differs from 3.3:
   - The timeline is `GET /api/c/{collection}/{id}/history` (paged like Activity: pinned tip, walk position, signed
     cursor bound to the record and the person; at most 1 000 commits walked, 0.7 s and 50 versions per request) and
     one version with the diff against today's record is `GET .../history/{commit}`, which the restore dialog uses.
     Commits are those with the exact `Record` trailer plus those that changed the collection's file and the
     record's content without naming it (hand edits, shown unverified); a commit whose file is the blob of its
     parent's is skipped without reading it, so trailer commits that left the file as it was are not versions, unless the commit named the record and changed the collection's key in `rackbook.yml`, which is a rename. Known limit: hand edits made before the collection file moved to its present path are not shown (the walk is limited to the present path; trailer commits are found regardless).
   - Cost. Nothing is read or parsed by commit but by blob: `git ls-tree -z <commit> -- <paths>` gives the blob ids of
     `rackbook.yml`, the collection file and the type, the blobs are read by id, and the parsed `rackbook.yml`
     collection definitions, collection files and type annotations are kept in bounded LRUs shared across requests
     (`internal/lru`). A file over 8 MiB, unreadable or not valid at a commit gives an `unreadable` version, not an
     error. A walk of 400 commits of a 2 200-record file takes about 0.7 s for the first page instead of 29 s.
   - The old record is read with `git rev-parse <commit>:./<path>` and `git cat-file blob <object id>`; the runner
     allows `cat-file` only with a bare 40 or 64 digit id and `ls-tree` only as `ls-tree -z <commit> -- <paths>`
     (plain relative paths, none in `.rackbook/` or `.git/`). Only the collection's file, list path, type and key are
     taken from the `rackbook.yml` of that commit (`config.ParseHistoric`: no file is touched, unknown fields are
     ignored); when it cannot be read, today's definition is used and the version is `approximate`. A rename of
     the key fields (same list position, old id gone) is marked `renamed`, not `created` and `deleted`.
   - What "the same hiding as for the current record" means: the record `GET` returns the stored values as they are, so
     the check made is the one the writes make. A value is hidden when the secret scan flags it with the type of that
     commit or with today's type (public in both: shown; only when neither type can be read is no type used), in the diff, the single version, the content that comes back with
     `restore_needs_edit` (which names the places, `hiddenPaths`) and the deleted summaries. A restore itself uses the
     full old content. The validation issues of a refused restore are rebuilt from path and rule, since the
     validator's messages quote values. The form refuses to save until each hidden value has a decision (new value,
     keep the current one, leave empty); "keep the current value" is taken from the current record that the form
     already loaded, not from history.
   - Restore is `POST .../restore` as designed, through `s.apply` and `edit.Op` (`RestoredFrom` adds the trailer and the
     subject `restore`). Beyond the design: `already_current` when the version is the current one, a collection without a
     key always answers `restore_needs_edit` (ids are positions), and restoring a deleted record needs create as well as
     update permission. The body key is `confirm_not_secret` as for `PUT`; `confirmNotSecret` is accepted too.
   - Deleted records: `GET /api/c/{collection}/deleted`, with the cache `<state-dir>/history/deleted-<collection>.json`
     (memory without `--state-dir`), a work budget of 200 commits or 0.7 s per request and `complete:false` until the
     history is read. Each entry holds the redacted id and summary fields without hidden values, so the list is served
     with no Git reads; the cache carries a fingerprint of the secret scan, the type, key and list fields and is made
     again when it changes, and every commit it names is checked to be on the tracked branch. It reads the history of the collection's current file path only, so deletions from before the file was
     moved are not found; collections without a key are skipped. The list shows the commit that removed the record
     and the commit before it (`last`), not the last commit that changed the record.
   - The Activity page shows `Restored-from` (`restoredFrom` on a ledger commit item).
4. `auth.auditors` and `--infra-auditors`. **Done** (README, "Auditors" and "Activity"; docs/api.md, "Activity and the audit
   log"). As built, and where it differs from 3.4:
   - `auth.auditors` is `config.Auth.Auditors`, compiled by `roles.CompileAuditors` with the parser and the validation of a
     role list (errors name `auth.auditors`; `rackbook check` reports them through `config.Load`). It lives in the
     `roles.Policy` next to the role lists, so a config reload (pull) recompiles both together. `Policy.IsAuditor` knows
     nothing about roles.
   - The capability is computed in one place, `Authenticator.evaluate`, which `Evaluate`, `EvaluateSubject` (sessions, API
     tokens, built-in OAuth grants, external-issuer tokens: the same paths that compute roles) and `RoleForVia` /
     `CapabilitiesForVia` (a token's creator, as the token list shows it) all use. The result is `Identity.Auditor`; every
     decision goes through `Identity.IsAuditor()` or `auth.IsAuditor(ctx)`, which also require that the credential can
     read at all (a scope that narrows the role to nothing takes the capability with it).
   - The viewer floor is applied in `evaluate`: on the list with no role gives viewer, with a role keeps it. The "no role"
     login refusal and the 403 `no_role` therefore do not apply to an auditor. A degraded config still caps the role at
     viewer.
   - An admin is not an auditor unless listed. Nothing else in the code treats "admin" as "auditor", so the only visible
     difference is `user.auditor` in `/api/meta`, the badge, and `creatorAuditor` in the token list.
   - `canSee`: `seeState`, `seeAudit` and `seeExport` are admin or auditor; `seeInfra` is infra administrator or infra
     auditor. `activityStreams` takes the state marker from `seeState` and the client address from `seeAudit` instead of
     asking for the admin role. `GET /api/audit/status` follows `seeAudit`; `POST /api/audit/ack` asks for the admin role
     itself and does not go through `canSee`.
   - **Tokens and grants.** An API token or OAuth grant created by an auditor carries the capability while its creator
     is on the list, because it is evaluated for the creator's subject on every request. API tokens can only reach record
     paths, so the capability shows there as `user.auditor` in `/api/meta` and in the history timeline's state marker;
     the activity and audit routes stay out of a token's reach, as they were. Removal from the list takes effect on the
     next request.
   - `--infra-auditors` reuses `auth.InfraAdmins` (`NewInfraAuditors`), pinned with the same issuer, client, claim and
     tenant, OIDC sessions only. It needs `--infra-admins`: a deployment with auditors and no administrator is refused at
     start. `InfraOptions.Auditors` is nil without the flag.
   - **Every `/api/infra` route is classed** (`infraRouteClass` in `internal/api/auditor_test.go`; a new route fails the
     test until it is classified): *read* (`infraReader`: hosts, host, certs, iplists, commits, groups, features, write
     state), *secret* and *write* (`infraAdmin`).
   - The API routes are registered through `routeMux`, which records the patterns; `api.RoutePatterns` (a test hook) lists
     them, so the write-route test and the infra table walk the mux itself. The login service and the built-in
     authorization server register through the same `routes.Mux` interface, so their routes are in the list too; their
     own packages walk them (`TestAuditorCannotTouchAnotherPersonsPasskeyOnAnyLoginRoute`,
     `TestAuditorCannotRevokeAnotherPersonsGrantOnAnyRoute`): the admin routes are 403 for an auditor, the routes on one's
     own passkey or grant are 404 for somebody else's, and a new route fails until it is classified.
   - Deviations from the brief: (1) `GET /api/infra/hosts/{name}/vars` is in the secret class, not read. It is the raw
     file for the editor; it sends no content when the hide scan finds anything, so this is defence in depth. The real
     boundary is that scan: a plaintext secret in host_vars that it does not recognise reaches an infra auditor through
     `GET /api/infra/hosts/{name}` (`HostDetail.Vars`) and through infra commit diffs, exactly as it reaches infra admins. (2) `--infra-auditors` grants nothing in the ledger: an infra auditor needs a ledger role (or a place on
     `auth.auditors`) of their own to sign in at all. (3) The only write an auditor can make is `PUT /api/account/preferences` (their own
     language, a state file, not the ledger), so the "never 200 on a write route" test exempts it by name. (4) The Groups
     tab stays an edit page; infra auditors see group membership on the host pages and through `GET /api/infra/groups`,
     but the console has no read-only groups view. (5) The audit `login` event still records the role (`viewer` for an
     auditor with no role); the capability is not in the event.
5. The optional daily anchor. **Done** (README, "The daily anchor"; docs/api.md, "Activity and the audit log"). Phase 1 is
   complete. As built, and where it differs from 3.1:
   - `audit.anchor: daily` (absent or `off`: off; anything else is a config error) is `config.Audit.Anchor`.
     `rackbook check` refuses `daily` with `write.mode: pr`, through the same config load the server uses, so
     the server refuses it at start too; a reload that carries it keeps the last good config as for any other
     config error. The anchor job reads the setting from the current config on every check.
   - `internal/anchor` writes the anchor: a loop (30 seconds after start, then hourly) that appends one JSON Lines
     line to `.rackbook/audit-anchors` through `Store.MutateStateFile`, with the subject `audit: anchor seq N`.
     The file is read again on a replay after a moved remote and only ever appended to; lines that are not
     anchors are left alone (a missing final newline is added before the new line, nothing else is touched).
   - "The head has advanced" ignores the anchor's own `commit` event, which always follows the anchored seq:
     otherwise an idle server would anchor every day for ever. The anchor commit is made by a fixed identity,
     `rackbook-audit-anchor` with method `system`, so that its `commit` line can be told from a person's (the
     check needs both); OIDC and MCP sign-in refuse that identity. It shows in Activity as an ordinary
     state-only ledger commit, verified.
   - "Already anchored today" is decided only from the newest anchor that is valid and matched the log
     (`Log.ReviewAnchors` returns those). A line dated far ahead cannot keep today's anchor away: the writer
     warns and writes it. It writes nothing while the audit log has a problem nobody has acknowledged, except
     `anchor_invalid`, which says nothing about the log. (Not in 3.1; a decision made while building.)
   - Verification runs at start (everything), after each periodic pull (`gitstore.Options.AfterPull`; only anchors
     not verified before in this process, and the newest) and in `rackbook audit verify --repo <clone>`, whether
     or not the setting is on. Lines are found through the log's offset index (at most 512 lines read per
     anchor). Kinds: `anchor_mismatch`, `anchor_ahead`, `anchor_invalid` (a day more than a day in the future,
     or a day or seq not after the anchor before it), `anchor_rewritten` and `anchor_more`. Each wrong anchor
     has its own fingerprint (anchor line, kind, what was found), so acknowledging one hides no other; at most 20
     are recorded per pass, then one `anchor_more` entry.
   - History. `Store.CheckStateFileHistory` lists every commit reachable from the tip that touches
     `.rackbook/audit-anchors` with `git log --full-history --format='%H %P'` and, for each such commit and each of
     its parents, requires the file at the commit to be the file at the parent (empty when absent) with lines
     appended. Checking edges rather than one line of history matters: default history simplification follows
     one side of a merge, so a branch cut before the file existed, with a forged file, merged into main taking the
     branch's version, would never have been compared with main's real anchors. A violating commit is an
     `anchor_rewritten` problem naming it (one per commit). The blobs are read with `git cat-file --batch` in chunks of a few commits (the
     guarded runner allows exactly `cat-file --batch`; `log` gained only `--full-history`). With a
     previous tip that is an ancestor of the new tip only `old..new` is looked at, otherwise everything. The last
     checked tip is kept in memory only (a file in `--state-dir` would be one more thing for somebody with that
     directory to forge, and a full check at start is cheap). `audit verify --repo` runs the same check on the
     clone's HEAD (`gitstore.CheckStateFileInClone`) when the clone is a Git repository. A hand-made merge that
     combines two sides' new lines is flagged too; the server never makes one.
   - Order. The baseline an anchor must come after is the last anchor that matched the log; a line that did not
     (ahead, mismatch, future) is never the baseline, so one forged line cannot turn the real anchors after it
     into `anchor_invalid`, and acknowledging it changes nothing for them.
   - What it does not do: a person with the server's push credentials can still push a forward commit that
     rewrites the anchor file. The change stays in Git history, visible to anyone with a clone or on the Git
     host, and Rackbook flags it; it is not prevented.
   - Retention. An anchor is skipped as removed by retention only if all of these hold: `--audit-retention-months`
     is above 0; its seq is below the first line kept; its day is on or before the first day of the cutoff month
     (now minus N months; the 1st itself is allowed because the writer can anchor the last line of the month
     before just after midnight); and it comes before the newest anchor that matched the log. `head.json` is not
     read for this, and the set of month files is read only for where the kept log begins: an earlier version
     trusted both. What a deletion that looks like retention can still hide is at most the lines retention itself
     would drop, plus the first day of the cutoff month. `audit verify --retention-months N` takes the server's
     number; its default of 0 skips nothing.
   - Checks that cannot be done. A failure to read or check the anchors is `anchor_unreadable`, never a silent
     pass: the file at the tip is not a regular file (`gitstore.ErrStateNotRegular`), the history check errored,
     git's answer did not fit (`gitstore.ErrStateDesync`), or a version is above 4 MiB (known from the object's
     header, so it is refused before it is read; larger outputs are cut). Fingerprint: reason and tip, so once
     per tip. Judgement: `history_error` and `read_error` may be a moment's trouble, so the first failure only
     warns and the second in a row of the same reason is recorded, whatever the tip is (the count is by reason; the
     recorded problem is by reason and tip); `not_regular`, `history_desync` and `too_large` are recorded at
     once. `audit verify --repo` turns the same failures into an `anchor_unreadable` problem or an error, so
     the exit status is 1, also for a directory that is no Git repository (`not_repository`); `--no-history` says only the
     file is wanted, and then it gets a note and does not fail.
   - The history check resolves each commit's entry with `git ls-tree -z <commit> -- .rackbook/audit-anchors`
     (the guard allows ls-tree on that one state file, and no other), so a tree, a symbolic link (mode 120000)
     or a gitlink (160000) at the path is an `anchor_rewritten` ("not a regular file"), never an empty file. Blobs
     are then read by object id with `cat-file --batch`, each header checked to name the id asked for and to be
     a blob, and exactly `size` bytes plus the closing newline consumed, a few commits at a time. An earlier
     version treated a tree as missing without consuming its body and read everything after it from the wrong
     place.
   - Lines of the anchor file that are not anchors are reported by `audit verify` (and logged once), not as a
     chain problem: they do not fail the exit status.
   - `rackbook audit verify` had no data repository path; `--repo <clone>` is the narrowest addition. It reads the
     file as checked out (pull first), through `os.OpenRoot`, and refuses a symbolic link as the file or as
     `.rackbook`.
   - Not done: the anchor is not checked against the remote's tip rather than the checkout, and there is no
     anchor in `/api/audit/status` beyond the problems. The console shows the two kinds in the banner in all three
     languages; no other page changed.

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
- **Editing roles in the console** (admin, **Users → Roles**; part 2, **not built yet**): the lists in `auth.roles` and
  `auth.auditors`, with a diff preview. Saving is a commit to `rackbook.yml` through `yamledit`, so comments
  and layout are kept and every change by hand is in the history. It refuses to remove the last admin, and
  refuses to remove the editing admin's own admin entry.
- **Local accounts beside SSO** (username, password and a mandatory second factor; **not built**), designed in
  [design-local-accounts.md](design-local-accounts.md). As in the owner's other products, a deployment can
  offer both: `auth.login.mode` decides what the sign-in page shows and `auth.login.sso_only` what the local
  endpoint accepts (admins are always exempt, as the break-glass path). Local identities are
  `local:<username>`, assigned in `auth.roles` beside SSO entries and edited with the same role editor;
  section 7 of that design says how the editor treats them. The same console gets a **Sign-in & security**
  page whose settings are `auth.*` keys in `rackbook.yml`, saved as commits like role edits.

### As built, part 1 (2026-11-23)

Done: app roles, overage, no passkeys for SSO identities, `claims_absolute`, `audit/identities.json` with
`role_changed` and its API, the token rule, and the README, `docs/api.md` and console work for them (account
page, token refusal, Activity sentences in zh-CN, zh-TW and en-US, the mock API). **Not built:** the console
role editor (part 2) and local accounts. Where it differs from the text above:

- **Roles from claims.** `app-role:<value>` is a new entry kind (`internal/roles`), accepted in `auth.roles` and
  `auth.auditors` through the same parser, so `rackbook check` validates it with the same messages (an empty value,
  control characters and wildcards are errors). It is exact and case-sensitive: `group:` folds ASCII case because group
  ids are GUIDs, app role values are names that Entra, Keycloak and Authentik keep apart by case. The prefix is not
  case-sensitive. Only the top-level `roles` claim is read. A subject login (`identity: subject`) still matches only
  `oidc:` entries, as with groups. Built-in OAuth grants carry the roles claim next to the groups, so an MCP client
  of an app-role person works. The claims of a grant are a snapshot of the approving sign-in, and they stop counting `claims_absolute` after the approval (`Server.effective`, from the grant's `created` time; a grant with none has none left, no migration): the grant is then evaluated by identity entries alone, like an API token, so a role removed at the provider cannot outlive that bound by refreshing (groups and app roles alike). A person with no identity entry ends the grant at the next refresh.
- **Caps and cookie.** Both lists are capped at the first 40 values and 700 bytes (one shared helper, `roles.BoundClaim`, for
  the session and the grants). Two full lists did not fit the old 2 048-byte cookie limit, so the whole `Set-Cookie` header
  (name, value and attributes) may be 4 096 bytes, the session is encoded without HTML escaping, and each list has an
  encoded-size budget of 900 bytes. Every sealed cookie is measured; if it is over, values are dropped from the longer list,
  last first, and the login event carries the overage marker; if even empty lists do not fit the sign-in is a
  `login_refused` with reason `session_too_large` and an error page, never a loop.
- **Overage.** (Corrected 2026-11-23: a list cut at the cap keeps a prefix; only Entra's overage drops all groups.) The `login` event gets `groups: "overage"` and `app_roles: "overage"` (new fields of the event, not
  `detail`; the design's `groups: overage`). Entra's two signals, `_claim_names` with a `groups` key and `hasgroups` (a
  boolean or `"true"`), both mean no group is used. A list cut at 40 values or 700 bytes keeps the values that fit, in
  token order, instead of none: a prefix can only lower a role, and "none past the cap" would have taken away today's
  group roles for people in 20 to 40 groups. A `login_refused` for no role carries the same note. The server logs a
  warning.
- **Passkeys.** The login service exists only with OIDC, and passkeys were only ever a feature of it (`auth.passkeys`
  already needed `auth.mode: oidc`), so "ignored when OIDC is configured" is "always, for now". `auth.passkeys` loads, with
  a warning at start and from `rackbook check`; the passkey routes are registered and answer `403 passkey_sso` (a refusal
  rather than a 404, so the console and any client can tell); nothing is built or written. The passkey code is kept and
  only built by an unexported option that the tests of it set. `auth.passkeys_oidc_max_age`, `passkey_needs_oidc` and
  `last_oidc` were never built (only an unused console label for the second was left; it is removed); a
  `passkeys_oidc_max_age` key in `rackbook.yml` is a `check` warning. There is no TOTP. The old error for `auth.passkeys`
  with `identity: subject` is gone (passkeys are ignored). Without OIDC `auth.passkeys` is still an error, as before.
  `rackbook.yml` warnings are a new `Config.Warnings`, printed by `rackbook check`.
- **`claims_absolute`.** Default 24 h; an explicit value must be positive and at most `absolute` (a default under a shorter
  `absolute` just gives way). It is read at start with `idle` and `absolute`. The flag is stored in the session (`fc`) and
  decided at sign-in as "the effective role is higher than the identity entries alone give, or the auditor capability
  exists only through claims": `Identity.FromClaims`, computed by `Authenticator.Evaluate`. An identity entry that grants
  the same role wins; `*` counts as an identity entry. Sessions issued before the upgrade keep the normal limit. The flag is decided again, one way, at the first request after a
  config change (`observeConfig`), with the cookie issued again, so `admin: [alice@x, group:ops]` losing `alice@x` makes the
  session end `claims_absolute` after it was issued; it is never decided while the config does not load (roles are capped
  at viewer then, which would hide the claims), and a sign-in under a degraded config is not marked as looked at, so the first
  look after it loads decides it.
- **`identities.json`.** In `audit/` beside the chain (the retention and verification code ignore it), `{version,
  identities: {id: {name, role, auditor, lastSignIn, method}}}`, mode 0600, replaced atomically, 5 000 entries (about 750 KB), the
  oldest sign-in evicted first. The event is appended before the file is rewritten, so a crash repeats an event rather than
  losing one. A file that cannot be read is set aside as `identities.json.unreadable` and the store starts empty.
- **`role_changed`.** Fields `from`, `to`, `auditor_from`, `auditor_to` and `cause`, which is `sign_in` or `config`, not
  the table's `because: config|claims`: the only moment claims change is a sign-in, so `claims` is `sign_in`. A first
  sign-in writes no event. A sign-in refused for no role is compared too and moves the last sign-in time (without a session), so an older session cannot write the old role back as a change later. The lazy
  comparison runs in `Identify`, once for each session (person and issue time) and role policy generation (the
  `*roles.Policy` the authenticator compiles when the config object changes), remembered in memory (bounded at
  20 000); a restart costs one extra comparison. Nothing is compared while the latest `rackbook.yml` does not load (roles
  are capped at viewer then), and a session older than the person's last sign-in is skipped, so two sessions with
  different claims cannot write each other's roles back and forth.
- **`GET /api/audit/identities`** is for administrators **and auditors** (`seeAudit`), not admins only as 4 says: it holds
  what the sign-in events hold (who, when, how, the role), which auditors see, and no more. It lists most recent first.
  `GET /api/account` gained `roleFrom`, `auditorFrom`, `claimsAbsolute` and `sessionEnds` for the account page.
- **Tokens.** A token creator was already evaluated by identity only (no groups, no app roles), so nothing to change
  in `RoleForVia`; `oauth:` and `mcphub:` never match because the creator's recorded method is the console's. Creation
  answers `403 creator_role_from_claims` when the identity-only role is below what the token needs (viewer for `read`,
  editor for `write`) and the creator's own role is not: which covers a role with no identity entry at all, and a
  viewer-by-name who is admin by group asking for a write token. A push token needs admin by identity: one made by an admin who is admin only by group is refused with the same code. The auditor capability of a token
  follows identity entries the same way.

Not done in part 1: the role editor; local accounts and the `local:` gate of design-local-accounts.md section 7; reading the audit log or `identities.json` from the CLI or MCP.

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
4. **Daily anchor** (3.1): stays off. It is built (piece 5) and off by default; this deployment does not turn it on.
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
