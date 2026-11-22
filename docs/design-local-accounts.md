# Local accounts, and passkeys off under SSO

Status: design, decided by the owner on 2026-11-22 and revised after three rounds of review the same day;
nothing here is built yet. Builds on [design-audit.md](design-audit.md) (the audit log, phase 2a) and
[design-v0.2.md](design-v0.2.md) (the built-in login). Section 13 lists what still needs the owner's decision.

Two changes:

1. **Local accounts** (username, password and a mandatory second factor, with an adaptive CAPTCHA at sign-in)
   for teams without SSO. A deployment is either SSO or local, never both.
2. **No passkey sign-in when SSO is configured.** Under SSO the identity provider is the only way in, so a
   disabled Entra account cannot keep signing in with a passkey. This makes `auth.passkeys_oidc_max_age`
   (design-audit.md, section 4) unnecessary; it is dropped.

The standing rules hold: no database (Git, plus files in `--state-dir`), Git history is never rewritten,
secret values never appear in Git, a diff, a log or the audit log, and the ledger never decides who may use
`/infra`.

---

## 1. What exists today

- **Modes.** `auth.mode` (or `--auth`, which wins) is `none`, `cloudflare-access` or `oidc`. Any other value
  of `auth.mode` is rejected by `Login.check` (`internal/config/login.go`).
- **Sessions** are stateless: the cookie `__Host-rackbook_session` holds `{id, name, method, issued,
  last_seen, ...}` in clear text, signed (not encrypted) with HMAC-SHA256 under `RACKBOOK_SESSION_KEY`
  (`seal` in `internal/login/session.go`), 12 h idle and 7 days absolute by default. The role is evaluated from
  `auth.roles` on every request. The codec accepts the methods `oidc` and `passkey` only.
- **Pending logins** are kept in a 10 000-entry store that evicts the oldest entry when full
  (`internal/login/pending.go:64`); authcore's captcha `MemoryStore` is bounded the same way. Minting entries
  costs an attacker nothing, so neither may hold state an attacker can push out (7.2).
- **Passkeys** are an alternative to OIDC, not a second factor, committed to `.rackbook/passkeys.yml` in the
  **data repository**.
- **Roles** are evaluated on three paths, all through `Policy().Evaluate` in `internal/auth/auth.go`:
  `Authenticator.Evaluate` (sessions), `Authenticator.RoleForVia` (an API token's creator, e.g.
  `internal/api/tokens.go:68`) and `Authenticator.EvaluateSubject` (OAuth grants in
  `internal/oauthserver/token.go:75`, OAuth access tokens and API tokens in `internal/mcpauth/mcpauth.go:233`
  and `:265`).
- **The audit log**: `audit.Log.Record(Event)` returns nothing; in its failed state later events are dropped.
- **The state dir** holds the audit log, token last-use, preferences, OAuth grants (`oauth-grants.json`) and
  keys; `secureStateDir` refuses a mode other than 0700 only in strict mode.
- **Security headers**: one Content-Security-Policy for every path (`securityHeaders`, `internal/api/api.go:295`),
  allowing only `'self'` scripts.
- **Rate limits.** `clientip.Of` names the client (IPv6 bucketed by /64). The audit log keeps the same /64 for an
  IPv6 client even with `--audit-addr full`.
- **CAPTCHA.** `github.com/KazuhaHub/authcore/captcha` (authcore is already a dependency) has a `TokenVerifier`
  for Turnstile, reCAPTCHA and hCaptcha (`NewTokenVerifier(provider, secret, opts...)`, `Verify(ctx, token,
  remoteIP)`, hostname pinning that is skipped when the provider returns no hostname) and a digit-image
  `Generator`. The package imports `github.com/mojocn/base64Captcha` and its image dependencies, which are not in
  `go.sum` today (section 12).
- **`/infra`** accepts only pinned OIDC sessions. Local accounts never reach it.

---

## 2. Threat model

| Threat | Defence | What is left |
|---|---|---|
| **Phishing** (real-time relay of password and code) | A second factor is mandatory; passkeys are origin-bound and offered first; `second_factor: passkey` turns TOTP off. | Password + TOTP can be relayed. |
| **Online password guessing** (stuffing, spraying, a targeted account) | A token CAPTCHA (Turnstile, hCaptcha, reCAPTCHA) once failures pile up, checked before any hash. **NIST SP 800-63B §5.2.2 cap**: at most 100 consecutive failed password checks, counted across all networks, then **restricted** and **passkey only** (7.4). Password and second factor are checked **in one step** with one undifferentiated answer, so a guess never learns whether the password alone was right (4.6). 12 characters minimum and a blocklist. | Up to 100 guesses per holder sign-in, each costing a CAPTCHA solve. A restricted account is a bounded denial of service, accepted as NIST intends (7.4). |
| **Lockout of a legitimate user** | No hard lock from new networks before the NIST cap; CAPTCHA instead of refusals; stateless attempts that cannot be evicted; reserved capacity for the holder's known networks (section 7). | Stated exactly in 7.7, by where the holder signs in from. |
| **An offline copy of the state dir** (a backup, a lost disk, a sidecar with the volume mounted) | The store is encrypted, `usernames` is MACed, and the admin socket is mutually authenticated and encrypted (sections 3, 9), all under a key that is not in the state dir. Without the key a copy reveals nothing and can do nothing; a planted or torn file stops the server instead of rolling anything back (3.2). | A copy *with* the key gives argon2id hashes, TOTP secrets and session secrets. Response in 4.10. |
| **A stolen session cookie** | `Secure`, `HttpOnly`, `SameSite=Lax`, `__Host-`; fresh password and second factor for sensitive actions; three failed re-authentications end every session; *Sign out everywhere* and *Disable* end sessions at once. | Reading and ordinary edits until expiry or revocation. |
| **A forged session** | A local cookie is MACed under a key derived from the session key **and** a per-account secret in the encrypted store (section 5). | Someone with both keys and the store holds everything already. |
| **The admin as the trust root** | Admins create accounts and issue resets; push access to the data repository already means admin; above the admins is whoever holds the account key. | By design. |
| **An insider admin** | A reset replaces only what it names (4.8); only a separate, warned *full reset* hands over an account, in effect a new invite. Every reset revokes tokens and grants, ends sessions, and is shown to the holder. All in the hash-chained audit log. | A full reset lets an admin act as the victim; the victim notices and the log tells the story. No two-person rule (section 13). |
| **A leaked invite or reset link** | 256-bit, single-use, expiring, in the URL fragment (removed once read); nothing happens until the person presses *Continue*; a 30-minute hold; a `password` or `second_factor` reset link alone is not enough. | Whoever presses *Continue* first wins on an invite. |
| **Account enumeration** | Usernames are not secret (they are in `auth.roles`). All CAPTCHA triggers come from one counter table for every typed name (7.3); unknown and non-active accounts get the same answers and the same argon2id time (7.5). | The variance of one argon2id run (7.5). |
| **Resource exhaustion** (argon2id, attempt state, image rendering, siteverify calls) | CAPTCHA before any hash; stateless attempt tokens with per-bucket quotas and no cross-bucket eviction; hashing slots with a reserved one; bounded siteverify concurrency; an image rendering budget (section 7). | A botnet of very many /48s that solves CAPTCHAs can make sign-in from **new** networks slow (7.7). |
| **CAPTCHA weaknesses** | Token providers only, by default; the image CAPTCHA needs `--captcha-image-weak-ok` and warns at start. No per-attempt fallback; fallback only on a provider outage the server itself detects, and only where allowed (7.1). | The image CAPTCHA is solved by OCR for free; where it is allowed, the NIST cap is the real bound. |
| **Flooding the audit log** (kept forever) | Refusals and CAPTCHA failures are aggregated per bucket per minute (section 8). | |

Out of scope: root on the running host (it holds the keys in memory), a compromised browser, and the data
repository's own access control.

---

## 3. Where account data lives, and why

**Not in Git.** Password hashes, TOTP secrets and session secrets are secrets, and Git history is never
rewritten. Local accounts' passkeys go to the same store too. **State dir mode:** in local mode the check is
strict: the server refuses to start unless the directory is (or can be made) 0700.

### 3.1 The store

`<state-dir>/accounts/accounts.enc`, mode 0600, small, decrypted once at start and kept in memory.

- **Format:** a plaintext header `{"v": 1, "alg": "AES-256-GCM", "kid": "3f9a1c2e"}` used as additional
  authenticated data, a fresh 96-bit nonce, and the ciphertext. **Everything else is inside the AEAD**: the
  accounts, the store's `change` id, `audit_seq`, `audit_month` and the store's copy of all usernames (3.4).
- **Key:** 32 random bytes, separate from the session key: `RACKBOOK_ACCOUNTS_KEY` (base64) or
  `--accounts-key-file`, loaded by `LoadKey(name, env, file)` with messages of its own ("`--auth local` needs the
  account store key: set RACKBOOK_ACCOUNTS_KEY (base64, 32 or more random bytes) or pass --accounts-key-file",
  "set only one of …", "… decodes to N bytes, need at least 32", "the account store key must differ from the
  session key"). Subkeys by HKDF-SHA256 with distinct `info`: `rackbook accounts v1` (encryption), `rackbook
  usernames v1` (3.4), `rackbook admin socket v1` (section 9), `rackbook attempts v1` (7.2). `kid` is the first 8
  hex digits of SHA-256 of the encryption subkey.
- **Why separate from the session key:** rotating the session key logs everyone out; it must not destroy every
  account.
- **Provisioning:** `openssl rand -base64 32`, kept with the deployment's other secrets (the infra repository's
  SOPS vault, or an `.env` outside the data volume), passed in the environment or as a read-only file from outside
  the state dir.

Per account:

| Field | Notes |
|---|---|
| `username`, `name` | `local:<username>` is the identity |
| `state` | `invited`, `active`, `restricted` and `passkey_only` (sign-in restrictions, 7.4), `reset_pending`, `disabled`, `removed` (a tombstone) |
| `created`, `created_by` | |
| `password` | PHC string, `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>` |
| `totp` | secret (20 bytes), `last_step`, `added` |
| `passkeys` | up to 10: credential id, public key, user handle, name, added, backup-eligible flag, AAGUID |
| `sid`, `session_secret` | 128-bit session id and 256-bit secret, renewed together; renewing them ends every session |
| `consecutive_failures` | failed sign-ins since the last success, all networks (the NIST cap, 7.4) |
| `totp_failures` | sign-ins where the password was right and the TOTP code wrong, last 24 h (7.4) |
| `reauth_failures` | failed re-authentications since the last success (4.7) |
| `good_buckets` | up to 10 address buckets with a successful sign-in in the last 30 days; cleared on every reset, on disable and on *sessions ended* |
| `pending` | an invite or reset: SHA-256 of the token, kind, scope, expires, issued by; the hold |
| `pending_revocations` | API token names and OAuth grant ids still to revoke (4.11) |
| `last_login`, `last_second_factor_failure` | time and address, shown on *My account* |
| `notices` | admin actions on the account not yet shown to the holder |

**Passwords.** argon2id, m = 64 MiB, t = 3, p = 4, 16-byte salt, 32-byte tag (RFC 9106, second recommended
setting), in fixed hashing slots (7.6). Constants; stored in each hash, so raising them rehashes at the next
sign-in. No pepper: the store is encrypted under a key outside the state dir.

**Password rules** (NIST SP 800-63B): at least 12 characters (`auth.local.password_min_length`, 12 to 64), at
most 128; NFKC-normalised; no composition rules, no expiry; refused if in the embedded list of the 100 000 most
common passwords, or if it contains the username or the host name.

### 3.2 Writing: one writer, audit first, and start

Every write, change or counter, goes through **one writer**: a single mutex held from building the new state to
the directory `fsync`. The in-memory state other requests read is replaced only after a write has landed, so a
counter write always encrypts the last *committed* state and can never persist an unaudited change. Every file is
written as a temporary file (`*.tmp`), `fsync`ed, renamed into place, and the directory `fsync`ed, so a named file
is always complete.

- **Counters** (the failure counts, `good_buckets`, `last_login`, `last_second_factor_failure`) keep the store's
  current `change` and `audit_seq` and have no audit event of their own.
- **Changes** are the events of section 8 that carry `change:`. Each:
  1. builds the new state with a fresh random `change` id and writes it to `accounts.enc.pending`;
  2. appends its audit event, carrying `detail: ["change:<id>"]` and the ids needed to re-apply it, with
     `RecordSync`; on error deletes `accounts.enc.pending`, changes nothing and answers `503 audit_unavailable`;
  3. puts the event's `audit_seq` and `audit_month` into the state, encrypts it **once** into `accounts.enc.next`,
     renames that over `accounts.enc`, deletes `accounts.enc.pending`, and only then answers and replaces the
     in-memory state.

**At start**, in this order (`E` is the last change event in the log, found from the store's `audit_seq` on):

1. Delete every `*.tmp` in `accounts/`: a temporary file was never renamed, so it never counted.
2. Load `accounts.enc`. No key, a wrong key or a file that does not decrypt: stop. Missing while the log has change
   events: stop (`code: missing`). Missing with no change events: a first start, create an empty store.
3. If the store's `audit_month` file is gone and retention does not explain it, or the store's `audit_seq` is past
   the end of the log: stop, "the audit log was rolled back or truncated" (`code: audit_truncated`; 3.3).
4. **`accounts.enc.next`**: if it decrypts **and** its `change` is `E`'s, rename it over `accounts.enc` and reload.
   Otherwise move it aside as evidence (`accounts.enc.next.evidence-<time>`).
5. **`accounts.enc.pending`**: if it decrypts **and** its `change` is exactly `E`'s **and** the store lacks `E`,
   finish step 3 from it and reload (`account_store_problem`, `code: recovered`): the change was audited, so it is
   applied. If it decrypts, names `E`, and the store **already has** `E`, delete it silently: a crash after the
   rename and before its deletion, not evidence. If it decrypts and its `change` is in no event, delete it: it was
   never audited or answered. Anything else (it does not decrypt, or names another audited change) is moved aside as
   evidence.
6. **Gap check**, always, after any rename: if the store's `change` is not `E`'s, the store lacks audited changes.
   That is a **gap**: stop (3.3). This includes the case of a store lacking `E` next to a missing, torn or
   undecryptable `.pending`: a crash cannot produce that (files are complete once named), so it is treated as
   tampering or a restore, never as a lost change. A keyless attacker who plants garbage therefore stops the server;
   they cannot roll back a password change.
7. After a clean start, delete any remaining `.pending` and `.next`. Evidence files stay until `accept-restore` or
   an operator removes them; **Users** shows that they exist.

### 3.3 Gaps and `accept-restore`

A gap is never accepted silently, and is not replayed (that would need secrets in the audit log). The server stops
with "the account store is older than the audit log" until the operator runs `rackbook accounts accept-restore`,
which:

- prints every change event after the store's `change`;
- **re-applies the restrictive ones**, which need no secret: `account_disabled`, `account_removed`,
  `sessions_ended`, `factor_removed` (the event names the factor), `account_reset_issued` (credentials in scope
  deleted again; `reset_pending` without a link), `account_invite_revoked`, and every revocation listed (API token
  names, re-revoked in `.rackbook/tokens.yml` if still active; OAuth grant ids, revoked again in
  `oauth-grants.json`);
- puts **every account named by any change event after the store's `change`** into `reset_pending` with scope
  `all`, so no credential replaced after the backup, and none rolled back by tampering, can be used;
- **renews `sid` and `session_secret` of every account** and clears every `good_buckets`;
- records `account_store_restored` with the seqs covered.

**The audit log rolled back or truncated** (step 3): `accept-restore` refuses unless given
`--accept-audit-truncation`, which records `account_store_problem` (`code: audit_truncated`, `detail:
["store_seq:<n>", "log_end:<m>"]`), puts **every** account into `reset_pending` with scope `all` (the lost events
cannot be listed) and renews every session secret.

**The store's month was pruned** (only possible if the retention pin was bypassed, 3.5): the events after the store
cannot be listed, so `accept-restore` refuses unless given `--reset-all-accounts`, which does the same as
`--accept-audit-truncation`.

### 3.4 Usernames are never reused

A username, once invited, is never invited again. Three records of it, unioned at every start:

- `<state-dir>/accounts/usernames`: one per line, then `mac:<HMAC-SHA256 under the usernames subkey>`. A bad MAC
  stops the server (`code: usernames_mac`).
- The store's own list (inside the AEAD).
- The `target` of every `account_invited` event in the retained audit log.

Any name in one but not another is added to all at start, so an older (validly MACed) copy of the file cannot
bring a name back. `discard-store` keeps the file; because the old key is lost then, it prints the list, asks the
operator to confirm, and MACs it again under the new key. `rekey` re-MACs it.

### 3.5 Retention and the checkpoint

The start check needs the store's `audit_month` file. At the first write in a new month, and whenever retention
would be held back, the store is written as a change with a `RecordSync` event `account_store_checkpoint`.
`--audit-retention-months` never deletes the month of the store's `audit_month`; with the checkpoint that holds a
month back by at most about one month past the configured retention, and every delayed prune logs a warning naming
the month. (This deployment keeps everything anyway.)

### 3.6 Backup and restore

- Back up the state dir and, **separately**, the key.
- Restoring both from the same backup is consistent and is not detected. Cookies issued after the backup are
  refused (older session secrets), but older cookies work again: after any restore run
  `rackbook accounts end-sessions --all` and review **Users**.
- Lost key: `rackbook accounts discard-store` moves the store aside, re-MACs `usernames` and records
  `account_store_problem` (`code: discarded`); everyone is invited again under new usernames.
- Key rotation: `rackbook accounts rekey --new-key-file`, recorded as `account_store_rekeyed` with both `kid`s.

---

## 4. The flows

Endpoints are under `/auth/local/` (no session needed) and `/api/account`, `/api/admin/accounts` (a session
needed; API tokens and OAuth tokens are refused). Every account change and every local sign-in **fails closed**
when the audit log cannot be written (section 8).

### 4.1 Invite

1. An admin, re-authenticated (section 5), opens **Users → Invite**: username, display name, role (optional),
   validity.
2. `POST /api/admin/accounts {username, name, role}`. Usernames match `^[a-z][a-z0-9._-]{0,31}$` and must not have
   been used (3.4). The store gets an `invited` account with a pending invite (SHA-256 of a 32-byte random token,
   expiry `auth.local.invite_ttl`, default 72 h, 1 h to 14 days). Audit `account_invited`.
3. A chosen role is saved as `local:<username>` in `auth.roles` through the phase 2a role editor (section 6). If
   that commit fails, **Users** shows "no role" with *Assign*.
4. The link is shown once: `https://<host>/auth/local/setup#<token>`. Nothing is e-mailed.

An admin can revoke a pending invite (`account_invite_revoked`) or issue a new one, which replaces it.

### 4.2 Opening a link (invite or reset)

1. On load the page reads the token from the fragment and removes it with `history.replaceState`. **Nothing is
   sent yet**; the page says what the link is for and shows *Continue*.
2. *Continue* sends `POST /auth/local/setup/open {token}`. The server checks the hash, the expiry and the account
   state, then **holds** the link for this browser for 30 minutes (a random value in the login cookie; its hash and
   the hold's end in the store, as a change; `account_link_opened` in the log). Another browser during the hold gets
   `invite_claimed`.
3. Once held, the link dies at the hold's end unless setup is finished.
4. An invite continues with 4.3, a reset with 4.8. Setup state (a password typed but not yet saved) is in memory,
   one per held link; only someone holding a link can create it.

### 4.3 First setup (invite)

1. **Password**, checked against 3.1.
2. **Second factor:** a passkey (4.5) or TOTP (4.4); with `second_factor: passkey`, only a passkey.
3. **Done:** one change sets both, makes the account `active`, consumes the token and makes a new `sid` and
   `session_secret`. Audit `account_setup_completed` (`code: invite`) and `login`.

### 4.4 TOTP enrolment

RFC 6238: HMAC-SHA1, 6 digits, 30-second period. A 160-bit secret; the `otpauth://` URI is drawn as a QR code by
the page itself, with the base32 secret for typing in; a current code confirms it. Verification accepts the
current step and one either side (±30 s) and refuses any step at or before `last_step`. One TOTP per account. The
server's clock must be synchronised (NTP).

**No recovery codes.** A lost factor is an admin reset (4.8). To be confirmed (section 13).

### 4.5 Passkey enrolment

WebAuthn with today's relying-party ID, resident key required (so the sign-in can use a discoverable ceremony
that does not reveal which credentials an account has), user verification as `auth.passkeys.user_verification`
says (`preferred` by default; `required` when passwordless sign-in is on). Attestation is requested as `direct`
only with `auth.local.passwordless: device_bound`. Up to 10 passkeys per account. Only the holder adds factors.

### 4.6 Sign-in: one step, one answer

The password and the second factor are checked **in the same request**, and a failure never says which part was
wrong. So a guess never learns that the password alone was right, and a password found here cannot be confirmed
for use elsewhere.

1. The sign-in page asks for an **attempt** (`POST /auth/local/attempt`), a stateless token (7.2). If a CAPTCHA is
   required for this bucket (7.4), the answer says so and the page shows it. A passkey ceremony, if the person
   chooses one, uses a discoverable challenge carried in the same attempt token (no `allowCredentials`, so nothing
   about the account is revealed).
2. One request, `POST /auth/local/login`, with the attempt token, the CAPTCHA solve if required, the username, the
   password, and **either** a 6-digit code **or** the passkey assertion.
3. The server opens the attempt token and checks that its nonce is unused (7.2), then verifies the CAPTCHA if one
   was solved, and only then records the nonce: in the **solved set** if the CAPTCHA verified, otherwise in the
   **replay set**. If the CAPTCHA turns out to be required by the name's counters (7.4) and was not solved, or the
   replay set has no room for this bucket, the answer is `401 captcha_required` and nothing else is checked.
4. With a passkey assertion it is verified **first** (no hash yet): it must be valid and belong to the named
   account. Then the password, by argon2id, in a slot (7.6). With a code, the password first, then the code.
5. Unknown, `invited`, `reset_pending`, `disabled` or `removed`, or refused by `restricted` or `passkey_only`
   (7.4): a **dummy argon2id**, then the same answer as any failure, so timing does not reveal the state.
6. Any failure: `401 sign_in_failed`, "username, password or code is wrong", whatever failed. It adds one to the
   name's failure counters (7.3) and, for an existing account, to `consecutive_failures`; a right password with a
   wrong code also adds to `totp_failures` and sets `last_second_factor_failure`, which *My account* shows: someone
   knew your password.
7. Success clears the counters, adds the bucket to `good_buckets`, rehashes the password if the parameters went up,
   issues the session (section 5) and writes `login` with the factor.

**The residual for a passkey second factor.** None: the assertion is checked before the password, and a failed
assertion ends the request before any hash, so the password is never confirmed to someone without the passkey.

**Passwordless passkey sign-in** is an owner option, **off by default** (section 13). When on, a user-verified
passkey (with `device_bound`, a device-bound one) signs in without the password.

### 4.7 Re-authentication

`POST /auth/local/reauth`: the same one-step form (password plus code or passkey; or a qualifying passkey alone when
passwordless is on), in the reserved hashing slot (7.6), with one undifferentiated answer. The counter is **per
account, in the store** (`reauth_failures`): each failure adds one, a success resets it, and **three failures end
every session of the account** (`sid` and `session_secret` renewed, `good_buckets` cleared, `sessions_ended` with
`reason: reauth_failed`). A failed re-authentication also counts toward `consecutive_failures`.

### 4.8 Admin reset

**Users → Reset**, re-authentication required. An admin cannot reset their own account here.

| Scope | Deleted at once | What the person must do with the link |
|---|---|---|
| `password` | the password | set a new password, then **pass an existing factor** (TOTP or passkey) |
| `second_factor` | TOTP and passkeys | **enter the current password**, then enrol a new factor |
| `all` (*Full reset*) | everything | set a password and enrol a factor: **in effect a new invite** |

- *Full reset* is a separate button with the warning "This lets whoever opens the link take over the account. It is
  the same as inviting a new person under this name." Audited with `code: all`.
- At issuance: `reset_pending` (no role; section 6), `sid` and `session_secret` renewed, counters and
  `good_buckets` cleared, the account out of `restricted`, tokens and grants revoked (4.11), and a reset link like an
  invite (`auth.local.reset_ttl`, default 24 h, 1 h to 7 days, with the hold). Audit `account_reset_issued`.
- On the link, the current password of a `second_factor` reset is confirmed only to someone holding the link (the
  admin, or the person they gave it to); its failures count toward `consecutive_failures`. Completion writes
  `account_setup_completed` (`code: reset`) and is refused (`409 revocation_pending`) while revocations are pending.
- The old password stops at once for `password` and `all`, not for `second_factor`.
- The holder sees a notice of every reset, *Disable*/*Enable* and *Unlock* at their next sign-in until dismissed.

### 4.9 Disabling and removing an account

**Disable** (re-authentication required): `state: disabled`, `sid` and `session_secret` renewed, `good_buckets`
cleared, tokens and grants revoked (4.11). Sessions end at once, sign-in fails as in 4.6, and `local:<username>`
has no role on every path (section 6). **Enable** reverses the state and is refused while revocations are pending.

**Remove** (re-authentication required): the same, then the credentials and pending tokens are deleted and a
tombstone is left. The console offers to take `local:<username>` out of `auth.roles`.

Refused for both: acting on yourself, or on the last active admin.

### 4.10 Incident response (the store and its key both leaked)

`rackbook accounts rekey`, then `rackbook accounts reset --all --scope all`.

### 4.11 Revoking tokens and grants

Disable, remove, every reset and `reset --all` revoke the account's API tokens (one commit to
`.rackbook/tokens.yml`) and its OAuth grants and refresh tokens (`oauth-grants.json`). The account event lists them
(`detail: ["tokens:<names>", "grants:<ids>"]`, never secrets); that is what `accept-restore` re-applies. They are
first written as `pending_revocations` in the same change and removed once applied; a failed commit is retried every
minute and at start, and **Users** shows it. While any is pending, *Enable* and reset completion are refused. The
account is not active meanwhile, so its tokens and grants have no role even before the commit lands.

### 4.12 Self-service (My account)

All need re-authentication: **change the password** (`password_changed`; renews `sid` and `session_secret`, keeps
this session), **add or remove a factor** (`factor_added`, `factor_removed`; not the last one), and **sign out
everywhere** (`sessions_ended`; renews `sid` and `session_secret`, clears `good_buckets`, issues a fresh cookie
here), with the box "Also revoke my API tokens and app connections" ticked by default and the list of what it
revokes.

---

## 5. Sessions

The same cookie and session key, with `method: local` added. A local session carries `sid`, `aat` (when the person
last fully authenticated) and the factor used. `auth.session.idle` and `absolute` apply.

**Bound to the store.** A local cookie's MAC key is

```
HKDF-SHA256(ikm = session key, salt = account.session_secret, info = "rackbook.session.local.v1" || sid)
```

The codec reads the (unverified) username, looks the account up in memory, derives the key, then verifies. The
account must exist, be `active`, `restricted` or `passkey_only`, and have the same `sid`. `restricted` and
`passkey_only` limit **how a new sign-in may happen**; they are not revocations, so live sessions keep working.
Only `disabled`, `removed` and `reset_pending` (and the invite state) end sessions.

**Re-authentication.** Sensitive actions need `aat` within `auth.local.reauth_window` (default 10 minutes,
1 minute to 1 hour), otherwise `403 reauth_required`. Sensitive: *My account* (password, factors, sign out
everywhere); account administration (invite, revoke an invite, resets, unlock, disable, enable, remove); creating or
revoking an API token; saving roles; approving an MCP client in the built-in OAuth server.

**Pages.** The sign-in, setup and re-authentication pages are separate documents under `/auth/local/`, served by a
full page load with a CSP of their own that allows the CAPTCHA provider's origin (for Turnstile,
`https://challenges.cloudflare.com` for `script-src` and `frame-src`) and nothing else beyond the console's. The
console's CSP stays as it is. `securityHeaders` gets a per-path policy for this. After sign-in the browser is sent to
the console with a full navigation, so the console is always loaded fresh under its own CSP; re-authentication
inside the console opens the re-authentication page in a full-page navigation and returns to the action.

---

## 6. Roles

A local account gets its role from `auth.roles` by its identity `local:<username>`. The store holds no role.

```yaml
auth:
  roles:
    admin:  ["local:alice"]
    editor: ["local:bob", "local:carol"]
    viewer: ["local:*"]
```

- New entry kinds `local:<username>` and `local:*`. Local identities match those and `*`, nothing else, so method
  `local` is **not** in `plainMethods` (`internal/roles/roles.go`).
- **One check on every path.** A private helper `(*Authenticator).policyRole(s roles.Subject)` replaces the direct
  `Policy().Evaluate(s)` calls in `RoleForVia` and `EvaluateSubject` (and so in `Evaluate`). It gates on the
  **identity**: for any subject whose ID starts with `local:`, the role is none unless the method is `local` and
  `localAccountActive(s.ID)` says the account is `active`, `restricted` or `passkey_only`. The two restricted
  states only limit new sign-ins (7.4); the account's tokens and grants keep their role in them, so an attacker who
  drives an account into `passkey_only` cannot revoke anything. Only `disabled`, `removed` and `reset_pending`
  (and `invited`) give no role. That covers sessions (`Evaluate`), token creators (`RoleForVia`, `internal/api/tokens.go:68`) and OAuth
  grants, OAuth access tokens and API tokens on `/mcp` (`EvaluateSubject`, `internal/oauthserver/token.go:75`,
  `internal/mcpauth/mcpauth.go:233` and `:265`). A test walks all three with a disabled account and with a look-alike
  identity from another method.
- `internal/tokens` records the creator's method `local` (`creatorMethod`). `passkey` stays in `plainMethods` and
  `creatorMethod`, so tokens and grants made from passkey sessions before section 10 keep their role.
- Git commits are authored `Display Name <local:alice>`.

**With phase 2a's role editor:** in local mode it offers the accounts by name for `local:` entries and marks
`group:`, `app-role:`, `*@domain` and `oidc:` entries as having no effect (the reverse under SSO). An entry for a
username with no account is kept with a warning. The last-admin rule counts only `local:` entries of `active`,
`restricted` or `passkey_only` accounts, and still refuses removing the editing admin's own entry.

---

## 7. Rate limits, CAPTCHA and capacity

### 7.1 Providers

- **Required in local mode: a token CAPTCHA.** `--captcha turnstile|hcaptcha|recaptcha` with
  `--captcha-site-key` and `RACKBOOK_CAPTCHA_SECRET` / `--captcha-secret-file` (deployment secrets only). Turnstile
  is preferred: this deployment is behind Cloudflare already, so it adds no new third party, and most people never
  see a puzzle. The verifier is `NewTokenVerifier(provider, secret, WithAllowedHostnames(HostOf(baseURL)),
  WithTimeout(5 s))`.
- **A hostname must be present.** authcore skips the pin when the provider returns no hostname; Rackbook refuses a
  successful result with an empty `Hostname` (`captcha_failed`, `reason: hostname_missing`). For reCAPTCHA the
  admin must keep domain verification on; the docs say so.
- **Failures fail closed.** `ErrDecodeResponse`, `ErrBadStatus` and `ErrNetwork` on an attempt refuse that attempt
  (`503 captcha_unavailable`, retry). There is **no fallback per attempt**.
- **Concurrency.** At most 32 siteverify calls for attempts at once; beyond that the attempt gets `503 busy` with
  `Retry-After`, not a fallback. The health probe (below) has a dedicated slot of its own outside this cap.
- **The image CAPTCHA** (authcore's five distorted digits, no outbound call) is allowed only with
  `--captcha image --captcha-image-weak-ok`, and the server logs a warning at every start: "the image CAPTCHA is
  solved by OCR and has no audio alternative; sign-in is protected mainly by the NIST cap". It is for deployments
  that cannot call out.
- **Outage fallback**, only where `--captcha-image-weak-ok` is set: a health probe sends one siteverify call with
  a dummy token every 30 seconds from its own slot. A **probe failure** is only a network error, a timeout or a 5xx
  answer on the probe's own request; a 200 answer refusing the dummy token is a success. Nothing from user attempts
  counts: not `busy`, not their `ErrBadStatus` or timeouts, so a server that is merely overloaded never declares an
  outage. At least 5 consecutive probe failures over at least 2 minutes declare an outage; image CAPTCHAs are used
  until the probe succeeds 3 times in a row. Start and end write
  `captcha_outage` and show admins a banner. Without the flag, an outage means that sign-ins needing a CAPTCHA wait
  ("try again shortly"); sign-ins that need none go on.

The `remoteIP` passed to `Verify` is the client address by the trusted-proxy rules, unbucketed (a new
`clientip.Addr`).

### 7.2 Attempts: stateless tokens, two sets, and admission

An attempt is a token, not server state:

```
attempt = base64(nonce(16) || bucket || issued || expires || flags || [image answer | passkey challenge]),
          sealed with AES-256-GCM under the attempts subkey
```

It expires after 5 minutes and binds the bucket it was issued to (a request from another bucket is refused). The
image answer and the WebAuthn challenge, when present, travel inside the sealed token, so the server keeps no
image-challenge store and no ceremony store for sign-in; authcore's image driver is used only to render. Minting an
attempt is free, so **nothing an attempt costs the server may be held before a CAPTCHA has verified**. Single use is
enforced by two sets of nonces, each entry kept until its token expires, and checked together (a nonce in either is
used):

**The replay set**, for attempts used **without** a verified CAPTCHA (no CAPTCHA was required, or a solve failed).
Two partitions, each with its own per-bucket quota:

| Partition | Size | Per bucket | Holds |
|---|---|---|---|
| **free** | 20 000 | 20 | uses with no CAPTCHA (none was required) |
| **image** | 20 000 | 10 | reservations for image answers about to be checked (below) |

When a bucket is at its quota in *free*, or *free* is full, the **newest** use is not recorded and the answer is
`401 captcha_required`: the attempt is refused, and the caller retries with a CAPTCHA. Filling *free*, which costs
nothing, therefore only makes everyone solve a CAPTCHA. It never stops a CAPTCHA from being checked: a token
CAPTCHA does not use the replay set before it verifies, and an image answer reserves its entry in *image*, which
free uses cannot reach. Filling *image* needs one rendered image per entry, which the rendering budget bounds.

**The solved set**, for attempts whose CAPTCHA **verified**: an entry is added only after the provider (or the image
answer) has accepted the solve, so every entry costs the attacker one CAPTCHA solve. 300 000 entries in three
partitions, with a quota of 30 entries per bucket (6 solved attempts per minute):

| Partition | Size | Admits a spend when |
|---|---|---|
| **good** | 50 000 | the bucket is in the named account's `good_buckets` (known at spend time, from the username) |
| **headroom** | 30 000 | the bucket holds fewer than 3 entries in the solved set |
| **general** | 220 000 | any bucket under its quota |

Admission at spend time: a good-bucket spend goes to *good* (then *general*); a spend from a bucket with fewer than
3 entries goes to *general* while it has room, else *headroom*; any other spend goes to *general*. When the
partition it needs is full, the spend is refused (`try again shortly`), and the attempt is not recorded. Nothing is
evicted: evicting a solved entry would let an image answer be replayed. A test fills *general* from many buckets and
checks that a new bucket still spends into *headroom* and a good bucket into *good*.

**Image rendering** has a global budget of 50 images per second and a per-bucket share of 10 per minute; over it,
"try again shortly". **Counters** have their own bounds (7.3).

**An image is checked once.** Before an image answer is checked, an entry for its nonce is reserved in the *image*
partition, so a failed solve is always recorded before the answer goes out (a correct one moves to the solved set).
If no entry can be reserved (the bucket is at its *image* quota, or the partition is full), the token is refused
without checking the answer: `401 captcha_required` with a new attempt and a new image. An image whose failure was not
recorded is never checked again, so one image never yields more than one guess at its digits.

One solve counts for one attempt: the nonce is recorded right after the solve verifies (the record and the check
are one atomic step, so two concurrent uses of one token cannot both pass), the provider refuses a token used twice,
and an image answer can be checked once.

### 7.3 Counters

Buckets: a new `clientip.Bucket(r, trusted, 48)`, IPv6 by /48, IPv4 by the full address.

| Counter | Kept | Window |
|---|---|---|
| attempts per bucket | memory | burst 10, 1 per minute |
| passkey ceremony attempts per bucket, **its own bucket** | memory | 30 per minute, burst 10 |
| link opens per bucket | memory | burst 5, 1 per minute |
| failures per (name, bucket), for **every** typed name | memory, the **pair table**, keyed by (HMAC(per-start key, name), bucket) | consecutive, cleared on success |
| failures per name, all buckets | memory, the **name table**, keyed by HMAC(name) | last hour |
| dummy hashes | memory, global | 30 per minute |
| `consecutive_failures`, `totp_failures` | the store, existing accounts only | 7.4 |

**Why one table for every name.** CAPTCHA triggers read only the in-memory table, which treats an existing and an
unknown name alike (same keys, same windows, same loss on restart), so whether a CAPTCHA appears never says whether
a name exists. The store counters affect only *which* answer follows a fully checked request, and every such answer
is the same `sign_in_failed` (4.6), so they reveal nothing either. Basing triggers on bucket counts alone would also
be uniform but would let a slow distributed attack on one name avoid every CAPTCHA.

**Bounds.** The pair table holds 100 000 rows, at most 1 000 per bucket; the name table holds 50 000 rows, and one
bucket may create at most 200 new name rows per hour. On overflow, each table drops the rows with the **fewest
failures** first, and never a row at or above its CAPTCHA threshold (3 for a pair, 20 for a name). If a table is
full of rows at or above the threshold, a name that cannot get a row is treated as **over** the threshold, so its
attempts need a CAPTCHA. Residual: in such a flood every sign-in needs a CAPTCHA (good buckets still skip the name
trigger), and a dropped low row can let a name with a few failures avoid the CAPTCHA for a little longer; neither
refuses anyone, and both treat existing and unknown names alike.

### 7.4 When the CAPTCHA is required, and the hard limits

A sign-in attempt needs a solved CAPTCHA when **any** of these holds:

- its (name, bucket) pair has 3 or more consecutive failures;
- its bucket is over its attempt rate (a NAT or carrier bucket gets a CAPTCHA, not a refusal);
- the global dummy-hash budget is used up;
- the name has more than 20 failures in the last hour from all buckets.

A bucket in the account's `good_buckets` skips the last two. A passkey ceremony needs a CAPTCHA only once its own
bucket is over its rate.

Two hard limits remain, both per account and both in the store:

- **The NIST cap** (SP 800-63B §5.2.2: at most 100 consecutive failed attempts). `consecutive_failures` counts
  every failed password check of the account **across all buckets**, good ones included, and is cleared only by a
  successful sign-in or an admin *Unlock*. A refused attempt that never reaches the password check (a failed passkey
  assertion, a refusal by the states below) does not count; it is not a guess.
  - At **99** the account becomes `restricted`. A password check then runs only for an attempt from one of its
    `good_buckets`, or after a verified passkey assertion (4.6), so a guess without the passkey from a new network
    never reaches the password.
  - The **100th** failure, which can therefore only come from a good bucket (or with the passkey), makes it
    `passkey_only`: a password check runs only after a verified passkey assertion. This also covers an attacker who
    sits in a good bucket (a NAT neighbour): from there too, the 100th failure closes the password path.
  - A failed password check after a verified passkey counts toward `consecutive_failures` like any other failure,
    in every state; in `passkey_only` the account simply stays `passkey_only`. There is no further lock: a holder's
    typo never needs an admin, and someone who has the passkey but not the password still needs one guess per
    passkey use, with a CAPTCHA once the counters trigger it.

  Each step writes `account_restricted` (`code`: `restricted` or `passkey_only`) and tells the holder and
  admins. Refusals by these states run the same dummy argon2id as every other refusal (7.5). So **at most 100
  password guesses can be made per holder sign-in** without the passkey, which is the NIST cap; this is a **bounded
  denial of service, accepted as NIST intends**, and the holder keeps a path from known networks until the 100th
  failure, and with a passkey after it.
- **TOTP limit:** 10 `totp_failures` in 24 hours (a right password with a wrong code, so only someone who knows the
  password can cause it) stops TOTP for the account (`account_locked`, `code: totp`) and tells the holder and admins
  that someone knows the password. A **passkey second factor still works** (the default, with passwordless off).
  Without a passkey, the way back is an admin *Unlock* followed by a `password` reset.

*Unlock* (console, or `rackbook accounts unlock` online) clears the store counters, ends `restricted`, `passkey_only` and the TOTP
limit, and clears the account's entries in the memory table.

### 7.5 Uniform answers

Unknown, invited, reset-pending, disabled and removed accounts get exactly the answers an existing account gets:
the same CAPTCHA triggers (7.3), then `401 sign_in_failed` after one argon2id run against a fixed dummy hash. A
restricted or passkey-only account's refusals are the same `sign_in_failed`, after the same dummy argon2id. Real and dummy runs use the same parameters in the same
slots; the residual is the variance of one argon2id run (a few percent, more under load), accepted: averaging many
samples might reveal that a username exists, and usernames are not secret here.

### 7.6 Hashing slots

Three slots (192 MiB peak): one **reserved** for re-authentication of a signed-in session and for attempts from a
bucket in that account's `good_buckets`; two **general**. Waiting callers queue, reserved first; past 5 seconds,
`503 busy` with `Retry-After: 5`, and the page retries once. The CAPTCHA, when required, and a passkey assertion are
verified before a caller queues for a slot.

### 7.7 What the holder can count on

For a holder who has their password and their second factor, and whose password nobody else knows:

- **From a network they used in the last 30 days** (`good_buckets`): they can always sign in, with at most one
  CAPTCHA per attempt, at any botnet size. Their solved attempts use the *good* partition and the reserved hashing
  slot, skip the "under attack" and budget triggers, and are accepted while the account is `restricted`. What can
  still stop them: the account reaching `passkey_only` when they have no passkey (100 failures; then an admin
  Unlock), a flood from inside their own bucket over its quota (30 solved attempts per 5 minutes, then "try again
  shortly"), and the audit log failing (fail closed).
- **From a new network**: they can sign in with a CAPTCHA per attempt unless (a) the account is `restricted` or
  beyond and they have no passkey (then: a known network, or an admin Unlock), (b) the CAPTCHA provider is out (7.1),
  or (c) an attacker keeps both the *general* and the *headroom* partitions full. Every entry there is a **verified
  CAPTCHA solve** that lives 5 minutes, so (c) costs about 250 000 solves every 5 minutes: some 830 a second, 72
  million a day, or roughly $70 000–220 000 a day at solver-farm prices of $1–3 per thousand, from at least about
  8 500 distinct buckets (the per-bucket quota), and at least 10 000 of them holding fewer than 3 entries each to keep
  *headroom* full. Filling the replay set or minting attempts costs nothing and only makes people solve a CAPTCHA.
- **Someone who knows the password** can trigger the TOTP limit; a passkey still works.

### 7.8 Someone who cannot solve the CAPTCHA

- With **Turnstile** most people are never shown a puzzle; it follows the provider's accessibility support.
- They can sign in from a **network they used before**, which skips the "under attack" and budget triggers.
- If the trigger is their own pair's failures (for example their own typing mistakes), only a success clears it, so
  they can ask an **admin to Unlock** the account, which clears its counters at once;
- with passwordless sign-in on (section 13), a qualifying passkey avoids the CAPTCHA unless the passkey bucket is
  exhausted.

The image CAPTCHA, where allowed, has no audio alternative; the start warning and the **Users** screen say so.

---

## 8. Audit events

```go
// RecordSync appends e and fsyncs it. It returns the seq it got, or an error,
// including when the log is in its failed state. It never drops an event silently.
func (l *Log) RecordSync(e Event) (seq int64, err error)
```

Every change (3.2) and every local `login` and `reauth` use `RecordSync` and **fail closed** with
`503 audit_unavailable`: the sign-in page says "Sign-in is unavailable: the server cannot write its audit log. An
administrator must check the server"; admins already signed in see the existing red audit banner, and the account
actions in **Users** are disabled with the same reason. `logout` clears the cookie and records with `Record`.
Refusals and CAPTCHA events use `Record`, aggregated (below). Local mode requires `--state-dir`.

All events are in the chain, area `audit`. `method` is `local` for the console and `cli` for the command line, with
`detail: ["operator:<text>"]` from the caller's `--operator` (default `unspecified`). `addr` comes from
`clientip.Of`, kept as `--audit-addr` says: `full` in this deployment, which still keeps an IPv6 client as its /64.
Passwords, codes, tokens, CAPTCHA answers, secrets and typed unknown usernames are never recorded. New field
**`target`**: the account acted on when that is not the actor. Every change event carries `detail: ["change:<id>"]`.

| Event | `identity` | Other fields |
|---|---|---|
| `login` | the account | `role`, `addr`, `detail: ["factor:totp"]`, `["factor:passkey"]` or `["factor:passkey", "passwordless"]` |
| `login_refused` | the account, empty if unknown | `addr`; `reason`: `unknown_account`, `bad_credentials` (any of password, code or passkey; the log, like the answer, does not say which), `restricted`, `totp_locked`, `disabled`, `not_set_up`, `reset_pending`, `no_role`, `quota`, `busy`, `invite_invalid`, `invite_expired`, `invite_claimed`; `code: reauth` for a failed re-authentication; `code: summary` for an aggregate |
| `captcha_failed` | the account, empty if unknown | `addr`; `reason`: `wrong_answer`, `rejected`, `hostname_mismatch`, `hostname_missing`, `expired`, `unavailable`; `detail`: the provider's error codes; `code: summary` for an aggregate |
| `captcha_outage` | none | `code`: `start` or `end`; `detail: ["failures:<n>"]` |
| `logout` | the account | `role`, `addr` |
| `reauth` | the account | `addr`, `detail: ["factor:…"]` |
| `account_restricted` | the account | `detail: ["failures:<n>"]`, `code`: `restricted` or `passkey_only` |
| `account_locked` | the account | `code: totp`, `detail: ["failures:<n>"]` |
| `account_unlocked` | the admin | `target` |
| `account_invited` | the admin | `target`, `detail: ["expires:<time>"]` |
| `account_invite_revoked` | the admin | `target` |
| `account_link_opened` | the account | `addr`, `code`: `invite` or `reset`, `detail: ["hold_until:<time>"]` |
| `account_setup_completed` | the account | `addr`, `code`: `invite` or `reset`, `detail: ["factor:…", "scope:…"]` |
| `account_reset_issued` | the admin | `target`, `code`: `password`, `second_factor`, `all`; `detail: ["expires:<time>", "tokens:<names>", "grants:<ids>"]` |
| `password_changed` | the account | `addr` |
| `factor_added`, `factor_removed` | the account | `code`: `totp` or `passkey`; `detail: ["name:<passkey name>", "credential:<id>"]` |
| `sessions_ended` | the account, or the admin/CLI with `target` | `addr`; `reason`: `self`, `reauth_failed`, `cli`; `detail: ["tokens:<names>", "grants:<ids>"]` |
| `account_disabled`, `account_removed` | the admin | `target`, `detail: ["tokens:<names>", "grants:<ids>"]` |
| `account_enabled` | the admin | `target` |
| `account_store_checkpoint` | none | (3.5) |
| `account_store_problem` | none | `code`: `gap`, `missing`, `recovered`, `audit_truncated`, `key_mismatch`, `unreadable`, `discarded`, `usernames_mac`, `evidence`; `detail` |
| `account_store_restored`, `account_store_rekeyed` | none, `method: cli` | `detail`: the seqs covered, or the old and new `kid` |
| `passkeys_removed` | the admin | `detail: ["count:<n>"]`; SSO deployments, section 10 |

**Aggregates.** Per address bucket and minute, the first `login_refused` and the first `captcha_failed` for each
account (and for unknown accounts) are written in full; the rest are counted and written once at the end of the
minute as the same event with `code: summary`, the bucket's `addr`, and `detail: ["count:<n>",
"reasons:<reason>=<n>,…", "accounts:<n>", "captcha_required:<n>", "from:<time>", "to:<time>"]`. Beyond 100 buckets
in one minute the rest fold into one summary without `addr`.

---

## 9. Config, flags, CLI and MCP

**Local mode is the deployment's choice:** `--auth local` or `RACKBOOK_AUTH=local`.

- `auth.mode: local` in `rackbook.yml` stays **rejected** by `Login.check`, with the message "local mode is set by
  the deployment: --auth local".
- With `--auth local`, `auth.mode` in the file must be absent, and the server refuses to start (and refuses a pulled
  config) when the file has an `auth.oidc` block or `auth.mcp.trusted_issuers` (section 13). `auth.mcp.builtin_issuer`
  is allowed.
- Local mode needs `--state-dir` (strictly 0700), `--base-url` (https), the session key, the account key and a
  token CAPTCHA (or the image CAPTCHA with the weak flag).

| Flag / variable | Meaning |
|---|---|
| `--auth local` | local accounts |
| `RACKBOOK_ACCOUNTS_KEY` / `--accounts-key-file` | the account store key (3.1) |
| `--captcha turnstile\|hcaptcha\|recaptcha\|image` | required in local mode; no default, no `off` |
| `--captcha-image-weak-ok` | allows `--captcha image`, and the outage fallback to it; warns at every start |
| `--captcha-site-key` | the public site key |
| `RACKBOOK_CAPTCHA_SECRET` / `--captcha-secret-file` | the provider's secret, from deployment secrets only, never logged |

These are flags, not `rackbook.yml` keys: whoever edits the ledger must not be able to weaken the CAPTCHA.

Tunables in `rackbook.yml`, with floors:

```yaml
auth:
  local:
    second_factor: any          # any (passkey or TOTP) | passkey
    passwordless: off           # off | synced | device_bound   (section 13)
    password_min_length: 12     # 12..64
    invite_ttl: 72h             # 1h..14d
    reset_ttl: 24h              # 1h..7d
    reauth_window: 10m          # 1m..1h
  passkeys: {user_verification: preferred}
  session: {idle: 12h, absolute: 7d}
```

argon2id, TOTP, counter, CAPTCHA trigger, quota, slot and budget parameters are constants.

**CLI** (`rackbook accounts`). Every command needs the account key. With the server running, commands go over the
**admin socket** `<state-dir>/admin.sock` (mode 0600). The uid is not trusted; possession of the key is:

1. The client sends a 32-byte nonce `Nc`.
2. The server answers a nonce `Ns` and `HMAC(k_socket, "server" || Nc || Ns)`, which the client checks before
   sending anything: the server proves it holds the key.
3. Both derive `k_session = HKDF-SHA256(k_socket, salt = Nc || Ns, info = "rackbook admin session v1")`. Every
   request and answer is sealed with AES-256-GCM under `k_session`, with a counter in the nonce and the direction
   in the additional data; the first request that opens correctly proves the client holds the key.
4. A caller without the key, such as a same-uid sidecar relaying the connection, can neither read nor forge a
   request or an answer. **Invite and reset links never cross the socket in clear.**

With the server stopped, commands take the state dir's lock and work on the files. Links are printed to the
operator's terminal only. Each writes its audit event with `method: cli` and `operator:<text>` from `--operator`
(free text; it identifies, it does not authorise).

| Command | Online | Offline | What |
|---|---|---|---|
| `list` | yes | yes | usernames, state, factors, counters, evidence files, pending revocations, whether a role entry matches |
| `invite <username> [--name] [--ttl]` | yes | yes | the first admin, or anyone |
| `reset <username> --scope password\|second_factor\|all`, `reset --all --scope …` | yes | yes | break-glass, also for the last admin |
| `unlock <username>` | yes | yes | clears counters, `restricted`, `passkey_only` and the TOTP limit |
| `disable`, `enable <username>` | yes | yes | |
| `end-sessions <username>\|--all` | yes | yes | renews session secrets |
| `rekey --new-key-file` | no | yes | 3.6 |
| `accept-restore [--accept-audit-truncation] [--reset-all-accounts]` | no | yes | 3.3 |
| `discard-store` | no | yes | 3.6 |

On Windows there is no admin socket; the commands work offline only (section 13).

**Bootstrap:** set `auth.roles.admin: ["local:alice"]`, run `rackbook accounts invite alice`, start the server, open
the link.

**MCP and API tokens:** unchanged in how they work; their role follows the account (section 6) and they are revoked
with it (4.11). No MCP tool manages accounts; the account endpoints refuse tokens.

---

## 10. Passkeys when SSO is configured

**Decision:** with `auth.mode: oidc` there is no passkey sign-in. Sign-in is only through the identity provider,
which is where phishing-resistant sign-in belongs (Entra supports passkeys itself) and which sees a disabled
account.

**Not a switch.** `auth.passkeys` in an OIDC deployment is accepted, ignored and logged as a warning at start. If it
is ever needed again, it returns as a server flag (default off) together with the `passkeys_oidc_max_age` rule.

**Migration:**

- On upgrade, `/auth/passkey/*` and the passkey parts of *My account* are gone. An existing passkey session is
  rejected at its next request; the person signs in through SSO. The release notes say so.
- Tokens and grants made from passkey sessions keep their role (`passkey` stays a recognised method).
- `.rackbook/passkeys.yml` is not changed and no longer read. It holds **personal data**: identity (e-mail address or
  UPN), display name, WebAuthn user handle, AAGUID (the device model), credential ids and dates. **Removing it is
  recommended.**
- **Users** offers **Remove old passkeys** (a commit deleting the file, `passkeys_removed`); until the file is gone,
  admins see a reminder banner on every page. History keeps the old file.
- **Downgrade risk:** while the file exists, an older Rackbook would accept those passkeys again, around the
  identity provider. Removing the file closes that.

---

## 11. Console screens

Each ships with a demo in three languages before merge.

- **Sign in** (local mode, its own page; section 5): username, password, and the second factor **on the same form**: a
  6-digit code field, or *Use a passkey instead*, which runs the passkey ceremony and then submits everything
  together. When a CAPTCHA is required it appears in place, keeping what was typed. With passwordless on, *Sign in
  with a passkey* comes first. Messages: "Username, password or code is wrong" (every credential failure), "Please
  confirm you are a person", "The CAPTCHA did not work, try again", "Try again shortly" (quota, busy, provider out),
  "Sign-in is unavailable" (audit). Also: "Cannot solve this? Sign in from a network you used before, or ask an
  administrator." No "forgot password" link.
- **Set up your account** (invite and reset links, its own page): first a page that only says what the link is for,
  with *Continue*; then what the link calls for: a new password with the rules and the reason a password is refused;
  the current password (a `second_factor` reset); the existing factor (a `password` reset); a new factor, *Add a
  passkey* (recommended) or *Use an authenticator app* (QR code, secret, code to confirm).
- **Re-authenticate** (its own page, a full navigation from the console and back): the same one-step form.
- **My account**: password; factors; *Sign out everywhere* with the ticked box and the list of what it revokes;
  last sign-in and from where; warnings when someone entered the password but failed the code, when the TOTP limit
  was reached, and when the account was restricted; notices of admin actions until dismissed.
- **Users** (admin): username, name, role ("no role" with *Assign*), state (invited until, link held until, active,
  restricted, passkey only, TOTP locked, reset pending, disabled), factors, last sign-in, pending revocations, and a
  warning when evidence files from a refused start exist. Actions: *Invite*, *Copy a new link*, *Revoke invite*,
  *Reset password*, *Reset second factor*, *Full reset…* (separate, with the warning), *Unlock*, *Disable* /
  *Enable*, *Remove*. Before *Disable*, *Remove* or a reset, the dialog lists the tokens and app connections it
  revokes. During a CAPTCHA outage, and whenever the image CAPTCHA is in use, a banner says so. While the audit log
  cannot be written, the actions are disabled with the reason.
- **Users → Roles** (phase 2a): as section 6.
- Under SSO: no passkey parts in *Sign in* and *My account*; the reminder of section 10 until
  `.rackbook/passkeys.yml` is gone.

---

## 12. Pieces (one PR each)

1. **Passkeys off under SSO** (section 10). Independent; it also removes `passkeys_oidc_max_age` from phase 2a.
2. **Audit and store foundations:** `RecordSync`; the retention pin and checkpoint; the encrypted store with
   `LoadKey`, subkeys and `kid`; the single writer and the start sequence of 3.2 with evidence files; the three
   username records; argon2id with slots; password rules and blocklist; TOTP. Offline `rackbook accounts rekey |
   accept-restore | discard-store | list`. No HTTP.
3. **Local identity and roles:** `--auth local` and its refusals, strict state dir, `auth.local`, `method: local` in
   the codec with the per-account MAC key, `local:` entries, `policyRole` on all three paths, token creator method,
   the `target` audit field.
4. **Sign-in, CAPTCHA and setup:** the separate sign-in, setup and re-authentication pages with their own CSP
   (`securityHeaders` per path); the one-step sign-in; stateless attempt tokens, the replay and solved sets with quotas and
   reservations; `clientip.Bucket` and `clientip.Addr`; the counter table; the token verifier with the hostname
   requirement, concurrency bound and health probe; restricted, the TOTP limit; aggregated events; the admin socket
   protocol and the online CLI.
   **Dependency:** importing `authcore/captcha` pulls in `github.com/mojocn/base64Captcha` and its image libraries,
   which are not in `go.sum` today. This piece reviews them, or (preferred) authcore first splits the token verifier
   into its own package, or puts the image generator behind a build tag, so that a deployment without
   `--captcha image` does not ship the image code at all.
5. **My account and re-authentication:** `aat`, `reauth_required`, the per-account re-authentication counter,
   self-service, sign out everywhere with revocation, the notices.
6. **Users administration:** the table and actions, revocation with `pending_revocations` and retry. The role choice
   in *Invite* needs phase 2a's role editor; until then this piece links to editing `rackbook.yml`.

Piece 1 goes first and can ship on its own. Pieces 2 to 6 are in order.

---

## 13. For the owner to decide

1. **Passwordless passkey sign-in**: proposed **off by default** (`auth.local.passwordless: off`); nothing in 7.7
   depends on it. Under NIST SP 800-63B a user-verified passkey is a multi-factor cryptographic authenticator: a
   **synced** passkey (iCloud Keychain, Google Password Manager, 1Password, …) reaches AAL2, and a **device-bound**
   one with attestation can reach higher. The risk of `synced`: whoever takes over the person's password manager or
   cloud account gets the passkey and the Rackbook account without a password. `device_bound` accepts only passkeys
   whose backup-eligible flag is off, checked at registration and every sign-in, with attestation requested (and
   optionally an AAGUID allow list), at the cost of excluding synced passkeys.
   Residual even with passwordless **off**: someone who holds the passkey but not the password (for example a synced
   passkey taken over through the person's cloud account) gets one password guess per passkey use, with a CAPTCHA
   once the counters trigger it, and the guesses count toward the NIST cap (7.4). Accepting only device-bound
   passkeys would close the cloud-account route; as written, `device_bound` applies only to passwordless sign-in,
   so whether to require it for the passkey second factor too is part of this decision.
2. **CAPTCHA provider**: proposed Turnstile for this deployment. The image CAPTCHA only with
   `--captcha-image-weak-ok`; confirm that it should exist at all, since it has no audio alternative.
3. **The NIST cap and restricted mode** (7.4): failures counted across all networks; at 99 the account accepts
   password checks only from known networks or after a passkey; the 100th failure leaves only the passkey path and
   Unlock. A bounded denial of service, accepted as NIST intends. Confirm the thresholds.
4. **Recovery codes:** proposed none (4.4).
5. **`second_factor` default:** proposed `any` (TOTP allowed); `passkey` is safer against phishing and keeps every
   holder on the passkey path of 7.4.
6. **Full reset by a single admin** (4.8): proposed allowed, warned and audited; the alternatives are a two-person
   rule, or full resets from the CLI only.
7. **Usernames are never reused**, even after `discard-store`.
8. **Outside OAuth issuers under local mode**: proposed refused (`auth.mcp.trusted_issuers`, including MCPHub).
9. **Windows:** no admin socket, so the CLI works only while the server is stopped.
10. **Old passkeys:** an admin button plus a reminder, or a one-time automatic commit deleting
    `.rackbook/passkeys.yml` at the first start after the upgrade (which closes the downgrade risk at once).
11. **authcore changes**: splitting the token verifier from the image generator (piece 4), and exposing Turnstile's
    `cdata` so the attempt id can also be bound into the token. Neither is required by this design.
