# Local accounts, and passkeys off under SSO

Status: design, decided by the owner on 2026-11-22 and revised after two rounds of review the same day; nothing
here is built yet. Builds on [design-audit.md](design-audit.md) (the audit log, phase 2a) and
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
  (`seal` in `internal/login/session.go`). It ends after `auth.session.idle` (12 h) without activity and after
  `auth.session.absolute` (7 days). The role is evaluated from `auth.roles` on every request. The codec
  accepts the methods `oidc` and `passkey` only.
- **Passkeys** are an alternative to OIDC, not a second factor, committed to `.rackbook/passkeys.yml` in the
  **data repository** (not the state dir).
- **Roles** are evaluated on three paths, all through `Policy().Evaluate` in `internal/auth/auth.go`:
  `Authenticator.Evaluate` (sessions), `Authenticator.RoleForVia` (an API token's creator, e.g.
  `internal/api/tokens.go:68`) and `Authenticator.EvaluateSubject` (OAuth grants in
  `internal/oauthserver/token.go:75`, OAuth access tokens and API tokens in `internal/mcpauth/mcpauth.go:233`
  and `:265`).
- **The audit log**: `audit.Log.Record(Event)` returns nothing; once the log is in its failed state every
  later event is dropped (`internal/audit/log.go`).
- **The state dir** (`--state-dir`, outside the clone, locked by one server through `rackbook.lock`) holds
  the audit log, token last-use, preferences, OAuth grants (`oauth-grants.json`) and keys. `secureStateDir`
  sets it to 0700 and refuses to start only in strict mode (today: with the built-in OAuth server).
- **Rate limits.** `clientip.Of` names the client (the connecting address, or `CF-Connecting-IP` from a
  `--trusted-proxy`; IPv6 bucketed by /64). The audit log keeps the same /64 for an IPv6 client even with
  `--audit-addr full`.
- **CAPTCHA.** `github.com/KazuhaHub/authcore/captcha`, already a dependency, offers a self-hosted digit-image
  `Generator` (single-use `Verify(id, answer)`, pluggable `Store`) and a `TokenVerifier` for Cloudflare
  Turnstile, reCAPTCHA and hCaptcha (`NewTokenVerifier(provider, secret, opts...)`,
  `Verify(ctx, token, remoteIP)`, hostname pinning with `WithAllowedHostnames`).
- **`/infra`** accepts only pinned OIDC sessions (`internal/auth/infra.go`). Local accounts never reach it.

---

## 2. Threat model

| Threat | Defence | What is left |
|---|---|---|
| **Phishing** (a look-alike site relays the password and code in real time) | A second factor is mandatory. Passkeys are bound to the origin; the setup page offers the passkey first. `auth.local.second_factor: passkey` turns TOTP off. | Password + TOTP can be relayed. |
| **Credential stuffing and password spraying** | A password alone never gives a session. Once failures pile up, every password attempt needs a CAPTCHA solve, checked before the password is hashed, so each guess costs a solve (section 7). At least 12 characters and a blocklist. A correct password followed by a failed second factor is recorded and shown to the person. | An attacker who pays for CAPTCHA solving gets one guess per solve against a 12-character, blocklisted password. |
| **Lockout of a legitimate user** (an attacker, a NAT neighbour, a botnet, timed requests) | There is **no hard lock on password attempts**. Where earlier drafts refused or slowed, the server now asks for a CAPTCHA (section 7.4). | Someone who **knows the password** can exhaust the second-factor limit (7.3); a flood from inside the same /48 can reach the flood ceiling; see 7.4 for the exact guarantee. |
| **An offline copy of the state dir** (a backup, a copied volume, a lost disk, a sidecar with the volume mounted) | The store is encrypted, the `usernames` file is MACed, and the admin socket demands proof of the key (sections 3, 9), all under a key that is not in the state dir. Without the key a copy reveals nothing and can do nothing. | A copy *with* the key gives argon2id hashes, the TOTP secrets and the session secrets. Response in 4.10. |
| **A stolen session cookie** | `Secure`, `HttpOnly`, `SameSite=Lax`, `__Host-`. Sensitive actions need a fresh password and second factor (section 5); three failed re-authentications end every session. *Sign out everywhere* and *Disable* end every session at once. | Reading and ordinary edits work until expiry or a revocation. |
| **A forged session** (someone with `RACKBOOK_SESSION_KEY` and old cookies) | A local cookie is MACed under a key derived from the session key **and** a per-account secret in the encrypted store (section 5). | Someone with both keys and the store already holds everything. |
| **The admin as the trust root** | Admins create accounts and issue resets. Admin is a role in `auth.roles`, so push access to the data repository already means admin. Above the admins is whoever holds the account key (section 9). | By design. |
| **An insider admin** | A reset replaces only what it names; the person must pass every factor it does not name (4.8). Only a separate, warned **full reset** hands over an account, and it is in effect a new invite. Every reset revokes tokens and grants, ends sessions, and is shown to the holder. All in the hash-chained audit log. | A full reset lets an admin act as the victim; the victim notices and the log tells the story. No two-person rule (section 13). |
| **A leaked invite or reset link** | 256-bit, single-use, expiring, in the URL fragment (removed from the address bar once read). Nothing happens on page load; the 30-minute hold starts only when the person presses *Continue*, so link scanners do not consume it. A `password` or `second_factor` reset link alone is not enough. | Whoever presses *Continue* first wins; the real person asks for a new link. |
| **Account enumeration** | Usernames are not secret (they are in `auth.roles`). Unknown and non-active accounts get the same status codes, the same CAPTCHA requirement and the same argon2id time as a wrong password (7.5). | Small timing differences remain, bounded in 7.5. |
| **CPU and memory exhaustion** | The CAPTCHA is checked before any hash once a bucket or the global budget is busy; hashing slots with a reserved one; a queue with a timeout (section 7). | A large botnet that solves CAPTCHAs can still make sign-in slow. |
| **Weak CAPTCHA** | Turnstile is preferred. The image CAPTCHA is a fallback for deployments that cannot call out (7.1). | The image CAPTCHA is solved by OCR at high rates; it raises the cost of automation, little more. |
| **Flooding the audit log** (kept forever) | Refusals and CAPTCHA failures are aggregated per address bucket per minute (section 8). | |

Out of scope: root on the running host (it holds the keys in memory), a compromised browser, and the data
repository's own access control.

---

## 3. Where account data lives, and why

**Not in Git.** Password hashes, TOTP secrets and session secrets are secrets, and Git history is never
rewritten. Local accounts' passkeys go to the same store too, not to `.rackbook/passkeys.yml`: one place per
account, and nothing about an account shows up in Git.

**State dir mode.** In local mode the state dir check is strict: the server refuses to start unless the
directory is (or can be made) 0700.

### 3.1 The store

`<state-dir>/accounts/accounts.enc`, mode 0600, small (tens of accounts), decrypted once at start and kept in
memory.

- **Format:** a plaintext header `{"v": 1, "alg": "AES-256-GCM", "kid": "3f9a1c2e"}` (used as additional
  authenticated data), a fresh 96-bit random nonce, and the ciphertext. **Everything else is inside the AEAD**,
  including the store's `change` id, `audit_seq` and `audit_month`; nothing in the header changes after
  encryption.
- **Key:** 32 random bytes, separate from the session key: `RACKBOOK_ACCOUNTS_KEY` (base64) or
  `--accounts-key-file`. The session key's loader becomes `LoadKey(name, env, file)` with messages of its own
  per key: "`--auth local` needs the account store key: set RACKBOOK_ACCOUNTS_KEY (base64, 32 or more random
  bytes) or pass --accounts-key-file", "set only one of RACKBOOK_ACCOUNTS_KEY and --accounts-key-file",
  "RACKBOOK_ACCOUNTS_KEY decodes to N bytes, need at least 32", "the account store key must differ from the
  session key". Subkeys by HKDF-SHA256 with distinct `info`: `rackbook accounts v1` (encryption),
  `rackbook usernames v1` (3.4), `rackbook admin socket v1` (section 9). `kid` is the first 8 hex digits of
  SHA-256 of the encryption subkey.
- **Why separate from the session key:** rotating the session key logs everyone out; it must not also destroy
  every account.
- **Provisioning:** `openssl rand -base64 32`, kept with the deployment's other secrets (the infra repository's
  SOPS vault, or an `.env` outside the data volume), passed in the environment or as a read-only file from
  outside the state dir. Never in the data repository, never in the state dir.
- **At start**, any of these stops the server with a clear error: no key, a wrong key, a store that does not
  decrypt, a missing store while the audit log has change events, or a gap (3.3). A first start (no store, no
  change events) creates an empty store.

Per account:

| Field | Notes |
|---|---|
| `username`, `name` | `local:<username>` is the identity |
| `state` | `invited`, `active`, `reset_pending`, `disabled`, `removed` (a tombstone) |
| `created`, `created_by` | |
| `password` | PHC string, `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>` |
| `totp` | secret (20 bytes), `last_step`, `added`; `second_factor_failures` (7.3) |
| `passkeys` | up to 10: credential id, public key, user handle, name, added, backup-eligible flag, AAGUID |
| `sid`, `session_secret` | 128-bit session id and 256-bit secret, renewed together; renewing them ends every session |
| `reauth_failures` | failed re-authentications since the last success (4.7) |
| `failures` | per address bucket, recent password failures (section 7) |
| `good_buckets` | up to 10 address buckets with a successful sign-in in the last 30 days; cleared on every reset, on disable and on *sessions ended* |
| `pending` | an invite or reset: SHA-256 of the token, kind, scope, expires, issued by; the hold (hash of the browser value, until) |
| `pending_revocations` | API token names and OAuth grant ids still to revoke (4.11) |
| `last_login`, `last_second_factor_failure` | time and address, shown on *My account* |
| `notices` | admin actions on the account not yet shown to the holder |

**Passwords.** argon2id, m = 64 MiB, t = 3, p = 4, 16-byte salt, 32-byte tag (the second recommended setting
of RFC 9106), in fixed hashing slots (7.6). Constants, not configuration; stored in each hash, so raising them
rehashes at the next sign-in. No pepper: the store is already encrypted under a key outside the state dir.

**Password rules** (NIST SP 800-63B): at least 12 characters (`auth.local.password_min_length`, 12 to 64), at
most 128; NFKC-normalised; no composition rules and no expiry; refused if in the embedded list of the 100 000
most common passwords, or if it contains the username or the host name. Checked on the server only.

### 3.2 Writing: one writer, audit first

Every write of the store, change or counter, goes through **one writer**: a single mutex held from building the
new state to the directory `fsync`. The in-memory state other requests read is replaced only after a write has
landed, so a counter write always encrypts the last *committed* state and can never persist a change that has
not been audited.

- **Counters** (failures, `good_buckets`, `last_login`, `last_second_factor_failure`, `reauth_failures`,
  `second_factor_failures`) are written without an audit event of their own and keep the store's current
  `change` and `audit_seq`.
- **Changes** are the events of section 8 that carry `change:`. Each one is written in this order:

1. Build the new state with a fresh random `change` id. Encrypt it into `accounts.enc.pending` (complete file,
   `fsync`, rename into place, `fsync` the directory).
2. Append the audit event, carrying `detail: ["change:<id>"]` and the ids needed to re-apply it (section 8),
   with `RecordSync`. On error: delete `accounts.enc.pending`, change nothing, answer `503 audit_unavailable`.
3. Put the event's `audit_seq` and `audit_month` into the new state, encrypt it **once** into
   `accounts.enc.next` (complete, `fsync`), rename it over `accounts.enc`, `fsync` the directory, delete
   `accounts.enc.pending`. Only then answer, and only then replace the in-memory state.

**At start**, with the last change event in the log found from the store's `audit_seq` onwards:

| Found | Meaning | Done |
|---|---|---|
| the store's own `change` is the last | normal | start |
| `.next` exists and decrypts | crash during step 3 | finish the rename |
| `.pending` decrypts and its `change` is the last event | crash between steps 2 and 3 | finish step 3 from `.pending` |
| `.pending` decrypts but its `change` is not in the log | crash before step 2; never confirmed | delete it; the change was not made |
| `.pending` or `.next` does not decrypt (a torn write) | crash | discard it. If the log has exactly one change event the store lacks, it is treated as **not made** (it was never answered), recorded as `account_store_problem` (`code: lost_change`), and its restrictive part, if any, is re-applied (3.3), so planting a fake torn file gains nothing. Anything more is a gap |
| the log has change events the store lacks (beyond the case above) | the store is older than the log: a restore | **gap**: refuse to start (3.3) |
| the store's `audit_seq` is past the end of the log, or its month file is gone and not explained by retention (3.5) | the **audit log was rolled back or truncated** | refuse to start, with a louder message (3.3) |

### 3.3 Gaps and `accept-restore`

A gap is never accepted silently. Replaying is not possible, because it would need the new password hashes, TOTP
secrets and session secrets in the audit log, which must never hold secrets. The server stops with "the account
store is older than the audit log" until the operator runs `rackbook accounts accept-restore`, which:

- prints every change event after the store's `change`;
- **re-applies the restrictive ones**, which need no secret: `account_disabled`, `account_removed`,
  `sessions_ended`, `factor_removed` (the event names the factor: `totp`, or the credential id),
  `account_reset_issued` (deletes the credentials in its scope again; `reset_pending` with no link),
  `account_invite_revoked`, and **every revocation the events list**: API token names (re-revoked in
  `.rackbook/tokens.yml` if still active there) and OAuth grant ids (revoked again in `oauth-grants.json`, which
  a restore of the state dir also brings back);
- puts every account that lost a **permissive** change (`account_setup_completed`, `password_changed`,
  `factor_added`, `account_enabled`) into `reset_pending` with scope `all`;
- **renews `sid` and `session_secret` of every account** and clears every `good_buckets`, so no cookie from
  before or after the backup is accepted;
- records `account_store_restored` with the seqs covered.

**The audit log is older than the store** (`audit_seq` past its end): this is not a store restore but the audit
log rolled back or cut, which is worse. `accept-restore` refuses it unless given `--accept-audit-truncation`,
which records `account_store_problem` (`code: audit_truncated`) with what was lost (`detail: ["store_seq:<n>",
"log_end:<m>"]`, so seqs *m*+1 to *n* are gone) and then renews every session secret.

### 3.4 The `usernames` file

`<state-dir>/accounts/usernames`: every username ever invited, one per line, then a last line
`mac:<HMAC-SHA256 under the usernames subkey of all lines before it>`. An invite refuses a name in it. A file
whose MAC does not verify stops the server (like a store that does not decrypt). It is outside the store on
purpose: `discard-store` keeps it, so names are not reused even after a lost key. Because the old key is lost
then, `discard-store` prints the list, asks the operator to confirm it, and MACs it again under the new key.

### 3.5 Retention and the checkpoint

The start check needs the month file of the store's `audit_month`, so retention must not delete it, but it must
not override the owner's retention setting for long either.

- **Checkpoint:** at the first write in a new month, and whenever retention would be held back, the store is
  written as a change with a `RecordSync` event `account_store_checkpoint` (no account change). This moves
  `audit_month` to the current month.
- **The pin:** `--audit-retention-months` never deletes the month of the store's `audit_month`. With the
  checkpoint the pin holds a month back by at most about one month past the configured retention. Whenever it
  does delay a prune, the server logs a warning naming the month. (This deployment keeps everything anyway.)
- A month file missing for any other reason is the "audit log rolled back or truncated" case above.

### 3.6 Backup and restore

- Back up the state dir and, **separately**, the key. The state dir alone is useless.
- Restoring both from the same backup is consistent and is not detected. Cookies issued after the backup are
  refused (older session secrets), but cookies from before it work again: after any restore run
  `rackbook accounts end-sessions --all` and review **Users**.
- Lost key: `rackbook accounts discard-store` moves the file aside, re-MACs `usernames` (3.4) and records
  `account_store_problem` (`code: discarded`); everyone is invited again under new usernames.
- Key rotation: `rackbook accounts rekey --new-key-file` re-encrypts the store, re-MACs `usernames`, and
  records `account_store_rekeyed` with both `kid`s.

---

## 4. The flows

Endpoints are under `/auth/local/` (no session needed) and `/api/account`, `/api/admin/accounts` (a session
needed; API tokens and OAuth tokens are refused). Sign-in attempts in progress live in memory, bounded, bound to
the browser by the existing `__Host-rackbook_login` cookie. Every account change and every local sign-in
**fails closed** when the audit log cannot be written (section 8).

### 4.1 Invite

1. An admin, re-authenticated (section 5), opens **Users → Invite**: username, display name, role (optional),
   validity.
2. `POST /api/admin/accounts {username, name, role}`. Usernames match `^[a-z][a-z0-9._-]{0,31}$` and must not
   be in `usernames`. The store gets an `invited` account with a pending invite (SHA-256 of a 32-byte random
   token, expiry `auth.local.invite_ttl`, default 72 h, 1 h to 14 days). Audit `account_invited`.
3. A chosen role is saved as `local:<username>` in `auth.roles` through the phase 2a role editor (section 6). If
   that commit fails, **Users** shows "no role" with *Assign*.
4. The link is shown once: `https://<host>/auth/local/setup#<token>`. Nothing is e-mailed.

An admin can revoke a pending invite (`account_invite_revoked`) or issue a new one, which replaces it.

### 4.2 Opening a link (invite or reset)

1. On load the console reads the token from the fragment and removes it from the address bar with
   `history.replaceState`. **Nothing is sent yet**; the page says what the link is for and shows *Continue*.
2. *Continue* sends `POST /auth/local/setup/open {token}`. The server checks the hash, the expiry and the
   account state, then **holds** the link for this browser for 30 minutes: a random value in the login cookie,
   its hash and the hold's end in the store (a change, so it survives a restart), `account_link_opened` in the
   audit log. Another browser during the hold gets `invite_claimed`.
3. Once held, the link dies at the hold's end unless setup is finished. The admin issues a new one.
4. An invite continues with 4.3, a reset with 4.8.

### 4.3 First setup (invite)

1. **Password**, checked against 3.1, hashed and kept with the setup in memory (re-entered after a restart; the
   hold survives).
2. **Second factor:** a passkey (4.5) or TOTP (4.4); with `second_factor: passkey`, only a passkey.
3. **Done:** one change sets the password and the factor, makes the account `active`, consumes the token and
   makes a new `sid` and `session_secret`. Audit `account_setup_completed` (`code: invite`) and `login`.

### 4.4 TOTP enrolment

RFC 6238: HMAC-SHA1, 6 digits, 30-second period. A 160-bit secret; the `otpauth://` URI is drawn as a QR code by
the console itself, with the base32 secret for typing in. A current code confirms it. Verification accepts the
current step and one either side (±30 s) and refuses any step at or before `last_step`. One TOTP per account;
replacing it means enrolling a new one. The server's clock must be synchronised (NTP).

**No recovery codes.** A lost factor is an admin reset (4.8); the console encourages two factors of different
kinds. To be confirmed (section 13).

### 4.5 Passkey enrolment

WebAuthn with today's relying-party ID (the host of `--base-url`), resident key required, user verification as
`auth.passkeys.user_verification` says (`preferred` by default; `required` when passwordless sign-in is on).
Attestation is requested as `direct` only when `auth.local.passwordless: device_bound` (section 13). The
backup-eligible flag and the AAGUID are kept. Up to 10 passkeys per account, each named. Only the account holder
adds factors; an admin never does.

### 4.6 Sign-in

1. `POST /auth/local/login {username, password, attempt?, captcha?}`.
2. If a CAPTCHA is required (7.4), and the request does not carry a solved one for a current `attempt`, the
   answer is `401 captcha_required {attempt, captcha}` and nothing else is checked (7.2).
3. Unknown, `invited`, `reset_pending`, `disabled` or `removed`: a **dummy argon2id**, then the same
   `401 sign_in_failed` as a wrong password (7.5).
4. Wrong password: the (account, bucket) failure count goes up; `401 sign_in_failed`.
5. Right password: a pending sign-in (5 minutes, this browser) answers which factors the account has.
6. `POST /auth/local/totp {code}`, or the passkey assertion for that account (no CAPTCHA at this step). At most 5
   tries per pending sign-in. A failure counts toward the account's `second_factor_failures` (7.3) and is kept as
   `last_second_factor_failure`, which *My account* shows: someone knew your password.
7. Success clears the failure counts of this bucket, adds the bucket to `good_buckets`, rehashes the password if
   the parameters went up, issues the session (section 5) and writes `login` with the factor.

**Passwordless passkey sign-in** is an owner option, **off by default** (section 13). When it is on, a
user-verified passkey (and, with `device_bound`, a device-bound one) signs in without the password, and its
ceremony is not subject to password failure counts.

### 4.7 Re-authentication

`POST /auth/local/reauth`: the password and the second factor (or a qualifying passkey when passwordless is on),
in the reserved hashing slot (7.6). The counter is **per account, in the store** (`reauth_failures`): each
failure adds one, a success resets it, and **three failures end every session of the account** (`sid` and
`session_secret` renewed, `good_buckets` cleared, `sessions_ended` with `reason: reauth_failed`). A failed
re-authentication also counts toward the (account, bucket) failure count.

### 4.8 Admin reset

**Users → Reset**, re-authentication required. An admin cannot reset their own account here (*My account* or the
CLI). Scopes:

| Scope | Deleted at once | What the person must do with the link |
|---|---|---|
| `password` | the password | set a new password, then **pass an existing factor** (TOTP or passkey) |
| `second_factor` | TOTP and passkeys | **enter the current password**, then enrol a new factor |
| `all` (*Full reset*) | everything | set a password and enrol a factor: **in effect a new invite** |

- *Full reset* is a separate button. The console warns: "This lets whoever opens the link take over the account.
  It is the same as inviting a new person under this name." Audited with `code: all`.
- At issuance, every scope: `reset_pending` (no role; section 6), `sid` and `session_secret` renewed,
  `good_buckets` and failure counts cleared, API tokens and OAuth grants revoked (4.11), and a reset link like an
  invite (`auth.local.reset_ttl`, default 24 h, 1 h to 7 days, with the hold of 4.2). Audit
  `account_reset_issued`.
- Completing writes `account_setup_completed` (`code: reset`, the scope in `detail`). The password check of a
  `second_factor` reset and the factor check of a `password` reset count like sign-in failures. Completion is
  refused (`409 revocation_pending`) while the account has pending revocations (4.11).
- The old password stops at once for `password` and `all`, not for `second_factor` (it is needed to complete).
- The holder sees a notice of every reset at their next sign-in until they dismiss it; likewise for
  *Disable*/*Enable* and *Unlock*.

### 4.9 Disabling and removing an account

**Disable** (re-authentication required): `state: disabled`, `sid` and `session_secret` renewed,
`good_buckets` cleared, tokens and grants revoked (4.11). Sessions end at once, sign-in fails (as in 4.6 step
3), and `local:<username>` has no role on every path (section 6). **Enable** reverses the state and is refused
while revocations are pending; old sessions, tokens and grants stay ended.

**Remove** (re-authentication required): the same, then the credentials and pending tokens are deleted and a
tombstone is left. The username stays in `usernames`. The console offers to take `local:<username>` out of
`auth.roles`.

Refused for both: acting on yourself, or on the last active admin.

### 4.10 Incident response (the store and its key both leaked)

`rackbook accounts rekey`, then `rackbook accounts reset --all --scope all`: every account to `reset_pending`
with new links, every session secret renewed, every local account's tokens and grants revoked.

### 4.11 Revoking tokens and grants

Disable, remove, every reset and `reset --all` revoke the account's API tokens (one commit to
`.rackbook/tokens.yml`, `rackbook(auth): revoke tokens of local:<username>`) and its OAuth grants and refresh
tokens (`oauth-grants.json`). The account event lists them: `detail: ["tokens:<name>,<name>", "grants:<id>,<id>"]`
(names and ids, never secrets), which is what `accept-restore` re-applies.

The revocations are first written into the store as `pending_revocations`, as part of the same change. Each is
removed from the list once applied. A failed `tokens.yml` commit stays pending and is retried every minute and at
start; **Users** shows it. While any revocation is pending, *Enable* and reset completion are refused. The
account is not active meanwhile, so its tokens and grants have no role even before the commit lands.

### 4.12 Self-service (My account)

All need re-authentication: **change the password** (`password_changed`; renews `sid` and `session_secret`,
keeps this session), **add or remove a factor** (`factor_added`, `factor_removed`; the last one cannot be
removed), and **sign out everywhere** (`sessions_ended`; renews `sid` and `session_secret`, clears
`good_buckets`, issues a fresh cookie here). Its box **"Also revoke my API tokens and app connections"** is ticked
by default, and the dialog lists them before confirming.

---

## 5. Sessions

The same cookie and session key, with `method: local` added. A local session carries `sid`, `aat` (when the
person last fully authenticated) and the factor used. `auth.session.idle` and `absolute` apply.

**Bound to the store.** The cookie is signed, not encrypted. A local cookie's MAC key is

```
HKDF-SHA256(ikm = session key, salt = account.session_secret, info = "rackbook.session.local.v1" || sid)
```

The codec reads the (unverified) username, looks the account up in memory, derives the key, then verifies. The
account must exist, be `active` and have the same `sid`. Forging a local session needs the session key **and** the
decrypted store.

**Re-authentication.** Sensitive actions need `aat` within `auth.local.reauth_window` (default 10 minutes,
1 minute to 1 hour), otherwise `403 reauth_required`; the console asks again (4.7) and repeats the action.
Sensitive: *My account* (password, factors, sign out everywhere); account administration (invite, revoke an
invite, resets, unlock, disable, enable, remove); creating or revoking an API token; saving roles; approving an MCP
client in the built-in OAuth server.

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
  `local` is **not** in `plainMethods` (`internal/roles/roles.go`). Other identities never match `local:` entries.
- **One check on every path.** A private helper `(*Authenticator).policyRole(s roles.Subject)` replaces the
  direct `Policy().Evaluate(s)` calls in `RoleForVia` and `EvaluateSubject` (and so in `Evaluate`). It gates on
  the **identity**, not the method: for any subject whose ID starts with `local:`, the role is none unless the
  method is `local` and `localAccountActive(s.ID)` says the account is `active` (no pending reset). That covers
  sessions (`Evaluate`), token creators (`RoleForVia`, `internal/api/tokens.go:68`) and OAuth grants, OAuth access
  tokens and API tokens on `/mcp` (`EvaluateSubject`, `internal/oauthserver/token.go:75`,
  `internal/mcpauth/mcpauth.go:233` and `:265`), and an identity from elsewhere that merely looks like `local:…`
  gets nothing. A test walks all three paths with a disabled account and with a look-alike identity.
- `internal/tokens` records the creator's method `local` (`creatorMethod`).
- `passkey` stays in `plainMethods` and `creatorMethod` (`internal/tokens/registry.go`), so tokens and grants
  made from passkey sessions before section 10 keep their role.
- Git commits are authored `Display Name <local:alice>`.

**With phase 2a's role editor:** in local mode it offers the accounts by name for `local:` entries and marks
`group:`, `app-role:`, `*@domain` and `oidc:` entries as having no effect (the reverse under SSO). An entry for a
username with no account is kept with a warning. The last-admin rule counts only `local:` entries of `active`
accounts (or `local:*` with one), and still refuses removing the editing admin's own entry. Anyone with push
access can still edit `auth.roles` directly.

---

## 7. Rate limits, CAPTCHA and hashing capacity

### 7.1 Providers

| Provider | Use | Weakness |
|---|---|---|
| **Cloudflare Turnstile** (preferred) | `captcha.NewTokenVerifier(captcha.ProviderTurnstile, secret, captcha.WithAllowedHostnames(captcha.HostOf(baseURL)), captcha.WithTimeout(5*time.Second))`. This deployment is behind Cloudflare already, so it adds no new third party. Usually invisible or one click. | Sends the client address and a browser signal to Cloudflare. The login page's CSP must allow `https://challenges.cloudflare.com` for script and frame, on the sign-in page only. |
| reCAPTCHA, hCaptcha | Same verifier, other provider. | A new third party that sees sign-ins. |
| **Image** (fallback) | `captcha.NewImageGenerator(store)`: five distorted digits, no outbound call. For deployments that cannot call out. | Solved by OCR and machine learning at high rates, so it only raises the cost of automation. No audio version, so blind and many low-vision users cannot solve it at all (7.7). |

Turnstile unreachable (`ErrNetwork`, `ErrBadStatus`, a timeout): that attempt falls back to the image CAPTCHA,
and `captcha_unavailable` is counted (section 8), so an outage of the provider does not lock anyone out.

The `remoteIP` passed to `Verify` is the client address by the trusted-proxy rules, unbucketed (a new
`clientip.Addr`; the audit log still keeps the /64).

### 7.2 Binding to the attempt

A CAPTCHA counts for exactly one password attempt:

- `401 captcha_required` creates an **attempt** in the pending-login state (bound to the login cookie, 5
  minutes) with a random `attempt` id. For the image CAPTCHA the attempt holds the `Challenge.ID`; the image
  generator's `Store` is a bounded in-memory store (10 000 entries, 5 minutes).
- The resubmitted request carries `attempt` and the solve (a Turnstile token, or the digits). The server takes the
  attempt **out** of the pending state first, then verifies: `TokenVerifier.Verify(ctx, token, remoteIP)` (the
  provider refuses a token used twice) or `Generator.Verify(id, answer)` (single-use, also consumed on a wrong
  answer). Only then does it check the password, once.
- A failed solve writes `captcha_failed` and answers a new `captcha_required`; it does not count as a password
  failure.
- The authcore `Result` does not expose Turnstile's `cdata`. If it did, the attempt id could also be bound into
  the token itself; that is a small authcore change worth making, but the binding above does not depend on it.

### 7.3 Counters

All address-keyed limits use **buckets**: a new `clientip.Bucket(r, trusted, 48)`, IPv6 by /48 (one site, often
one carrier), IPv4 by the full address. Tables are bounded in memory (10 000 entries, least recently seen
forgotten first), except the per-account ones, which are in the store.

| Counter | Window |
|---|---|
| password attempts per bucket (all accounts) | token bucket, burst 10, 1 per minute |
| passkey ceremonies per bucket, **its own bucket** | 30 per minute, burst 10 (today's limiter) |
| link opens per bucket | burst 5, 1 per minute |
| password failures per (account, bucket); also kept for unknown usernames (keyed by a hash of the typed name, in memory) | consecutive, cleared on success |
| password failures per account, all buckets | last hour |
| dummy hashes, all addresses | 30 per minute |
| second-factor failures per account (`second_factor_failures`) | 10 in 24 hours |

**The second-factor limit is the one hard limit**, because reaching it requires the correct password: past 10
failures in 24 hours, TOTP and the passkey second step are refused for the account (a qualifying passwordless
passkey still works if that option is on), `account_locked` (`code: second_factor`) is written, and the holder
and admins are told that the password is known to someone else. The way back is an admin *Unlock* plus a
`password` reset, or the holder's passkey. Without it, someone with the password could try a million TOTP codes at
one CAPTCHA per five.

### 7.4 When the CAPTCHA is required, and the guarantee

A password attempt needs a solved CAPTCHA when **any** of these holds:

- its (account, bucket) pair has 3 or more consecutive failures;
- its bucket is over its password-attempt limit;
- the global dummy-hash budget is used up;
- the account has more than 20 failures in the last hour from all buckets ("under attack").

Exception: a bucket in the account's `good_buckets` skips the last two triggers (not the first two).

A passkey ceremony needs a CAPTCHA only once its own bucket is over its limit; its success then does not depend on
the password counters.

This **replaces every refusal and slowdown** of the earlier drafts: an office behind one NAT, or a carrier's /48,
gets a CAPTCHA, not a `429`; an account under attack asks its owner for a CAPTCHA, not to wait. There is no
per-(account, bucket) hard lock any more: under a shared address, any hard lock keyed on the bucket can be set off
by a neighbour, so no such lock can coexist with the guarantee below.

**The guarantee.** A person who has their password and their authenticator app (or passkey) can always sign in,
from any network, by solving at most one CAPTCHA per attempt, whatever a NAT neighbour, a botnet or carefully timed
requests do, as long as nobody else knows their password. Checked against the combined case: the neighbour's
failures raise the shared pair and bucket counters, the botnet's raise the account and global counters, and timing
cannot take a slot from them, because no trigger refuses; each only asks for a solve, and a solve is tied to the
person's own attempt (7.2). What can still stop them:

- someone who **knows the password** exhausting the second-factor limit (7.3), which is the point of that limit;
- a flood from **inside their own bucket** above the flood ceiling: more than 600 requests a minute from one
  bucket to `/auth/local/*` get `429` without further checks, because otherwise a flood could push the server over;
- all hashing slots busy past the queue timeout (7.6), which the CAPTCHA, checked before any hash, makes expensive;
- the audit log failing, where everything fails closed (section 8).

*Unlock* by an admin (console, or `rackbook accounts unlock` online) clears the account's counters, so the CAPTCHA
triggers that come from the account stop at once.

### 7.5 Uniform answers

For the password step, unknown, invited, reset-pending, disabled and removed accounts get exactly the answers an
existing account gets: `401 captcha_required` under the same triggers (the per-(account, bucket) count is kept for
unknown names too), otherwise `401 sign_in_failed`, after one argon2id run against a fixed dummy hash. Past the
dummy-hash budget the CAPTCHA is required for every attempt, so the budget is not the thing that differs.

Response time: real and dummy runs use the same parameters in the same slots, so the difference is the variance of
one argon2id run (a few percent, more under load). Below that it is accepted and stated: an attacker averaging
many samples might tell a real account from an unknown one, which reveals a username, and usernames are not secret
here.

### 7.6 Hashing slots

Three slots (192 MiB peak): one **reserved** for re-authentication of a signed-in session and for sign-ins from a
bucket in that account's `good_buckets`; two **general**, which reserved callers may also use. Waiting callers
queue, reserved first. Past 5 seconds: `503 busy`, `Retry-After: 5`; the console says "the server is busy" and
retries once by itself. The CAPTCHA, when required, is verified before a caller queues for a slot.

### 7.7 Someone who cannot solve the CAPTCHA

- With **Turnstile** most people are never shown a puzzle; it follows the provider's accessibility support.
- They can **sign in from a network they used before** (`good_buckets`), which skips the "under attack" and budget
  triggers.
- They can ask an **admin to Unlock** the account, which clears its counters at once.
- With the **image** CAPTCHA, *New image* gives another one; there is no audio alternative, which is why the image
  CAPTCHA is only a fallback and the console says so to admins (section 13).
- With passwordless sign-in on (section 13), a qualifying passkey avoids the CAPTCHA unless the passkey bucket is
  exhausted.

---

## 8. Audit events

**The API.**

```go
// RecordSync appends e and fsyncs it. It returns the seq it got, or an error,
// including when the log is in its failed state. It never drops an event silently.
func (l *Log) RecordSync(e Event) (seq int64, err error)
```

Every change (3.2) and every local `login` and `reauth` use `RecordSync` and **fail closed** with
`503 audit_unavailable`: the sign-in page says "Sign-in is unavailable: the server cannot write its audit log. An
administrator must check the server"; admins already signed in see the existing red audit banner, and the account
actions in **Users** are disabled with the same reason. `logout` clears the cookie and records with `Record`.
Refusals and CAPTCHA events use `Record`, aggregated (below): losing one must not keep a correct sign-in out, and a
correct sign-in fails closed anyway when the log fails. Local mode requires `--state-dir`.

**The events.** All in the chain, area `audit`. `method` is `local` for the console and `cli` for the command line,
with `detail: ["operator:<text>"]` from the caller's `--operator` (default `unspecified`; section 9). `addr` comes
from `clientip.Of` and is kept as `--audit-addr` says: `full` in this deployment, which still keeps an IPv6 client
as its /64. Passwords, codes, tokens, CAPTCHA answers, secrets and typed unknown usernames are never recorded. New
field **`target`**: the account acted on when that is not the actor. Every change event carries
`detail: ["change:<id>"]`.

| Event | `identity` | Other fields |
|---|---|---|
| `login` | the account | `role`, `addr`, `detail: ["factor:totp"]`, `["factor:passkey"]` or `["factor:passkey", "passwordless"]` |
| `login_refused` | the account, empty if unknown | `addr`; `reason`: `unknown_account`, `bad_password`, `bad_second_factor`, `second_factor_locked`, `disabled`, `not_set_up`, `reset_pending`, `no_role`, `flood`, `busy`, `invite_invalid`, `invite_expired`, `invite_claimed`; `code: reauth` for a failed re-authentication; `code: summary` for an aggregate |
| `captcha_failed` | the account, empty if unknown | `addr`; `reason`: `wrong_answer`, `rejected`, `hostname_mismatch`, `expired`, `no_attempt`; `detail`: the provider's error codes; `code: summary` for an aggregate |
| `logout` | the account | `role`, `addr` |
| `reauth` | the account | `addr`, `detail: ["factor:…"]` |
| `account_locked` | the account | `addr`, `code: second_factor`, `detail: ["failures:<n>"]` |
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
| `account_store_problem` | none | `code`: `gap`, `missing`, `lost_change`, `audit_truncated`, `key_mismatch`, `unreadable`, `discarded`, `usernames_mac`; `detail` |
| `account_store_restored`, `account_store_rekeyed` | none, `method: cli` | `detail`: the seqs covered, or the old and new `kid` |
| `passkeys_removed` | the admin | `detail: ["count:<n>"]`; SSO deployments, section 10 |

**Aggregates.** Per address bucket and minute, the first `login_refused` and the first `captcha_failed` for each
account (and for unknown accounts) are written in full; later ones are counted and written once at the end of the
minute, as the same event with `code: summary`, the bucket's `addr`, and `detail: ["count:<n>",
"reasons:<reason>=<n>,…", "accounts:<n>", "captcha_required:<n>", "captcha_unavailable:<n>", "from:<time>",
"to:<time>"]`. Beyond 100 buckets in one minute the rest fold into one summary without `addr`. So a flood costs the
log at most about two lines per bucket per minute and a hundred buckets' worth.

---

## 9. Config, flags, CLI and MCP

**Local mode is the deployment's choice:** `--auth local` or `RACKBOOK_AUTH=local`.

- `auth.mode: local` in `rackbook.yml` stays **rejected**, as `Login.check` rejects every unknown mode today, with
  the message "local mode is set by the deployment: --auth local".
- With `--auth local`, `auth.mode` in the file must be absent, and the server refuses to start (and refuses a
  pulled config) when the file has an `auth.oidc` block or `auth.mcp.trusted_issuers` (outside identities;
  section 13). `auth.mcp.builtin_issuer` is allowed.
- Local mode needs `--state-dir` (strictly 0700), `--base-url` (https), the session key, the account key and a
  CAPTCHA provider.

| Flag / variable | Meaning |
|---|---|
| `--auth local` | local accounts |
| `RACKBOOK_ACCOUNTS_KEY` / `--accounts-key-file` | the account store key (3.1) |
| `--captcha turnstile\|recaptcha\|hcaptcha\|image` | the provider; default `image`. There is no `off` in local mode: the lockout guarantee depends on it |
| `--captcha-site-key` | the public site key (Turnstile, reCAPTCHA, hCaptcha) |
| `RACKBOOK_CAPTCHA_SECRET` / `--captcha-secret-file` | the provider's secret, from the deployment's secrets only; required for the token providers; same `LoadKey`-style loader, never logged |

The CAPTCHA settings are flags, not `rackbook.yml` keys: whoever edits the ledger must not be able to swap the
provider for a weaker one or point it at another account. The hostname pinned is the host of `--base-url`.

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

argon2id, TOTP, counter, CAPTCHA trigger, slot and budget parameters are constants.

**CLI** (`rackbook accounts`). Every command needs the account key. With the server running, commands go over the
**admin socket** `<state-dir>/admin.sock` (mode 0600). Access is by **possession of the key**, not by uid: on
connect the server sends a 32-byte nonce; each request is `{op, args, operator}` with
`HMAC-SHA256(admin_socket_subkey, nonce || request)`, each answer is MACed the same way, and the nonce is
single-use. A caller without the key, such as a sidecar running as the same uid with the state dir mounted, can do
nothing. With the server stopped, commands take the state dir's lock and work on the files. Links are printed to
the operator's terminal only. Each writes its audit event with `method: cli` and `operator:<text>` from
`--operator` (free text the caller supplies; it identifies, it does not authorise).

| Command | Online | Offline | What |
|---|---|---|---|
| `list` | yes | yes | usernames, state, factors, counters, pending revocations, whether a role entry matches |
| `invite <username> [--name] [--ttl]` | yes | yes | the first admin, or anyone |
| `reset <username> --scope password\|second_factor\|all`, `reset --all --scope …` | yes | yes | break-glass, also for the last admin |
| `unlock <username>` | yes | yes | clears the account's counters and the second-factor lock |
| `disable`, `enable <username>` | yes | yes | |
| `end-sessions <username>\|--all` | yes | yes | renews session secrets |
| `rekey --new-key-file` | no | yes | 3.6 |
| `accept-restore [--accept-audit-truncation]` | no | yes | 3.3 |
| `discard-store` | no | yes | 3.6 |

On Windows there is no admin socket; the commands work offline only (section 13).

**Bootstrap:** set `auth.roles.admin: ["local:alice"]`, run `rackbook accounts invite alice`, start the server,
open the link. A server in local mode with no accounts logs a warning saying exactly this.

**MCP and API tokens:** unchanged in how they work. Their role follows the account (section 6) and they are revoked
with it (4.11). No MCP tool manages accounts; the account endpoints refuse tokens.

**`/infra`:** unavailable in local mode.

---

## 10. Passkeys when SSO is configured

**Decision:** with `auth.mode: oidc` there is no passkey sign-in. Sign-in is only through the identity provider,
which is where phishing-resistant sign-in belongs (Entra supports passkeys and FIDO2 keys itself) and which sees a
disabled account.

**Not a switch.** `auth.passkeys` in an OIDC deployment is accepted, ignored and logged as a warning at start. If a
team ever needs it back, it returns as a server flag (default off) together with the `passkeys_oidc_max_age` rule;
until then that rule is not built.

**Migration:**

- On upgrade, `/auth/passkey/*` and the passkey parts of *My account* are gone. An existing passkey session is
  rejected at its next request, and the person signs in through SSO. The release notes say so.
- Tokens and grants made from passkey sessions keep their role (`passkey` stays a recognised method; section 6).
- `.rackbook/passkeys.yml` is not changed and is no longer read. It holds no secret but does hold **personal
  data**: each person's identity (e-mail address or UPN), display name, WebAuthn user handle, the authenticator's
  AAGUID (which names the device model), credential ids and dates. **Removing it is recommended.**
- **Users** offers **Remove old passkeys**, which commits the file's deletion (`rackbook(auth): remove unused
  passkeys`) and writes `passkeys_removed`. Until the file is gone, admins see a reminder banner on every page.
  History keeps the old file; it is not rewritten.
- **Downgrade risk:** while the file exists, an older Rackbook would accept those passkeys again, around the
  identity provider. Removing the file closes that.
- A deployment moving from OIDC to local mode treats the file the same way; local accounts enrol passkeys again.

---

## 11. Console screens

Each ships with a demo in three languages before merge.

- **Sign in** (local mode): username and password, then the second step (passkey or 6-digit code). With
  passwordless on, *Sign in with a passkey* first. When a CAPTCHA is required, the form shows it **in place** under
  the password field, keeping what was typed: the Turnstile widget, or the digit image with an answer field and
  *New image*. Messages: "Sign-in failed" (any wrong or unknown combination), "Please confirm you are a person",
  "The CAPTCHA did not work, try again", "The server is busy", "Sign-in is unavailable" (audit). The page also says
  "Cannot solve this? Sign in from a network you used before, or ask an administrator." No "forgot password" link,
  only "ask an administrator".
- **Set up your account** (invite and reset links): first a page that only says what the link is for, with
  *Continue*; then what the link calls for: a new password with the rules and the reason a password is refused; the
  current password (a `second_factor` reset); the existing factor (a `password` reset); a new factor, *Add a
  passkey* (recommended) or *Use an authenticator app* (QR code, secret, code to confirm).
- **Re-authenticate**: a dialog over the current page, then the action continues.
- **My account**: password; factors (passkeys with names and dates, the authenticator app); *Sign out everywhere*
  with the ticked box and the list of what it revokes; last sign-in and from where; a warning when someone entered
  the password but failed the second factor, and when the second-factor limit was reached; the notices of admin
  actions until dismissed.
- **Users** (admin): username, name, role ("no role" with *Assign*), state (invited until, link held until, active,
  under attack, second factor locked, reset pending, disabled), factors, last sign-in, pending revocations. Actions:
  *Invite*, *Copy a new link*, *Revoke invite*, *Reset password*, *Reset second factor*, *Full reset…* (separate,
  with the warning), *Unlock*, *Disable* / *Enable*, *Remove*. Before *Disable*, *Remove* or a reset, the dialog
  lists the tokens and app connections it revokes. A link appears once, with its expiry. With the image CAPTCHA, a
  note says it is weak and inaccessible and recommends Turnstile. While the audit log cannot be written, the actions
  are disabled with the reason.
- **Users → Roles** (phase 2a): as section 6.
- Under SSO: no passkey parts in *Sign in* and *My account*; **Users** and the admin banner carry the reminder of
  section 10 until `.rackbook/passkeys.yml` is gone.

---

## 12. Pieces (one PR each)

1. **Passkeys off under SSO** (section 10), with *Remove old passkeys*, the reminder, `passkeys_removed`, README
   and release notes. Independent; it also removes `passkeys_oidc_max_age` from phase 2a.
2. **Audit and store foundations:** `RecordSync`; the retention pin and `account_store_checkpoint`; the encrypted
   store with `LoadKey`, subkeys and `kid`; the single writer and the pending/next protocol with the start-up table;
   `usernames` with its MAC; argon2id with slots, budget and queue; password rules and blocklist; TOTP. Offline
   `rackbook accounts rekey | accept-restore | discard-store | list`. No HTTP.
3. **Local identity and roles:** `--auth local` and its refusals, strict state dir, `auth.local`, `method: local`
   in the codec with the per-account MAC key, `local:` entries, `policyRole` gating on the `local:` prefix on all
   three paths, token creator method, the `target` audit field.
4. **Sign-in, CAPTCHA and setup:** the `/auth/local/*` flows, `clientip.Bucket` and `clientip.Addr`, the counters
   and CAPTCHA triggers, Turnstile and image providers with fallback and attempt binding, the flood ceiling, uniform
   answers, aggregated events, the admin socket with its challenge/response, the online CLI, the *Sign in* and *Set
   up* screens.
5. **My account and re-authentication:** `aat`, `reauth_required`, the per-account re-authentication counter,
   self-service, sign out everywhere with revocation, the notices.
6. **Users administration:** the table and actions, revocation with `pending_revocations` and retry. The role
   choice in *Invite* needs phase 2a's role editor; until then this piece links to editing `rackbook.yml`.

Piece 1 goes first and can ship on its own. Pieces 2 to 6 are in order.

---

## 13. For the owner to decide

1. **Passwordless passkey sign-in**: proposed **off by default** (`auth.local.passwordless: off`); the lockout
   guarantee (7.4) does not depend on it. Under NIST SP 800-63B a user-verified passkey is a multi-factor
   cryptographic authenticator: a **synced** passkey (iCloud Keychain, Google Password Manager, 1Password, …)
   reaches AAL2, and a **device-bound** one with attestation can reach higher. The risk of `synced`: whoever takes
   over the person's password manager or cloud account gets the passkey, and with it the Rackbook account without
   any password. `device_bound` accepts only passkeys whose backup-eligible flag is off, checked at registration and
   at every sign-in, with attestation requested (and optionally an AAGUID allow list), at the cost of excluding
   phones' synced passkeys.
2. **CAPTCHA provider for this deployment:** proposed Turnstile, with `--captcha image` as the default where no
   provider is set. The image CAPTCHA has no audio alternative; if a team must rely on it, an accessible fallback is
   needed (authcore has none today).
3. **No hard lock on password attempts**, only the CAPTCHA (7.4), and the second-factor limit as the one hard limit.
   This trades an attacker's cost per guess (a CAPTCHA solve) for never locking out the owner. Confirm.
4. **Recovery codes:** proposed none (4.4).
5. **`second_factor` default:** proposed `any` (TOTP allowed); `passkey` is safer against phishing.
6. **Full reset by a single admin** (4.8): proposed allowed, warned and audited; the alternatives are a two-person
   rule, or full resets from the CLI only.
7. **Usernames are never reused**, even after `discard-store`.
8. **Outside OAuth issuers under local mode**: proposed refused (`auth.mcp.trusted_issuers`, including MCPHub).
9. **Windows:** no admin socket, so the CLI works only while the server is stopped.
10. **Old passkeys:** an admin button plus a reminder, or a one-time automatic commit deleting
    `.rackbook/passkeys.yml` at the first start after the upgrade (which closes the downgrade risk at once).
