# Local accounts, and passkeys off under SSO

Status: design, decided by the owner on 2026-11-22, revised after review the same day; nothing here is built
yet. Builds on [design-audit.md](design-audit.md) (the audit log, phase 2a) and
[design-v0.2.md](design-v0.2.md) (the built-in login). Section 13 lists what still needs the owner's decision.

Two changes:

1. **Local accounts** (username, password and a mandatory second factor) for teams without SSO. A
   deployment is either SSO or local, never both.
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
  `auth.session.absolute` (7 days). The role is not in the cookie; it is evaluated from `auth.roles` on every
  request. The codec accepts the methods `oidc` and `passkey` only.
- **Passkeys** are an alternative to OIDC, not a second factor. They are committed to
  `.rackbook/passkeys.yml` in the **data repository** (not the state dir). Enrolling needs an OIDC sign-in
  within the last 10 minutes. A passkey session ends when its credential is deleted.
- **Roles** are evaluated on three paths, all through `Policy().Evaluate` in `internal/auth/auth.go`:
  `Authenticator.Evaluate` (sessions), `Authenticator.RoleForVia` (an API token's creator, e.g.
  `internal/api/tokens.go:68`) and `Authenticator.EvaluateSubject` (OAuth grants in
  `internal/oauthserver/token.go:75`, OAuth access tokens and API tokens in `internal/mcpauth/mcpauth.go:233`
  and `:265`).
- **The audit log**: `audit.Log.Record(Event)` returns nothing. A write error is logged, and once the log is
  in its failed state every later event is dropped (`internal/audit/log.go`).
- **The state dir** (`--state-dir`, outside the clone, mode 0700, locked by one server through
  `rackbook.lock`) holds the audit log, token last-use, preferences, OAuth grants and keys.
- **Rate limits.** `clientip.Of` names the client (the connecting address, or `CF-Connecting-IP` from a
  `--trusted-proxy`; IPv6 bucketed by /64). The unauthenticated login endpoints share a token bucket of 30
  per minute, burst 10, per address (`internal/login/limit.go`). The audit log keeps the same /64 for an IPv6
  client even with `--audit-addr full`.
- **`/infra`** accepts only OIDC sessions under the pinned issuer, client, claim and tenant
  (`internal/auth/infra.go`). That stays: local accounts never reach `/infra`.

---

## 2. Threat model

| Threat | Defence | What is left |
|---|---|---|
| **Phishing** (a look-alike site collects the password and the code, and relays them at once) | A second factor is mandatory. Passkeys are bound to the origin, so a look-alike site gets nothing usable; the setup page offers the passkey first, and a passkey with user verification signs in on its own (4.5). `auth.local.second_factor: passkey` turns TOTP off. | Password + TOTP can be relayed in real time. Teams that care set `second_factor: passkey`. |
| **Credential stuffing and password spraying** | A password alone never gives a session. Limits per address and per (account, address) pair, a slowdown per account that never fully closes, a global budget for attempts on unknown accounts (sections 4.6, 7). At least 12 characters and a blocklist. A correct password followed by a failed second factor is recorded and shown to the person. | A botnet can slow down sign-ins **by password** to a known account from new addresses. It cannot block a passkey sign-in, nor a sign-in from an address bucket that account recently used successfully. |
| **An offline copy of the store** (a backup, a copied volume, a lost disk) | The store is encrypted with a key that is not in the state dir (section 3). Without the key a copy reveals nothing, not even the usernames. | A copy *with* the key gives argon2id hashes (slow; weak passwords still fall), the TOTP secrets in usable form (TOTP needs them) and the per-account session secrets. Response in 4.10. Passkey public keys are useless to an attacker. |
| **A stolen session cookie** (malware, a shared machine) | `Secure`, `HttpOnly`, `SameSite=Lax`, `__Host-`. Sensitive actions need a fresh password and second factor (section 5), so a stolen cookie cannot change the password, add a factor, mint a token or manage accounts; three failed re-authentications end every session of the account. *Sign out everywhere* and an admin's *Disable* end every session at once. | Reading and ordinary edits work until expiry, sign-out everywhere or a disable. Cookies are not bound to an address (mobile networks change it). |
| **A forged session** (someone who has `RACKBOOK_SESSION_KEY`, perhaps also an old cookie) | A local session is MACed under a key derived from the session key **and** a per-account secret kept only in the encrypted store, renewed with the session id (section 5). The session key alone, with or without old cookies, forges nothing. | Someone who has the session key and the decrypted store can forge; they already hold everything. |
| **The admin as the trust root** | Admins create accounts and issue resets. Admin is a role in `auth.roles`, so anyone with push access to the data repository can make themselves admin; that is unchanged. Above the admins is the host: whoever holds the state dir, the key and a shell can run the CLI (section 9). | By design. The deployment decides who has the host and the key. |
| **An insider admin** (wants to act as someone else) | A reset replaces only what it names; the person must still pass every factor it does not name (4.7). A `password` reset leaves the attacker needing the victim's TOTP or passkey; a `second_factor` reset leaves them needing the victim's password. Only a **full reset** (both) hands over the account, and that is a separate, warned, audited action that is in effect a new invite. Every reset revokes the account's tokens and grants, ends its sessions, and is shown to the holder at their next sign-in. Everything is in the hash-chained audit log, which an admin cannot edit without root on the host. | An admin who does a full reset and uses the link can act as the victim; their commits show as *verified*. The victim notices (their password stops working, and the notice says who did it), and the audit log tells the story. There is no two-person rule (section 13). |
| **A leaked invite or reset link** | 256-bit, single-use, expiring, carried in the URL fragment (kept out of server logs and `Referer`, and removed from the address bar once read). The first browser that opens it holds it for 30 minutes, recorded in the store and the audit log; after that hold the link is dead unless setup was finished. For a `password` or `second_factor` reset the link alone is not enough (above). | Whoever opens an invite first wins. The real person finds it refused and asks the admin, who revokes and re-issues. |
| **Account enumeration** | Usernames are not secret (they are in `auth.roles`), so this is not a goal. Still, unknown, invited, disabled, removed and locked accounts all answer after the same argon2id time, and unauthenticated callers are not told unlock times. | |
| **CPU and memory exhaustion** (argon2id is expensive by design) | Pre-authentication limits per IPv6 /48, a global budget for unknown accounts, a fixed number of hashing slots with one reserved for signed-in and known-good callers, and a queue with a timeout (section 7). | A large botnet can make password sign-in from new addresses slow. |
| **Flooding the audit log** (kept forever) | Refusals are aggregated per address bucket per minute (section 8). | |

Out of scope: root on the running host (it holds the keys in memory), a compromised browser, and the data
repository's own access control.

---

## 3. Where account data lives, and why

**Not in Git.** Password hashes, TOTP secrets and session secrets are secrets. The data repository is cloned
by people, CI and backups, and Git history is never rewritten, so anything committed stays forever. Account data
does not go into `.rackbook/`. Local accounts' passkeys go to the same store, not to `.rackbook/passkeys.yml`:
one place per account, so removing an account is one atomic write and nothing about an account shows up in Git.

**The store.** `<state-dir>/accounts/accounts.enc`, mode 0600. A team has tens of accounts, so the file is
small; it is decrypted once at start and kept in memory. The state dir's lock means one server owns it.

Format: a one-line JSON header, then the nonce and the ciphertext.

```json
{"v": 1, "alg": "AES-256-GCM", "kid": "3f9a1c2e", "change": "b2c4…", "audit_seq": 1842, "audit_month": "2026-11"}
```

- **Cipher:** AES-256-GCM, a fresh 96-bit random nonce on every write, the header bytes as additional
  authenticated data. The whole content is encrypted.
- **Key:** 32 random bytes, separate from the session key: `RACKBOOK_ACCOUNTS_KEY` (base64) or
  `--accounts-key-file`. The session key's loader is generalised to `LoadKey(name, env, file)`, so each key
  has its own messages: "`--auth local` needs the account store key: set RACKBOOK_ACCOUNTS_KEY (base64, 32 or
  more random bytes) or pass --accounts-key-file", "set only one of RACKBOOK_ACCOUNTS_KEY and
  --accounts-key-file", "RACKBOOK_ACCOUNTS_KEY decodes to N bytes, need at least 32", and "the account store
  key must differ from the session key". The encryption key is HKDF-SHA256 of it (info `rackbook accounts v1`);
  `kid` is the first 8 hex digits of SHA-256 of the derived key, so a wrong key is reported as such.
- **Why separate from the session key:** rotating the session key logs everyone out; it must not also destroy
  every account.
- **Provisioning:** `openssl rand -base64 32`, kept where the deployment keeps its other secrets (the infra
  repository's SOPS vault, or an `.env` outside the data volume), passed in the environment or as a file mounted
  read-only from outside the state dir. Never in the data repository, never in the state dir.
- **At start** in local mode, any of these stops the server with a clear error: no key, a wrong key, a file
  that does not decrypt, or a missing `accounts.enc` while the audit log has change events. It never
  starts with an empty store in place of one it cannot read. (A first start, with no file and no account events
  in the log, creates an empty store.)

Per account:

| Field | Notes |
|---|---|
| `username`, `name` | `local:<username>` is the identity |
| `state` | `invited`, `active`, `reset_pending`, `disabled`, `removed` (a tombstone) |
| `created`, `created_by` | |
| `password` | PHC string, `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>` |
| `totp` | secret (20 bytes), `last_step`, `added` |
| `passkeys` | up to 10: credential id, public key, user handle, name, added |
| `sid`, `session_secret` | 128-bit session id and 256-bit secret, renewed together; renewing them ends every session (section 5) |
| `failures` | recent failures per address bucket and in total, for 4.6; `good_buckets`: up to 10 address buckets with a successful sign-in in the last 30 days |
| `pending` | an invite or reset: SHA-256 of the token, kind, scope, expires, issued by; and the **hold**: hash of the browser value, held until |
| `last_login`, `last_second_factor_failure` | time and address (as `--audit-addr` says), shown on *My account* |
| `notices` | resets and other admin actions on the account not yet shown to the holder |

Beside it, **`<state-dir>/accounts/usernames`**: every username ever invited, one per line, not encrypted
(usernames are not secret; they are in `auth.roles`). An invite refuses a name in this list. It is kept by
`discard-store`, so the rule "a username is never reused" survives a lost key.

**Passwords.** argon2id, m = 64 MiB, t = 3, p = 4, 16-byte salt, 32-byte tag (the second recommended setting
of RFC 9106). Hashing runs in a fixed number of slots (section 7). The parameters are constants, not
configuration, so nobody can weaken them by editing `rackbook.yml`; they are stored in each hash, so raising
them later rehashes at the next sign-in. No separate pepper: the store is already encrypted under a key outside
the state dir.

**Password rules** (NIST SP 800-63B): at least 12 characters (`auth.local.password_min_length`, 12 to 64),
at most 128; NFKC-normalised before hashing; no composition rules and no expiry; refused if it is in the
embedded list of the 100 000 most common passwords, or contains the username or the host name. Checked on the
server; nothing is sent anywhere.

**Writing a change, and crashes.** The store is written in two ways.

- **Counters** (failures, locks, the slowdown, `last_login`, `last_second_factor_failure`, `good_buckets`)
  are written in place (temporary file, `fsync`, rename) without a change id. Losing or rolling them back is
  harmless, so they take no part in the check below.
- **Changes** are everything else: the events in the table of section 8 that carry `change:` (invite, revoke,
  link opened, setup completed, reset issued, password changed, factor added or removed, sessions ended,
  unlock, disable, enable, remove). Each goes through one sequence, so a crash is always resolved without
  guessing:

1. Make a random `change` id. Write the new store to `accounts.enc.next` (header carries `change`), `fsync`.
2. Append the audit event, carrying `detail: ["change:<id>"]`, with `RecordSync` (section 8). On error: delete
   `accounts.enc.next`, change nothing, answer `503 audit_unavailable`.
3. Write `audit_seq` and `audit_month` of that event into the header, rename `accounts.enc.next` over
   `accounts.enc`, `fsync` the directory. Then answer.

At start, the last event carrying a `change:` id (found from `audit_seq` onwards) is compared with the
store:

- its `change` is the store's: fine;
- its `change` is that of `accounts.enc.next`: the crash came after step 2. The rename is finished;
- `accounts.enc.next` exists without a matching event: the crash came before step 2. The change was never
  confirmed to anyone; the file is deleted;
- anything else (a later event the store does not have, `audit_seq` pointing past the end of the log, or into
  a month file that no longer exists): a **gap**. The server does not start in local mode (below).

**Retention never prunes past the store.** `--audit-retention-months` keeps the month named by the store's
`audit_month` and every later one, whatever the setting, so the start-up check always has its anchor. This
deployment keeps everything anyway.

**A gap means a restore, and is never accepted silently.** The choice is to refuse to start, not to replay:
replaying would need the new password hashes, TOTP secrets and session secrets in the audit log, which must
never hold secrets. The server stops with "the account store is older than the audit log" until the operator
runs `rackbook accounts accept-restore`, which:

- prints every change event after the store's `change`;
- **re-applies the restrictive ones**, which need no secret: `account_disabled`, `account_removed`,
  `sessions_ended`, `factor_removed` (the event names the factor: `totp`, or the passkey's credential id),
  `account_reset_issued` (the credentials in its scope are deleted again; the account goes to `reset_pending`
  with no link, and an admin issues a new one), `account_invite_revoked`;
- puts every account that lost a **permissive** change (`account_setup_completed`, `password_changed`,
  `factor_added`, `account_enabled`) into `reset_pending` with scope `all`, so nobody signs in with a credential
  that was replaced after the backup;
- **renews `sid` and `session_secret` of every account**, so no cookie issued before or after the backup is
  accepted, and a disable that was lost and re-applied cannot be undone by an old cookie;
- ignores the rest (`account_invited`, `account_link_opened`, `account_unlocked`): a lost invite or hold only
  means a new link;
- records `account_store_restored` with the range of seqs it covered.

**Backup and restore.**

- Back up the state dir (accounts and audit log together) and, **separately**, the key. A backup of the
  state dir alone is useless without the key.
- Restoring the state dir and the key from the same backup is consistent and is not detected. Every cookie
  issued after the backup is refused anyway (the session secrets are older), but cookies from before it are
  valid again, so after any restore run `rackbook accounts end-sessions --all`, and review **Users**.
- Lost key: `rackbook accounts discard-store` moves the file aside (`accounts.enc.discarded-<time>`) and records
  `account_store_problem` (`code: discarded`). `usernames` stays, so old names are not reused; everyone is
  invited again under new usernames, or the owner decides otherwise (section 13).
- Key rotation: `rackbook accounts rekey --new-key-file` re-encrypts under the new key and records
  `account_store_rekeyed` with both `kid`s.

---

## 4. The flows

Endpoints are under `/auth/local/` (no session needed) and `/api/account`, `/api/admin/accounts` (a session
needed; API tokens and OAuth tokens are refused, as for passkeys today). Sign-in ceremonies in progress live in
memory, bounded, bound to the browser by the existing `__Host-rackbook_login` cookie.

Every account change and every local sign-in **fails closed** when the audit log cannot be written (section 8).

### 4.1 Invite

1. An admin, re-authenticated (section 5), opens **Users → Invite**: username, display name, role (optional),
   validity.
2. `POST /api/admin/accounts {username, name, role}`. Usernames match `^[a-z][a-z0-9._-]{0,31}$` and must not
   be in `usernames`. The store gets an `invited` account with a pending invite: SHA-256 of a 32-byte random
   token, expiring after `auth.local.invite_ttl` (default 72 h, 1 h to 14 days). Audit `account_invited`.
3. If a role was chosen, the console then saves `local:<username>` into that list of `auth.roles` through the
   role editor of phase 2a (section 6). If that commit fails, the account exists without a role and **Users**
   shows "no role" with *Assign*.
4. The answer carries the link once: `https://<host>/auth/local/setup#<token>`. The admin passes it on by
   whatever channel the team trusts. Nothing is e-mailed.

An admin can **revoke** a pending invite (`account_invite_revoked`), or issue a new one, which replaces it.

### 4.2 Opening a link (invite or reset)

1. The console reads the token from the fragment, removes it from the address bar at once with
   `history.replaceState`, and `POST /auth/local/setup/open {token}`.
2. The server checks the hash, the expiry and the account state, then **holds** the link for this browser for
   30 minutes: a random value goes into the login cookie, its hash and the hold's end into the store (an account
   change, so it survives a restart), and the audit log gets `account_link_opened` with the address. Another
   browser opening it during the hold gets `invite_claimed`.
3. **Once held, the link dies at the hold's end** if setup is not finished, whatever its original expiry. The
   admin issues a new one.
4. What follows depends on the link: an invite is 4.3; a reset is 4.8.

### 4.3 First setup (invite)

1. **Password:** `POST /auth/local/setup/password {password}`, checked against section 3, hashed, kept with the
   setup in memory. A restart during setup means entering it again; the hold survives.
2. **Second factor:** a passkey (4.5) or TOTP (4.4), at least one. With `second_factor: passkey`, only a
   passkey.
3. **Done:** one store change sets the password and the factor, makes the account `active`, consumes the
   token and makes a new `sid` and `session_secret`. Audit `account_setup_completed` (`code: invite`, the
   factor in `detail`) and `login`. The person is signed in.

### 4.4 TOTP enrolment

RFC 6238: HMAC-SHA1, 6 digits, 30-second period (what every authenticator app supports).

- The server makes a 160-bit secret and returns
  `otpauth://totp/Rackbook%20(<host>):<username>?secret=…&issuer=Rackbook%20(<host>)`. The console draws the QR
  code itself (no outside service) and shows the base32 secret for typing in.
- The person enters a current code to confirm; only then is TOTP part of the setup or the account.
- Verification accepts the current step and one either side (±30 s), and refuses any step at or before
  `last_step`, so a code cannot be used twice.
- One TOTP per account. Replacing it: enrol a new one, confirm, the old one is gone.
- The server's clock must be synchronised (NTP).

**No recovery codes.** A lost factor is an admin reset (4.8). Recovery codes would be a third credential,
usually kept badly, for a problem the admin already solves. The console encourages a second factor of a
different kind (a passkey and TOTP, or two passkeys). To be confirmed (section 13).

### 4.5 Passkey enrolment

WebAuthn with the relying-party ID of today (the host of `--base-url`): resident key *required* (so the passkey
can sign in on its own, 4.6), user verification as `auth.passkeys.user_verification` says (`preferred` by
default). The user handle is random per account. Up to 10 passkeys per account, each named. Stored in the
account store, not in Git. Only the account holder adds factors; an admin never does.

### 4.6 Sign-in

Two ways in, both offered on the sign-in page.

**With a passkey alone.** `POST /auth/local/passkey/begin` (discoverable, no username) and `…/finish`. If the
assertion has the **user-verified** flag set, the passkey is two factors (the device and its PIN or biometric)
and the person is signed in: `login` with `detail: ["factor:passkey", "passwordless"]`. If it is not
user-verified, the password step follows, as below. **This path is never blocked by password lockout**; only
the per-address pre-authentication limit and the hashing-free ceremony limits apply.

**With username and password, then the second factor.**

1. `POST /auth/local/login {username, password}`. The pre-authentication limit per address bucket comes
   first (section 7).
2. Unknown, `invited`, `reset_pending`, `disabled`, `removed`, or locked for this address bucket (below):
   refused after a **dummy argon2id** (or, past the global budget, an equal wait; section 7), so response time
   does not tell these states apart, and the password is never checked, so a lock cannot be used to test
   passwords.
3. Wrong password: the failure is counted (below) and refused (`bad_password`).
4. Right password: a pending sign-in (5 minutes, this browser) answers which factors the account has.
5. `POST /auth/local/totp {code}` or the passkey assertion for that account. At most 5 tries per pending
   sign-in. A failure counts like a wrong password, is refused (`bad_second_factor`) and is kept as
   `last_second_factor_failure`, which *My account* shows: someone knew your password.
6. Success clears the failures of this address bucket, adds the bucket to `good_buckets`, rehashes the password
   if the parameters went up, updates `last_login`, issues the session (section 5) and writes `login` with the
   factor.

The first refusal per (account, address bucket) per minute is a full `login_refused`; the rest are counted into
a summary (section 8).

**Lockout, by where the attempts come from.**

- **Per (account, address bucket):** five consecutive failures (password, second factor, or re-authentication)
  lock that pair for 1 minute; each further failure after a lock doubles it, capped at 60 minutes. Attempts
  during a lock are refused unchecked and do not extend it. Other addresses are not affected.
- **Per account, a slowdown, never a lock:** once the account has more than 20 failures in the last hour from
  all buckets together, password checks for it from buckets **not** in `good_buckets` are spaced: at most one
  per 2 seconds, doubling per further 20 failures, capped at one per 30 seconds. An early attempt gets
  `429 slow_down` and is not checked. Sign-ins from `good_buckets` and passkey sign-ins are not slowed.
- The start of a pair lock and the start of the account slowdown each write `account_locked` (`code: address`
  or `slowdown`).
- **What callers are told:** an unauthenticated caller gets `423 locked` "too many attempts from this network;
  try later, or sign in with a passkey", with no unlock time. The exact times are shown to the account holder
  on *My account* and to admins on **Users**.
- **Unlock** by an admin, from the console or with `rackbook accounts unlock` against the running server
  (section 9), clears every pair lock and the slowdown (`account_unlocked`).
- Lockout parameters are constants.

So an attacker can make password sign-ins to a known account slow from new networks, but cannot lock its owner
out: a passkey always works, a recently used network always works, and an admin can unlock at any time without
a restart.

### 4.7 Re-authentication

`POST /auth/local/reauth` asks for the password and the second factor, or a user-verified passkey alone. It
runs in the reserved hashing slot (section 7). A failure counts toward the (account, address bucket) lock only,
not the account slowdown. **Three failed re-authentications in one session end every session of the account**
(`sid` and `session_secret` renewed, `sessions_ended` with `reason: reauth_failed`): a stateless cookie cannot
be ended alone, and someone failing re-authentication with a live cookie is the stolen-cookie case.

### 4.8 Admin reset

**Users → Reset**, re-authentication required. An admin cannot reset their own account here (they use *My
account*, or the CLI). Scopes:

| Scope | Deleted at once | What the person must do with the link |
|---|---|---|
| `password` | the password | set a new password, then **pass an existing factor** (TOTP or passkey) |
| `second_factor` | TOTP and passkeys | **enter the current password**, then enrol a new factor |
| `all` (*Full reset*) | everything | set a password and enrol a factor: **in effect a new invite** |

- A *Full reset* is a separate button, not a third option of the same dialog. The console warns: "This lets
  whoever opens the link take over the account. It is the same as inviting a new person under this name." It is
  audited as `account_reset_issued` with `code: all`.
- For every scope, at issuance: the account goes to `reset_pending` (it has no role while pending; section 6),
  `sid` and `session_secret` are renewed so every session ends, its **API tokens and OAuth grants are revoked**
  (4.11), any lock is lifted, and a reset token is issued like an invite (expiry `auth.local.reset_ttl`,
  default 24 h, 1 h to 7 days, and the 30-minute hold of 4.2). Audit `account_reset_issued`.
- Completing writes `account_setup_completed` (`code: reset`, the scope in `detail`) and signs the person in.
  The password check of a `second_factor` reset and the factor check of a `password` reset count toward the
  (account, address bucket) lock.
- The old password stops working at once for `password` and `all`; for `second_factor` it keeps working, since
  it is needed to complete the reset.
- The holder is told: at their next sign-in, a notice shows each reset since the last one they saw ("*admin*
  reset your *password* on *date*"), until they dismiss it. The same goes for *Disable*/*Enable* and admin
  *Unlock*.

### 4.9 Disabling and removing an account

**Disable** (re-authentication required) sets `state: disabled`, renews `sid` and `session_secret`, and revokes
the account's API tokens and OAuth grants (4.11). Sessions end at once, sign-in is refused (`disabled`), and the
role of `local:<username>` evaluates to none on every path (section 6). **Enable** reverses the state; old
sessions, tokens and grants stay ended.

**Remove** (re-authentication required) does the same, deletes the password, factors and pending tokens, and
leaves a tombstone (`state: removed`). The username stays in `usernames` and is never reused, so `local:alice` in
old commits and audit lines always means the same person. The console then offers to take `local:<username>`
out of `auth.roles` (a role-editor commit).

Refused for both: acting on yourself, or on the last active admin.

### 4.10 Incident response (the store and its key both leaked)

`rackbook accounts rekey`, then `rackbook accounts reset --all --scope all`: every account goes to
`reset_pending` with new links, every session secret is renewed, and every local account's API tokens and OAuth
grants are revoked. Because the TOTP secrets are in the leak, a lesser scope would not do.

### 4.11 Revoking tokens and grants

Disable, remove, every reset and `reset --all` revoke the account's API tokens (one commit to
`.rackbook/tokens.yml`, `rackbook(auth): revoke tokens of local:<username>`, as for any token revocation) and its
OAuth grants and refresh tokens in the built-in OAuth server (`oauth-grants.json`). The account event carries
`detail: ["tokens:<n>", "grants:<n>"]`. Because the account is not active while disabled, removed or pending a
reset, its tokens and grants have no role even before the commit lands; the revocation makes that permanent,
so they do not come back on *Enable* or when a reset is completed. If the token commit fails, the console says
so and offers to retry; the role check still blocks them.

### 4.12 Self-service (My account)

All need re-authentication:

- **Change the password** (`password_changed`; renews `sid` and `session_secret`, keeps the current session).
- **Add or remove a factor** (`factor_added`, `factor_removed`; removing the last one is refused).
- **Sign out everywhere** (`sessions_ended`): renews `sid` and `session_secret` and issues a fresh cookie for this
  browser. A box **"Also revoke my API tokens and app connections"** is ticked by default, and the dialog lists
  them by name (API tokens with their scope, OAuth clients with their last use) before confirming.

---

## 5. Sessions

The same cookie and the same session key, with `method: local` added to what the codec accepts. A local session
carries `sid`, `aat` (when the person last gave password and second factor, or a user-verified passkey) and the
factor used. `auth.session.idle` and `absolute` apply (defaults 12 h and 7 days).

**Bound to the store.** The cookie is signed, not encrypted, so an OIDC-style MAC under the session key alone
would let anyone who holds that key, and has seen one cookie, forge more. A local cookie's MAC key is instead

```
HKDF-SHA256(ikm = session key, salt = account.session_secret, info = "rackbook.session.local.v1" || sid)
```

The codec reads the (unverified) username from the payload, looks up the account in memory, derives the key and
only then verifies. The account must exist, be `active`, and have the same `sid`. Renewing `sid` and
`session_secret` ends every session and makes old cookies worthless even to someone with the session key.
Forging a local session needs the session key **and** the decrypted store.

**Re-authentication.** Sensitive actions need `aat` within `auth.local.reauth_window` (default 10 minutes,
1 minute to 1 hour); otherwise `403 reauth_required` (the code `/infra` uses), and the console asks again (4.7),
writes `reauth`, and repeats the action. Sensitive:

- *My account*: password, factors, sign out everywhere;
- account administration: invite, revoke an invite, reset, full reset, unlock, disable, enable, remove;
- creating or revoking an API token;
- saving roles (**Users → Roles**);
- approving an MCP client in the built-in OAuth server (it mints a long-lived credential for the person).

SSO deployments are unchanged; `/infra` keeps its own `--infra-write-max-age`.

---

## 6. Roles

A local account gets its role from `auth.roles`, by its identity `local:<username>`. The store holds no role.
One source of truth, reviewable in Git; phase 2a's `role_changed` and `audit/identities.json` work unchanged.

```yaml
auth:
  roles:
    admin:  ["local:alice"]
    editor: ["local:bob", "local:carol"]
    viewer: ["local:*"]
```

- New entry kinds `local:<username>` and `local:*`. Local identities match those and `*`, nothing else (not
  `*@domain`, `group:`, `app-role:`, `oidc:`, `mcphub:` or `oauth:`), and are therefore **not** in
  `plainMethods` (`internal/roles/roles.go`). Other identities never match `local:` entries.
- **One check for every path.** A new private helper `(*Authenticator).policyRole(s roles.Subject)` replaces the
  direct `Policy().Evaluate(s)` calls in `RoleForVia` and `EvaluateSubject` (and so in `Evaluate`). For a
  subject with method `local` it returns none unless `localAccountActive(s.ID)` (an option of the
  Authenticator, answered from the store in memory) says the account is `active`. That covers sessions
  (`Evaluate`), API token creators (`RoleForVia`, `internal/api/tokens.go:68`) and OAuth grants, OAuth access
  tokens and API tokens on `/mcp` (`EvaluateSubject`, `internal/oauthserver/token.go:75`,
  `internal/mcpauth/mcpauth.go:233` and `:265`). A test walks all three with a disabled account.
- `internal/tokens` records the creator's method `local` (`creatorMethod`), so a token's creator is evaluated
  as a local identity.
- `passkey` stays in `plainMethods` and in `creatorMethod` (`internal/tokens/registry.go`), so API tokens and
  OAuth grants created from a passkey session before section 10 keep their role.
- Git commits are authored `Display Name <local:alice>`, as MCPHub usernames are today.

**With phase 2a's role editor** (**Users → Roles**):

- In local mode it offers the accounts by name for `local:` entries, and marks `group:`, `app-role:`,
  `*@domain` and `oidc:` entries as having no effect. The reverse under SSO for `local:` entries.
- An entry naming a username with no account is kept, with a warning.
- The last-admin rule counts only entries that can sign in: `local:` entries of `active` accounts (or
  `local:*` with at least one active account). It also refuses removing the editing admin's own entry.
- The invite dialog's role choice and the offer after *Remove* are ordinary role-editor commits.

Anyone with push access to the data repository can still edit `auth.roles` directly; that was always true.

---

## 7. Rate limits and hashing capacity

**Address buckets.** Pre-authentication limits key on a new `clientip.Bucket(r, trusted, v6bits)` with
**/48** for IPv6 (one site gets a /48, so /64 is too cheap to rotate through) and the full address for IPv4. The
audit log and the existing token limits keep `clientip.Of` (/64). Tables are bounded in memory (10 000 entries,
least recently seen forgotten first).

| What | Limit | Over the limit |
|---|---|---|
| `POST /auth/local/login`, `/auth/local/reauth`, per address bucket (/48) | burst 10, then 1 per minute | `429 rate_limited` |
| passkey ceremony starts, TOTP enrolment, per address bucket | the existing limiter, 30 per minute, burst 10 | `429` |
| `POST /auth/local/setup/open`, per address bucket | burst 5, then 1 per minute | `429` |
| second-factor step | 5 tries per pending sign-in | the pending sign-in is dropped |
| per (account, address bucket) | lock, 4.6 | `423 locked`, no time given |
| per account | slowdown, 4.6 | `429 slow_down` |
| **dummy hashes**, all addresses together | 30 per minute | an equal wait instead of a hash (below) |

**Dummy hashes.** Unknown and non-active accounts run argon2id against a fixed dummy hash, so their timing
matches. All of them together get 30 such hashes per minute. Past that budget, the request waits the server's
measured median hashing time without hashing, so timing still matches while costing no CPU or memory. A flood
of made-up usernames therefore cannot use up the hashing slots.

**Slots.** Three hashing slots (192 MiB peak):

- one **reserved** slot for re-authentication of a signed-in session, and for sign-ins from an address bucket
  in that account's `good_buckets` (known before hashing: username plus address);
- two **general** slots for everyone, which the reserved callers may also use.

Waiting callers queue, reserved ones first. A wait longer than 5 seconds ends with `503 busy` and
`Retry-After: 5`; the console says "the server is busy, try again in a few seconds" and retries once by itself.

The per-address limit stops one source from trying many accounts; the per-pair lock and the per-account
slowdown stop many sources from trying one account; the global budget and the reserved slot keep the hashing
from being exhausted.

---

## 8. Audit events

**The API.** A new method on the audit log:

```go
// RecordSync appends e and fsyncs it. It returns the seq it got, or an error,
// including when the log is in its failed state. It never drops an event silently.
func (l *Log) RecordSync(e Event) (seq int64, err error)
```

`Record` stays for events that must not break a request. Every account change (section 3, step 2) and every
local `login` and `reauth` use `RecordSync` and **fail closed**: the change is not made, the sign-in gets no
session, and the answer is `503 audit_unavailable`. The sign-in page then says "Sign-in is unavailable: the
server cannot write its audit log. An administrator must check the server." Admins already signed in see the
existing red audit banner (`auditAlert` in `/api/meta`), and every account action in **Users** is disabled with
the same reason. `logout` still clears the cookie and records with `Record` (ending a session is always safe).
Without `--state-dir` there is no audit log, which is why local mode requires it.

**The events.** All in the chain, under the activity area `audit` (admins, later auditors). `method` is `local`
for the console and `cli` for the command line (with `detail: ["uid:<n>"]` when it came through the admin
socket). `addr` comes from `clientip.Of` and is kept as `--audit-addr` says: `full` in this deployment, which
still keeps an IPv6 client as its /64. Passwords, codes, tokens, secrets and typed unknown usernames are never
recorded. One new field, **`target`**: the account acted on when that is not the actor. Every change event
(section 3) also carries `detail: ["change:<id>"]`.

| Event | `identity` | Other fields |
|---|---|---|
| `login` | the account | `role`, `addr`, `detail: ["factor:totp"]`, `["factor:passkey"]` or `["factor:passkey", "passwordless"]` |
| `login_refused` | the account, empty if unknown | `addr`; `reason`: `unknown_account`, `bad_password`, `bad_second_factor`, `locked`, `slow_down`, `disabled`, `not_set_up`, `reset_pending`, `no_role`, `rate_limited`, `busy`, `invite_invalid`, `invite_expired`, `invite_claimed`; `code: reauth` for a failed re-authentication; `code: summary` for an aggregate (below) |
| `logout` | the account | `role`, `addr` (as today) |
| `reauth` | the account | `addr`, `detail: ["factor:…"]` |
| `account_locked` | the account | `addr`, `code`: `address` or `slowdown`, `detail: ["until:<time>", "failures:<n>"]` |
| `account_unlocked` | the admin | `target` |
| `account_invited` | the admin | `target`, `detail: ["expires:<time>"]` |
| `account_invite_revoked` | the admin | `target` |
| `account_link_opened` | the account | `addr`, `code`: `invite` or `reset`, `detail: ["hold_until:<time>"]` |
| `account_setup_completed` | the account | `addr`, `code`: `invite` or `reset`, `detail: ["factor:…", "scope:…"]` |
| `account_reset_issued` | the admin | `target`, `code`: `password`, `second_factor` or `all`; `detail: ["expires:<time>", "tokens:<n>", "grants:<n>"]` |
| `password_changed` | the account | `addr` |
| `factor_added` | the account | `code`: `totp` or `passkey`; `detail: ["name:<passkey name>", "credential:<id>"]` |
| `factor_removed` | the account | as `factor_added` |
| `sessions_ended` | the account, or the admin with `target` | `addr`; `reason`: `self`, `reauth_failed`, `cli`; `detail: ["tokens:<n>", "grants:<n>"]` |
| `account_disabled`, `account_removed` | the admin | `target`, `detail: ["tokens:<n>", "grants:<n>"]` |
| `account_enabled` | the admin | `target` |
| `account_store_problem` | none | `code`: `gap`, `missing`, `key_mismatch`, `unreadable`, `discarded`; `detail` |
| `account_store_restored`, `account_store_rekeyed` | none, `method: cli` | `detail`: the seqs covered, or the old and new `kid` |
| `passkeys_removed` | the admin | `detail: ["count:<n>"]`; SSO deployments, section 10 |

**Aggregated refusals.** The log is kept forever, so refusals must not be able to flood it. Per address bucket
and minute, the first `login_refused` for each account (and the first for unknown accounts) is written in full;
later ones in that minute are counted and written once, at the end of the minute, as one `login_refused` with
`code: summary`, the bucket's `addr`, and `detail: ["count:<n>", "reasons:bad_password=…,unknown_account=…",
"accounts:<n>", "from:<time>", "to:<time>"]`. When more than 100 buckets have refusals in one minute, the rest
are folded into a single summary without `addr`. Refusals use `Record`, not `RecordSync`: losing a refusal
must not keep a correct sign-in out, and a correct sign-in fails closed anyway when the log fails.

The server log keeps its `login`, `logout` and refusal lines, with the same care about what is never logged.

---

## 9. Config, flags, CLI and MCP

**Selecting local mode is the deployment's choice:** `--auth local` or `RACKBOOK_AUTH=local`.

- `auth.mode: local` in `rackbook.yml` stays **rejected**, as `Login.check` rejects every unknown mode today; the
  message gains "local mode is set by the deployment: --auth local". People who can edit the ledger should not
  switch how everybody signs in, and the mode needs a key from the environment anyway.
- With `--auth local`, `auth.mode` in the file must be absent, and the server refuses to start (and refuses a
  pulled config, like any invalid one) when the file has an `auth.oidc` block or `auth.mcp.trusted_issuers`
  (MCPHub and other OAuth issuers bring identities from an outside provider, which a local deployment does not
  have; section 13). The built-in OAuth server (`auth.mcp.builtin_issuer`) is allowed: it authorises with the
  local session.
- Local mode needs `--state-dir`, `--base-url` (https), the session key and the account key.

| Flag / variable | Meaning |
|---|---|
| `--auth local` | local accounts; no OIDC, no Cloudflare Access, no outside OAuth issuers |
| `RACKBOOK_ACCOUNTS_KEY` / `--accounts-key-file` | the account store key (section 3) |

Tunables in `rackbook.yml`, with floors so editing the ledger cannot weaken much:

```yaml
auth:
  local:
    second_factor: any          # any (passkey or TOTP) | passkey
    password_min_length: 12     # 12..64
    invite_ttl: 72h             # 1h..14d
    reset_ttl: 24h              # 1h..7d
    reauth_window: 10m          # 1m..1h
  passkeys: {user_verification: preferred}   # in local mode: options of the passkey factor
  session: {idle: 12h, absolute: 7d}
```

argon2id, TOTP, lockout, slot and budget parameters are constants.

**CLI** (`rackbook accounts`). With the server running, the commands talk to it over an **admin socket**,
`<state-dir>/admin.sock` (a Unix socket, mode 0600 in the 0700 state dir; the server also checks that the peer's
uid, from `SO_PEERCRED`, is its own). With the server stopped, they take the state dir's lock and work on the
files. Links are printed to the operator's terminal only. Each writes its audit event with `method: cli`.

| Command | Online | Offline | What |
|---|---|---|---|
| `list` | yes | yes | usernames, state, factors, locks, last sign-in, whether `rackbook.yml` gives a role |
| `invite <username> [--name] [--ttl]` | yes | yes | the first admin, or anyone; warns when no role entry matches |
| `reset <username> --scope password\|second_factor\|all`, `reset --all --scope …` | yes | yes | break-glass, also for the last admin |
| `unlock <username>` | yes | yes | clears the locks and the slowdown at once |
| `disable`, `enable <username>` | yes | yes | |
| `end-sessions <username>\|--all` | yes | yes | renews session secrets (after a restore, section 3) |
| `rekey --new-key-file` | no | yes | section 3 |
| `accept-restore` | no | yes | section 3; the server does not start until it has run |
| `discard-store` | no | yes | section 3, lost key |

On Windows there is no admin socket; the commands work offline only (section 13).

**Bootstrap:** set `auth.roles.admin: ["local:alice"]` in `rackbook.yml`, run `rackbook accounts invite alice`,
start the server, open the link. A server in local mode with no accounts logs a warning that says exactly this.

**MCP and API tokens:** no change to how they work. `/mcp` takes API tokens and the built-in server's OAuth access
tokens; their role follows the account (section 6) and they are revoked with it (4.11). No MCP tool manages
accounts, and the account endpoints refuse tokens. `rackbook mcp` against a local clone is unaffected.

**`/infra`:** unavailable in local mode; it accepts pinned OIDC sessions only.

---

## 10. Passkeys when SSO is configured

**Decision:** with `auth.mode: oidc` there is no passkey sign-in. Sign-in is only through the identity
provider, which is where phishing-resistant sign-in belongs (Entra supports passkeys and FIDO2 keys itself) and
which sees a disabled account.

**Not a switch.** `auth.passkeys` in an OIDC deployment is accepted, ignored, and logged as a warning at start,
so existing `rackbook.yml` files keep loading. No server flag brings it back. If a team ever needs it, it returns
as a server flag (default off; not a `rackbook.yml` key, because it bypasses the provider) together with the
`passkeys_oidc_max_age` rule; until then that rule is not built.

**Migration of existing passkeys:**

- On upgrade, `/auth/passkey/*` and the passkey parts of *My account* are gone. An existing passkey session is
  rejected at its next request (the code already treats a passkey session without passkeys as revoked), and the
  person signs in through SSO. The release notes say so.
- API tokens and OAuth grants made from passkey sessions keep their role: `passkey` stays a recognised method
  (section 6).
- `.rackbook/passkeys.yml` is not changed by the upgrade and is no longer read for sign-in. It holds no secret,
  but it does hold **personal data**: each person's identity (e-mail address or UPN), display name, WebAuthn user
  handle, the authenticator's AAGUID (which names the device model), credential ids and dates. **Removing it is
  recommended.**
- **Users** shows admins "*n* passkeys from an earlier version are no longer used" with **Remove old passkeys**,
  which commits the file's deletion (`rackbook(auth): remove unused passkeys`, straight to the tracked branch as
  passkey commits are today) and writes `passkeys_removed`. Until the file is gone, admins see a reminder banner
  on every page; removing it by hand in Git also ends the reminder. History keeps the old file, which is not
  rewritten.
- **Downgrade risk:** while the file exists, going back to an older Rackbook re-enables passkey sign-in with
  those credentials, around the identity provider. Removing the file closes that. The release notes and the
  reminder say so.
- People can delete the Rackbook entry from their password manager or security key; it does nothing now.
- A deployment that moves from OIDC to local mode treats the file the same way; local accounts enrol their
  passkeys again into the account store.

---

## 11. Console screens

Each ships with a demo in three languages before merge, as for the audit pieces.

- **Sign in** (local mode): *Sign in with a passkey* first, then username and password with a second step
  (passkey or 6-digit code). Locked: "too many attempts from this network; try later, or use a passkey". Busy:
  "the server is busy". Audit failure: "sign-in is unavailable". No "forgot password" link, only "ask an
  administrator".
- **Set up your account** (invite and reset links): the username; then what the link calls for: a new password
  with the rules and the reason a password is refused; the current password (a `second_factor` reset); the
  existing factor (a `password` reset); a new factor, *Add a passkey* (recommended) or *Use an authenticator app*
  (QR code, secret, code to confirm). A link held elsewhere, expired or used says so.
- **Re-authenticate**: a dialog over the current page, then the action continues.
- **My account**: password; factors (passkeys with names and dates, the authenticator app) with add and remove;
  *Sign out everywhere* with the ticked box and the list of tokens and app connections it will revoke; last
  sign-in and from where; locks on the account with their times; a warning when someone entered the password but
  failed the second factor; the notices of admin actions (resets, disable/enable, unlock) until dismissed.
- **Users** (admin): username, name, role (from `auth.roles`; "no role" with *Assign*), state (invited until,
  link held until, active, locked from *n* networks, slowed down, reset pending, disabled), factors, last
  sign-in. Actions: *Invite*, *Copy a new link*, *Revoke invite*, *Reset password*, *Reset second factor*,
  *Full reset…* (separate, with the warning), *Unlock*, *Disable* / *Enable*, *Remove*. Before *Disable*,
  *Remove* or any reset, the dialog lists the API tokens and app connections that will be revoked. A link appears
  once, with a copy button and its expiry. While the audit log cannot be written, the actions are disabled with
  the reason.
- **Users → Roles** (phase 2a): as section 6.
- Under SSO: no passkey parts in *Sign in* and *My account*; **Users** and the admin banner carry the reminder of
  section 10 until `.rackbook/passkeys.yml` is gone.

---

## 12. Pieces (one PR each)

1. **Passkeys off under SSO** (section 10): ignore `auth.passkeys` in OIDC mode with a warning, drop the passkey
   endpoints and console parts, *Remove old passkeys*, the reminder banner, `passkeys_removed`, README and
   release notes (including the downgrade note). Independent; it also removes `passkeys_oidc_max_age` from
   phase 2a's work.
2. **Audit and store foundations:** `RecordSync`; retention honouring the store's month; the encrypted store
   with `LoadKey`, HKDF and `kid`, the `.next`/change-id write sequence and start-up check; `usernames`;
   argon2id with slots, budget and queue; password rules and blocklist; TOTP. `rackbook accounts rekey`,
   `accept-restore`, `discard-store`, `list` (offline). No HTTP.
3. **Local identity and roles:** `--auth local` and its refusals, `auth.local` config, `method: local` in the
   codec with the per-account MAC key and the `sid` check, `local:` entries, `policyRole` and
   `localAccountActive` on all three evaluation paths, token creator method, the `target` audit field.
4. **Sign-in and setup:** the `/auth/local/*` flows (links with holds, setup and reset scopes, password, TOTP
   and passkey factors, passwordless passkey sign-in), `clientip.Bucket`, locks, slowdown, aggregated refusals,
   their audit events, the admin socket and the online CLI commands, the *Sign in* and *Set up* screens. After
   this a team can bootstrap and sign in.
5. **My account and re-authentication:** `aat`, `reauth_required` on the sensitive actions, the
   three-failures rule, self-service, sign out everywhere with revocation, the notices.
6. **Users administration:** the table and actions, revocation of tokens and grants on disable, remove and
   reset. The role choice in *Invite* and the offer after *Remove* need phase 2a's role editor; until it is
   merged, this piece links to editing `rackbook.yml` instead.

Piece 1 goes first and can ship on its own. Pieces 2 to 6 are in order.

---

## 13. For the owner to decide

1. **Passwordless passkey sign-in** (4.6): a user-verified passkey signs in without the password. Proposed
   **yes**: it is two factors, phishing-resistant, and it is what keeps lockout from ever shutting the owner of an
   account out. The alternative is password always, and then lockout can block a passkey user too.
2. **Recovery codes:** proposed none (4.4). Confirm.
3. **`second_factor` default:** proposed `any` (TOTP allowed). `passkey` is safer against phishing but every
   person then needs a device that supports passkeys.
4. **Full reset by a single admin** (4.8): proposed allowed, warned and audited. The alternative is a two-person
   rule (a second admin approves), or allowing a full reset only from the CLI on the host.
5. **Usernames are never reused**, even after `discard-store`. Confirm, or allow reuse after an explicit,
   recorded admin action.
6. **Outside OAuth issuers under local mode**: proposed refused (`auth.mcp.trusted_issuers`, including MCPHub). If
   a team needs MCPHub agents in a local deployment, that is an exception to "SSO or local" to be named here.
7. **Windows:** no admin socket, so the CLI works only while the server is stopped. Acceptable, or is a named-pipe
   equivalent wanted?
8. **Old passkeys:** proposed an admin button plus a reminder, and no automatic commit. The alternative is a
   one-time commit deleting `.rackbook/passkeys.yml` on the first start after the upgrade, which also closes the
   downgrade risk without waiting for an admin.
