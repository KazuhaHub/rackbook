# Local accounts, and passkeys off under SSO

Status: design, decided by the owner on 2026-11-22; nothing here is built yet. Builds on
[design-audit.md](design-audit.md) (the audit log, phase 2a) and [design-v0.2.md](design-v0.2.md) (the built-in
login). Section 13 lists what still needs the owner's confirmation.

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

- **Modes.** `auth.mode` (or `--auth`, which wins) is `none`, `cloudflare-access` or `oidc`
  (`internal/config/login.go`).
- **Sessions** are stateless: the cookie `__Host-rackbook_session` holds `{id, name, method, issued,
  last_seen, ...}` signed with HMAC-SHA256 under `RACKBOOK_SESSION_KEY` (`internal/login/session.go`). It ends
  after `auth.session.idle` (12 h) without activity and after `auth.session.absolute` (7 days). The role is not
  in the cookie; it is evaluated from `auth.roles` on every request. The codec accepts the methods `oidc` and
  `passkey` only.
- **Passkeys** are an alternative to OIDC, not a second factor. Their public keys are committed to
  `.rackbook/passkeys.yml` in the **data repository** (not the state dir). Enrolling needs an OIDC sign-in
  within the last 10 minutes. A passkey session ends when its credential is deleted, because every request
  checks that the credential is still in the file.
- **The state dir** (`--state-dir`, outside the clone, mode 0700, locked by one server through
  `rackbook.lock`) holds the audit log, token last-use, preferences, OAuth grants and keys.
- **Rate limits.** `internal/clientip` names the client (the connecting address, or `CF-Connecting-IP` from
  a `--trusted-proxy`; IPv6 bucketed by /64). The unauthenticated login endpoints share a token bucket of 30
  per minute, burst 10, per address (`internal/login/limit.go`).
- **`/infra`** accepts only OIDC sessions under the pinned issuer, client, claim and tenant
  (`internal/auth/infra.go`). That stays: local accounts never reach `/infra`.

---

## 2. Threat model

Who we defend against, what each attack gives, and what is left.

| Threat | Defence | What is left |
|---|---|---|
| **Phishing** (a look-alike site collects the password and the code, and relays them at once) | A second factor is mandatory. Passkeys are bound to the origin, so a look-alike site gets nothing usable; the setup page offers the passkey first. `auth.local.second_factor: passkey` turns TOTP off entirely. | Password + TOTP can be relayed in real time. Teams that care set `second_factor: passkey`. |
| **Credential stuffing** (passwords leaked elsewhere, tried here) | A password alone never gives a session. Per-address and per-account limits, lockout with backoff (sections 4.6 and 7), at least 12 characters, a blocklist of common passwords. A correct password followed by a failed second factor is recorded and shown to the person, so a reused password is noticed. | A botnet can keep a known username locked out (at most 1 hour at a time; an admin can unlock). |
| **An offline copy of the hashes** (a backup, a copied volume, a lost disk) | The account store is encrypted with a key that is not in the state dir (section 3). A copy without the key reveals nothing, not even the usernames. | A copy *together with* the key gives argon2id hashes (slow to crack, but weak passwords fall) and the TOTP secrets in usable form, because TOTP needs the secret. Response: rotate the key, reset every account (section 4.9). Passkey public keys are useless to an attacker. |
| **A stolen session cookie** (malware, a shared machine) | `Secure`, `HttpOnly`, `SameSite=Lax`, `__Host-`. Sensitive actions need a fresh sign-in (section 5), so a stolen cookie cannot change the password, add a factor, mint a token or manage accounts. "Sign out everywhere" and an admin's *Disable* end every session at once, because each request checks the account's session id. | The cookie works for reading and ordinary edits until it expires, the person signs out everywhere, or an admin disables the account. Cookies are not bound to an address (mobile networks change it). |
| **The admin as the trust root** | Admins create accounts and issue resets, so an admin can take over any account. Admin is a role in `auth.roles`, so anyone with push access to the data repository can already make themselves admin; that is unchanged. Above the admins is the host: whoever holds the state dir, the account key and a shell can run the break-glass CLI (section 9). | By design. The deployment decides who has the host and the key. |
| **An insider admin** (issues a reset for someone, uses the link, works as that person) | Every step is in the hash-chained audit log: `account_reset_issued` by the admin, `account_setup_completed` with the address it came from. The victim's old password stops working at once, and *My account* shows "your password was reset by *admin* at *time*". An admin cannot reset their own account from the console, and cannot edit the audit log without root on the host. | Commits made while impersonating show as *verified* under the victim's name; the audit log tells the story. There is no two-person rule (section 12). |
| **A leaked invite or reset link** (pasted in the wrong chat) | 256-bit, single-use, expires (72 h / 24 h), carried in the URL fragment so it never reaches a server log or a `Referer`. The first browser that opens it holds it for 30 minutes; another browser is refused and that refusal is recorded. The admin sees when and from where setup was completed. | Whoever opens it first wins. The real person then finds the link refused and asks the admin, who revokes and re-issues. |
| **Account enumeration** | Usernames are not secret (they are in `auth.roles` in the data repository), so this is not a goal. Unknown usernames still cost one argon2id run, so timing does not tell them apart. | A locked account says it is locked. |
| **A forged session** (someone who has `RACKBOOK_SESSION_KEY`) | A local session also carries the account's random session id (128 bits), which lives only in the encrypted store. Forging one needs the session key *and* the decrypted store. | Someone who has both is root on the host already. |

Out of scope: root on the running host (it holds the key in memory), a compromised browser, and the data
repository's own access control.

---

## 3. Where account data lives, and why

**Not in Git.** Password hashes and TOTP secrets are secrets. The data repository is cloned by people,
CI and backups, and Git history is never rewritten, so anything committed stays forever. Account data therefore
does not go into `.rackbook/`. Local accounts' passkeys go to the same store, not to `.rackbook/passkeys.yml`:
one place per account, so removing an account is one atomic write and nothing about an account shows up in Git.

**The store.** One file, `<state-dir>/accounts/accounts.enc`, mode 0600, rewritten whole on every change
(write a temporary file, `fsync`, rename, `fsync` the directory). A team has tens of accounts, so the file is
small; it is decrypted once at start and kept in memory, and every change is written before it is answered.
The state dir's lock means one server owns it.

Format: a one-line JSON header, then the nonce and the ciphertext.

```json
{"v": 1, "alg": "AES-256-GCM", "kid": "3f9a1c2e", "audit_seq": 1842, "written": "2026-11-22T10:15:03Z"}
```

- **Cipher:** AES-256-GCM with a fresh 96-bit random nonce on every write, and the header bytes as additional
  authenticated data, so the header cannot be swapped. The whole content is encrypted, so usernames and
  states do not leak either.
- **Key:** 32 random bytes, separate from the session key. `RACKBOOK_ACCOUNTS_KEY` (base64) or
  `--accounts-key-file`, with the same loader as the session key; exactly one source, at least 32 bytes, and
  the server refuses a key equal to the session key. The encryption key is derived with HKDF-SHA256 (info
  `rackbook accounts v1`). `kid` is the first 8 hex digits of SHA-256 of the derived key, so a wrong key is
  reported as such instead of as corruption.
- **Why a separate key, not the session key:** rotating the session key is the way to log everyone out; it must
  not also destroy every account.
- **Provisioning:** `openssl rand -base64 32`, kept where the deployment keeps its other secrets (the infra
  repository's SOPS vault, or an `.env` outside the data volume), and passed in the environment or as a file
  mounted read-only from outside the state dir. Never in the data repository, never in the state dir.
- **At start** in local mode: no key, a wrong key or a file that does not decrypt stops the server with a
  clear error. It never starts with an empty store in place of one it cannot read.

What the content holds per account:

| Field | Notes |
|---|---|
| `username`, `name` | `local:<username>` is the identity |
| `state` | `invited`, `active`, `disabled`, `removed` (a tombstone: the username is never reused) |
| `created`, `created_by` | |
| `password` | PHC string, `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>` |
| `totp` | secret (20 bytes), `last_step`, `added` |
| `passkeys` | up to 10: credential id, public key, user handle, name, added (as in `.rackbook/passkeys.yml` today) |
| `sid` | random 128-bit session id; a new one ends every session of the account |
| `failures`, `locked_until` | the lockout (section 7) |
| `pending` | an invite or reset: SHA-256 of the token, kind, scope, expires, issued by |
| `last_login`, `last_second_factor_failure` | time and address (kept as `--audit-addr` says), shown on *My account* |
| `reset_notice` | who reset what and when, shown to the person once |

**Passwords.** argon2id, m = 64 MiB, t = 3, p = 4, 16-byte salt, 32-byte tag (the second recommended setting
of RFC 9106). At most 2 hashes run at once (128 MiB peak); a request that waits more than 2 seconds for a slot
gets `503`. The parameters are constants, not configuration, so nobody can weaken them by editing
`rackbook.yml`; they are stored in each hash, so raising them later rehashes at the next sign-in. There is no
separate pepper: the store is already encrypted under a key outside the state dir, which gives the same
protection.

**Password rules** (NIST SP 800-63B): at least 12 characters (`auth.local.password_min_length`, 12 to 64),
at most 128; NFKC-normalised before hashing; no composition rules and no expiry; refused if it is in the
embedded list of the 100 000 most common passwords, or contains the username or the host name. The check runs
on the server; nothing is sent anywhere.

**Rollback detection.** `audit_seq` in the header is the seq of the audit event for the last change written.
Account changes append their audit event first, then write the store. At start the server reads the audit
lines after `audit_seq` (a tail read):

- no account-changing event: fine;
- exactly one, the last account-changing line: a crash between the two writes. That change was not saved; the
  server records `account_store_problem` (`code: lost_change`) and starts;
- more: the store is older than the log, for instance restored from a backup. The server does not start in local
  mode until the operator runs `rackbook accounts accept-restore`, which prints the account events since the
  store's `audit_seq` (so an admin can disable again whoever was disabled after the backup) and records
  `account_store_restored`.

Account-changing events: `account_invited`, `account_invite_revoked`, `account_setup_completed`,
`account_reset_issued`, `password_changed`, `factor_added`, `factor_removed`, `sessions_ended`,
`account_disabled`, `account_enabled`, `account_removed`. Sign-ins, failures and locks also change the
store, but rolling them back is harmless, so they do not count.

**Backup and restore.**

- Back up the state dir (accounts and audit log together) and, **separately**, the key. A backup of the
  state dir alone is safe to keep anywhere; it is useless without the key.
- Restoring the state dir with the key brings back the accounts as they were at the backup. If the audit log
  is newer than the store, the server stops and `accept-restore` shows what to redo (above). If both come from
  the same backup, the restore is consistent and nothing is detected: review **Users** afterwards.
- Lost key: the store cannot be read. `rackbook accounts discard-store` moves the file aside
  (`accounts.enc.discarded-<time>`) and records `account_store_problem` (`code: discarded`); everyone is then
  invited again. The audit log still names every account, so they can be invited under the same usernames.
- Key rotation: `rackbook accounts rekey --new-key-file` re-encrypts under the new key and records
  `account_store_rekeyed` with both `kid`s.

---

## 4. The flows

Endpoints are under `/auth/local/` (no session needed) and `/api/account`, `/api/admin/accounts` (a session
needed; API tokens and OAuth tokens are refused, as for passkeys today). Ceremonies in progress live in memory,
bounded, bound to the browser by the existing `__Host-rackbook_login` cookie; a restart only makes someone
start again.

### 4.1 Invite

1. An admin, signed in within the re-authentication window (section 5), opens **Users → Invite**: username,
   display name, role (optional), validity.
2. `POST /api/admin/accounts {username, name, role}`. Usernames match `^[a-z][a-z0-9._-]{0,31}$` and must
   be new, including removed ones. The store gets an `invited` account with a pending invite: SHA-256 of a
   32-byte random token, expiring after `auth.local.invite_ttl` (default 72 h, 1 h to 14 days). Audit
   `account_invited`.
3. If a role was chosen, the console then saves `local:<username>` into that list of `auth.roles` through the
   role editor of phase 2a (section 6). Two writes, two stores: if the commit fails, the account exists without
   a role and **Users** shows "no role" with *Assign*.
4. The answer carries the link once: `https://<host>/auth/local/setup#<token>`. The admin passes it on by
   whatever channel the team trusts. Nothing is e-mailed.

An admin can **revoke** a pending invite (`account_invite_revoked`), or issue a new one, which replaces it.

### 4.2 First sign-in (setup)

The same page serves invites and resets.

1. The console reads the token from the fragment and `POST /auth/local/setup/open {token}`. The server checks
   the hash, the expiry and the account state, then binds the token to this browser for 30 minutes (a random
   value in the login cookie; its hash is kept with the pending setup). Another browser opening it in that time
   gets `invite_claimed`. Answers: the username and what remains to do.
2. **Password:** `POST /auth/local/setup/password {password}`, checked against the rules of section 3, hashed,
   and kept with the setup in memory. Nothing is written yet.
3. **Second factor:** a passkey (4.4) or TOTP (4.3), at least one. With `second_factor: passkey`, only a
   passkey.
4. **Done:** one store write sets the password and the factor, makes the account `active`, consumes the token
   and makes a new `sid`. Audit `account_setup_completed` (`code: invite`, the factor in `detail`) and `login`.
   The person is signed in.

Abandoning setup leaves the account as it was; the link keeps working until it expires.

### 4.3 TOTP enrolment

RFC 6238: HMAC-SHA1, 6 digits, 30-second period. These are what every authenticator app supports; SHA-256 or 8
digits are not reliably supported.

- The server makes a 160-bit secret and returns the `otpauth://totp/Rackbook%20(<host>):<username>?secret=…&issuer=Rackbook%20(<host>)`
  URI. The console draws the QR code itself (no outside service) and shows the base32 secret for typing in.
- The person enters a current code to confirm. Only then is TOTP part of the setup or the account.
- Verification accepts the current step and one step either side (±30 s), and refuses any step at or
  before `last_step`, so a code cannot be used twice.
- One TOTP per account. Replacing it is: enrol a new one, confirm, the old one is gone.
- The server's clock must be synchronised (NTP); a wrong clock breaks TOTP for everyone.

**No recovery codes.** A lost factor is handled by an admin reset (4.7), and an admin who loses theirs by
another admin or the break-glass CLI (section 9). Recovery codes would be a third credential, usually kept
badly, for a problem the admin already solves. The console instead encourages a second factor of a different
kind (a passkey on the phone and TOTP, or two passkeys). To be confirmed (section 12).

### 4.4 Passkey enrolment (as a second factor)

WebAuthn with the relying-party ID of today (the host of `--base-url`): resident key *preferred* (not
required: the username is typed anyway), user verification as `auth.passkeys.user_verification` says
(`preferred` by default). The user handle is random per account. Up to 10 passkeys per account, each with a
name. Stored in the account store, not in Git.

### 4.5 Sign-in

1. `POST /auth/local/login {username, password}`. Per-address limit first (section 7). An unknown username
   still runs argon2id against a fixed dummy hash. A disabled, removed or not yet set-up account, or a locked
   one, is refused **without checking the password**, so a locked account cannot be used to test passwords.
2. Wrong password: the account's failure counter goes up (section 7) and `login_refused` (`bad_password`).
3. Right password: a pending sign-in (5 minutes, this browser) answers which factors the account has, with
   WebAuthn options listing only that account's passkeys.
4. `POST /auth/local/totp {code}` or `POST /auth/local/passkey/finish`. At most 5 tries per pending sign-in.
   A failure counts against the account like a wrong password, writes `login_refused`
   (`bad_second_factor`) and is kept as `last_second_factor_failure`, which *My account* shows: someone
   knew your password.
5. Success resets the counter, rehashes the password if the parameters went up, updates `last_login`, issues
   the session (section 5) and writes `login` with the factor.

### 4.6 Lockout

Five consecutive failures (password or second factor) lock the account for 1 minute; each further failure
after a lock doubles it (2, 4, 8, 16, 32 minutes), capped at 60 minutes. Attempts during a lock are refused
without being checked and do not extend it. A success resets everything. There is no permanent lock: that
would let anyone who knows a username lock its owner out for good. An admin can **Unlock**
(`account_unlocked`). The start of each lock writes `account_locked`. Lockout parameters are constants.

### 4.7 Admin reset

**Users → Reset** with a scope: `password`, `second_factor` or `all`. Re-authentication required. An admin
cannot reset their own account here (they use *My account*, or the CLI).

- At once: the credentials in scope are deleted (a lost phone may be in someone else's hands), `sid` is renewed
  so every session ends, any lock is lifted, and a reset token is issued like an invite (expiry
  `auth.local.reset_ttl`, default 24 h, 1 h to 7 days). Audit `account_reset_issued` with the scope.
- The person opens the link and goes through 4.2, doing only what the scope removed. Audit
  `account_setup_completed` (`code: reset`).
- Next time they are signed in, *My account* shows "*admin* reset your *second factor* on *date*" once.

### 4.8 Disabling an account

**Disable** (re-authentication required) sets `state: disabled` and renews `sid`. Effect at once:

- sessions end (every request checks the account);
- sign-in is refused (`login_refused`, `disabled`);
- the role of `local:<username>` evaluates to none while disabled, wherever roles are evaluated, so the
  account's API tokens and OAuth grants stop too.

**Enable** reverses it; old sessions stay ended. Refused: disabling yourself, or the last active admin.

### 4.9 Removing an account

**Remove** (re-authentication required) deletes the password, factors and pending tokens and leaves a
tombstone (`state: removed`, who and when). The username is never reused, so `local:alice` in old commits
and audit lines always means the same person. The console then offers to take `local:<username>` out of
`auth.roles` (a role-editor commit). Same refusals as *Disable*.

**Incident response** (the store and its key both leaked): `rackbook accounts rekey`, then
`rackbook accounts reset --all --scope all` (section 9); every person sets a new password and enrols new
factors.

### 4.10 Self-service (My account)

All need re-authentication: change the password (`password_changed`; renews `sid`, keeps the current
session), add or remove a factor (`factor_added`, `factor_removed`; removing the last one is refused), and
**Sign out everywhere** (`sessions_ended`; renews `sid` and issues a fresh cookie for this browser).

---

## 5. Sessions

The same cookie, codec and key as today; `method: local` is added to what the codec accepts. A local session
carries `sid` (the account's session id) and `aat` (when the person last gave password and second factor) and
the factor used. `auth.session.idle` and `absolute` apply (defaults 12 h and 7 days). On every request the
server checks, in memory, that the account exists, is `active` and has the same `sid`; otherwise the session is
rejected and the cookie cleared. Unlike OIDC sessions, a local session can therefore be revoked at once.

**Re-authentication.** Sensitive actions need `aat` within `auth.local.reauth_window` (default 10 minutes,
1 minute to 1 hour); otherwise `403 reauth_required` (the code `/infra` already uses), and the console asks
for the password and the second factor again (`POST /auth/local/reauth`, then the factor step), writes
`reauth`, and repeats the action. Sensitive:

- *My account*: password, factors, sign out everywhere;
- account administration: invite, revoke an invite, reset, unlock, disable, enable, remove;
- creating or revoking an API token;
- saving roles (**Users → Roles**);
- approving an MCP client in the built-in OAuth server (it mints a long-lived credential for the person).

Ordinary reads and edits do not ask again. SSO deployments are unchanged: their re-authentication is the
identity provider's business, and `/infra` keeps its own `--infra-write-max-age`.

---

## 6. Roles

A local account gets its role like everybody else: from `auth.roles` in `rackbook.yml`, by its identity
`local:<username>`. The account store holds no role. One source of truth, reviewable in Git, and phase 2a's
`role_changed` and `audit/identities.json` work unchanged.

```yaml
auth:
  roles:
    admin:  ["local:alice"]
    editor: ["local:bob", "local:carol"]
    viewer: ["local:*"]
```

- New entry kinds `local:<username>` and `local:*`. Local identities match those and `*`, nothing else:
  not `*@domain` (they have no e-mail), not `group:`, `app-role:`, `oidc:`, `mcphub:` or `oauth:`. Other
  identities never match `local:` entries. This mirrors how `oidc:<sub>` works today.
- `Authenticator.Evaluate` gives a `local:` identity no role unless its account is `active`. This one check
  covers sessions, API tokens (their creator) and OAuth grants.
- API tokens are unchanged. `internal/tokens` records the creator's method `local`, so a token's creator is
  evaluated as a local identity.
- Git commits are authored `Display Name <local:alice>`, as MCPHub usernames are today.

**With phase 2a's role editor** (**Users → Roles**):

- In local mode it offers the accounts by name for `local:` entries, and marks `group:`, `app-role:`,
  `*@domain` and `oidc:` entries as having no effect (they cannot match anybody here). The reverse holds under
  SSO for `local:` entries.
- An entry naming a username with no account is kept, with a warning: a commit made by hand may well add the
  role before the invite.
- The last-admin rule counts only entries that can sign in: in local mode, `local:` entries of `active`
  accounts (or `local:*` with at least one active account). It also refuses removing the editing admin's own
  entry, as designed.
- The invite dialog's role choice and the offer after *Remove* are role-editor commits like any other
  (`yamledit`, comments kept, diff preview).

Anyone with push access to the data repository can still edit `auth.roles` directly; that was always true and
is why the threat model treats push access as admin.

---

## 7. Rate limits

All keyed by `clientip.Of` (so `--trusted-proxy` decides whether `CF-Connecting-IP` is believed; IPv6 is
counted per /64), in bounded in-memory tables (10 000 entries, least recently seen forgotten first).

| What | Limit | Over the limit |
|---|---|---|
| `POST /auth/local/login`, `/auth/local/reauth` (password step), per address | burst 10, then 1 per minute | `429 rate_limited`, `Retry-After`; `login_refused` (`rate_limited`, no identity), at most one line per address per minute |
| second-factor step | 5 tries per pending sign-in; each failure counts against the account | the pending sign-in is dropped |
| `POST /auth/local/setup/open`, per address | burst 5, then 1 per minute | `429` |
| ceremony starts (passkey options, TOTP enrolment), per address | the existing limiter, 30 per minute, burst 10 | `429` |
| per account | lockout, section 4.6 | `423 locked` with `Retry-After` |
| argon2id | 2 at once, 2-second wait | `503` |

The per-address limit stops one source from trying many accounts (password spraying); the per-account
lockout stops many sources from trying one account. Neither alone is enough.

---

## 8. Audit events

All go to the existing audit log, in the chain, under the activity area `audit` (admins, later auditors).
`method` is `local` for the console and `cli` for the command line. `addr` comes from `clientip` and is
kept as `--audit-addr` says (`full` in this deployment). Passwords, codes, tokens, secrets and typed unknown
usernames are never recorded (people type passwords into the username field). One new field: **`target`**,
the account acted on when that is not the actor.

| Event | `identity` | Other fields |
|---|---|---|
| `login` | the account | `role`, `addr`, `detail: ["factor:totp"]` or `["factor:passkey"]` |
| `login_refused` | the account, empty if unknown | `addr`; `reason`: `unknown_account`, `bad_password`, `bad_second_factor`, `locked`, `disabled`, `not_set_up`, `no_role`, `rate_limited`, `invite_invalid`, `invite_expired`, `invite_claimed` |
| `logout` | the account | `role`, `addr` (as today) |
| `reauth` | the account | `addr`, `detail: ["factor:…"]`; a failure is `login_refused` with `code: reauth` |
| `account_locked` | the account | `addr`, `detail: ["until:<time>", "failures:<n>"]` |
| `account_unlocked` | the admin | `target` |
| `account_invited` | the admin | `target`, `detail: ["expires:<time>"]` |
| `account_invite_revoked` | the admin | `target` |
| `account_setup_completed` | the account | `addr`, `code`: `invite` or `reset`, `detail: ["factor:…"]` |
| `account_reset_issued` | the admin | `target`, `code`: `password`, `second_factor`, `all`; `detail: ["expires:<time>"]` |
| `password_changed` | the account | `addr` |
| `factor_added`, `factor_removed` | who did it | `target` when an admin; `code`: `totp` or `passkey`; `detail: ["name:<passkey name>"]` |
| `sessions_ended` | the account | `addr` (sign out everywhere) |
| `account_disabled`, `account_enabled`, `account_removed` | the admin | `target` |
| `account_store_problem` | none | `code`: `lost_change`, `rollback`, `key_mismatch`, `unreadable`, `discarded`; `detail` |
| `account_store_restored`, `account_store_rekeyed` | none, `method: cli` | `detail`: the seqs, or the old and new `kid` |
| `passkeys_removed` | the admin | `detail: ["count:<n>"]`; SSO deployments, section 10 |

The server log keeps its `login`, `logout` and refusal lines for local sign-ins as for OIDC, with the same
care about what is never logged.

---

## 9. Config, flags, CLI and MCP

**Selecting local mode is the deployment's choice:** `--auth local` or `RACKBOOK_AUTH=local`. It is not
accepted as `auth.mode` in `rackbook.yml` (people who can edit the ledger should not switch how everybody
signs in), and it needs a key from the environment anyway. With `--auth local` the server refuses to start,
and a pulled config is refused like any invalid one, when `rackbook.yml` has an `auth.oidc` block or an
`auth.mode` other than `local`: a deployment is either SSO or local. Local mode needs `--state-dir`,
`--base-url` (https), the session key and the account key.

| Flag / variable | Meaning |
|---|---|
| `--auth local` | local accounts; no OIDC, no Cloudflare Access |
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

argon2id, TOTP and lockout parameters are constants (sections 3, 4.3, 4.6).

**CLI** (`rackbook accounts`, for bootstrap and break-glass). Each needs `--state-dir` and the key and takes
the state dir's lock, so it runs while the server is stopped (`docker compose run --rm rackbook accounts …`).
Links are printed to the operator's terminal only. Each writes its audit event with `method: cli`.

| Command | What |
|---|---|
| `list` | usernames, state, factors, lock, last sign-in, and whether `rackbook.yml` gives them a role |
| `invite <username> [--name] [--ttl]` | the first admin, or anyone; warns when no role entry matches |
| `reset <username> --scope password\|second_factor\|all`, `reset --all --scope …` | break-glass, including for the last admin |
| `unlock`, `disable`, `enable <username>` | |
| `rekey --new-key-file` | section 3 |
| `accept-restore` | section 3 |
| `discard-store` | section 3, lost key |

**Bootstrap:** set `auth.roles.admin: ["local:alice"]` in `rackbook.yml`, run
`rackbook accounts invite alice`, start the server, open the link. A server in local mode with no accounts
logs a warning that says exactly this.

**MCP and API tokens:** no change. `/mcp` takes API tokens and OAuth access tokens as today; the built-in
OAuth server authorises with the local session (plus re-authentication). No MCP tool manages accounts, and
the account endpoints refuse tokens. `rackbook mcp` against a local clone is unaffected.

**`/infra`:** unavailable in local mode; it accepts pinned OIDC sessions only.

---

## 10. Passkeys when SSO is configured

**Decision:** with `auth.mode: oidc` there is no passkey sign-in. Sign-in is only through the identity
provider, which is where phishing-resistant sign-in belongs (Entra supports passkeys and FIDO2 keys
itself) and which sees a disabled account at once.

**Not a switch.** `auth.passkeys` in an OIDC deployment is accepted, ignored, and logged as a warning at start
("passkey sign-in is not available with SSO; remove auth.passkeys"), so existing `rackbook.yml` files keep
loading and CI stays green. No server flag brings it back. If a team ever needs it, it returns as a server flag
(default off; not a `rackbook.yml` key, because it bypasses the provider) together with the
`passkeys_oidc_max_age` rule from design-audit.md; until then that rule is not built.

**Migration of existing passkeys:**

- On upgrade, `/auth/passkey/*` and the passkey parts of *My account* are gone. An existing passkey session is
  rejected at its next request (the code already treats a passkey session without passkeys as revoked), and
  the person signs in through SSO. The release notes say so.
- `.rackbook/passkeys.yml` is **left untouched** by the upgrade: it holds only public keys, which are not
  secret, and nothing is committed automatically. It is no longer read for sign-in.
- **Users** shows admins "*n* passkeys from an earlier version are no longer used" with
  **Remove old passkeys**, which commits the file's deletion (`rackbook(auth): remove unused passkeys`,
  straight to the tracked branch as passkey commits are today) and writes `passkeys_removed`. Removing it by hand
  in Git works as well. History keeps the old file, which is harmless.
- People can delete the Rackbook entry from their password manager or security key; it does nothing now.
- The same applies to a deployment that moves from OIDC to local mode: the file is ignored, and local
  accounts enrol their passkeys again into the account store.

---

## 11. Console screens

Each ships with a demo in three languages before merge, as for the audit pieces.

- **Sign in** (local mode): username and password, then a second step: *Use a passkey* (shown first when the
  account has one) or a 6-digit code field. A locked account shows until when. No "forgot password" link,
  only "ask an administrator".
- **Set up your account** (invite and reset links): the username, a password field with the rules and the
  reason a password is refused, then *Add a passkey* (recommended) or *Use an authenticator app* (QR code,
  secret to type in, code to confirm). A link opened elsewhere, expired or used says so.
- **Re-authenticate**: a dialog over the current page, password then factor, then the action continues.
- **My account**: password; factors (passkeys with names and dates, the authenticator app) with add and remove;
  *Sign out everywhere*; last sign-in and from where; a warning when someone entered the password but failed
  the second factor; the one-time notice of an admin reset.
- **Users** (admin): one table: username, name, role (from `auth.roles`; "no role" with *Assign*), state
  (invited until, active, locked until, disabled, reset pending), factors, last sign-in. Actions: *Invite*,
  *Copy a new link* for a pending invite or reset, *Revoke invite*, *Reset…* (scope), *Unlock*, *Disable* /
  *Enable*, *Remove*. The link appears once, with a copy button and its expiry.
- **Users → Roles** (phase 2a): as section 6.
- Under SSO: the passkey parts of *Sign in* and *My account* disappear, and **Users** gets the notice of
  section 10.

---

## 12. Pieces (one PR each)

1. **Passkeys off under SSO** (section 10): ignore `auth.passkeys` in OIDC mode with a warning, drop the
   passkey endpoints and console parts, *Remove old passkeys* and `passkeys_removed`, README and release
   notes. Independent of the rest; it also removes `passkeys_oidc_max_age` from phase 2a's work.
2. **Account store**: the encrypted file, key loading, HKDF and `kid`, atomic writes, rollback detection,
   argon2id, the password rules and blocklist, TOTP, with tests. `rackbook accounts rekey`, `accept-restore`,
   `discard-store`, `list`. No HTTP.
3. **Local identity and roles**: `--auth local` and its refusals, `auth.local` config, `method: local` in the
   session codec with the `sid` check, `local:` role entries, `Evaluate` honouring the account state, token
   creator method, the `target` audit field.
4. **Sign-in and setup**: the `/auth/local/*` flows (invite and reset redemption, password, TOTP and passkey
   factors, lockout, rate limits), their audit events, `rackbook accounts invite | reset | unlock | disable |
   enable`, the *Sign in* and *Set up* screens. After this a team can bootstrap and sign in.
5. **My account and re-authentication**: `aat`, `reauth_required` on the sensitive actions, self-service, the
   notices.
6. **Users administration**: the account table and actions. The role choice in *Invite* and the offer after
   *Remove* need phase 2a's role editor; if that is not merged yet, this piece links to editing
   `rackbook.yml` instead and gains the picker later.

Piece 1 goes first and can ship on its own. Pieces 2 to 6 are in order.

---

## 13. Open questions

1. **Recovery codes:** proposed none (4.3); a lost factor is an admin reset, a lost admin factor another admin
   or the CLI. Confirm.
2. **Passkey alone for local accounts:** a passkey with user verification is already two factors. Should it
   sign someone in without the password (passwordless)? Proposed: not now; it would be an
   `auth.local.passwordless` option later.
3. **`second_factor` default:** proposed `any` (TOTP allowed). `passkey` is safer against phishing but every
   person then needs a device that supports passkeys.
4. **Two-person rule** for resetting an admin account (a second admin approves). Proposed: not now; the audit
   trail and the notice to the victim are the control.
5. **Usernames are never reused** (tombstones). Confirm, or allow reuse after an explicit admin action that
   is recorded.
6. **Lockout trade-off:** temporary locks capped at 60 minutes, no permanent lock, so a botnet can keep a known
   account locked but cannot lock it for good, and cannot test passwords while it is locked.
7. **Old passkeys:** proposed an admin button and no automatic commit. The alternative is a one-time
   commit deleting `.rackbook/passkeys.yml` on the first start after the upgrade.
