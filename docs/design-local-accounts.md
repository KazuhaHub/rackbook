# Local accounts beside SSO, and sign-in security settings

Status: design. Decided by the owner on 2026-11-22, reviewed six times, then restructured the same day to follow
the owner's own products, Passwall-Sub-Panel (PSP) and StockAnalysisPrediction-Report-Portal (RP). Pieces 2, 3 and 4 of
section 13 are built (the audit and state foundations, the local identity, and local sign-in and setup, all 2026-11-28); the rest is not. Builds on [design-audit.md](design-audit.md) (the audit log, phase 2a) and
[design-v0.2.md](design-v0.2.md) (the built-in login). Section 14 records the owner's last answers; nothing is
open.

What this adds:

1. **Local accounts** (username, password, mandatory second factor) **beside SSO**, not instead of it. As in PSP,
   RP, GitLab, Gitea, Grafana and Mattermost, a deployment can offer both. Two settings decide how: `login_mode`
   (what the sign-in page shows) and `sso_only` (what the local endpoint accepts).
2. **A "Sign-in & security" page** in the console, where admins set the login mode, the CAPTCHA, the throttle and
   lock, and SSO. Changes take effect without a restart.
3. **Passkeys and TOTP for local accounts only.** SSO identities get their second factor from the identity
   provider; Rackbook offers them neither a passkey sign-in nor TOTP.

The standing rules hold: no database (Git, plus files in `--state-dir`), Git history is never rewritten, secret
values never appear in Git, a diff, a log or the audit log, and the ledger never decides who may use `/infra`.

References to PSP and RP below are to the owner's clones and say where an idea comes from; Rackbook does not
depend on either.

---

## 1. What exists today

- **Modes.** `auth.mode` (or `--auth`, which wins) is `none`, `cloudflare-access` or `oidc`
  (`internal/config/login.go`). With `oidc`, Rackbook's built-in login signs people in through one OIDC provider.
- **Sessions** are stateless: the cookie `__Host-rackbook_session` is signed (not encrypted) with HMAC-SHA256 under
  `RACKBOOK_SESSION_KEY` (`seal` in `internal/login/session.go`), 12 h idle and 7 days absolute by default. The role
  is evaluated from `auth.roles` on every request.
- **Passkeys** exist in code as an alternative to OIDC sign-in, stored in `.rackbook/passkeys.yml`. They were never
  enabled in this deployment and no such file exists.
- **Pending logins** are kept in a 10 000-entry store that evicts the oldest entry when full
  (`internal/login/pending.go:64`), and RP keeps its image CAPTCHAs in authcore's bounded `MemoryStore`
  (`rp/internal/captcha/captcha.go:99,130`). Minting entries costs an attacker nothing, so neither design may hold
  state an attacker can push out (8.7).
- **Roles** are evaluated on three paths, all through `Policy().Evaluate` in `internal/auth/auth.go`:
  `Authenticator.Evaluate` (sessions), `Authenticator.RoleForVia` (an API token's creator, e.g.
  `internal/api/tokens.go:68`) and `Authenticator.EvaluateSubject` (OAuth grants in
  `internal/oauthserver/token.go:75`, OAuth access tokens and API tokens in `internal/mcpauth/mcpauth.go:233` and
  `:265`).
- **The audit log**: `audit.Log.Record(Event)` returns nothing; in its failed state later events are dropped.
- **The state dir** holds the audit log, token last-use, preferences, OAuth grants (`oauth-grants.json`) and keys.
- **Security headers**: one Content-Security-Policy for every path (`securityHeaders`, `internal/api/api.go:295`).
- **Rate limits.** `clientip.Of` names the client (IPv6 bucketed by /64). The audit log keeps the same /64 for an
  IPv6 client even with `--audit-addr full`.
- **CAPTCHA.** `github.com/KazuhaHub/authcore/captcha` (authcore is already a dependency) has a `TokenVerifier` for
  Turnstile, reCAPTCHA and hCaptcha and a digit-image `Generator` with a pluggable `Store`. Rackbook uses it as RP
  does (`rp/internal/captcha/captcha.go`), without splitting the package, because RP imports it whole.
- **`/infra`** accepts only OIDC sessions under the issuer, client, claim and tenant pinned by deployment flags
  (`internal/auth/infra.go`).

---

## 2. The model: local accounts and SSO together

### 2.1 Two settings, as in RP

RP separates what the sign-in **page** shows from what the sign-in **endpoint** accepts
(`rp/internal/app/login_mode.go:3-21`): a mode is a rendering hint, and anyone can POST to the endpoint whatever the
page drew. Rackbook adopts both axes.

| Setting | Values | Default | Effect |
|---|---|---|---|
| `auth.login.mode` | `dual`, `sso_first`, `sso_redirect`, `local_only` | `dual` | presentation: password form and SSO button together; SSO first with the password form behind a click; straight to the provider; password form only |
| `auth.login.sso_only` | `true`, `false` | `false` | enforcement: the local endpoint refuses accounts that are not admins |

Both **fail safe** (`rp/internal/app/login_mode.go:51-75`):

- When no SSO provider is **configured and enabled**, any mode degrades to `local_only`: there is nothing to
  redirect to, and an admin could not undo it from inside the product. "Configured and enabled" means the OIDC
  settings are complete, a usable client secret is present (9.3) and the provider is not switched off; it **never**
  means "healthy". A discovery failure, a timeout or an outage at the provider changes nothing here, so a passing
  problem at the IdP cannot open local sign-in to non-admins.
- `sso_only` is inert unless the page actually offers SSO (so it is inert under `local_only`, and without a
  configured and enabled provider). Refusing passwords only means something when there is a visible way in that is
  not a password.
- When local accounts are unavailable (section 11: no state dir or key), the page shows SSO only and the local
  endpoint is off.

**Admins are always exempt from `sso_only`.** That is the break-glass path when the identity provider breaks, in
place of a secret bypass URL. Who is an admin is decided by the role (`auth.roles`), not by a name. Turning
`sso_only` on is refused unless a **local admin exists** (`rp/internal/app/captcha_api.go:330`, `login_mode.go:94`):
an `active` local account whose `local:` identity holds the admin role and has a password and a second factor.
Otherwise an organisation whose admins all sign in through SSO would have no way in when the provider broke.

**The same guard at load time.** `rackbook.yml` can also change by a push, which skips the console. At every load the
server checks the guard itself: if `sso_only` is on but no `active` local admin with a second factor exists (none was
ever made, or the last one was disabled, removed or lost the admin role), `sso_only` is **treated as off**, admins see
a banner saying why, and the rest of the config loads normally. The config is not refused, because refusing it would
also block the unrelated changes in the same push. Every setting a pull changes writes `settings_changed` with
`because: config` and the commit, as phase 2a does for `role_changed`.

**One switch, not two.** PSP has a separate `disallow_user_local_login` that applies "regardless of LoginMode"
(`psp/internal/ports/repos.go:1240-1244`, enforced at `psp/internal/transport/http/handler/auth_local.go:381-386`).
It reads the flag alone (`auth_local.go:50-56`), so with no SSO offered it refuses every non-admin and leaves them no
way in. RP's `sso_only` covers the same need and degrades safely. Rackbook therefore folds PSP's switch into
`sso_only` and has no second one.

### 2.2 Second factors

- **Local accounts:** a second factor is **mandatory**, TOTP or passkey, both always available (owner decision 5).
  Local accounts keep the passkey as a second factor even when SSO is configured; the owner's rule "no passkey
  sign-in when SSO is configured" applies to SSO identities (confirmed, section 14).
- **SSO identities:** none from Rackbook. Their second factor is the identity provider's (as in PSP, where only
  local-password accounts are gated: `psp/internal/service/authpolicy/authpolicy.go:44-50`). Rackbook offers SSO
  identities neither a passkey sign-in nor TOTP.

PSP never gates when no second factor can be enrolled panel-wide (`authpolicy.go:55-60`), because a requirement that
cannot be met is a lockout. Rackbook has no setting that turns off both methods, and TOTP needs nothing outside the
server, so a factor can always be enrolled and the mandatory rule never becomes a lockout. That fail-safe is
therefore not needed. If passkey enrolment is ever made switchable, the switch stops **new** enrolments only;
existing passkeys keep working as factors, so no account falls back to the password alone (PSP's alternative,
`authpolicy.go:73-79`, lets a passkey-only account sign in with the password and then enrol TOTP, which is one
sign-in with a single factor; Rackbook avoids that).

### 2.3 What else follows from "both"

- **`--auth`.** The built-in login is `--auth login` (`oidc` stays accepted as an alias). It enables whichever of
  SSO and local accounts are configured. There is no `--auth local` and no "refuse to start with OIDC". The server
  refuses to start only if neither SSO nor local accounts are available.
- **`/infra`** stays OIDC-only and pinned by deployment flags (`--infra-oidc-issuer`, `--infra-oidc-client-id`,
  `--infra-oidc-tenant`, `--infra-oidc-identity-claim`, `--infra-admins`). None of it is a console setting, and
  editing SSO in the console cannot change who reaches `/infra` (9.4). Local accounts never reach `/infra`.
- **Outside OAuth issuers** (`auth.mcp.trusted_issuers`, including MCPHub). Like Grafana and Authentik, Rackbook
  trusts only issuers an admin has configured explicitly, in any mode. They are an admin setting on the SSO tab
  with the warning "every identity this issuer vouches for can reach the ledger with the role its entries give
  it". They are not refused when local accounts are on.
- **Role entries.** `local:<username>` entries and SSO entries (`*@domain`, `group:`, `app-role:`, `oidc:`) live
  side by side in `auth.roles` (section 7).

---

## 3. Threat model

| Threat | Defence | What is left |
|---|---|---|
| **Phishing** | SSO: the provider's business. Local accounts: a mandatory second factor; passkeys are origin-bound and offered first. | Password + TOTP of a local account can be relayed in real time. |
| **Online password guessing** | A throttle that is always on, an optional lock, an optional CAPTCHA, and the **NIST SP 800-63B §5.2.2 cap**, which admins can lower but not raise past 100 (section 8). Password and second factor are checked in **one step** with one undifferentiated answer (5.6). | Up to the cap per holder sign-in, at the throttle's pace, and with the CAPTCHA's cost when it is on. |
| **Lockout of a legitimate user** (NAT neighbours, botnets, targeted DoS) | Locks are off by default; the CAPTCHA replaces refusals where it is on; a verified passkey goes past the throttle and the locks; stateless attempts that cannot be evicted; reserved capacity for known networks (section 8). | Depends on the settings; 8.9 says exactly what, per setting, and the console's help text says it too. |
| **An admin (or a push) repoints SSO** to a provider they control | Changing the issuer, client or identity claim is a sensitive action, a commit, and an audited `settings_changed`; the stored client secret is bound to (issuer, client id) and never sent to another issuer, and an environment secret pins both; old SSO sessions end by the settings generation; `/infra` is pinned by the deployment and unaffected (9.3, 9.4). | An admin can already change `auth.roles`; repointing SSO gives them no new access and no longer leaks the secret. |
| **Someone with push access to the data repository** | Settings are in `rackbook.yml`, so push access is admin, as it already is for `auth.roles`. Hard bounds stay in code (the NIST cap ≤ 100, argon2id parameters, lock ≤ 1 week, throttle bounds), and secrets are not in Git. | By design. |
| **The identity provider fails or is compromised** | Local admins remain (break-glass, 2.1). A compromised provider can sign in anyone matching SSO entries, as today. | |
| **An offline copy of the state dir** | Accounts and secrets are encrypted, `usernames` is MACed, the admin channel is mutually authenticated and encrypted, all under the state key, which is not in the state dir (section 4, 11.3). A planted or torn file stops the server instead of rolling anything back (4.3). | A copy *with* the key gives argon2id hashes, TOTP secrets, session secrets and the stored provider secrets. Response in 5.10. |
| **Rolling back the store together with the end of the audit log** | The start compares the store with the log (4.3, 4.4), so an old store beside the current log is a gap. | **Not detected by the account store itself:** someone who can write the state directory can, without the key, put back an older copy of `accounts.enc` *and* cut the audit log back to the same point with `head.json` rewritten to match; the store and the log then agree. The daily anchor (`audit.anchor: daily`, [design-audit.md](design-audit.md) 3.1) catches the cut log once the anchored day is inside the cut, and so does any copy of the log kept outside the state directory (a log collector, `GET /api/activity?format=jsonl`). Run one of them (4.7). |
| **A stolen session cookie** | `Secure`, `HttpOnly`, `SameSite=Lax`, `__Host-`; fresh authentication for sensitive actions; three failed re-authentications end every session of a local account; *Sign out everywhere* and *Disable* end sessions at once. | Reading and ordinary edits until expiry or revocation. |
| **A forged local session** | MACed under a key derived from the session key **and** a per-account secret in the encrypted store (section 6). | Someone with both keys and the store holds everything already. |
| **An insider admin** | A reset replaces only what it names; only a separate, warned *full reset* hands over an account (5.8). Every reset revokes tokens and grants, ends sessions and is shown to the holder. All in the hash-chained audit log. | A full reset lets an admin act as the victim; the victim notices and the log tells the story. |
| **A leaked invite or reset link** | 256-bit, single-use, expiring, in the URL fragment; nothing happens until *Continue*; a 30-minute hold; a CAPTCHA on the link when enabled; a `password` or `second_factor` reset link alone is not enough. | Whoever presses *Continue* first wins on an invite. |
| **Account enumeration**, including which names are admins | Usernames are not secret. Refusals before the name is looked up take no hash and look the same for every name; after it, unknown and non-active accounts get the same answers and the same argon2id time; under `sso_only` every failure is `sso_required`, and only verified admins get through (5.6, 8.8). | The variance of one argon2id run. |
| **Resource exhaustion** | CAPTCHA before any hash; stateless attempt tokens; a solved set that only verified CAPTCHAs can fill, with partitions and no eviction; hashing slots with a reserved one; bounded siteverify concurrency; an image budget (8.7). | A botnet that solves CAPTCHAs can make sign-in from **new** networks slow (8.9). |
| **A weak CAPTCHA** | The console warns that the image CAPTCHA is solved by OCR and has no audio version, and recommends a token provider. | With the image CAPTCHA, the throttle and the NIST cap are the real bound. |
| **Flooding the audit log** (kept forever) | Refusals and CAPTCHA failures are aggregated per bucket per minute (section 10). | |

Out of scope: root on the running host (it holds the keys in memory), a compromised browser, and the data
repository's own access control.

---

## 4. Where things live, and why

| What | Where | Why |
|---|---|---|
| Non-secret settings (login mode, `sso_only`, CAPTCHA provider, trigger and site key, throttle, lock, the NIST cap, 2FA limits, OIDC issuer, client id, claims, label, tenants, trusted issuers) | `rackbook.yml`, `auth.*`, in the data repository | Versioned, reviewable and audited like `auth.roles`; edited in the console as ordinary commits (as phase 2a's role editor does); hot-reloaded on save and on pull |
| Provider secrets (CAPTCHA secret, OIDC client secret, the latter bound to its issuer and client id, 9.3) | `<state-dir>/secrets.enc`, encrypted under the state key | Secrets never go into Git |
| Local accounts | `<state-dir>/accounts/accounts.enc`, encrypted under the state key | The same |
| Usernames ever used | `<state-dir>/accounts/usernames`, MACed | Survives a lost key (4.5) |

### 4.1 The state key

32 random bytes: `RACKBOOK_STATE_KEY` (base64) or `--state-key-file`, separate from the session key, loaded by a
`LoadKey(name, env, file)` with its own messages ("local accounts and secrets set in the console need the state
key: set RACKBOOK_STATE_KEY (base64, 32 or more random bytes) or pass --state-key-file", "set only one of …", "…
decodes to N bytes, need at least 32", "the state key must differ from the session key"). Subkeys by HKDF-SHA256
with distinct `info`: `rackbook accounts v1`, `rackbook secrets v1`, `rackbook usernames v1`, `rackbook admin
channel v1`, `rackbook attempts v1`. Each encrypted file has a plaintext header `{"v": 1, "alg": "AES-256-GCM",
"kid": "<8 hex>"}` used as additional authenticated data, a fresh 96-bit nonce, and the ciphertext; everything else
is inside the AEAD. (Built with XChaCha20-Poly1305 and a 192-bit random nonce instead of AES-256-GCM and 96 bits, see
"As built, piece 2".)

- **Why separate from the session key:** rotating the session key logs everyone out; it must not destroy accounts.
- **Provisioning:** `openssl rand -base64 32`, kept with the deployment's other secrets (the infra repository's SOPS
  vault, or an `.env` outside the data volume), passed in the environment or as a read-only file from outside the
  state dir.
- **Without the key** (or without `--state-dir`), local accounts and console-set secrets are unavailable: the page
  is SSO only, and provider secrets come from the environment. The **Security** tab says so.
- **State dir mode:** with the key set, the server refuses to start unless the state dir is (or can be made) 0700.

### 4.2 The account store

Small (tens of accounts), decrypted once at start and kept in memory. Per account:

| Field | Notes |
|---|---|
| `username`, `name` | `local:<username>` is the identity |
| `state` | `invited`, `active`, `restricted` and `passkey_only` (sign-in restrictions, 8.4), `reset_pending`, `disabled`, `removed` (a tombstone) |
| `created`, `created_by` | |
| `password` | PHC string, `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>` |
| `totp` | secret (20 bytes), `last_step`, `added` |
| `passkeys` | up to 10: credential id, public key, user handle, name, added, backup-eligible flag, AAGUID |
| `sid`, `session_secret` | 128-bit session id and 256-bit secret, renewed together; renewing them ends every session |
| `consecutive_failures` | failed password checks since the last success, all networks (8.4) |
| `totp_failures`, `passkey_path_failures` | 8.4 |
| `reauth_failures` | failed re-authentications since the last success (5.7) |
| `locks` | active locks of scope `account` (8.3) |
| `good_buckets` | up to 10 address buckets with a successful sign-in in the last 30 days; cleared on every reset, on disable and on *sessions ended* |
| `pending` | an invite or reset: SHA-256 of the token, kind, scope, expires, issued by; the hold |
| `pending_revocations` | API token names and OAuth grant ids still to revoke (5.11) |
| `last_login`, `last_second_factor_failure` | time and address, shown on *My account* |
| `notices` | admin actions on the account not yet shown to the holder |

The store also holds its `change` id, `audit_seq`, `audit_month` and its own copy of all usernames (4.5).

**Passwords.** argon2id, m = 64 MiB, t = 3, p = 4, 16-byte salt, 32-byte tag (RFC 9106, second recommended
setting), in fixed hashing slots (8.7). Constants; stored in each hash, so raising them rehashes at the next
sign-in. **Password rules** (NIST SP 800-63B): at least 12 characters (12 to 64, a setting), at most 128;
NFKC-normalised; no composition rules, no expiry; refused if in the embedded list of the 100 000 most common
passwords, or if it contains the username or the host name.

### 4.3 Writing: one writer, audit first, and start

Every write of the account store, change or counter, goes through **one writer**: a single mutex held from building
the new state to the directory `fsync`. The in-memory state is replaced only after a write has landed, so a counter
write always encrypts the last *committed* state and can never persist an unaudited change. Every file is written
as `*.tmp`, `fsync`ed, renamed into place, and the directory `fsync`ed, so a named file is always complete.

- **Counters** (failure counts, locks, `good_buckets`, `last_login`, `last_second_factor_failure`) keep the store's
  current `change` and `audit_seq` and carry no `change:` id. A failed attempt's counters are written after its
  answer is sent, with the attempt's audit line appended by `RecordSync` (8.6).
- **Changes** are the events of section 10 that carry `change:`. Each:
  1. builds the new state with a fresh random `change` id and writes it to `accounts.enc.pending`;
  2. appends its audit event, carrying `detail: ["change:<id>"]` and the ids needed to re-apply it, with
     `RecordSync`; on error deletes `accounts.enc.pending`, changes nothing and answers `503 audit_unavailable`;
  3. puts the event's `audit_seq` and `audit_month` into the state, encrypts it **once** into `accounts.enc.next`,
     renames that over `accounts.enc`, deletes `accounts.enc.pending`, and only then answers and replaces the
     in-memory state.

**At start**, in this order (`E` is the last change event in the log, found from the store's `audit_seq` on):

1. Delete every `*.tmp` in `accounts/`.
2. Load `accounts.enc`. A wrong key or a file that does not decrypt: stop. Missing while the log has change
   events: stop (`code: missing`). Missing with no change events: create an empty store.
3. If the store's `audit_month` file is gone and retention does not explain it, or its `audit_seq` is past the end
   of the log: stop, "the audit log was rolled back or truncated" (`code: audit_truncated`; 4.4).
4. **`accounts.enc.next`**: if it decrypts **and** its `change` is `E`'s, rename it over `accounts.enc` and reload.
   Otherwise move it aside as evidence (`accounts.enc.next.evidence-<time>`).
5. **`accounts.enc.pending`**: if it decrypts, its `change` is exactly `E`'s and the store lacks `E`, finish step 3
   from it and reload (`account_store_problem`, `code: recovered`). If it decrypts, names `E`, and the store already
   has `E`, delete it silently (a crash between the rename and its deletion). If it decrypts and its `change` is in
   no event, delete it (never audited or answered). Anything else is moved aside as evidence.
6. **Gap check**, always, after any rename: if the store's `change` is not `E`'s, it lacks audited changes: a
   **gap**, stop (4.4). This includes a store lacking `E` beside a missing, torn or undecryptable `.pending`, which
   a crash cannot produce, so it is treated as tampering or a restore: a keyless attacker who plants garbage stops
   the server but cannot roll back a password change.
7. After a clean start, delete any remaining `.pending` and `.next`. Evidence files stay until `accept-restore` or
   an operator removes them; **Users** shows that they exist.

`secrets.enc` is written the same way, with its own `settings_secret_*` events (section 10).

### 4.4 Gaps and `accept-restore`

A gap is never accepted silently, and is not replayed (that would need secrets in the audit log). The server stops
with "the account store is older than the audit log" until the operator runs `rackbook accounts accept-restore`,
which:

- prints every change event after the store's `change`;
- **re-applies the restrictive ones**, which need no secret: `account_disabled`, `account_removed`,
  `sessions_ended`, `factor_removed`, `account_reset_issued`, `account_invite_revoked`, and every revocation listed
  (API token names, re-revoked in `.rackbook/tokens.yml` if still active; OAuth grant ids, revoked again in
  `oauth-grants.json`);
- puts every account named by any change event after the store's `change` into `reset_pending` with scope `all`;
- renews `sid` and `session_secret` of every account and clears every `good_buckets`;
- records `account_store_restored` with the seqs covered.

**The audit log rolled back or truncated** (start step 3): refused unless given `--accept-audit-truncation`, which
records `account_store_problem` (`code: audit_truncated`, `detail: ["store_seq:<n>", "log_end:<m>"]`), puts every
account into `reset_pending` with scope `all` and renews every session secret. **The store's month was pruned**
(possible only if the retention pin was bypassed, 4.6): refused unless given `--reset-all-accounts`, which does the
same.

### 4.5 Usernames are never reused

Three records, unioned at every start: `<state-dir>/accounts/usernames` (one per line, then
`mac:<HMAC-SHA256 under the usernames subkey>`; a bad MAC stops the server), the store's own list, and the `target`
of every `account_invited` event in the retained audit log. An older, validly MACed copy cannot bring a name back.
`discard-store` keeps the file and, because the old key is lost then, prints the list, asks the operator to confirm
and MACs it again under the new key; `rekey` re-MACs it.

### 4.6 Retention and the checkpoint

The start check needs the store's `audit_month` file. At the first write in a new month, and whenever retention
would be held back, the store is written as a change with a `RecordSync` event `account_store_checkpoint`.
`--audit-retention-months` never deletes the month of the store's `audit_month`; with the checkpoint that holds a
month back by at most about one month past the configured retention, and every delayed prune logs a warning.

### 4.7 Backup and restore

- Back up the state dir and, **separately**, the key.
- Restoring both from the same backup is consistent and is not detected. Cookies issued after the backup are refused,
  but older cookies work again: after any restore run `rackbook accounts end-sessions --all` and review **Users**.
- **What this does not catch.** If the state directory is rolled back together with the *end of the audit log*, `head.json`
  rewritten to match, the store and the log agree and the account store cannot tell: it only compares the two. That needs
  write access to the state directory (and the old files), but not the key. Two things catch it from outside: the daily audit
  anchor in Git (`audit.anchor: daily`), and any copy of the log kept elsewhere. Enable one when local accounts are on.
- Lost key: `rackbook accounts discard-store` moves the stores aside, re-MACs `usernames` and records
  `account_store_problem` (`code: discarded`); everyone is invited again under new usernames, and the provider
  secrets are entered again in the console.
- Key rotation: `rackbook accounts rekey --new-key-file`, recorded as `account_store_rekeyed`.

---

## 5. The flows

Endpoints are under `/auth/local/` (no session needed) and `/api/account`, `/api/admin/accounts` (a session needed;
API tokens and OAuth tokens are refused). Every account change and every local sign-in **fails closed** when the
audit log cannot be written (section 10).

### 5.1 Invite

1. An admin, re-authenticated (section 6), opens **Users → Invite**: username, display name, role (optional),
   validity.
2. `POST /api/admin/accounts {username, name, role}`. Usernames match `^[a-z][a-z0-9._-]{0,31}$` and must not have
   been used (4.5). The store gets an `invited` account with a pending invite (SHA-256 of a 32-byte random token,
   expiry `auth.local.invite_ttl`, default 72 h, 1 h to 14 days). Audit `account_invited`.
3. A chosen role is saved as `local:<username>` in `auth.roles` through the phase 2a role editor. If that commit
   fails, **Users** shows "no role" with *Assign*.
4. The link is shown once: `https://<host>/auth/local/setup#<token>`. Nothing is e-mailed; there is no
   self-registration and no "forgot password".

### 5.2 Opening a link (invite or reset)

1. On load the page reads the token from the fragment and removes it with `history.replaceState`. **Nothing is sent
   yet**; the page says what the link is for and shows *Continue* (and the CAPTCHA, when it is enabled for links).
2. *Continue* sends `POST /auth/local/setup/open {token, captcha}`. The server checks the CAPTCHA, the hash, the
   expiry and the account state, then **holds** the link for this browser for 30 minutes (a change;
   `account_link_opened`). Another browser during the hold gets `invite_claimed`.
3. Once held, the link dies at the hold's end unless setup is finished.
4. An invite continues with 5.3, a reset with 5.8.

### 5.3 First setup (invite)

A password (4.2), then a second factor: a passkey (5.5) or TOTP (5.4). One change sets both, makes the account
`active`, consumes the token and makes a new `sid` and `session_secret`. Audit `account_setup_completed` and
`login`.

### 5.4 TOTP enrolment

RFC 6238: HMAC-SHA1, 6 digits, 30-second period. A 160-bit secret; the `otpauth://` URI is drawn as a QR code by the
page itself, with the base32 secret for typing in; a current code confirms it. Verification accepts the current step
and one either side (±30 s) and refuses any step at or before `last_step`. One TOTP per account. No recovery codes
(owner decision 4): a lost factor is an admin reset.

### 5.5 Passkey enrolment

WebAuthn with the relying-party ID of `--base-url`, resident key required (so sign-in can use a discoverable
ceremony that reveals nothing about the account), user verification `preferred`, or `required` when passwordless
sign-in is on. Up to 10 passkeys per account. Only the holder adds factors.

### 5.6 Sign-in: one step, one answer

The password and the second factor are checked **in the same request**, and a failure never says which part was
wrong, so a guess never learns that the password alone was right.

1. When the CAPTCHA is enabled, the page first gets an **attempt** (`POST /auth/local/attempt`), a stateless token
   (8.7), which says whether a CAPTCHA is needed now. A passkey ceremony uses a discoverable challenge carried in the
   same token.
2. One request, `POST /auth/local/login`: the attempt token and CAPTCHA solve when needed, the username, the
   password, and **either** a 6-digit code **or** the passkey assertion.
3. **Before the name is looked up** (8.1): the flood ceiling; the CAPTCHA when needed (the server opens the attempt,
   checks that its nonce is unused, verifies the solve, and only then records the nonce, 8.7; an unsolved required
   CAPTCHA answers `401 captcha_required`); the throttle; the locks of scope `ip` and `ip_account`. These refusals
   do not depend on whether the account exists, so they answer **without hashing**, after a fixed delay of 250 ms,
   with "too many attempts, try later" (no time given), the same for every name. A verified passkey assertion
   (step 4) goes past the throttle and the locks.
4. With a passkey assertion it is verified next, before any hash: it must be valid and belong to the named account.
   Nobody can guess with it, which is why it goes past the throttle and the locks (8.2, 8.3).
5. **The name is looked up** (an in-memory read). A lock of scope `account` is checked now, from the store for an
   existing account and from the name table for any other name, with the same answer and fixed delay as step 3.
   Unknown, `invited`, `reset_pending`, `disabled` or `removed`, or an account whose `restricted` or `passkey_only`
   state refuses this attempt: a **dummy argon2id** while the dummy-hash budget allows, otherwise an equal wait
   (8.6), then the same answer as a wrong password. Here the timing would otherwise show the account's state.
   Otherwise the password, by argon2id, in a slot (8.7), and then the code.
6. **`sso_only`** (2.1), when active, is checked only **after** the password and the second factor verified. Until
   then every outcome, for unknown names, non-admins and admins alike, is the same `403 sso_required` ("use your
   organisation's sign-in"): a wrong password, an unknown name and a non-admin's correct credentials cannot be told
   apart. Only an admin whose credentials verified is let through. The cost of this order: under `sso_only` every
   local attempt costs one argon2id run (no cheap refusal for non-admins), bounded by the throttle, the dummy-hash
   budget and the CAPTCHA; an admin who mistypes sees "use your organisation's sign-in" rather than "wrong
   password"; and non-admins' attempts count as guesses toward their counters like any other.
7. Any other failure: `401 sign_in_failed`, "username, password or code is wrong", whatever failed. It adds to the
   counters of 8.2–8.5.
8. Success clears the counters, adds the bucket to `good_buckets`, rehashes the password if needed, issues the
   session (section 6) and writes `login`.

**Passwordless passkey sign-in** is an admin setting, off by default (owner decision 1); device-bound passkeys are
not required. When on, a user-verified passkey signs a local account in without the password.

### 5.7 Re-authentication

The same one-step form, in the reserved hashing slot, with one answer. `reauth_failures` is per account, in the
store; a success resets it, and **three failures end every session of the account** (`sessions_ended`, `reason:
reauth_failed`). A failure also counts toward `consecutive_failures`. SSO identities re-authenticate through the
provider.

### 5.8 Admin reset

**Users → Reset**, re-authentication required; not on yourself.

| Scope | Deleted at once | What the person must do with the link |
|---|---|---|
| `password` | the password | set a new password, then **pass an existing factor** |
| `second_factor` | TOTP and passkeys | **enter the current password**, then enrol a new factor |
| `all` (*Full reset*) | everything | set a password and enrol a factor: **in effect a new invite** |

*Full reset* is a separate button with the warning "This lets whoever opens the link take over the account. It is the
same as inviting a new person under this name." At issuance, every scope: `reset_pending` (no role), `sid` and
`session_secret` renewed, counters, locks and `good_buckets` cleared, tokens and grants revoked (5.11), and a link
like an invite (`auth.local.reset_ttl`, default 24 h). Completion is refused while revocations are pending. The
holder sees a notice of every reset, *Disable*/*Enable* and *Unlock* at their next sign-in.

### 5.9 Disabling and removing

**Disable**: `disabled`, `sid` and `session_secret` renewed, `good_buckets` cleared, tokens and grants revoked;
sessions end at once and `local:<username>` has no role on every path. **Enable** reverses the state, refused while
revocations are pending. **Remove**: the same, then credentials deleted and a tombstone left. Refused for both: on
yourself, or on the last active local admin while `sso_only` is on.

### 5.10 Incident response (the state dir and its key both leaked)

`rackbook accounts rekey`, `rackbook accounts reset --all --scope all`, and new provider secrets in the console.

### 5.11 Revoking tokens and grants

Disable, remove, every reset and `reset --all` revoke the account's API tokens (one commit to `.rackbook/tokens.yml`)
and its OAuth grants (`oauth-grants.json`). The event lists them (`detail: ["tokens:<names>", "grants:<ids>"]`,
never secrets). They are first written as `pending_revocations` in the same change, removed once applied, and a
failed commit is retried every minute and at start.

### 5.12 Self-service (My account)

Local accounts, with re-authentication: change the password, add or remove a factor (not the last), *Sign out
everywhere* (with "Also revoke my API tokens and app connections" ticked by default and the list shown). SSO
identities see their identity, role and sessions; their password and factors are the provider's.

---

## 6. Sessions

The same cookie and session key, with method `local` added. A local session carries `sid`, `aat` (when the person
last fully authenticated) and the factor. Its MAC key is

```
HKDF-SHA256(ikm = session key, salt = account.session_secret, info = "rackbook.session.local.v1" || sid)
```

The account must exist, be `active`, `restricted` or `passkey_only`, and have the same `sid`. `restricted` and
`passkey_only` limit **new sign-ins** only; live sessions, tokens and grants keep working. Only `disabled`,
`removed`, `reset_pending` and `invited` end sessions.

**SSO sessions carry a settings generation**: `ssog`, the first 16 hex digits of SHA-256 over the issuer, the client
id, the identity claim and the identity mode in force when the session was issued. `readSession` refuses an SSO
session whose `ssog` differs from the current settings, which replaces today's comparison of `Iss` alone. Changing
the client id or the identity claim therefore ends old SSO sessions too, not only changing the issuer.

**Re-authentication.** Sensitive actions need `aat` (local) or the last SSO sign-in within
`auth.local.reauth_window` (default 10 minutes, 1 minute to 1 hour), otherwise `403 reauth_required`. Sensitive:
password and factors; account administration; API tokens; saving roles; **saving any setting on the Sign-in &
security page**; approving an MCP client in the built-in OAuth server.

**Pages.** The sign-in, setup and re-authentication pages are separate documents under `/auth/`, loaded by a full
page load with a CSP of their own that allows the configured CAPTCHA provider's origin (for Turnstile,
`https://challenges.cloudflare.com` for `script-src` and `frame-src`) and nothing else beyond the console's.
`securityHeaders` gets a per-path policy for this. After sign-in the browser goes to the console with a full
navigation, so the console always loads fresh under its own CSP.

---

## 7. Roles

Roles come from `auth.roles` for everybody; the account store holds no role.

```yaml
auth:
  roles:
    admin:  ["local:alice", "group:<entra-admins>"]
    editor: ["local:bob", "*@example.com"]
    viewer: ["local:*"]
```

- `local:<username>` and `local:*` match only local identities; SSO entries never match them, and the reverse.
- **One check on every path.** A private helper `(*Authenticator).policyRole(s roles.Subject)` replaces the direct
  `Policy().Evaluate(s)` calls in `RoleForVia` and `EvaluateSubject` (and so in `Evaluate`). It gates on the
  identity: for any subject whose ID starts with `local:`, the role is none unless the method is `local` and
  `localAccountActive(s.ID)` says the account is `active`, `restricted` or `passkey_only`. That covers sessions,
  token creators (`internal/api/tokens.go:68`) and OAuth grants, access tokens and API tokens on `/mcp`
  (`internal/oauthserver/token.go:75`, `internal/mcpauth/mcpauth.go:233` and `:265`). A test walks all three with a
  disabled account and with a look-alike identity from another method.
- `internal/tokens` records the creator's method `local`.
- **The role editor** (phase 2a) offers local accounts by name and marks entries that cannot match anybody: `local:`
  entries while local accounts are unavailable, `group:`, `app-role:` and `oidc:` entries while no SSO is configured.
  The last-admin rule counts admins who can actually sign in. While `sso_only` is on, it also refuses to remove the
  last local admin (2.1).

---

## 8. Sign-in protection

Everything here is a setting on the **Security** tab, with the bounds in the table of 9.2, except where it says
constant. Buckets: `clientip.Bucket(r, trusted, 48)`, IPv6 by /48, IPv4 by the full address.

### 8.1 Order

A local sign-in passes, in order:

1. **Without looking up the name, without hashing** (a fixed 250 ms delay on refusal, the same for every name): the
   flood ceiling (constant: 600 requests a minute per bucket, then `429`); the CAPTCHA when needed (8.5); the
   throttle (8.2); the locks of scope `ip` and `ip_account` (8.3). A verified passkey assertion, verified at this
   point when given, goes past the throttle and the locks.
2. **The name is looked up**: the lock of scope `account` (same answer and delay as step 1), then the account's state
   and the restriction states (8.4), with a dummy argon2id, or past the budget an equal wait (8.6), wherever the
   answer would otherwise come faster for an account that cannot sign in.
3. The password and the second factor.
4. `sso_only`, only after step 3 succeeded (5.6).

### 8.2 The throttle (always on)

As RP's `login_fail_max` / `login_fail_window_min` (`rp/internal/app/limits.go:26-51,86-92`): at most `max` failed
sign-ins per bucket in `window`, default **10 per 15 minutes**, bounds 1–1000 and 1 minute–1 day.

- **CAPTCHA enabled:** reaching the limit makes the CAPTCHA required for that bucket instead of refusing. A shared
  office NAT gets a CAPTCHA, not a `429`.
- **CAPTCHA disabled:** reaching the limit refuses the bucket until the window ends. Help text: "Everyone behind the
  same address shares this limit. Turn on the CAPTCHA so that a shared network gets a CAPTCHA instead of a refusal."

### 8.3 The lock (optional, off by default)

As RP (`rp/internal/app/security_policy.go:28-52,368-421`): when on, reaching the throttle's `max` locks the scope's
key for `duration` (default **30 minutes**, 1 minute to **1 week**). The lock refuses even a correct password, except
after a verified passkey. Scopes, with the help text the console shows:

| Scope | Key | Help text |
|---|---|---|
| `ip` | the bucket | "Locks the whole network. Everyone behind a shared address (an office, a carrier) is locked out by one person's mistakes." |
| `ip_account` (default) | the bucket and the account | "Locks the account on that network only. Someone on the same network as the owner can still lock them out there." |
| `account` | the account | "Locks the account everywhere. **Anyone who knows the username can keep the owner locked out**, a denial of service. The owner can still sign in with a passkey; an admin can unlock." |

Locks are never permanent (the bound), a verified passkey goes past them, and *Unlock* clears them.

### 8.4 The NIST cap and the 2FA limits

**The NIST cap** (SP 800-63B §5.2.2, at most 100 consecutive failed attempts) is a setting `cap`, default and
**maximum 100**, minimum 10: admins may lower it, never raise it, and never so far that a few typing mistakes
restrict an account. `consecutive_failures` counts every failed password check of the
account across all buckets and is cleared only by a success or *Unlock*. A refusal that never reaches the password
check does not count.

- At `cap − 1` the account is `restricted`: a password check runs only from one of its `good_buckets` or after a
  verified passkey.
- The `cap`th failure, which can therefore only come from a good bucket or with the passkey, makes it
  `passkey_only`: a password check runs only after a verified passkey.

Each step writes `account_restricted` and tells the holder and admins. At most `cap` password guesses per holder
sign-in can be made without the passkey; this is a bounded denial of service, accepted as NIST intends.

**2FA limits** (admin-editable): `totp_failures` (a right password with a wrong code) at most **10 per 24 hours**
(bounds 3–20) stops TOTP for the account (`account_locked`, `code: totp`); a passkey still works; otherwise *Unlock*
and a `password` reset. `passkey_path_failures` (a wrong password after a verified passkey, which goes past the
throttle) at most **10 per hour** (bounds 3–20) refuses the passkey path until the hour passes; it bounds someone who
holds a synced passkey but not the password.

### 8.5 CAPTCHA settings

Matched to PSP (`psp/internal/ports/repos.go:1270-1295`) and RP (`rp/internal/app/captcha_api.go:24-104`):

- **Off until enabled.** Local accounts may run with it off; the throttle and the NIST cap always apply.
- **Providers:** `image` (the default when enabled: self-hosted, no external calls, works where outside services are
  blocked), `turnstile`, `recaptcha` (v2), `hcaptcha`. Switching needs no restart: settings are read per request.
- **Contexts:** sign-in, and opening invite and reset links. There is no self-registration and no forgot-password.
- **Trigger** for sign-in: `always`, or `after_failures` with a threshold (default **3**, 1–100) that fires when
  either the bucket **or** the typed name has that many failures in the throttle window
  (`rp/internal/app/captcha_api.go:99-103`). Links: always, when enabled. In addition, while the CAPTCHA is enabled
  it is always required when the replay set has no room (8.7).
- **Hostname pinned** to the host of `--base-url`; a successful result **with no hostname** is refused (authcore
  skips the pin then; reCAPTCHA needs domain verification on).
- **Errors fail closed**, as in RP (`captcha_api.go:120-138`): `ErrNetwork`, `ErrBadStatus`, `ErrDecodeResponse` and
  timeouts refuse that attempt with a retry. There is no fallback to another provider. At most 32 siteverify calls run
  at once; beyond that, `503 busy`.
- **Outage alert:** a probe (a siteverify call with a dummy token every 30 seconds, in its own slot) counts only its
  own network errors, timeouts and 5xx answers; 5 in a row over at least 2 minutes is an outage, shown to admins as a
  banner and written as `captcha_outage`. Nothing switches automatically: an admin can switch to `image` in the
  console, which takes effect at once.
- **The image CAPTCHA warning**, shown whenever it is selected: "Image CAPTCHAs are read by OCR software and have no
  audio version, so they slow automated guessing only a little and some people cannot solve them. Prefer Turnstile,
  hCaptcha or reCAPTCHA where outside services are allowed." It replaces the earlier deployment flag.
- **Turnstile `action` and `cdata`.** The sealed attempt token (8.7) is the primary binding of a solve to one
  attempt. As an extra check, the sign-in page renders the Turnstile widget with `action: "login"` (or `"link"`)
  and `cdata` set to the attempt's id (its nonce, hex), and the server, after siteverify, requires the returned
  `action` and `cdata` to equal what it expects, as Cloudflare recommends; a mismatch is `captcha_failed` (`reason:
  binding`). This relies on an additive authcore change, made separately, that exposes `Action` and `CData` on
  `Result` (one file per provider is fine). For reCAPTCHA v2 and hCaptcha, which return no `cdata`, the attempt
  token alone binds.
- `remoteIP` passed to `Verify` is the client address by the trusted-proxy rules, unbucketed (`clientip.Addr`).

### 8.6 Counters

| Counter | Kept | Window |
|---|---|---|
| failures per bucket | memory | the throttle window |
| failures per (name, bucket), for every typed name | memory, the **pair table**, keyed by (HMAC(per-start key, name), bucket) | consecutive, cleared on success |
| failures per name, all buckets | memory, the **name table**, keyed by HMAC(name) | the throttle window |
| locks of scope `ip` (by bucket) and `ip_account` (in the pair table) | memory, for every typed name | the lock duration |
| locks of scope `account` for **existing** accounts, `consecutive_failures`, `totp_failures`, `passkey_path_failures` | the store | 8.3, 8.4 |
| locks of scope `account` for names that do **not** exist | memory, the name table | the lock duration |
| dummy hashes | memory | 60 per minute for the server, 2 per minute per bucket |

CAPTCHA triggers read only the memory tables, which treat existing and unknown names alike, so whether a CAPTCHA
appears never says whether a name exists. Bounds: the pair table 100 000 rows, at most 1 000 per bucket; the name
table 50 000 rows, at most 200 new rows per bucket per hour. On overflow the rows with the fewest failures go first,
unlocked rows before locked ones, but **locked rows can be dropped too**, so made-up names locked for days cannot
fill the tables. A name or pair that cannot get a row is treated as over the CAPTCHA threshold and gets the
**throttle only, never a lock**, in both CAPTCHA modes. Existing accounts never depend on a row for an `account`
lock: theirs is in the store. A restart loses the memory locks, which only shortens them.

**Enumeration check.** A lock answer is the same for every name, and the `account`-lock check sits right after an
in-memory lookup, so its timing does not differ. What differs is only durability: an existing account's `account`
lock survives a restart and table pressure, a made-up name's lock may not. To use that, an attacker must lock both
names and then fill the name table (some 250 buckets for an hour at 200 new rows each) or wait for a restart, to
learn whether a username exists. Usernames are not secret here (they are in `auth.roles`), so this residual is
accepted.

**The dummy-hash budget.** Dummy argon2id runs (5.6 step 5) are limited to **60 a minute for the server and 2 a
minute per bucket**, in both CAPTCHA modes, so the buckets that spend the budget are the ones that run out of it.
Past either limit, an unknown or non-active name is answered after **sleeping** instead of hashing. The sleeper
joins the slot queue like a real check and, when its turn comes, releases the slot at once, so it waits the queue
time **of this moment**; then it sleeps a duration drawn from the **hash-only** sample (the time real argon2id runs
took inside their slot). Its total therefore has a real check's queue wait plus a real hash's median and jitter. It
never answers `busy`, and real accounts keep hashing in their slots.

**The hash-only sample** is a ring of 256 durations:

- **Seeded at start** by 16 calibration hashes run in the background on a fixed input, through the slots.
- **Before it holds 16 durations** (the first seconds after start), the budget does not switch to sleeping:
  unknown and non-active names run a real dummy hash, as within the budget. Sign-in is not delayed by the
  calibration.
- **Bounded per source:** one bucket, and one account, may hold at most 16 entries; a further duration from them
  replaces their own oldest entry, so no bucket or account can steer the distribution. Calibration entries are
  replaced as real ones arrive.

**Counter writes are off the response path.** A failed attempt's store updates (`consecutive_failures`,
`totp_failures`, `passkey_path_failures`, an `account` lock) are written **after the answer has been sent**, through
the single writer (4.3), with their audit line appended by `RecordSync`, so an existing account's failure takes
no longer to answer than an unknown name's. If that write or its audit append fails, the answer already sent stands;
the server enters the fail-closed state of section 10, and it is the **next** attempt that is refused with
`503 audit_unavailable`. Changes (4.3) still write before they answer; only these counters move. So nobody can exhaust the budget to block others: the cost of a made-up name past the budget is a sleeping
goroutine, bounded by the flood ceiling and the throttle, and the answer is the same as before the budget ran out.

Residual: the hash-only sample follows changes in CPU speed (thermal throttling, a noisy neighbour) only as fast as
real checks arrive; the queue part is always current. Test: exhaust the
budget (globally, and for one bucket) with unknown names, then check that an existing account with a wrong password
and an unknown name get byte-identical answers, and that their response times have the same distribution within the
variance of one argon2id run (a two-sample Kolmogorov–Smirnov test over 500 samples each, in both CAPTCHA modes).

### 8.7 Attempts, sets and capacity (when the CAPTCHA is enabled)

An attempt is a token, not server state:

```
attempt = base64(nonce(16) || bucket || issued || expires || flags || [image answer | passkey challenge]),
          sealed with AES-256-GCM under the attempts subkey
```

It expires after 5 minutes and binds its bucket. authcore's `ImageGenerator` is used as RP uses it, with a
Rackbook `Store` whose `Set` seals the answer into the attempt being minted and whose `Verify` checks the answer
carried in the request's attempt; so there is no image store to evict. Minting is free, so **nothing an attempt costs
the server is held before a CAPTCHA has verified**. Single use is enforced by two sets of nonces, each entry kept
until its token expires:

- **The replay set**, two partitions with per-bucket quotas: *free* (20 000, 20 per bucket) for uses with no CAPTCHA,
  and *image* (20 000, 10 per bucket) for the reservation made just before an image answer is checked, so a failed
  image is always recorded and one image yields one guess. When *free* has no room, the answer is `captcha_required`;
  when *image* has no room, the token is refused without checking and a new image is issued. Filling *free* only
  makes everyone solve a CAPTCHA; it never stops a CAPTCHA from being checked.
- **The solved set**, for attempts whose CAPTCHA verified, so every entry costs a solve: 300 000 entries, 30 per
  bucket, in partitions *good* (50 000; buckets in the named account's `good_buckets`), *headroom* (30 000; buckets
  holding fewer than 3 entries) and *general* (220 000). When the partition a spend needs is full, the spend is
  refused; nothing is evicted.

Image rendering has a budget of 50 per second and 10 per bucket per minute. **Hashing**: three argon2id slots
(192 MiB peak), one reserved for re-authentication and for attempts from a good bucket; a 5-second queue, then `503
busy`. The CAPTCHA and a passkey assertion are verified before a caller queues.

### 8.8 Uniform answers

Unknown, invited, reset-pending, disabled and removed accounts, and refusals by `restricted` or `passkey_only`, get
exactly the answers an existing account gets, after one argon2id run against a fixed dummy hash, or past the budget
a sleep with the same distribution (8.6). Refusals taken before the name is looked up (flood, CAPTCHA, throttle, `ip`
and `ip_account` locks), and the `account` lock right after it, take no hash, a fixed delay, and the same answer for
every name. Under `sso_only` every failure is `sso_required` (5.6). The residual is the
variance of one argon2id run.

### 8.9 What the holder of a local account can count on

For a holder who has their password and second factor, and whose password nobody else knows:

- **With a passkey**, in every configuration: they can sign in from any network. A verified passkey goes past the
  throttle and every lock scope, and the passkey path survives `restricted` and `passkey_only`. What can stop them:
  a flood above the flood ceiling from inside their own bucket, a CAPTCHA provider outage while a CAPTCHA is needed,
  the audit log failing.
- **With TOTP only**, it depends on the settings:

| Settings | From a known network | From a new network |
|---|---|---|
| CAPTCHA on, lock off (recommended) | always, one CAPTCHA per attempt at most | yes, unless the account is `restricted` (then a known network or Unlock), the provider is out, or someone keeps the *general* and *headroom* partitions full (about 250 000 verified solves every 5 minutes; with a token provider roughly $70 000–220 000 a day; with the **image** provider much cheaper, which is why the console warns) |
| CAPTCHA off, lock off | yes, unless someone on the same network exhausts the throttle (wait for the window) | unaffected by others apart from the bucket's own throttle; plus the NIST cap |
| lock `ip_account` | as above, plus: a neighbour on the same network can lock them there for the lock duration | unaffected by others |
| lock `ip` | a neighbour can lock the whole network | unaffected by others |
| lock `account` | **anyone who knows the username can lock them out everywhere** for the duration | the same |

In every case an admin *Unlock* clears the account's locks and counters at once.

---

## 9. The Sign-in & security page

### 9.1 Layout

An admin page with tabs, as PSP (`psp/web-react/src/views/admin/SettingsView.tsx:576-693`, Security; `:2421+`, SSO)
and RP (`rp/web/src/pages/manage/SecurityPage.tsx`, `SSOPage.tsx`):

- **Security**: login mode and `sso_only` (with the local-admin guard and its message); local accounts (available or
  not, and why; passwordless; password minimum length; invite, reset and re-authentication windows); CAPTCHA
  (enabled, provider, site key, secret, contexts, trigger and threshold, the image warning, the outage banner);
  throttle; lock (enabled, duration, scope with its help text); the NIST cap and the 2FA limits.
- **SSO**: the OIDC provider (9.3), its test sign-in, and trusted outside issuers (2.3). SAML is out of scope;
  Rackbook has no SAML support, and this page does not pretend otherwise.

Saving any tab is a sensitive action (re-authentication) and shows a diff of `rackbook.yml` before committing, as
the phase 2a role editor does.

### 9.2 Where each setting lives

Non-secret settings are `auth.*` keys in `rackbook.yml`, saved by the console as commits through `yamledit`
(comments and layout kept), applied at once after the commit, and on every pull. Code enforces the bounds, so a
hand edit outside them is refused like any invalid config.

```yaml
auth:
  login:
    mode: dual                 # dual | sso_first | sso_redirect | local_only
    sso_only: false
  local:
    passwordless: off          # off | synced | device_bound
    password_min_length: 12    # 12..64
    invite_ttl: 72h            # 1h..14d
    reset_ttl: 24h             # 1h..7d
    reauth_window: 10m         # 1m..1h
  captcha:
    enabled: false
    provider: image            # image | turnstile | recaptcha | hcaptcha
    site_key: ""
    login: true
    links: true
    trigger: after_failures    # always | after_failures
    threshold: 3               # 1..100
  throttle: {max: 10, window: 15m}            # 1..1000, 1m..24h
  lock: {enabled: false, duration: 30m, scope: ip_account}   # 1m..7d; ip | ip_account | account
  nist_cap: 100                # 10..100
  twofa_limits: {totp_per_day: 10, passkey_path_per_hour: 10}   # 3..20 each
  oidc: {issuer: …, client_id: …, scopes: […], identity_claim: …, name_claim: …, label: …, allowed_tenants: […]}
  mcp: {trusted_issuers: […]}
```

Constants, not settings: argon2id parameters, TOTP parameters, the flood ceiling, the set and table sizes, the
dummy-hash budget, the hashing slots, the image budget, the probe.

### 9.3 Secrets

The CAPTCHA secret and the OIDC client secret are stored in `secrets.enc` (4.1), never in Git and never returned:
the API answers `has_captcha_secret` / `has_oidc_client_secret`, and the console shows "configured — *Change*".

**Empty means keep.** A blank secret field on save keeps the stored value; removing it takes the explicit *Clear*
button, which sends `{"clear": ["captcha_secret"]}`. This is PSP's rule
(`psp/internal/transport/http/handler/admin_settings.go:223-226,690-696`). RP differs: an absent field keeps and an
explicit empty string clears (`rp/internal/app/sso_admin.go:96-113,178-189`). Rackbook uses PSP's rule everywhere,
because a form that sends every field cannot then clear a secret by accident.

- A token provider cannot be saved as enabled without a secret (stored or new), as PSP refuses it
  (`admin_settings.go:753-760`).
- **The environment wins.** If `RACKBOOK_CAPTCHA_SECRET` or `RACKBOOK_OIDC_CLIENT_SECRET` is set, it is used, and
  the console shows "set by the deployment" without *Change* or *Clear*.
- Without the state key, secrets can come only from the environment.

**The OIDC client secret is bound to its provider.** A client secret is a credential for one client at one issuer;
sent anywhere else, it is leaked. So:

- **Stored in the console:** `secrets.enc` keeps it together with the `(issuer, client_id)` it was entered for.
  Changing either in the console clears it, and the form cannot be saved until a new secret is entered in the same
  save. When `rackbook.yml` changes by a push and its issuer or client id no longer match the binding, the server
  **does not use** the stored secret (no token request is ever sent with it), treats SSO as not configured (2.1),
  shows admins a banner ("the SSO client secret belongs to another provider; enter it again"), and writes
  `settings_problem` (`code: oidc_secret_binding`).
- **From the environment:** `RACKBOOK_OIDC_CLIENT_SECRET` requires the pins `RACKBOOK_OIDC_ISSUER` and
  `RACKBOOK_OIDC_CLIENT_ID`. The server refuses to start if `rackbook.yml`'s issuer or client id differ from them;
  a pulled config that differs is refused like any invalid config (the last good one stays, and admins see a
  banner); and the console shows issuer and client id as "pinned by the deployment", not editable. This changes
  existing deployments that set only the secret: the release notes, and the start-up error, say which two values to
  add.
- **Rollout for this deployment.** Production sets only `RACKBOOK_OIDC_CLIENT_SECRET`, in
  `/etc/rackbook/rackbook.env`. The infra change that bumps the image to the version with this rule must, in the same
  change, add `RACKBOOK_OIDC_ISSUER` and `RACKBOOK_OIDC_CLIENT_ID` to that file, with the values of
  `rackbook_infra_oidc_issuer` and `rackbook_infra_oidc_client_id`; and the version assert in
  `roles/rackbook/tasks/main.yml` should fail early, before the restart, when they are missing. This is guidance for
  that infra change; this design does not edit the infra repository. The release notes say the same for other
  deployments.
- The CAPTCHA secret needs no such binding: a CAPTCHA secret sent to the wrong provider is refused there and
  grants nothing, and the provider is chosen from a fixed list of endpoints.

Setting or clearing a secret writes `settings_secret_set` or `settings_secret_cleared` (the name only).

### 9.4 Which OIDC fields the console edits, and the risk

**Editable** (in `rackbook.yml`, as today): issuer, client id, scopes, identity claim and mode, name claim, button
label, allowed tenants; the client secret (in `secrets.enc`). **Deployment only**: everything `/infra` pins
(`--infra-oidc-*`, `--infra-admins`) and `--base-url` (the redirect URI and relying-party ID).

The risk: an admin can point SSO at a provider they control and sign in as anyone an SSO entry in `auth.roles`
matches. As a way to gain access that is no new power, since an admin can already edit `auth.roles` (and anyone with
push access already can edit `auth.oidc`). What would be new is **leaking the client secret** to the other provider;
the binding above prevents that: the stored secret is cleared on any change of issuer or client id and never sent to
an issuer it was not entered for, and an environment secret pins both values. The console makes the change visible:
saving the issuer, client id or identity claim needs re-authentication, shows a warning ("everyone signed in through
SSO will be signed out; roles matched by SSO entries will follow the new provider"), commits, writes
`settings_changed` with `area: sso`, and ends every SSO session through the settings generation in the cookie
(section 6). `/infra` is unaffected: it compares sessions with its own pinned issuer, client, claim and
tenant, so a repointed provider's sessions never reach it. The **Test sign-in** button runs a sign-in against the
unsaved settings first, so a broken provider is caught before saving; local admins remain the way back.

---

## 10. Audit events

```go
// RecordSync appends e and fsyncs it. It returns the seq it got, or an error,
// including when the log is in its failed state. It never drops an event silently.
func (l *Log) RecordSync(e Event) (seq int64, err error)
```

Every account change, every secret change and every local `login` and `reauth` use `RecordSync` and **fail closed**
with `503 audit_unavailable` ("Sign-in is unavailable: the server cannot write its audit log. An administrator must
check the server"; the admin banner; account and settings actions disabled with that reason). `logout` and refusals
use `Record`. SSO sign-ins keep their existing events.

All events are in the chain, area `audit`. `method` is `local`, `oidc` or `cli` (with `detail:
["operator:<text>"]`). `addr` is kept as `--audit-addr` says (`full` in this deployment, which still keeps an IPv6
client as its /64). Passwords, codes, tokens, CAPTCHA answers, secrets and typed unknown usernames are never
recorded. New field **`target`**: the account acted on when that is not the actor. Every account change carries
`detail: ["change:<id>"]`.

| Event | `identity` | Other fields |
|---|---|---|
| `login` | the account | `role`, `addr`, `detail: ["factor:totp"]`, `["factor:passkey"]` or `["factor:passkey", "passwordless"]` |
| `login_refused` | the account, empty if unknown | `addr`; `reason`: `unknown_account`, `bad_credentials`, `sso_required`, `throttled`, `locked`, `restricted`, `totp_locked`, `passkey_path_limit`, `disabled`, `not_set_up`, `reset_pending`, `no_role`, `quota`, `busy` (hashing slots or siteverify full, never the dummy-hash budget), `invite_invalid`, `invite_expired`, `invite_claimed`; `code: reauth`; `code: summary` for an aggregate |
| `captcha_failed` | the account, empty if unknown | `addr`; `reason`: `wrong_answer`, `rejected`, `hostname_mismatch`, `hostname_missing`, `binding`, `expired`, `unavailable`; `detail`: provider error codes; `code: summary` |
| `captcha_outage` | none | `code`: `start` or `end` |
| `logout`, `reauth` | the account | `addr` |
| `account_restricted` | the account | `code`: `restricted` or `passkey_only`; `detail: ["failures:<n>"]` |
| `account_locked` | the account | `code`: `totp` or `account` (a lock of scope `account`); `detail` |
| `account_unlocked` | the admin | `target` |
| `account_invited`, `account_invite_revoked` | the admin | `target`, `detail: ["expires:<time>"]` |
| `account_link_opened` | the account | `addr`, `code`: `invite` or `reset` |
| `account_setup_completed` | the account | `addr`, `code`: `invite` or `reset`, `detail: ["factor:…", "scope:…"]` |
| `account_reset_issued` | the admin | `target`, `code`: `password`, `second_factor`, `all`; `detail: ["expires:<time>", "tokens:<names>", "grants:<ids>"]` |
| `password_changed`, `factor_added`, `factor_removed` | the account | `addr`; factors: `code`, `detail: ["name:…", "credential:<id>"]` |
| `sessions_ended` | the account, or the admin/CLI with `target` | `reason`: `self`, `reauth_failed`, `cli`; `detail: ["tokens:<names>", "grants:<ids>"]` |
| `account_disabled`, `account_enabled`, `account_removed` | the admin | `target`; disable and remove list revocations |
| `settings_changed` | the admin, or none with `because: config` for a change that arrived by a pull | `area`: `security`, `captcha`, `lockout`, `sso`, `trusted_issuers`; `detail`: the keys changed (names, and old → new for non-secret values); the commit is its own `commit` line |
| `settings_secret_set`, `settings_secret_cleared` | the admin | `detail: ["name:captcha_secret"]` or `oidc_client_secret`; a clear caused by an issuer or client id change says `because: binding` |
| `settings_problem` | none | `code`: `oidc_secret_binding`, `oidc_pin_mismatch`, `sso_only_without_local_admin`; shown as an admin banner until resolved |
| `account_store_checkpoint`, `account_store_problem`, `account_store_restored`, `account_store_rekeyed` | none | as in 4.3–4.7 |

**Aggregates.** Per bucket and minute, the first `login_refused` and the first `captcha_failed` for each account (and
for unknown accounts) are written in full; the rest are written once at the end of the minute as the same event with
`code: summary` and `detail: ["count:<n>", "reasons:…", "accounts:<n>", "captcha_required:<n>", "from:…", "to:…"]`.
Beyond 100 buckets in one minute the rest fold into one summary without `addr`.

---

## 11. Deployment, the CLI, and MCP

### 11.1 Flags

| Flag / variable | Meaning |
|---|---|
| `--auth login` (alias `oidc`) | the built-in login: SSO and/or local accounts |
| `--state-dir` | required for local accounts and console-set secrets |
| `RACKBOOK_STATE_KEY` / `--state-key-file` | the state key (4.1); without it, SSO only |
| `RACKBOOK_SESSION_KEY` / `--session-key-file`, `--base-url` | as today |
| `RACKBOOK_CAPTCHA_SECRET` | optional; overrides the console (9.3) |
| `RACKBOOK_OIDC_CLIENT_SECRET` with `RACKBOOK_OIDC_ISSUER` and `RACKBOOK_OIDC_CLIENT_ID` | optional; overrides the console and pins the issuer and client id (9.3) |
| `--infra-*` | as today; never console settings |

Everything else is in the console. There are no CAPTCHA flags and no `--captcha-image-weak-ok`; the console warning
replaces it.

### 11.2 Recovery CLI

PSP has `reset-admin-password` (`psp/cmd/reset-admin-password/main.go:1-20`, which rewrites the hash in the database
and wants the panel stopped) and RP has `report-portal adduser <username> <password> [admin]`
(`rp/cmd/report-portal/main.go:59-72`). Rackbook's equivalent is `rackbook accounts`, with two differences: it works
against the **running** server over an authenticated, encrypted channel, and it never takes a password on the command
line (where other users can read it in the process list); it prints a one-time link instead.

| Command | What |
|---|---|
| `recover <username> [--grant-admin]` | the lockout fallback: creates the local account if it does not exist (an invite) or issues a *full reset* if it does, and prints the link. `--grant-admin` (online only) also commits `local:<username>` to `auth.roles.admin`; offline it prints the line to add |
| `list` | usernames, state, factors, counters, locks, evidence files, pending revocations, role |
| `invite`, `reset --scope …`, `reset --all`, `unlock`, `disable`, `enable`, `end-sessions` | as in the console |
| `rekey`, `accept-restore`, `discard-store` | offline only (4.4, 4.7) |

Every command needs the state key, writes its audit event with `method: cli` and `operator:<text>` from `--operator`,
and prints links to the operator's terminal only.

### 11.3 The admin channel, the same on Linux, macOS and Windows

With the server running, commands go over a local channel: a Unix socket `<state-dir>/admin.sock` (mode 0600) on
Linux and macOS, and a named pipe `\\.\pipe\rackbook-<first 16 hex of SHA-256 of the state dir's absolute path>` on
Windows, created with `FILE_FLAG_FIRST_PIPE_INSTANCE` and a security descriptor that grants access only to the
server's account and Administrators. If a pipe of that name already exists, the server refuses to start ("another
process holds the admin pipe"), so nothing else can stand in for the server's end. The
OS permission is defence in depth; **access is by possession of the state key**, with the identical protocol on all
three:

1. The client sends a 32-byte nonce `Nc`.
2. The server answers a nonce `Ns` and `HMAC(k_channel, "server" || Nc || Ns)`, which the client checks before
   sending anything.
3. Both derive `k_session = HKDF-SHA256(k_channel, salt = Nc || Ns, info = "rackbook admin session v1")`; every
   request and answer is sealed with AES-256-GCM under it, with a counter in the nonce and the direction in the
   additional data; the first request that opens correctly proves the client holds the key.

A caller without the key, such as a sidecar under the same account relaying the connection, can neither read nor
forge anything, and links never cross the channel in clear. With the server stopped, commands take the state dir's
lock and work on the files directly; the behaviour and output are the same.

### 11.4 MCP and API tokens

Unchanged in how they work. A local account's tokens and grants follow its role and are revoked with it (5.11). No
MCP tool manages accounts or settings; those endpoints refuse tokens.

---

## 12. Console screens

Each ships with a demo in three languages before merge.

- **Sign in** (its own page, section 6), shaped by `login_mode`: *dual* shows the password form and *Sign in with
  <label>*; *sso_first* shows the SSO button with "Use a local account" behind a click; *sso_redirect* goes straight
  to the provider (with `?local=1` showing the form for admins, the break-glass path); *local_only* shows the form.
  The local form asks for username, password and the second factor together: a 6-digit code, or *Use a passkey
  instead*. The CAPTCHA appears in place when required (the image with *New image*, or the provider's widget), as RP's
  `CaptchaField` (`rp/web/src/components/CaptchaField.tsx`) and PSP's `LoginView.tsx` do. Messages: "Username,
  password or code is wrong", "Use your organisation's sign-in" (`sso_only`), "Too many attempts, try later", "Please
  confirm you are a person", "The CAPTCHA did not work, try again", "Try again shortly", "Sign-in is unavailable".
- **Set up your account** (invite and reset links): *Continue* first (with the CAPTCHA if enabled), then what the link
  calls for.
- **Re-authenticate**: a local account gets the one-step form; an SSO identity is sent through the provider.
- **My account**: for local accounts, password, factors, *Sign out everywhere*, last sign-in, warnings and notices; for
  SSO identities, identity, role and sessions.
- **Users** (admin): local accounts with state (invited, link held, active, restricted, passkey only, TOTP locked,
  locked, reset pending, disabled), factors, last sign-in, pending revocations, evidence files; the actions of section
  5; SSO identities seen, with their role.
- **Sign-in & security** (admin): section 9. Each control has its help text, including the lock scopes' warnings, the
  image CAPTCHA warning and the NAT note on the throttle.
- **Users → Roles** (phase 2a): section 7.

---

## 13. Pieces (one PR each)

1. **Passkey sign-in for SSO identities removed.** The OIDC-alternative passkey endpoints and `.rackbook/passkeys.yml`
   reading go; `auth.passkeys` with SSO is ignored with a warning. Passkey code is kept for local accounts.
2. **Audit and state foundations:** `RecordSync`; the retention pin and checkpoint; the state key, `LoadKey`, subkeys;
   the account store with its single writer and start sequence; `secrets.enc`; the three username records; argon2id
   with slots; password rules; TOTP. Offline `rackbook accounts rekey | accept-restore | discard-store | list`.
3. **Local identity and roles:** `--auth login`, method `local` in the codec with the per-account MAC key, `local:`
   entries, `policyRole` on all three paths, token creator method, the `target` audit field. **Built (2026-11-28): see
   "As built, piece 3".**
4. **Local sign-in and setup:** the separate pages with their CSP (`securityHeaders` per path); the one-step sign-in;
   `login_mode` and `sso_only` with the local-admin guard; the throttle, locks, NIST cap and 2FA limits;
   `clientip.Bucket` and `clientip.Addr`; the counter tables; aggregated events; the admin channel (socket and named
   pipe) and the online CLI including `recover`. **Built (2026-11-28): see "As built, piece 4".**
5. **CAPTCHA:** authcore's `TokenVerifier` and `ImageGenerator` as RP uses them, with the sealing `Store`; attempt
   tokens, the replay and solved sets, budgets, the hostname rule, concurrency, the outage probe. authcore/captcha
   brings `github.com/mojocn/base64Captcha` and its image libraries into `go.sum` for the first time; this PR reviews
   them.
6. **The Sign-in & security page:** the Security and SSO tabs, `yamledit` commits with diff preview, secrets with
   `has_*` and *Change*/*Clear*, the environment override, the OIDC test sign-in, `settings_changed`.
7. **My account, re-authentication and Users administration**, with revocation and `pending_revocations`.

Piece 1 can ship on its own. The others are in order; piece 6 needs phase 2a's `yamledit` commit path.

### As built, piece 2 (2026-11-28): audit and state foundations

**Built.** `audit.Log.RecordSync` (and `RecordSyncMonth`, which also returns the month of the file the line went into),
`EachEvent`, the `target` field of `Event`, and `Options.Pin`, the retention pin (`audit.RetentionPin`); `internal/statekey`
(`LoadKey`, the five subkeys, the encrypted file format with its header as AAD, the key id); `internal/accounts`: the account
store (one writer, audit first, the start sequence of 4.3, the gap rules of 4.4), `secrets.enc` with write-only secrets and
the OIDC binding, the three username records, argon2id with three slots (one reserved), the password rules, TOTP,
the checkpoint (4.6) and the offline commands `rackbook accounts list | rekey | accept-restore | discard-store`. Nothing is
reachable from HTTP: `rackbook serve` neither takes `--state-key-file` nor reads `RACKBOOK_STATE_KEY`. Not built here: sign-in,
sessions, the `local` method, pages, the CAPTCHA, the throttle, the counter tables, the dummy-hash budget and its sample (8.6),
and the online admin channel with `recover`, `invite`, `reset`, `unlock`, `disable`, `enable` and `end-sessions` (piece 4).

**Where it differs from, or fills in, the text above:**

- **`target`** (listed under piece 3) is added to `audit.Event` now: the start reads the `target` of every `account_invited` event
  (4.5) and accept-restore names accounts by it. It is the account as `local:<username>`; a bare username is accepted too.
- **Secrets have their own change ids.** `secrets.enc` runs the same sequence with its own marker, `detail: ["secrets_change:<id>"]`,
  so each document finds its own last change event. Its events are `settings_secret_set`, `settings_secret_cleared` (with
  `cause: binding` when a changed issuer or client id cleared the OIDC secret) and the shared `account_store_*` ones. Both documents
  pin the retention; the older month wins.
- **The pin exists before the log is open.** Retention runs when the audit log opens, so `accounts.NewPin` reads the audit month
  of both files first (it decrypts them) and is passed to `audit.Open`. A file that exists but cannot be read (a wrong or missing
  key) pins `0000-00`, which holds every month, so a start with the wrong key deletes nothing. A prune that the pin held back calls
  the checkpoint; before the stores are open it is remembered and written when they open. `Store.Counter` writes a checkpoint first
  at the first write in a month later than the store's.
- **Extra refusals in the writer** (4.5): a change may not delete an account, replace an account by another under the same name (each
  account has an immutable random `id`), or bring a `removed` tombstone back, and a new name that is in any username record is
  refused with `ErrUsernameUsed`. After a write fails once its audit event is recorded the writer refuses all further writes until a
  restart (`ErrStoreFailed`): continuing would build on a state that lacks the audited change.
- **Start, beyond the text.** The event at the store's `audit_seq` must be the store's own change event, otherwise the log was rolled
  back or edited (`audit_truncated`). `accounts.enc.next` that decrypts under the loaded key and names `E` is accepted even when
  `accounts.enc` itself does not (an interrupted `rekey`); `usernames.next` is promoted the same way. A missing store with no change
  event in the log is created empty, as written; with change events it stops (`missing`).
- **`rekey`** re-encrypts both documents and `usernames` in one audit event (`account_store_rekeyed`, with the key ids, never key
  material). The `.pending` files stay under the old key, the `.next` files are under the new one, so a crash is undone by the old key
  until the new files are complete and finished by the new key after that. `--generate` makes the new key file (mode 0600, never printed).
- **`accept-restore`** prints the plan and asks for confirmation (`--yes` skips it). Disabled and removed accounts keep their state (they
  cannot sign in), but lose their credentials like the others; an account that is reset has `pending: {kind: reset, scope: all}`
  with **no link issued yet**, which the online `recover` of piece 4 issues. OAuth grants listed by a gap event are revoked directly
  in `oauth-grants.json`; API token names cannot be (that is a commit to the data repository, piece 7), so they are written as
  `pending_revocations` and printed. For `secrets.enc`, the secrets named by `settings_secret_*` events after the backup are cleared
  (so a clear is never undone), and when the log cannot be trusted every secret is cleared; the operator enters them again. The
  evidence files are moved to `accounts/evidence-<time>/`, kept and out of the Users view. `--accept-audit-truncation` and
  `--reset-all-accounts` are flags of this command, and each only accepts its own case.
- **`discard-store`** acts only on a store that no key opens or that is missing; a store that opens, or a gap, is refused. The old files
  go to `accounts/discarded-<time>/` (kept), and the list of usernames is shown and confirmed before it is MACed again.
- **`list`** reads without recovering anything and without the lock, so it works while the server runs; it has no role column (roles
  come with piece 3) and prints no hash, secret or token. The offline commands refuse a key file inside `--state-dir`, and check
  the state key against the session key when `--session-key-file` or `RACKBOOK_SESSION_KEY` is given.
- **The common-password list is short.** The design asks for the 100 000 most common passwords; that list is not in the repository and
  was not downloaded. `internal/accounts/commonpasswords.txt` holds about 270 entries of 12 characters or more (shorter ones are
  refused for their length first), and a password that is one to four characters repeated is refused as well. The file is read
  with `go:embed`: replacing it with the full list changes nothing else. **This is open until the list is added, and it must be in place before piece 4 enables sign-in** (see "Review fixes").
- **"Contains the username or the host name"** applies to names of three characters or more: a one- or two-letter username
  would otherwise be found in nearly every password.
- **TOTP**: `Store.UseTOTP` verifies and records `last_step` in one counter write under the writer, so one code passes once, also across
  restarts. A wrong, malformed, replayed or unknown-account code all give `ErrBadCode`.
- **argon2id** runs in `Hasher` with three slots (two general, one reserved for `ClassPriority`) and a 5-second queue; the parameters
  are the constants of 4.2 and `NeedsRehash` compares a stored hash with them. The verifier refuses stored parameters beyond sane
  bounds. Nothing calls it yet.
- **Review fixes (2026-11-28).**
  - *Gap and untrusted-log recovery.* `accept-restore` re-applies the store-level events in a gap in order: an earlier
    `account_store_restored`, or an `account_store_problem` with `audit_truncated`, `month_pruned` or `discarded`, resets every account.
    When the log cannot be trusted (`audit_truncated`, `month_pruned`, or such an earlier event) it also re-applies every
    restrictive event that is still readable after the store's seq, resets every account, revokes every OAuth grant in
    `oauth-grants.json`, and writes the names of every API token as pending revocations of every account when `--repo` (a clone of the data repository) lets it
    list them (otherwise it says to revoke them by hand). Everything is printed. Resetting a disabled account clears its pending link.
  - *Change events* are recognised by their names (`accountChangeEvents`, `secretsChangeEvents`) and the document's marker; a
    `change:` detail on any other event counts for nothing, and the writer refuses an event name outside its set.
  - *Pending files.* An older audited `.pending` is set aside as evidence (4.3 step 5); only one that no retained event names is deleted.
  - *Temporary files* are created with `O_EXCL` and mode 0600 after the old one (a symlink included) is removed; start removes every
    `.tmp` of the accounts directory, `secrets.enc.*.tmp` and `oauth-grants.json.tmp`, links included.
  - *Counters.* `Store.Counter` may change only counter fields (4.2) and the restriction states they drive; anything else is `ErrNotCounterOnly`.
  - *Retention pin.* A store file that is missing while the log has its change events, or that cannot be read (no key, wrong key), pins the
    oldest month with a change event of that document. `rackbook serve` has no key yet and builds the pin that way before it opens the log, so
    `--audit-retention-months` never deletes a month from the oldest account-store change on while files exist; this is the choice made for the
    time before serve reads the key, and piece 3 or 4 replaces it with the exact month. The pin outranks the "unfinished delete" of `head.json`.
    A hold that happened before the stores opened is remembered for each store, and each writes its own checkpoint.
  - *Audit durability.* If the line is written and fsynced but closing the file or the fsync of the directory of a new month file fails, the line
    keeps its seq (the next append never reuses it) and `RecordSync` returns `ErrNotDurable`; the account writer then stops and leaves `.pending`
    for the next start to finish.
  - *Cipher.* XChaCha20-Poly1305 with a random 192-bit nonce replaces AES-256-GCM with 96 bits, because the store is rewritten at every counter and
    a random 96-bit nonce has a bound near 2^32 messages per key. Nothing was deployed, so no migration is needed. Keys are zeroed when a command ends.
  - *Passwords.* Stored hashes are refused as corrupt beyond one slot's memory (64 MiB), 6 passes and 8 lanes. The minimum length counts the smaller of
    the typed and the NFKC-folded length (U+FDFA is one character, not eighteen), the maximum the larger.
  - *Common-password list.* **The full list (at least 10 000 entries, the design says 100 000) must be in place before piece 4 enables sign-in.** A test,
    `TestFullCommonPasswordListIsInPlaceBeforeSignIn`, fails below 10 000 entries and is skipped until the constant `piece4SignInBuilt` is set.
  - *discard-store* shows the key id it tried and the one each file was encrypted under, and refuses unless `--key-is-lost` says that key is lost.
  - *rekey --generate* writes the key file through a temporary file, fsyncs it, links it into place and fsyncs the directory before anything is
    re-encrypted; a failure leaves nothing behind. A key file that is a symlink into the state directory is refused.
  - *wrong_key* messages say which key id each file needs.
  - *Second review.* For `secrets.enc`, `accept-restore` clears every secret when the log cannot be trusted, and also when the retained log holds,
    after the backup's seq, an `account_store_restored` or an `account_store_problem` (`audit_truncated`, `month_pruned`, `discarded`) whatever its
    marker, so an older `secrets.enc` put back later never brings back what an earlier reset cleared. `--repo` is an error, not a silent
    omission, when it is missing, is not a Git checkout or has no `.rackbook/tokens.yml`. A counter write may not lower `last_step`, and may
    not leave `restricted` or `passkey_only`, lower `consecutive_failures` or remove a running lock unless `last_login` advanced in the same write
    (an expired lock may be dropped); otherwise it needs the audited path. "Advanced" means the write carries a `login` event for that account
    (appended with `RecordSync` in the same write) and a `last_login` that moved forward and is not after the store's clock; the same
    proof is needed to lower `totp_failures`, `passkey_path_failures` (24 hours and 1 hour windows) and `reauth_failures`, or to move their windows,
    while a window is running. The plan names the event that made accept-restore clear every secret, and `--repo` prints the commit the clone is at
    with the reminder to pull first. If the audit line is written but `ErrNotDurable` comes back, the change may still complete at the next start.
- **New dependency:** none. `golang.org/x/crypto` (argon2) moved from indirect to direct in `go.mod`; `crypto/hkdf` is the standard
  library, and `golang.org/x/text` (`norm`, `cases`) was already a direct dependency.

### As built, piece 3 (2026-11-28): local identity and roles

**Built.**

- **`--auth login`** (alias `oidc`; `auth.ParseMode`, both are the one internal mode) with `--state-key-file` / `RACKBOOK_STATE_KEY`.
  `serve` reads the state key (`statekey.LoadKey`) before it opens anything, builds the retention pin with it (the exact month of each
  store, as 4.6 asks; with no key the pin stays conservative as in piece 2), opens the audit log, then opens the account store with the
  start sequence of 4.3. A refusal stops the server with the code, the message and the offline command that applies. Refused as well: a
  state key without `--state-dir`, a key file inside the state directory, a state key equal to the session key, and a state directory
  that holds `accounts/accounts.enc` or `secrets.enc` while no key is given (starting without it would leave the accounts unreadable and
  their `local:` roles silent). With no state key there are no local accounts; with no `auth.oidc` and no state key `serve` says neither
  is available and does not start. The login service starts without SSO (`sso` false: no provider, `/auth/oidc/*` is `404 sso_off`,
  `/auth/config` says `oidc: false`), and `RACKBOOK_OIDC_CLIENT_SECRET` is needed only when `auth.oidc` is configured. YAML `auth.mode`
  is unchanged (`none`, `cloudflare-access`, `oidc`); only the flag has the name `login`.
- **Method `local` in the codec.** `session` has `sid`, `aat` and `fac`; the cookie is signed with
  `HKDF-SHA256(ikm = session key, salt = account.session_secret, info = "rackbook.session.local.v1" || sid)` and its own MAC label. `open`
  looks at the claimed method of the unverified payload only to choose the key: a payload that says `local` is checked with its account's
  key alone and one that says anything else with the session key alone. The account must be live (`active`, `restricted`, `passkey_only`)
  and have the payload's `sid`, otherwise the cookie is refused and cleared. Without a store of local accounts no local session is valid.
  The store gives it `LiveSession(username)` (sid and a copy of the secret); `accounts.Account.Live` is the one definition of the live states.
- **No route issues a local session.** `Service.issue` refuses the method, the sealing path is reached only with the account's current
  `sid`, and the tests' helper (`internal/login/local_harness_test.go`) stands in for the sign-in of piece 4. `TestNoRouteIssuesALocalSession`
  walks every route of the API mux (`api.RoutePatterns`) with three kinds of body, as nobody, as an SSO administrator and as a local
  administrator, and fails if any answer sets a session cookie that opens as method `local`.
- **`local:` entries** (`internal/roles`): `local:<username>` and `local:*`; the username is validated by the rule of 5.1 (`roles.ValidLocalUsername`,
  held equal to `accounts.ValidUsername` by a test), folded like every entry. They match only method `local` (`*` and `*@domain` never
  reach a local identity, and no other method matches a `local:` entry). A file without a roles block gives a local account no role (the
  "everyone is an editor" default is not for it). An OIDC identity that starts with `local:` is refused at sign-in, as `oidc:` is.
- **`policyRole`** (`(*Authenticator).policyRole(p, s)`) is the one place `evaluate` computes role and auditor capability, so it covers
  `Evaluate`, `RoleForVia` / `CapabilitiesForVia`, `EvaluateSubject` (OAuth grants and access tokens on `/mcp`, API tokens) and
  `CapabilitiesUnder` (the role editor). For a subject whose ID starts with `local:`, or whose method is `local`, role and capability are
  none unless the ID is `local:<valid username>`, the method is `local` and `auth.LocalAccounts.LocalActive(username)` says the account is
  live. `auth.Config.Local` is the store (nil: no local identity has a role).
- **Token creator method.** `tokens.creatorMethod` records `local` (`created_via: local`), so the creator is evaluated as the local
  identity. The piece-2 behaviour (a local creator evaluated as method `none`) is gone. Tokens and grants stop and come back with the account's
  live state; their revocation at disable and reset (5.11, `pending_revocations`) is piece 7.
- **The role editor** (`rolesedit.Local`, `AnnotateLocal`, `Request.Local`; `api.Options.Local`): `GET /api/admin/roles` has
  `local: {available, accounts: [{username, name, state}]}`; notes `local_unavailable`, `local_no_account`, `local_inactive`; the last-admin
  rule counts the admin entries through which someone can sign in (7: "counts admins who can actually sign in"): a `local:` entry only while
  local accounts are available and the account (for `local:*`, some account) is not disabled or removed. A list that has no such admin already is
  not refused for an edit that leaves it so, only an edit that takes the last one away. Self-lockout needs no code of its own: the caller is
  evaluated by `CapabilitiesUnder`, which goes through `policyRole`. The part of 7 that refuses to remove the last local admin while `sso_only`
  is on belongs to piece 4 with `sso_only` itself.
- **`target`** (the field exists since piece 2) now reaches the Activity items and the JSONL export of audit rows.
- **Layering.** The HTTP-facing packages still do not import `internal/accounts` or `internal/statekey` (`TestNoHTTPPackageDependsOnTheAccountStore`
  stays, with its comment changed): they see the store through `login.LocalSessions`, `auth.LocalAccounts` and `api.LocalRoster`, and
  `cmd/rackbook` adapts it. `rolesedit` keeps its own two state names (a test holds them to `accounts`).

**Where it differs from the text above:**

- **"Rekey".** The per-account key has the session key as its input and the account's secret as its salt, as 6 says, so a rekey of the *state
  key* (`rackbook accounts rekey`) does not end sessions: the secrets are re-encrypted unchanged. What ends them is a renewal of the
  account's `sid` and `session_secret` (a reset, ending sessions, disable and remove as the writers do them), which is what the tests call a
  rekey of the account. A leaked state key alone, or a leaked session key alone, forges nothing; both together would.
- **Disabled, then enabled.** A disabled account has no live session whatever its `sid`, but an old cookie would come back on enabling if disable
  had not renewed `sid` and secret. Nothing online disables an account yet (`accept-restore` renews them when it re-applies a disable, and so
  must the online disable of piece 4, as 5.9 implies); a test holds the codec side: an old cookie stays dead after the account is renewed and enabled.
- **Last-admin** is refined as written above: 7 says "counts admins who can actually sign in" and does not say how an edit that does not touch the
  admins is treated.
- **No web change.** The console's TypeScript type of an Activity item does not name `target`, and the console words no note code for
  `local_no_account` and `local_inactive` (it falls back to the server's English message); both come with the Users screens (piece 7).
- **Not here.** Sign-in, `aat` and re-authentication (`403 reauth_required`), `sso_only` and `login_mode`, the throttle, the admin channel and the
  online `recover`, the revocation of tokens and grants at disable and reset (`pending_revocations`), `settings_problem` banners. `secrets.enc` is not
  opened by `serve` yet (the console-set secrets are piece 6); its presence without a key is refused like the account store's.

### As built, piece 4 (2026-11-28): local sign-in and setup

**Built.**

- **`internal/localauth`** is the one package that sees the account store and the state key on the HTTP side; it issues a
  session only through `login.Service.IssueLocal`, the one sanctioned path (`Service.issue` still refuses `local`).
  `login.Service` also has `LocalSession`, `RecentAuth(r, window)` (the check of 6) and `LocalRole`.
- **The pages and endpoints** under `/auth/local/`: `GET setup` and `GET reauth` (the console's pages), `POST attempt`, `login`,
  `setup/open`, `setup/totp`, `setup/passkey`, `setup/finish`, `reauth`; documented in docs/api.md. **`securityHeaders` has a
  policy per path:** every path under `/auth/` gets `api.AuthPageCSP` (no `'unsafe-eval'`, `form-action 'self'`, `frame-src
  'none'`, the CAPTCHA provider's origin added for scripts and frames when piece 5 passes it), the rest the console's.
- **The one-step sign-in (5.6)** in the order of 8.1: flood ceiling (600 a minute per /48 or IPv4 address, `429`); a passkey
  assertion verified before any hash; the throttle and the `ip` and `ip_account` locks (fixed 250 ms, no hash, the same for every
  name); the name lookup; the `account` lock (from the store for an account, from the name table otherwise); a dummy argon2id
  (or, past the budget, an equal wait) for every name that cannot sign in; the password in a slot (the reserved one from a known
  network); the code or the passkey; `sso_only` only after both verified; the audit line (`login`, `RecordSync`) before the
  session. The failure counters of an answered attempt are written after the answer (`Content-Length` known, `Flush`ed first); if
  that write fails the next attempt is the one refused with `503 audit_unavailable`.
- **`login_mode` and `sso_only` (2.1)** in `config.SignInSettings` (`PageMode`, `SSOOnlyConfigured`) and `localauth.Service.ssoOnly`
  (the local-admin guard). `GET /auth/config` carries `mode` and `local`; `sso_redirect` redirects `/auth/login` unless `?local=1`
  or `?error=`. The last active local administrator cannot be disabled or removed while `sso_only` is in force (the account
  change refuses with `last_local_admin`), and the role editor refuses an edit that takes the last local `admin` entry away
  (`422 last_local_admin`).
- **Counters (8.6):** the bucket table (throttle), the pair table and the name table, keyed by HMAC under a key made at start,
  bounded as 8.6 says (100 000 pair rows, 1 000 per bucket, 50 000 name rows, 200 new name rows per bucket and hour; the rows
  with the fewest failures go first, locked ones too), a name or pair without a row gets the throttle only; the store's
  `consecutive_failures`, `totp_failures`, `passkey_path_failures` and `account` locks. The dummy-hash budget (60 a minute, 2 per
  bucket), the hash-only sample (256 entries, at most 16 per bucket and per account, 16 calibration runs in the background at
  start, no sleeping before it holds 16) and the sleeper (queue wait of the moment, then a drawn duration). `clientip.Bucket` and
  `clientip.Addr`. Aggregated `login_refused` events (first per account per bucket and minute in full, a `summary` after, beyond
  100 buckets one summary without `addr`).
- **Links and setup (5.1 to 5.5, 5.8):** `accounts.Store.Invite`, `OpenLink` (the 30-minute hold bound to a browser by a cookie
  whose hash is in the account), `CompleteSetup` (password and a mandatory second factor in one change), `Reset` (the three
  scopes; at issuance the account is `reset_pending`, sessions are renewed, counters, locks and known networks are cleared),
  `Disable`, `Enable`, `Remove`, `EndSessions`, `Unlock`, `Recover`. TOTP enrolment seals the secret into a token; a passkey
  ceremony is sealed into its token (nothing minted by an unauthenticated caller is kept by the server).
- **Re-authentication (5.7):** `POST /auth/local/reauth`, in the reserved slot, one answer; three failures end the account's
  sessions (`sessions_ended`, `reason: reauth_failed`).
- **The admin channel (11.3):** the handshake and sealed frames of 11.3 on a Unix socket (mode 0600) and a Windows named pipe
  (`FILE_FLAG_FIRST_PIPE_INSTANCE`, a descriptor for the server's account and Administrators; it compiles and vets with
  `GOOS=windows`, it was not run on Windows). The online command line: `rackbook accounts invite | reset | unlock | disable |
  enable | remove | end-sessions | recover`, with the same code run on the files when no server answers. The online disable renews
  `sid` and the session secret, as piece 3 asked. `recover --grant-admin` commits the `local:<username>` admin entry through the
  role editor's write path.
- **The console:** the sign-in form and the modes on `/auth/login`, `LocalSetup` (one page for invite and reset links, by scope),
  `LocalReauth`, in zh-CN, zh-TW and en-US, laid out for 375 px, with a mock demo of each page and of the uniform failure answer
  (`web/dev/mock.ts`, `localAuthDemo`).

**Where it differs from the text above:**

- **Cipher of the sealed tokens:** XChaCha20-Poly1305 with a random 192-bit nonce, as in piece 2, instead of AES-256-GCM.
- **The replay set** is one set (20 000 entries, 20 per bucket, nothing evicted) for the sealed passkey ceremonies. The *free*,
  *image* and *solved* partitions of 8.7 belong to the CAPTCHA and are piece 5. **The CAPTCHA is off:** `localauth.Captcha` is the
  hook point (`Required`, `Verify`; nil), asked before the throttle when set; `auth.captcha` in `rackbook.yml` is read and
  reported as a warning, never acted on, and the throttle refuses a network until its window ends.
- **The pair table's failures are counted in the throttle window** (a row that sat idle for a window starts again) instead of
  strictly "consecutive, cleared on success"; a success still deletes the pair's row.
- **Local-admin guard at every sign-in, not at load.** 2.1 says the server checks the guard at every load of the config. It is
  computed from the store and the roles on each sign-in instead (so that disabling the last local administrator is felt at
  once), and `settings_problem` (`sso_only_without_local_admin`) is written when it first fails. The admin banner is piece 6.
- **Passwordless passkey sign-in** is not built: `auth.local.passwordless` other than `off` is refused as a config error.
- **Revoking API tokens and OAuth grants (5.11) is built here, pulled forward from piece 7** because sign-in exposes it, in two
  layers. Disable, remove, every reset scope and `recover` record `pending_revocations` in the same change (the marker `*` stands
  for "every token and grant the account owns when it is applied", beside the names and ids that could be listed, which the event
  shows). `localauth.ApplyRevocations` then resolves them and, in one audited change (`account_revocations_applied`), writes the
  **revocation list of the account store** (`State.Revoked`: a token by the SHA-256 of its secret, which a reused name cannot
  inherit, and a grant by its id) and clears the pending entries. The token registry (`Registry.Blocked`) and the OAuth server
  (`Options.Blocked`, in every read and in the refresh) consult that list on every use, so a listed token or grant is refused at
  once, whatever Git, a pull request or the grants file says. That is what "done" means; it does not depend on Git. The **record
  layer** follows: the token is also revoked in `.rackbook/tokens.yml` with a direct commit (`gitstore.Direct()`, as the passkeys of
  single sign-on are written: this is Rackbook's own state, and a pull request nobody merges would leave the record alive), and the
  grant is removed from its state file. A commit or a push that fails is retried at start and every minute
  (`RunRevocations`, `RecordRevoked`) and nothing waits for it: setup, enable and `recover` do not depend on Git. Only a revocation
  that cannot be resolved (tokens.yml unreadable) stays pending, and then enable and the completion of a setup are refused (`409
  revocations_pending`). The offline command line records them as pending and the server applies them at its start, before it
  serves.
- **The standing rule, `credentials_valid_after`.** The list is made from the checkout, so by itself it misses a token that is not in it
  yet: one waiting in a pull request (write mode `pr`), or a create waiting on the Git lock. So every disable, remove, reset (every
  scope) and `recover` also sets the account's `credentials_valid_after` in its own change, and an API token whose creator is
  `local:<x>` and whose creation time is before it, and an OAuth grant approved by `local:<x>` before it, are refused wherever the list
  is consulted (`Registry.Lookup`, the OAuth server's reads, refresh and code exchange). The token's creation time is the one Rackbook
  wrote into `tokens.yml` when it made it (changing `tokens.yml` is an administrator's act, as it already is), the grant's is the
  server's own record of the approval (`Grant.Approved`, the time the code was issued), so a grant whose code exchange raced with a disable
  is refused too, and no grant is made for it. The console lists a token the local accounts revoked as revoked (`Registry.Listed`)
  while its record in `tokens.yml` is still to be made.
- **Restore and discard.** The revocation list lives in the account store, so `accept-restore` brings back the list of the backup and
  loses what was added after it. The safe default is built in: `accept-restore` sets `credentials_valid_after` of **every** account to
  the restore time, so the API tokens and OAuth grants every local account made before it are refused until they are made again, and
  (in its untrusted mode, as before) writes every API token as a pending revocation of every account, which the server applies at its
  start. `discard-store` starts a store with no accounts, so every `local:` token and grant has no live account and no role, and a
  username is never reused: nothing can inherit them.
- **Re-authentication gates the sensitive actions that make a credential:** creating an API token, saving roles, and approving an
  OAuth/MCP client answer `403 reauth_required` (with `reauth`: the page and the way back) to a local session whose last full
  authentication is older than `auth.local.reauth_window`; the console opens that page and returns. `auth.Authenticator.NeedsReauth`
  and `RequireRecentAuth` are the check; only local accounts are asked (a person from single sign-on re-authenticates at the
  provider). The account administration screens and the settings page, which would be gated too, are piece 6 and 7. The counter rule of piece 2 gets one addition: a `reauth` event for
  the account may reset `reauth_failures` (and nothing else), because a re-authentication proves the password and the factor
  again without being a sign-in (`last_login` does not move).
- **Reserve before work (8.4, 8.6).** The throttle, the pair and name counters, and the account's own attempt counters are
  reserved before any hash or code check: `tables.Begin` checks and counts in one critical section and a success gives its place
  back (`Refund`); an account's reservations (`reservePassword`, `reserveTOTP`) read the stored count plus the attempts in flight
  under a lock of the account, add this attempt, and are released in the same critical section as the counter write that
  replaces them. The success write re-checks the state, the known network and the second-factor limits on the committed state.
  The counter writes remain after the answer, as 8.6 asks.
- **A failed counter write latches the sign-in:** every attempt, right or wrong, gets the same `503` before anything is
  verified, an event `sign_in_degraded` (`code: start`) is written, and a probe write on a 5-second backoff clears it (`end`).
- **The reset proof by passkey:** `VerifyAssertion` accepts an account in `reset_pending` for a password-scope reset proof only.
  The TOTP proof of a reset link counts against the account's own per-day limit (reserved before the code is checked); the
  per-link cap of ten wrong proofs stays as an extra.
- **Smaller changes:** the local-admin guard counts `restricted` and `passkey_only` administrators; a repeated open of a link keeps
  the first 30-minute hold; the flood ceiling is checked before any body is read; the passkey user handle has its own subkey
  (`rackbook passkey handle v1`); the admin socket is made in a private directory and moved to its name (no process-wide umask);
  a wrong password takes the account writer like a right one (`Store.ProbeTOTP`); under `sso_only` a non-admin's right credentials
  make the same synced audit write an administrator's sign-in does; `reauth_failures` is cleared when the sessions end and on a full
  sign-in; under `sso_only` every refusal waits for a time drawn around the running estimate of what an administrator's success
  spends writing before its answer (nothing is written for it, no lock is held while it sleeps, the waiters are bounded to 64 for the
  whole server and past that the answer is the `503 busy` of the hashing slots, and the refusals stay aggregated per network and minute); the current password that proves a second-factor reset is reserved against the account's
  persistent counter; a ticket of the tables gives back only into the window it was counted in; the offline `disable` and `remove` apply the last-administrator guard when `--config` names rackbook.yml; `remove`,
  `disable` and `reset --all` ask for confirmation (`--yes` skips it).
- **Administrators act through the command line only.** The `/api/admin/accounts` endpoints and the Users screens are piece 7;
  every command is `account_*` with `method: cli`. The holder's `notices` (reset, disable, enable, unlock) are recorded and not
  shown yet.
- **Offline command line.** Without a server there is no `rackbook.yml` to read: the link lifetimes are `--invite-ttl` and
  `--reset-ttl` (72 h and 24 h by default), the link is `--base-url` (else it starts at `/auth/local/setup`), and the `sso_only`
  guard and `--grant-admin` are online only.
- **No QR code is drawn.** The page shows the base32 secret with a copy button and an `otpauth://` link; no QR library is in
  the console's dependencies and none could be checked against a scanner here, and a wrong picture is worse than none (the code
  that confirms the factor would fail, so nothing wrong is ever stored).
- **Throttle on setup proofs.** The existing password or factor a reset link asks for is checked in the reserved slot and counts
  in the memory tables like a sign-in; ten failures kill the link (in memory, forgotten at a restart).
- **Tests of timing** run the Kolmogorov-Smirnov comparison with cheap argon2id parameters and 150 samples each (`accounts.NewHasherCost`
  is the seam; the server never calls it), with a critical value at alpha = 0.00001 because the machine is shared.
- **zh-TW** uses 通行密鑰 for a passkey, as the console already did.
- **`piece4SignInBuilt` stays false.** The full common-password list (at least 10 000 entries) is not in the repository yet
  (about 270 entries are), so the guard test of piece 2 is still skipped; the constant is to be set when the list is in.

---

## 14. Decisions on the last open points (2026-11-22)

The owner answered the remaining questions as proposed:

1. **Lock scope:** `ip_account` is the default (8.3).
2. **CAPTCHA default when enabled:** `image`, as in PSP and RP. For this deployment the owner chose Cloudflare
   Turnstile, a one-time console setting.
3. **`sso_redirect` and admins:** admins reach the local form at `/auth/login?local=1` (section 12).
4. **Passkeys for local accounts beside SSO:** allowed as a second factor. The rule "no passkey sign-in when SSO is
   configured" applies to SSO identities (2.2).
5. **Turnstile `cdata`:** to be exposed in authcore as additive fields on `Result`, in a separate change; Rackbook
   then validates `action` and `cdata` server-side as an extra check, with the sealed attempt token as the primary
   binding (8.5).

Nothing is open.
