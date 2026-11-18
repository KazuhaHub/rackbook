# Expiry tracking and modules (decision 17)

Rackbook tracks when things expire: certificates, client secrets, API tokens,
domains, support contracts. Records are entered by hand, as always, or kept
up to date by **modules**: small programs that run next to Rackbook, read
another system and write what they find into one collection.

The Rackbook server stays small and generic. It knows which field holds an
expiry date and can list what is about to expire. It contains no code for any
upstream system and sends no mail. That lives in modules.

This release ships two modules in the same release archives and image:

| module | does |
|---|---|
| `rackbook-entra` | reads application secrets and certificates from Microsoft Entra ID into a collection |
| `rackbook-notify` | sends reminders at 30, 14 and 7 days and on the day of expiry, by e-mail and/or webhook, for every collection |

## 1. Expiry in the core

### 1.1 Schema marks

A collection opts in through annotations on its JSON Schema properties
(top-level properties only):

```json
"expires": {"type": ["string", "null"], "title": "到期",
            "pattern": "^(\\d{4}-\\d{2}-\\d{2}|待补)$",
            "x-rackbook": {"expires": true}},
"revoked": {"type": ["string", "null"], "title": "已吊销",
            "pattern": "^\\d{4}-\\d{2}-\\d{2}$",
            "x-rackbook": {"revoked": true}},
"source":  {"type": ["string", "null"], "title": "来源"}
```

- **`x-rackbook: {expires: true}`** marks the expiry date. A value of
  `YYYY-MM-DD` or an RFC 3339 time (read as a UTC date) is a date. An empty,
  null or missing value means the record never expires. Any other value (for
  example `待补`, "to be filled in") means the date is unknown; such records
  are listed separately so they get filled in.
- **`x-rackbook: {revoked: true}`** marks a field that retires a record. Any
  non-empty value (a date, `true`) takes the record out of the expiry list. It
  is optional; without it no record is retired.
- **`source`** (a plain field, by convention) names the module that maintains
  the record. Empty, missing or `manual` means the record was entered by hand.

One collection has at most one `expires` and one `revoked` field. A collection
without an `expires` mark is never listed. Nothing else changes for existing
ledgers: the marks are additive and v0.2 configs and schemas stay valid.

### 1.2 What is listed

For a window of N days (default 30, at most 3650), relative to today's date in
UTC:

| status | when |
|---|---|
| `expired` | the date is before today |
| `expiring` | the date is today or within N days |
| `unknown` | the value is not a date (`待补`); only with `unknown=true` |

Revoked records and records without a date are never listed. Items are sorted
by `daysLeft` (most overdue first); unknown items come last.

### 1.3 API

`GET /api/expiring?days=30[&collection=<name>…][&unknown=true]`
needs read access (any role, a `read` token).

```json
{
  "today": "2026-11-18",
  "days": 30,
  "items": [
    {"collection": "credentials", "id": "tls-www", "label": "tls-www",
     "expires": "2026-11-10", "daysLeft": -8, "status": "expired", "source": ""},
    {"collection": "credentials", "id": "entra-rackbook-1a2b3c4d", "label": "entra-rackbook-1a2b3c4d",
     "expires": "2026-12-01", "daysLeft": 13, "status": "expiring", "source": "entra"}
  ]
}
```

`/api/meta` gains, per collection, `expiryField` and `revokedField` (the marked
fields, or empty), and a top-level `modules` list (section 2.3, without token
names).

### 1.4 MCP

A new tool family `expiry` (scope `rackbook:read`, see
[mcp-surface.md](mcp-surface.md)):

- `expiry_list(days?, collections?, include_unknown?, cursor?, limit?)`
  returns `{today, days, items, next_cursor}` with the same items as the API.
  `limit` defaults to 50, at most 500. Annotations: `readOnlyHint: true`,
  `openWorldHint: false`. It declares an `outputSchema` and returns
  `structuredContent`.

### 1.5 Console

- **到期** in the navigation: expired, expiring within 30 / 60 / 90 / 365
  days, and (in its own section) unknown dates, each linking to the record.
- The dashboard shows how many records are expired or expiring within 30 days.
- A record shows its source (手动 or the module name). Editing a record that a
  module maintains shows which fields the module owns and that changes to
  them are overwritten on the next sync.

## 2. Module contract

### 2.1 What a module is

- A **separate executable**. The `rackbook` binary never imports module code,
  and modules never import Rackbook's internal packages; a test enforces both.
- It talks to Rackbook **only through the public HTTP API**
  (`/api/meta`, `/api/c/<collection>`, `/api/expiring`) with a Rackbook API
  token (`Authorization: Bearer rbk_…`). It never touches Git or the data
  repository, so every write goes through the same validation, secret scan,
  history and never-force rules as a person's.
- Its own credentials (for the upstream system, for SMTP) come from files,
  normally systemd credentials in `$CREDENTIALS_DIRECTORY`, never from the
  command line or the config file.

### 2.2 Writing rules

A module that writes keeps to these rules; for modules listed in `modules:`
(2.3) the server enforces the ones marked **(enforced)**.

1. **Tag every record** with `source: <module name>`. **(enforced)**
2. **Upsert idempotently.** Each run reads the collection, matches its own
   records by a stable upstream id (Entra: the key id in `kid`), creates what
   is new, updates only what changed (with the record hash, so a concurrent
   edit is a conflict, never an overwrite) and does nothing when nothing
   changed. Two runs in a row write nothing the second time.
3. **Never overwrite or delete manual records.** A module only updates records
   whose `source` is its own name. **(enforced)** If a manual record already
   covers an upstream item, the module leaves that item alone (Entra: a manual
   record with the same `kid`, or naming the same app in `ids` with the same
   expiry date).
4. **Never delete.** An upstream item that has gone is marked revoked: the
   field marked `revoked` is set to today's date. **(enforced: modules cannot
   delete)**
5. **Change only its own fields** after creating a record. Fields it fills
   only on create (owner, location, notes) belong to people from then on.
   **(enforced: on update, every field not in `fields` must stay as it is)**
6. `--dry-run` shows the planned changes and writes nothing; `--once` runs one
   sync and exits (for a systemd timer); without `--once` it repeats every
   `interval`.

### 2.3 The allow list: `modules:` in rackbook.yml

```yaml
modules:
  entra:                       # the module's name = the source value it writes
    token: entra-sync          # the Rackbook API token it uses
    collection: credentials    # the one collection it may write
    fields: [kind, self_signed, purpose, expires, not_before, kid, ids, revoked]
    direct_push: true          # create/update go straight to the branch, no daily PR
```

- A write made with a listed token is a module write. It may only create or
  update records in `collection`, every record it writes must carry
  `source: <name>`, an update must target a record that already carries that
  source, and an update may change only `fields` (plus `source`). Deletes are
  refused.
- **`direct_push: true`** lets the module's creates and updates skip the pull
  request that token writes get by default (decision 5), so a nightly sync does
  not open a PR a day. Without it, merge the module's PR before its next run:
  the module reads the tracked branch, so it proposes the same change again
  until the PR is merged. As for a token's `write_mode: push`, it counts only
  while the token's creator is an admin. Without it, every module write is a
  PR. Deletes would always be PRs, but modules cannot delete at all.
- The token itself is created on the 令牌 page as usual: scope `write`,
  collections `[credentials]`, actions `[create, update]`. A token listed here
  is still bounded by its creator's role (decision 5).
- Module names are 1–32 characters of `a-z 0-9 . _ -` and not `manual`. Each
  token and each name appears once.
- Commits by a module carry the trailer `Source: <name>` next to the usual
  `Edited-via: rackbook (token:<token>)`.

`rackbook-notify` only reads, so it needs a `read` token and no entry here.

## 3. `rackbook-entra`

Reads `applications` and `servicePrincipals` from Microsoft Graph
(`passwordCredentials` and `keyCredentials`, following `@odata.nextLink`)
and keeps one record per credential.

### 3.1 Entra setup (done once, by an administrator)

1. Register an application, for example "Rackbook Entra sync", single tenant.
2. API permissions: Microsoft Graph, **application** permission
   `Application.Read.All`, then **Grant admin consent**. Nothing else.
3. Certificate credential (no client secret):
   - RSA, 2048 bits or more;
   - upload the certificate (`.cer`/`.pem`, public part only) under
     Certificates & secrets;
   - the module reads one PEM file holding the private key (PKCS#8 or PKCS#1)
     and the certificate. The certificate is needed for its thumbprint, which
     goes into the token request (`x5t`, `x5t#S256`).

   ```sh
   openssl req -x509 -newkey rsa:3072 -sha256 -days 730 -nodes \
     -subj "/CN=rackbook-entra" -keyout entra.key -out entra.crt
   cat entra.key entra.crt > entra.pem && chmod 600 entra.pem   # for the module
   # upload entra.crt to the app registration; keep entra.pem off Git
   ```
4. Note the tenant id and the application (client) id for the config.

The module signs a short-lived client assertion (RS256, 5 minutes) with the
key and exchanges it for a Graph token; nothing long-lived is sent anywhere.

### 3.2 Config (`/etc/rackbook/entra.yml`)

```yaml
rackbook:
  url: https://rackbook.example.org
  token_file: rackbook-token        # file name in $CREDENTIALS_DIRECTORY (or an absolute path)
  collection: credentials
  source: entra                     # must match the name under modules: in rackbook.yml
entra:
  tenant_id: 00000000-0000-0000-0000-000000000000
  client_id: 00000000-0000-0000-0000-000000000000
  certificate_file: entra.pem       # private key + certificate, in $CREDENTIALS_DIRECTORY
  service_principals: true          # also read service principals (default true)
  exclude_app_ids: []               # application (client) ids or service principal object ids
interval: 24h                       # without --once
record:
  name_prefix: entra-               # record name: <prefix><app slug>-<first 8 of the key id>
  purpose: 'Entra application "{app}": {type} "{name}"'
  type_labels: {password: client secret, certificate: certificate}
  password: {kind: api_token}       # extra fields for client secrets (module-owned)
  certificate: {kind: client_cert, self_signed: true}
  defaults:                         # filled on create only, then left to people
    used_by: [all]
    stored_at: Entra ID
    owner: ops
    rotation: create a new secret in Entra, deploy it, delete the old one
    renewed_by: manual
```

Fields the module maintains (list them under `fields:` in rackbook.yml):
`kind` and the other per-type fields, `purpose`, `expires`, `not_before`,
`kid` (the Entra key id), `ids` (`entra_app_id=<uuid>`,
`entra_tenant_id=<uuid>`) and `revoked`. It also sets `source` and, on create,
`name` and the `defaults`. Annotate `ids` with
`"x-rackbook": {"public": "uuid"}` in the schema: without it Rackbook's secret
scan holds `<label>=<uuid>` values as possible secrets, and a module never
confirms "not a secret".

### 3.3 Rules

- **Mirrored credentials are kept once.** The same key id can appear on an
  application and on its service principal, and a certificate can appear in
  both `keyCredentials` and `passwordCredentials`. Credentials are keyed by
  (app id, key id); the application's copy wins over the service principal's,
  and the certificate entry over the password entry.
- **Excluded apps** (`exclude_app_ids`, matched on the application id or the
  service principal object id) are skipped, for platform-managed apps whose
  credentials the tenant cannot rotate.
- **A rotated credential is retired.** An expired credential is treated as
  gone (marked revoked) when the same owner has a newer, unexpired credential
  of the same type and family; the family is the display name without a
  trailing `[tag]` such as `[2025]`.
- Credentials without an end date are skipped and logged.
- **Scope changes retire records.** Turning `service_principals` off or adding
  an app to `exclude_app_ids` makes those credentials gone, so the next run
  marks their records revoked. Run with `--dry-run` first after such a change.
  A failed Graph call aborts the run without marking anything.
- `fields` in rackbook.yml must list every field the module maintains,
  including the per-type ones (`self_signed` in the example above); otherwise
  the server refuses the module's updates of that record.
- Graph throttling (429, 503, 504) is retried with `Retry-After`; paging links
  are followed only on the Graph host.

### 3.4 Command line

```
rackbook-entra --config /etc/rackbook/entra.yml [--once] [--dry-run]
```

## 4. `rackbook-notify`

Reads `/api/expiring` and sends one digest per run with the records that
crossed a reminder threshold since the last run: 30, 14 and 7 days before,
and on expiry (configurable). A state file remembers which thresholds fired
for each record, so each one fires once; a record whose date changes (it was
renewed) starts over.

```yaml
rackbook:
  url: https://rackbook.example.org
  token_file: rackbook-token        # a read token
collections: []                     # empty = every collection with an expiry field
thresholds: [30, 14, 7, 0]          # 0 = on the day of expiry and after
state_file: notify-state.json       # relative to $STATE_DIRECTORY
language: en                        # en or zh
interval: 6h
smtp:                               # optional
  host: smtp.example.org
  port: 587                         # STARTTLS is required
  username: rackbook@example.org
  password_file: smtp-password      # in $CREDENTIALS_DIRECTORY
  from: Rackbook <rackbook@example.org>
  to: [ops@example.org]
  helo: notify.example.org          # optional; default: this host's name
webhook:                            # optional
  url_file: webhook-url             # in $CREDENTIALS_DIRECTORY (webhook URLs are secrets)
```

- `helo` is the name the module gives the mail server in `EHLO`. It
  defaults to the host's fully qualified name (else `localhost`); some relays,
  such as smtp-relay.gmail.com, offer no STARTTLS to a client that calls
  itself `localhost`, and the module never sends without STARTTLS.
- The state is saved only after every configured channel accepted the
  message; a failed send is retried on the next run.
- The webhook receives `POST` JSON
  `{"text": "<the digest as text>", "items": [<expiring items>]}`.
- `--dry-run` prints the digest and saves nothing; `--once` runs once.

## 5. Running with systemd

Both modules work as a oneshot service plus a timer. `LoadCredential` puts
the secrets in `$CREDENTIALS_DIRECTORY` (readable only by the service), and
`StateDirectory` gives `rackbook-notify` its state directory.

```ini
# /etc/systemd/system/rackbook-entra.service
[Unit]
Description=Rackbook: sync Entra ID credentials
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/rackbook-entra --config /etc/rackbook/entra.yml --once
LoadCredential=rackbook-token:/etc/rackbook/credentials/entra-rackbook-token
LoadCredential=entra.pem:/etc/rackbook/credentials/entra.pem
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

# /etc/systemd/system/rackbook-entra.timer
[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/rackbook-notify.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/rackbook-notify --config /etc/rackbook/notify.yml --once
LoadCredential=rackbook-token:/etc/rackbook/credentials/notify-rackbook-token
LoadCredential=smtp-password:/etc/rackbook/credentials/smtp-password
StateDirectory=rackbook-notify
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

# /etc/systemd/system/rackbook-notify.timer
[Timer]
OnCalendar=*-*-* 08:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

In Docker, the image contains both modules:
`docker run --entrypoint rackbook-entra -v …:/run/credentials -e CREDENTIALS_DIRECTORY=/run/credentials ghcr.io/kazuhahub/rackbook:0.3 --config /etc/rackbook/entra.yml --once`.

## 6. Writing another module

Copy the shape of `rackbook-entra`: read the collection, compute the wanted
records, then create, update or mark revoked through the API, following 2.2.
`modules/rbclient` is a small Go client for the endpoints a module needs. Add
the module under `cmd/`, list its token under `modules:`, and nothing in the
server changes.
