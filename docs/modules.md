# Expiry tracking and modules (decision 17)

Rackbook tracks when things expire: certificates, client secrets, API tokens,
domains, support contracts. Records are entered by hand, as always, or kept
up to date by **modules**: small programs that run next to Rackbook, read
another system and write what they find into one collection.

The Rackbook server stays small and generic. It knows which field holds an
expiry date and can list what is about to expire. It contains no code for any
upstream system and sends no mail. That lives in modules.

Since v0.5.0 an administrator also sees and manages the modules in the
console (page **模块**): when each one last ran, whether it failed, pause and
"run now", and the settings that are safe to change from a browser (section 7).

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
6. `--dry-run` shows the planned changes and writes nothing (it ignores the
   schedule); `--once` does one cycle and exits (for the hourly systemd timer,
   section 5); `--force` syncs now even if nothing is due or the module is
   paused in the console. Without `--once` the program repeats: every hour when
   the server supplies settings (section 7), else every `interval`.

### 2.3 The allow list: `modules:` in rackbook.yml

```yaml
modules:
  entra:                       # the module's name = the source value it writes
    type: entra                # entra or notify: which settings the console edits (section 7)
    token: entra-sync          # the Rackbook API token it uses
    collection: credentials    # the one collection it may write
    fields: [kind, self_signed, purpose, expires, not_before, kid, ids, revoked]
    direct_push: true          # create/update go straight to the branch, no daily PR
    settings:                  # edited in the console, see section 7
      sync_at: ["03:00"]
  notify:
    type: notify
    token: notify-read         # a read token: this module writes nothing,
                               # so it has no collection and no fields
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
- `collection` and `fields` go together: give both, or neither for a module
  that only reads (such a module can write nothing). A module named `entra` or
  `notify` without a `type` is read as that type, so entries from before
  v0.5.0 keep working. An unknown `type`, an unknown key under `settings`, or
  a value that does not check out is a config error that names the key.
- Module names are 1–32 characters of `a-z 0-9 . _ -` and not `manual`. Each
  token and each name appears once.
- Commits by a module carry the trailer `Source: <name>` next to the usual
  `Edited-via: rackbook (token:<token>)`.

`rackbook-notify` only reads, so it needs a `read` token. It needs an entry
here only to use the console (a read-only entry as above); without one it keeps
working from its local config.

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

This is the local file on the host that runs the module. Since v0.5.0 some of
it can be set in the console instead (section 7); the comments below say which.
A field that the console sets wins over the same field here.

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
  service_principals: true          # console: also read service principals (default true)
  exclude_app_ids: []               # console: application (client) ids or service principal object ids
interval: 24h                       # without --once, and only when the server has no console settings
record:
  name_prefix: entra-               # console. Record name: <prefix><app slug>-<first 8 of the key id>
  purpose: 'Entra application "{app}": {type} "{name}"'   # console
  type_labels: {password: client secret, certificate: certificate}
  password: {kind: api_token}       # extra fields for client secrets (module-owned)
  certificate: {kind: client_cert, self_signed: true}
  defaults:                         # console. Filled on create only, then left to people
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
  credentials the tenant cannot rotate. The list is the union of `entra.yml`'s
  and the console's (7.7). Their existing records are left as they
  are: not updated, not revoked.
- **A rotated credential is retired.** An expired credential is treated as
  gone (marked revoked) when the same owner has a newer, unexpired credential
  of the same type and family; the family is the display name without a
  trailing `[tag]` such as `[2025]`.
- Credentials without an end date are skipped and logged.
- **Turning `service_principals` off retires records.** A credential that is
  no longer read counts as gone, so the next run marks its record revoked.
  Adding an app to `exclude_app_ids` does not: it freezes the app's records.
  The console asks before saving either change and lists the records
  (section 7.5); `--dry-run` shows exactly what the next run would do. A failed
  Graph call aborts the run without marking anything.
- `fields` in rackbook.yml must list every field the module maintains,
  including the per-type ones (`self_signed` in the example above); otherwise
  the server refuses the module's updates of that record.
- Graph throttling (429, 503, 504) is retried with `Retry-After`; paging links
  are followed only on the Graph host.

### 3.4 Command line

```
rackbook-entra --config /etc/rackbook/entra.yml [--once] [--dry-run] [--force]
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
  module: notify                    # its name under modules: in rackbook.yml (default notify)
collections: []                     # console. Empty = every collection with an expiry field
thresholds: [30, 14, 7, 0]          # console. 0 = on the day of expiry and after
state_file: notify-state.json       # relative to $STATE_DIRECTORY
language: en                        # console. en or zh
interval: 6h                        # without --once, and only when the server has no console settings
smtp:                               # optional
  host: smtp.example.org
  port: 587                         # STARTTLS is required
  username: rackbook@example.org
  password_file: smtp-password      # in $CREDENTIALS_DIRECTORY
  from: Rackbook <rackbook@example.org>
  to: [ops@example.org]             # console: "recipients". Needed here only without the console
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
- When another module's last run failed, the digest says so (once per failed
  run), so a broken Entra sync is not silent. This needs the module to be
  listed under `modules:` with `type: notify` (section 7.6).
- `--dry-run` prints the digest and saves nothing (it ignores the schedule);
  `--once` does one cycle and exits; `--force` sends now even if nothing is due
  or the module is paused in the console.

## 5. Running with systemd

Both modules work as a oneshot service plus a timer. `LoadCredential` puts
the secrets in `$CREDENTIALS_DIRECTORY` (readable only by the service), and
`StateDirectory` gives `rackbook-notify` its state directory.

**Since v0.5.0 the timer runs every hour**, not once a day. The module asks the
server what to do each time and acts only when a send or sync time has passed
(section 7.2), so changing the time in the console needs no change on the
host. `OnCalendar=hourly` is the whole requirement. (With an old daily timer
and the console's times, the module would only get a chance to run once a day.)

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
OnCalendar=hourly
RandomizedDelaySec=5m
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
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

In Docker, the image contains both modules:
`docker run --entrypoint rackbook-entra -v …:/run/credentials -e CREDENTIALS_DIRECTORY=/run/credentials ghcr.io/kazuhahub/rackbook:0.5 --config /etc/rackbook/entra.yml --once`
(run it every hour from cron or your scheduler).

## 6. Writing another module

Copy the shape of `rackbook-entra`: read the collection, compute the wanted
records, then create, update or mark revoked through the API, following 2.2.
`modules/rbclient` is a small Go client for the endpoints a module needs. Add
the module under `cmd/`, list its token under `modules:`, and nothing in the
server changes. A module that is listed shows up in the console at once, with
its runs, if it reports them (`rbclient.ReportRun`); a new settings type for it
means adding a struct to `modsettings` (the server rejects settings it does
not know).

## 7. The modules panel (v0.5.0)

An administrator sees every module under **模块** in the console, edits the
settings that are safe to edit from a browser, pauses a module, and asks for a
run right now. This section explains how each piece works. None of it makes
Rackbook connect to a host: **Rackbook never calls a module.** The modules call
Rackbook.

### 7.1 Settings live in `rackbook.yml`

The editable settings are stored in the data repository, under
`modules.<name>.settings`:

```yaml
modules:
  notify:
    type: notify
    token: notify-read
    settings:
      send_at: ["08:00"]
      timezone: Asia/Shanghai
      thresholds: [30, 14, 7, 0]
      recipients: [ops@example.org, sec@example.org]
      language: zh
```

- Saving in the console is **one Git commit** (author = the administrator, the
  message names the module and the keys that changed, for example
  `modules(notify): change recipients, thresholds`). Only the settings lines
  change; the rest of the file, comments included, stays as it was. With
  `write.mode: pr` the save opens a pull request, as every console write does,
  and the settings apply once it is merged.
- A save carries the **version** of the settings you started from (a hash).
  If someone else saved meanwhile, you get a conflict (`409`) and the console
  offers to load their version first, exactly like the data type editor.
- Everything is checked on the server: addresses, `HH:MM` times, time zones
  (a name from the IANA database such as `Asia/Shanghai`), thresholds between 0
  and 3650, collection names, application ids (UUIDs). A value that fails is
  refused with the reason and nothing is written. Settings go through the
  secret scan like every other write.
- You can also edit `settings:` in the file by hand. The same checks run when
  the server loads it; an unknown key is a config error that names the key.
- The settings are defined once, in the Go package `modsettings`, which the
  server and both module programs share.

What the console edits, and what it does not:

| | in the console (`settings:`) | stays on the module's host or elsewhere |
|---|---|---|
| both | `paused` | install and uninstall, the systemd timer |
| `rackbook-notify` | `send_at` (daily times) and `timezone`, `thresholds`, `recipients`, `language`, `collections` | SMTP host, port, user, password and `from`; the webhook URL; `helo`; the state file |
| `rackbook-entra` | `sync_at` and `timezone`, `service_principals`, `exclude_app_ids`, `name_prefix`, `purpose`, `defaults` | tenant id, client id and the certificate; `type_labels` and the per-type fields |
| the token | | its scope, collection, `fields` and `direct_push` (the `modules:` entry and the 令牌 page) |

An empty `name_prefix` box means "use the default" (`entra-`), except that a
prefix that is explicitly empty (no prefix) stays so when you save other
settings.

Secrets never go through the console: certificates, the SMTP password and the
webhook URL stay in files on the module's host (`$CREDENTIALS_DIRECTORY`).

### 7.2 How a module decides to run

The timer starts the module every hour (section 5). Each time it:

1. asks `GET /api/modules/<name>/settings` with its own token. The answer holds
   its settings, when it last succeeded, and whether a "run now" is waiting;
2. if the module is **paused**, it reports a `skipped` run and exits;
3. otherwise it runs if a "run now" request is waiting, or if a daily time
   (`send_at` / `sync_at`, in the module's time zone) has passed since its last
   *successful* run, counted from when that run **started** (a run that starts
   just before a daily time and ends after it does not use up that time's
   successor). A module that never ran is due at once. A run that failed
   does not count, so it is tried again at the next hourly check;
4. after a run it reports the result (`POST /api/modules/<name>/runs`).

Defaults when a setting is empty: `send_at` 08:00, `sync_at` 03:00, time zone
UTC. The rule is one small function (`modsettings.Decide`) with its own tests.

A module that checks and finds nothing due says nothing and exits. A paused
module's repeated `skipped` runs are merged into one entry, so they do not
push the real history out.

### 7.3 Run history, and the state directory

Each run is reported with its start and end time, a result (`ok`, `failed` or
`skipped`), counts (`created`, `updated`, `revoked` for entra; `sent` for
notify), a short error text and, when it answers one, the id of the "run now"
request.

The times are checked against the server's clock. A run whose `finished` is
ahead of the server (a module host with a fast clock) is accepted and its times
are stored exactly as reported (the module compares its own clock with its own
times, so they stay consistent), and the server logs it when the difference is
more than 10 minutes; only more than 24 hours ahead is refused. Otherwise one
fast clock would block every report. The times the console shows (last run,
last success, next run, "due") are the ones the module host reported, compared
with the server's clock, so module hosts should run NTP.

The server keeps the **last 30 runs per module** in `<state-dir>/modules.json`,
the same `--state-dir` that keeps `token-use.json` (written to a temporary file
and renamed, so a crash cannot leave half a file; it holds no secrets).
Without `--state-dir` the history and the waiting requests live in memory and
are lost when the server restarts; the page says so. Only the module's own
token may report its runs.

A module whose last run failed is red in the list and in the sidebar, and its
error is shown on its page. `rackbook-notify` also puts failed runs of the
other modules into its digest (7.6).

### 7.4 Run now

The button stores one pending request (an id) in the state file. The module
sees it at its next hourly check, runs, and reports the run with that id, which
clears the request. Asking again while one waits does not queue a second.
A paused module cannot be asked; resume it first. It takes up to an hour,
because nothing connects to the module; the page says "waiting".

The settings form keeps what you typed. Saving sends the version the edit
started from, not the latest one the page refreshed to in the background (every
30 s). If the settings are saved elsewhere meanwhile, the page keeps your edits
and says so; saving then gets `409` and offers to load the latest settings.

### 7.5 Changes that ask first

Two entra settings can change records that already exist:

- **adding an app to `exclude_app_ids`**: the module stops touching that app's
  records (frozen: kept as they are, not revoked);
- **turning `service_principals` off**: credentials that are only found on
  service principals are no longer read, so the next sync marks their records
  revoked.

Before saving such a change the console calls
`POST /api/modules/<name>/preview` and shows the records in a confirmation
dialog. The preview uses the same rules as `cmd/rackbook-entra/sync.go`,
computed from the ledger's records with `source` equal to the module's name.
The ledger does not record whether a credential came from the application or
from a service principal, so for the second change the dialog lists every
active record of the module as "may be revoked"; `rackbook-entra --dry-run`
gives the exact list. The server also refuses an unconfirmed risky change
(`422 confirm_required`), so a script cannot skip the question.

### 7.6 Recipients, and failures in the digest

When a successful fetch of the settings shows a recipient list that differs
from the one the module remembers (in its local state file, `recipients`), it
remembers the new list at once and sends **one** notice ("收件人已变更" /
"Recipients changed") to the old and the new addresses together, so a wrong or
malicious change is seen by the people it removed. Each address is tried on its
own: one the mail server rejects (a deleted mailbox, say, answered with 550) is
logged and skipped, and the others still get the notice. There is no retry; if
no address accepted it, the failure shows in the module's log. This happens at
the next hourly check, whether or not a digest is due. The first time the module
only remembers the list.

The module compares only with recipients it got while it could reach the
console. If the settings cannot be fetched (console down, network, older
server), it does **not** announce anything and does not treat the local
`smtp.to` as a change. The run still goes ahead with the local config, as
section 7.7 says, but the digest goes to the **last recipients the module
received** (kept in the same state file), not to a possibly older list in the
local file; with none remembered, it uses `smtp.to`. When the console is
reachable again, only a real difference to the remembered list is announced.

For the failed-run lines the notify module reads `GET /api/modules/status` with
its own token. Only a module of `type: notify` and administrators may read it.
Each failed run is reported once.

### 7.7 Migrating from local config

Nothing has to change on upgrade, and a module keeps working if the server is
older than v0.5.0 or unreachable (it logs a warning and uses its local config).
To move a setting into the console, set it there and delete it from the local
file:

- a field **set in the console wins**; if the local file also has it with a
  different value, the module logs a warning that names the field. The one
  exception is `exclude_app_ids`: the console list and `entra.yml`'s list are
  **added together** (union, ignoring case), so a console edit can only exclude
  more apps and never un-freezes an app the local file excludes. The impact
  preview (7.5) therefore looks at the console list only; it cannot see the
  local file, and an app that is already excluded locally is listed as frozen
  although nothing changes for it;
- a field the console leaves empty keeps its local value, and then the default;
- `smtp.to` is optional locally once the console has recipients.

Check the hourly timer (section 5) and add `type` (and, for notify, an entry
without `collection` and `fields`) to the `modules:` block.

### 7.8 API

See [api.md](api.md#modules-panel). Admin calls need a signed-in administrator;
a token reaches only its own module's `settings` and `runs` (and `status` for a
notify module). Any other caller gets `403` for a module name that is not its
own, whether or not the module exists.
