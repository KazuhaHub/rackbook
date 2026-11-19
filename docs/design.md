# Rackbook design (v1)

Status: accepted (see section 10).

Rackbook is a Git-native infrastructure ledger. A Git repository holds the
ledger as YAML files plus JSON Schema files; Rackbook validates it, serves a
web console and a JSON API over it, exposes it to AI agents over MCP, and
exports it as Markdown / `llms.txt` / JSON. Every write becomes a Git commit.
There is no database: the YAML in Git is the only source of truth.

## 1. Data model

### 1.1 Data repository layout

A data repository contains one config file and any number of YAML and schema
files. Paths in the config are relative to the config file and may not escape
the repository root.

```
rackbook.yml            # config (below)
ledger/devices.yml      # data files: YAML, any layout
ledger/networks.yml
schemas/device.json     # one JSON Schema (draft 2020-12) per collection
schemas/service.json
```

### 1.2 Collections

A **collection** is a list of records (YAML mappings) found at a path inside a
YAML file. A file may hold the list at its top level, or several collections
may live in one file under different keys. This covers every shape in the
existing ledger without changing it:

| existing file    | shape                                  | collections                         |
|------------------|----------------------------------------|-------------------------------------|
| `devices.yml`    | top-level list                         | `devices`                           |
| `addresses.yml`  | top-level list                         | `addresses`                         |
| `services.yml`   | top-level list                         | `services`                          |
| `ports.yml`      | top-level list                         | `ports`                             |
| `todo.yml`       | top-level list                         | `todo`                              |
| `sites.yml`      | `rule:` text + `sites:` list           | `sites` + note `sites.rule`         |
| `networks.yml`   | `tailscale:`, `lan:`, `docker.ranges:` lists + `docker.rule` text | `tailscale_ranges`, `lan_ranges`, `docker_ranges` (one nav group) + note |

Free-text values that are not records (`docker.rule`, `sites.rule`) are declared
as **notes**: shown on the related collection page and included in exports.

```yaml
# rackbook.yml
title: Kazuha Hub 网络台账
collections:
  devices:
    title: 设备
    file: ledger/devices.yml          # path: "" = top-level list
    schema: schemas/device.json
    key: [name]                       # record identity + uniqueness check
    label: name                       # what a reference displays
    list: [name, category, site, os, ipv4, domain, managed]   # default columns
    facets: [category, site, managed]
  services:
    title: 服务端口
    file: ledger/services.yml
    schema: schemas/service.json
    key: [device, service]
    facets:
      - device
      - managed
      - {field: exposure, contains: [公网, Tailscale, 局域网, 本机, Cloudflare]}  # tag facet
  tailscale_ranges:
    title: Tailscale 网段
    group: 网段规划
    file: ledger/networks.yml
    path: tailscale                   # dotted path to the list inside the file
    schema: schemas/network-range.json
    key: [range]
notes:
  - {title: Docker 地址池规则, file: ledger/networks.yml, path: docker.rule, collection: docker_ranges}
```

**Record identity.** `key` lists the fields that identify a record; the
record id in URLs, the API, the CLI and MCP is those values joined with `/`
(URL-escaped). `key` doubles as a uniqueness rule. A collection without `key`
is addressed by position (`#3`) and every write must carry the record's
content hash, so a stale edit can never hit the wrong row.

**Schemas.** One JSON Schema per collection describes a single record. It is
standard JSON Schema 2020-12 (validated with `santhosh-tekuri/jsonschema`),
so the same file drives validation in the CLI, the server and the web forms.
Field labels and help text come from the standard `title` / `description`
keywords (Chinese titles in the owner's config, so the console reads
`设备名` while the YAML says `name`). Field order in forms and exports follows
`properties` order. Nothing about presentation is invented on top of the
schema except the `list` / `facets` hints in `rackbook.yml`.

### 1.3 Rules (cross-collection checks, declared in config)

`rackbook check` runs, in order: YAML parse → JSON Schema per record → rules.
Rules are declared in `rackbook.yml`; none are hardcoded.

```yaml
rules:
  # references: services.device must name a device, or be the literal "all"
  - ref: {from: services.device, to: devices.name, allow: [all]}
  - ref: {from: addresses.device, to: devices.name}
  # set equality with a key set in another YAML file in the same repo
  - same_set:
      left:  {collection: devices, field: name, where: {managed: true}}
      right: {file: inventory/hosts.yml, path: all.children.managed.hosts, take: keys}
      message: devices marked managed must equal the inventory group "managed"
```

Rule kinds in v1: `unique` (implied by `key`, also usable on other fields),
`ref` (with `allow` literals and optional `many: true` for list fields), and
`same_set`. Reverse references are derived from `ref` rules: the device detail
page lists its addresses and services because those collections reference
devices — no device-specific code.

This reproduces every check in `scripts/ledger-build`:

| `ledger-build` check                                    | Rackbook rule             |
|---------------------------------------------------------|---------------------------|
| device names unique                                     | `devices.key: [name]`     |
| services/addresses reference an existing device         | two `ref` rules           |
| `device: all` only in services                          | `allow: [all]` on services only |
| `managed: true` devices == inventory group `managed`    | `same_set`                |

plus schema checks (types, required fields, no unknown fields) and key
uniqueness on the other collections.

## 2. YAML writes that keep the file as it was

Round-tripping the real ledger through a YAML encoder loses blank lines,
re-folds `>-` text and changes quoting on every line. Rackbook therefore never
re-serialises a whole file. A write parses the file to a node tree (with
`go.yaml.in/yaml/v3`, the maintained continuation of `gopkg.in/yaml.v3`),
finds the line span of the one record being changed, and splices only those
lines:

- **edit**: replace the record's lines with the new record, emitted in the
  same style as the old one (flow `{...}` on one line, or block);
- **add**: insert after the last record of the collection (or after the last
  record with the same reference value, so services stay grouped under their
  device's `# --- host` comment), in the style of its neighbours;
- **delete**: remove the record's lines, keeping surrounding comments.

Every other byte of the file stays identical, so Git diffs show exactly one
record. After the splice the file is re-parsed and the whole ledger is
re-validated; any error aborts the write.

## 3. Git write path

**Shell out to `git`, not go-git.** System git brings SSH agent / deploy keys,
credential helpers, commit signing, `includeIf` config and correct
rebase/merge behaviour; go-git lacks rebase and has a narrower SSH/auth
story. Read-only use (`check`, `export`, `mcp`, `serve --read-only`) needs no
git at all. The Docker image ships `git` and `openssh-client`.

**Server-owned clone.** `rackbook serve --repo /data/repo` works in a clone it
owns; nobody edits that checkout by hand. **The server clone must contain only
tracked files**: any modified, untracked or ignored file outside `.git` makes
every write, pull and accept fail with `repo_dirty` (one `git status
--porcelain --untracked-files=all --ignored=matching` check), so a hard reset
can never overwrite or delete anything unknown. The server also runs git with
hooks disabled, the system config ignored and the user's global config ignored
(so HTTPS credential helpers in `~/.gitconfig` do not apply: use SSH deploy
keys or a repo-local config); the CLI keeps the user's config but also runs
without hooks. It fetches every `--pull-interval`
(default 60 s) and fast-forwards, so the console shows pushes made from
elsewhere (ansible-pull hosts, laptops, the owner's agents).

**One write, end to end** (serialised by a mutex):

1. `git fetch` and reset the worktree to `origin/<branch>`;
2. check the client's base: the record's content hash must still match (else
   HTTP 409 with the current record — the console shows "someone changed this
   record, review and retry");
3. splice the YAML, re-validate the whole ledger (else HTTP 422 with errors);
4. commit with author = the editor (`Name <email-or-id>`), committer = the
   configured service identity, and message
   `ledger(<collection>): <add|edit|delete> <id>` plus trailers (below);
5. push. If the push is rejected because the remote moved: go back to step 1
   and replay the same semantic edit on the new tip (at most 3 times). A real
   conflict — the same record changed upstream — surfaces as the 409 from
   step 2, never as a merge.

**Commit message trailers.** One function builds every Rackbook commit message
(`gitstore.CommitMessage`, used by the server, the CLI and MCP):

```
ledger(services): edit web-1/SSH

Edited-by: ann@example.com
Edited-via: rackbook (oidc)            # or (cloudflare-access), (mcphub, client <client_id>), (cli), ...
Record: services/web-1/SSH
```

`Edited-by` is the identity id and is left out for an anonymous local user.
`Record: <collection>/<id>` is on every record commit (one function,
`edit.RecordRef`, computes the value: ids longer than 100 characters are cut
and get `~` plus 8 hex digits of their SHA-256; History matches it with
`--fixed-strings`, whatever `grep.patternType` is); `GET /api/history`
with `collection` and `id` selects by it, and falls back to the collection
file's history when no commit carries the trailer.

**Rackbook never force-pushes.** It never runs a force push (plain, with lease,
or a `+` refspec), never deletes or rewrites remote branches or tags, never
mirrors, and never resets anything on the remote. The only reset is on the
server's own clone, to the remote tip, after the ancestry check below.

- Exactly one function (`pushArgs` in `internal/gitstore/safegit.go`) builds a
  push command line, and it can only produce
  `git push --quiet origin HEAD:refs/heads/<branch>` (the pull request branch
  uses the same function). Every git call goes through one `Runner`, whose
  real implementation also refuses any push that is not that exact shape and
  every git subcommand outside a short allow-list (so no branch/tag/ref
  deletion, `update-ref`, `send-pack`, `receive-pack` or alias tricks). Only
  the global options Rackbook itself uses may precede it (`-C <dir>`,
  `-c` with a fixed set of keys, `--no-pager`); any other is refused. Each
  subcommand then has its own list of allowed options (nothing like
  `--upload-pack`, `--exec`, `--output`, `-o`, `--ext-diff`, `--textconv`), and
  `config` and `remote` only read fixed keys.
- The tests run the whole gitstore suite through a recording runner and fail if
  any recorded command is a force or lease push, a mirror, a deletion, a
  refspec starting with `+` or `:`, `update-ref -d`, or a `reset` outside the
  clone; a static test keeps those words and every push command line out of
  all other non-test sources, and `os/exec` out of every other package.

**Rewritten remote history.** The server remembers the last remote commit it
accepted: in memory and in `.git/rackbook-last-good/<branch>` inside its clone (one file per branch, name escaped; an older single file is migrated). At
startup, after every periodic fetch and before every write it checks that
`origin/<branch>` is a descendant of that commit (`git merge-base
--is-ancestor`); fast-forwards advance it. If it is not (a force push, or a
branch deleted and recreated), Rackbook:

- does **not** reset the clone and keeps serving read-only from the last good
  commit;
- refuses every write (API, CLI `--commit`/`--push`, MCP) with
  `503 {"error":"history_rewritten","lastGood":"…","remote":"…"}`;
- logs an error and reports `alert: {kind: "history_rewritten", lastGood,
  remote}` in `/api/meta`, which the console shows as a red banner.

Our own successful pushes and every fast-forward pull advance the last good
commit, so a later force push of "our commit's parent plus something else" is
still detected.

An administrator clears it after checking the new history:
`rackbook serve --accept-remote <commit>`, `POST /api/admin/accept-remote
{"commit": "<hash>"}` (admin only, refused in `--read-only`), or, in a plain
clone, `rackbook accept-remote <commit>`. All three accept only the commit that
is the current remote tip, and only while a rewrite is active (otherwise
`no_alert`). They refuse, changing nothing, when the accepted tip's
`rackbook.yml` does not load (`config_error`), and (server only) when the clone
has any modified, untracked or ignored file or has commits that are on no remote branch and not part of the old
accepted history (`local_commits`); only then is the clone reset to the tip and
the tip recorded as the new base. After the reset the server reloads
everything; if that fails (for example a schema path turned into a symlink out
of the repository) it resets back, keeps the old base and the alert, and
returns `config_error`. `rackbook accept-remote` in a plain clone only records
the base: it never resets or touches the user's work tree. If the remote later becomes a descendant of
the last good commit again (the rewrite was undone) the state clears by itself.

The CLI (`rackbook add|set|rm --commit|--push`) runs the same check before it
edits any file.

**Broken config.** If `rackbook.yml` fails to load after a pull or reset, the
server keeps serving the last good config and ledger for reads, fails closed
for writes and admin actions (everyone is capped at viewer, writes return
`503 config_error`) and reports `alert: {kind: "config_error", message}` in
`/api/meta`; it recovers on its own when a config loads again.

**Two write modes** (`write.mode` in config):

- `push` (default): commit to the tracked branch and push. Right for a small
  team where Cloudflare Access already limits who can edit.
- `pr`: push to `rackbook/<user>/<timestamp>` and open a pull request with the
  GitHub REST API (token from an env var). Edits then go through review/CI.

## 4. Auth

- `--auth none` (default for local use): no identity checks; writes are
  attributed to `--editor "Name <email>"` or git's own `user.name/email`.
- `--auth cloudflare-access --cf-team <team> --cf-aud <aud tag>`: every request
  must carry a valid `Cf-Access-Jwt-Assertion` header (or `CF_Authorization`
  cookie). Rackbook verifies signature against
  `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` (cached JWKS,
  rotated automatically), `iss`, `aud` and expiry using `coreos/go-oidc` — the
  library Cloudflare's own Go example uses. The identity is the `email` claim;
  for Access service tokens (AI agents), the `common_name` claim.
- Roles (`auth.roles` in `rackbook.yml`, see below). The v0.1 `editors:`
  allow-list still works as editor entries: everyone who passes Access can
  read, only the listed editors can write. Empty list = everyone may write.
- The server listens on 127.0.0.1 by default; it is meant to sit behind
  Cloudflare Tunnel or a reverse proxy, never directly on the internet.

### Roles

```yaml
auth:
  roles:
    admin:  [owner@example.com]
    editor: ["*@example.com", "mcphub:alice", "group:ops"]
    viewer: ["*"]
```

Every authenticated request gets an `Identity` (`internal/auth`) with a `Role`
that is evaluated from the **current** config on every request, so a config
reload on pull takes effect without a restart.

- Entries (case-insensitive, ASCII letters only: a Unicode look-alike such as
  the Kelvin sign never folds onto an ASCII name): an exact identity or
  e-mail, `*@domain`, `mcphub:<username>` / `mcphub:*` (MCPHub identities),
  `group:<id>` (matched against the groups on the identity) and `*` (anyone
  authenticated). The highest matching role wins.
- Which entries can match depends on the login method. oidc, passkey,
  cloudflare-access, none and cli identities match everything except
  `mcphub:`. MCPHub identities match only `mcphub:` entries, plus exact and
  `*@domain` entries when their username is an e-mail address **and**
  `auth.mcp.match_email: true` is set (default false). Token identities match
  no entry; they take their creator's role.
- `viewer` reads; `editor` also creates, edits and deletes records; `admin`
  also does administrative actions (accepting a rewritten remote, later data
  types). Checks use the actions `read`, `write`, `delete` and `admin`.
- No `roles` block: every authenticated identity is an editor (v0.1). With
  only the v0.1 `editors` list (or `--editors`), those identities are editors
  and everyone else is a viewer. `editors` entries are added to `roles.editor`
  when both exist.
- With a `roles` block an identity that matches nothing has no role and gets
  `403 {"error":"no_role"}` everywhere. (Auth `none` without `--editor` has no
  identity to refuse: it is anonymous and never below viewer.)
- A credential that carries scopes (MCPHub tokens) can only lower the role,
  through `Identity.Narrow`; it can never raise it.
- Writes need `editor` in the API; viewers get `403 {"error":"forbidden"}`.

## 5. Interfaces

### 5.1 CLI

```
rackbook check   [--format text|json]                      validate; exit 1 on errors
rackbook serve   [--listen 127.0.0.1:8080] [--repo DIR] [--auth ...] [--read-only]
rackbook mcp                                               MCP server on stdio
rackbook export  --format markdown|llms|json [-o FILE]
rackbook list    <collection> [--where field=value]... [--format table|json|yaml]
rackbook get     <collection> <id>
rackbook add     <collection> field=value...               edits the local files
rackbook set     <collection> <id> field=value...
rackbook rm      <collection> <id>
rackbook schema  [<collection>]                            print the JSON Schema
```

Global flags: `--config` (default: `rackbook.yml`, searched upwards from the
current directory). `add/set/rm` edit the working tree with the same splice
code and validate before writing; `--commit` also commits (and `--push`
pushes) using the same Git path as the server. Values are parsed against the
schema type (`managed=true` → boolean).

### 5.2 HTTP API (used by the console; also for scripts)

```
GET    /api/meta                             title, collections, schemas, rules, notes
GET    /api/c/{collection}                   records (+ id, hash); filtering/sorting client-side
GET    /api/c/{collection}/{id}              record + reverse references
POST   /api/c/{collection}                   add
PUT    /api/c/{collection}/{id}              edit   (body: record + base hash)
DELETE /api/c/{collection}/{id}?hash=...     delete
GET    /api/check                            validation result
GET    /llms.txt, /llms-full.txt, /export.md, /export.json
POST   /mcp                                  MCP over streamable HTTP (same tools as stdio)
```

A ledger is small (hundreds of rows), so lists are returned whole and the
console filters/sorts in the browser — instant search, no server query
language to maintain.

### 5.3 MCP (read-only in v1)

Official Go SDK (`modelcontextprotocol/go-sdk`). Tools:
`list_collections`, `list_records(collection, where?)`,
`get_record(collection, id)` (with reverse references),
`search(query)` (substring over all fields, all collections),
`get_schema(collection)`, `check`, and `export_markdown`. The generic tools
cover "services of a host" (`list_records services where device=X`) and
"who uses a port" (`search "10511"`); the tool descriptions say so, and
the owner's config can add saved queries later. Write tools (with the same
Git path and an `Edited-via: mcp` trailer) are a v2 item.

### 5.4 Exports

- `markdown`: title, then per collection a heading, its notes and a table with
  schema titles as column headers; deterministic output.
- `llms`: an `llms.txt` (llmstxt.org format: H1, summary blockquote, a
  section per collection linking to its JSON/Markdown when `--base-url` is
  given) and `llms-full.txt` = the Markdown export.
- `json`: `{meta, collections: {name: [records]}}`.

## 6. Web console

React + Vite + TypeScript, Refine core (headless: data provider, routing,
resource CRUD hooks) with `@refinedev/react-router` and
`@refinedev/react-table` (TanStack Table), shadcn/ui components on Tailwind.
Forms: `@rjsf/core` with its shadcn theme, driven by the collection's JSON
Schema (the same schema the server validates with; server-side errors are
mapped back onto fields). UI copy in Chinese, kept in one strings file.

Pages: dashboard (counts, check status, recent commits) · one list page per
collection (global search, per-column filter, facet chips, sorting, column
visibility) · record detail with reverse references (device → its addresses
and services) · create / edit / delete with "who changed it last" from
`git log`. Dark mode follows the system.

The built `dist/` is embedded in the Go binary with `go:embed`; Node is only
needed at build time.

### 6.1 Console usability (v0.4.0)

Everything below is driven by the collection model (schema, `refs`, `facets`,
`list`, `backref_columns`); nothing is written for a particular ledger.

**Record page.** The fields card comes first. Below it, each collection that
references the record is a tab, with its record count in the tab title. The
selected tab is kept in the URL hash (`#<collection>`, `#<collection>+generic`),
so a link or a reload opens the same tab. Each tab has a quick search (matches
across the columns it shows), a rows-per-page choice (10 / 25 / 50 / all, kept in
`localStorage` per collection) and simple paging. On a narrow screen the tab bar
and the tables scroll sideways inside their cards, never the page.

**General records.** A referencing record whose field holds a literal that the
ref rule allows (`allow: [all]`; for an array field such as `used_by: [all]`, an
array that contains it) applies to every record of the page's collection, not to
this one. Those records are not mixed with the record's own: they get a separate
tab, `通用 · <collection title>`, with its own count, after the own tabs. A record
that names this record explicitly is always its own, even if it also lists the
literal.

**Rows.** Rows of the list page and of the record page's tables open the record
when clicked anywhere, and by keyboard: up / down move between rows, Home / End
jump to the first / last, Enter opens, and the focused row has a visible ring.
Links and buttons inside a row work as usual, and selecting text does not
navigate.

**Edit in place.** When the user may edit, a list cell of an enum, boolean or
date field, or of an array of enum values, edits without leaving the page:
a toggle for booleans, a searchable picker for enums and tags (tags save when the
picker closes), a date input for dates. The change shows at once and is saved with
`PUT` and the record's hash. If the server answers 409 (somebody else changed the
record) or 422 (a rule refuses it), the old value comes back and a toast says why.
Only that collection's queries are refreshed. Key fields, reference fields and the
fields a module maintains are not edited in place; use the form.

**Record ids.** An id escapes `/` inside a key value as `%2F` and `%` as `%25`
(unchanged in URLs and in the API). Wherever the console shows an id to people
it shows the unescaped key parts, joined with ` / `.

### 6.2 Form widgets and schema conventions

The form picks a widget from the property:

| property | widget |
|---|---|
| `type: string` + `enum` | searchable select |
| `type: array`, `items: {type: string, enum: [...]}` (`uniqueItems: true`) | tags: chips plus a searchable dropdown |
| reference field (a `ref` rule; `many` too) | searchable selector over the target's values plus the allowed literals, which are marked 特殊值 |
| `type: array` of strings, `items.pattern` and/or `items.format` | chip list; each entry is checked as it is typed and only a valid one is added |
| `format: date` | the browser's date input |
| `format: textarea` | multi-line text |
| `type: boolean` | switch |
| plain short text (see below) | text with a dropdown of values already used |

**Suggest.** A field gets the dropdown of values already used in that field
across the collection (taken from the records the console has already loaded;
there is no server endpoint) when it is `type: string` (or `["string", "null"]`),
has no `enum`, no `format` and no `pattern`, is not a textarea or a reference
and is not part of the collection's `key`. Choose a suggestion or type a new
value. The list narrows as you type. A property turns it off or forces it on:

```json
"os":   {"type": ["string", "null"], "title": "系统", "x-rackbook": {"suggest": false}},
"kind": {"type": "string", "pattern": "^[a-z-]+$", "x-rackbook": {"suggest": true}}
```

**Port lists.** An array of strings whose `items.pattern` is
`^[0-9]{1,5}(-[0-9]{1,5})?$` is a port list: the entry must be a port or a range,
at most 65535, and a range runs upwards. The hint under the input is the
property's `description`, else `端口或范围，如 443、20000-20018`. For another
pattern the hint is `description`, else the pattern itself. Entries that already
hold invalid data show in red.

**Errors.** A required field is marked `*`. A field shows its error as soon as
you have left it or changed it, not before; saving shows all of them. The server's
errors are placed on the field they belong to.

**Type editor.** Tags (array of enum) and port lists are not field types of the
type editor yet: such properties are read as "高级（在 YAML 中编辑）" fields, kept
exactly as written, and left byte for byte when another field is edited. So is a
text property that carries `x-rackbook`. Facets on an array field count and filter
each element separately (one facet value per tag).

## 7. Repository layout

```
cmd/rackbook/            main package (cobra CLI)
internal/config/         rackbook.yml loading
internal/ledger/         load, index, records, ids, hashes
internal/yamledit/       node-span splicing (add/edit/delete)
internal/validate/       JSON Schema + rules
internal/gitstore/       git CLI wrapper: fetch/reset/commit/push/retry, PR mode
internal/auth/           Cloudflare Access JWT middleware
internal/api/            HTTP API + static console
internal/mcpserver/      MCP tools
internal/export/         markdown / llms / json
web/                     React console (built into web/dist, embedded)
examples/homelab/        fictional example ledger using the same schemas as the owner's
docs/                    design, deployment notes
Dockerfile, .github/workflows/{ci,release}.yml, .goreleaser.yaml
```

The example is fictional (documentation IP ranges, `example.com` names) but
uses the same collections, schemas and rules the owner's ledger uses, so it
doubles as the template for KazuhaHub/infra. The infra repo adopts Rackbook by
adding `rackbook.yml` and `schemas/` next to `docs/ledger/`; no data file
changes.

## 8. Build and release

- CI on pull requests: `go vet`, `go test ./...`, web lint/typecheck/build,
  `rackbook check` on the example.
- On `v*` tags: GoReleaser builds static binaries (linux/darwin × amd64/arm64,
  `CGO_ENABLED=0`, web embedded) to the GitHub release, and Docker Buildx pushes
  `ghcr.io/kazuhahub/rackbook:{X.Y.Z,X.Y,X,latest}` for linux/amd64+arm64.
  Image: distroless-like Alpine base with `git` and `openssh-client`, non-root
  user.

### Held-back dependency upgrades

Dependabot ignores these major versions (`.github/dependabot.yml`). Upgrade
them later, by hand, when the reason no longer holds:

- `@types/node` stays on the major that matches the Node used in CI and for
  the web build (22.x), so the types match the runtime.
- `react-router` stays on 7: `@refinedev/react-router` 2.x requires
  `react-router ^7`. With 8 installed, refine keeps its own copy of 7 and the
  console renders nothing ("useLocation() may be used only in the context of a
  <Router>"). Upgrade when refine supports 8.
- `@tanstack/react-table` stays on 8: 9 changes the generics and the features
  API, and `@refinedev/react-table` 6.x requires `^8`. Upgrade together with a
  refine release that supports 9.

## 9. Out of scope for v1

Write tools in MCP; history/diff view per record; per-field permissions;
editing notes in the console; non-GitHub PR providers; SQLite/Datasette-style
SQL queries.

### Known limitations of v1 YAML splicing

- Editing a block record loses a comment in three edge cases: a comment after an
  empty value (`note: # why`) when the value is set, a comment after a nested
  mapping's key when that mapping changes, and a comment line indented deeper
  than the keys after a changed scalar.
- An anchor written on the record's own line (`- &a`) is dropped on edit (edits
  that would break an alias are refused).
- Raw U+2028/U+2029/U+0085 characters typed by hand into an existing file may
  confuse line-span lookups; values written by Rackbook always escape them.
- `rackbook add/set --commit` commits the whole changed file, including hand
  edits already present in it.
- Multi-document YAML files are refused for writes.

## 10. Decisions

Agreed with the owner on 2026-11-17:

1. License: Apache-2.0.
2. Default write mode for the owner's deployment: `push` straight to `main`
   (`pr` mode is implemented too).
3. In KazuhaHub/infra, `rackbook.yml` and `schemas/` live at the repository
   root, pointing at `docs/ledger/*.yml` and `inventory/hosts.yml`.
4. `main` starts with a license + README commit; all work lands through pull
   requests.
