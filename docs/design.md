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
owns; nobody edits that checkout by hand. It fetches every `--pull-interval`
(default 60 s) and fast-forwards, so the console shows pushes made from
elsewhere (ansible-pull hosts, laptops, the owner's agents).

**One write, end to end** (serialised by a mutex):

1. `git fetch` and reset the worktree to `origin/<branch>`;
2. check the client's base: the record's content hash must still match (else
   HTTP 409 with the current record — the console shows "someone changed this
   record, review and retry");
3. splice the YAML, re-validate the whole ledger (else HTTP 422 with errors);
4. commit with author = the editor (`Name <email>` from Cloudflare Access),
   committer = the configured service identity, message
   `ledger(<collection>): <add|edit|delete> <id>` plus an `Edited-via: rackbook`
   trailer and the editor's email;
5. push. If the push is rejected because the remote moved: go back to step 1
   and replay the same semantic edit on the new tip (at most 3 times). A real
   conflict — the same record changed upstream — surfaces as the 409 from
   step 2, never as a merge.

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
- Optional `editors:` allow-list (emails / service-token names). Everyone who
  passes Access can read; only editors can write. Empty list = everyone may
  write.
- The server listens on 127.0.0.1 by default; it is meant to sit behind
  Cloudflare Tunnel or a reverse proxy, never directly on the internet.

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
