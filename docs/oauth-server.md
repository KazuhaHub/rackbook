# The built-in authorization server

Rackbook can be its own OAuth 2.1 authorization server for MCP clients, so
Claude Code, MCP Inspector, VS Code, Cursor and other clients can connect to
`/mcp` without MCPHub, Entra ID or Keycloak in between. A person approves the
client once, in the console they already use; after that the client keeps
working, also across restarts of Rackbook, until someone revokes it.

Everything here follows the MCP authorization specification (revision
2026-07-28) and a small set of standard RFCs, with no options beyond those
listed below. Design decisions: `design-v0.2.md`, decisions 7-12 and round 7.

## Turning it on

```yaml
# rackbook.yml
auth:
  mcp:
    resource: https://ledger.example.com/mcp     # the public URL of /mcp (required)
    builtin_issuer:
      enabled: true
      # Everything below is optional; these are the defaults.
      idle_expiry: 90d              # a grant not refreshed for this long ends
      refresh_reuse_grace: 60s      # see "The grace window"
      dynamic_registration: true    # RFC 7591; false once every client uses a metadata document
      allowed_clients: []           # client ID metadata document URLs; empty = any https client_id
                                    # (when set, registration is off: only these clients may authorize)
      signing_key_file: ""          # see "The signing key"
```

and start the server with a state directory and the public URL:

```sh
rackbook serve --config /srv/rackbook/repo/rackbook.yml \
  --state-dir /var/lib/rackbook --base-url https://ledger.example.com
```

`--base-url` is the **issuer** of the tokens (an origin, no path) and
`--state-dir` is where the grants and the signing key live. Rackbook refuses to
start without both. With systemd use `StateDirectory=rackbook`; with Docker mount
a volume at the state directory. People sign in with the console's own login
(OIDC or passkeys), and `auth.roles` decides what each person may do, exactly
as in the console.

### Network

Put nothing between the clients and these paths that asks for a login: the
client calls them without a browser session. In front of Cloudflare Access, add
a Bypass policy for `/mcp`, `/.well-known/oauth-protected-resource*`,
`/.well-known/oauth-authorization-server`, `/oauth/token`, `/oauth/register` and
`/oauth/jwks`. Keep `/oauth/authorize`, `/oauth/consent` and `/api/` behind the
login: that is where the person signs in.

## How it works, in plain language

**PKCE (S256 only).** When a client starts, it makes up a secret and sends only
its fingerprint (a SHA-256 hash) with the authorization request. When it comes
back with the code it received, it must show the secret itself. A thief who
steals the code on the way back, for example from the address bar or a log,
cannot use it because they do not know the secret. Rackbook requires this for
every request and accepts only the S256 method; the older "plain" method, which
sends the secret itself, is refused.

**Resource binding.** Every request must say which server the token is for (the
`resource` parameter, RFC 8707), and it must be exactly the `/mcp` URL in
`auth.mcp.resource`. The access token then names that URL as its audience. A
token issued for Rackbook is therefore useless anywhere else, and a token made
for another service is useless here.

**Client ID metadata documents (CIMD).** A client may identify itself with an
https URL. Rackbook fetches the JSON document at that URL and reads the client's
name and its allowed redirect addresses from it. The document must say that its
own `client_id` is that same URL, so nobody can claim someone else's page. It is
fetched with a short time limit and a small size limit (8 KiB), never follows
redirects, and is refused if the address behind the URL is anything but an
ordinary public one (loopback, private, link-local, carrier-grade NAT, the
special-use and transition ranges are all refused), which stops it being used to
make Rackbook probe your own network. If the fetch fails, the person sees only
"could not fetch the client's metadata document"; the detail goes to the server
log. Documents are kept in memory for a few minutes. By default any https URL is
accepted; `allowed_clients` restricts it to the URLs you list, and then **only**
those clients may authorize and dynamic registration is switched off (the server
logs that at start), because a registered client would otherwise bypass the list.
The consent page always shows the address the result will be sent back to.
Client URLs and redirect addresses may contain only plain ASCII (an
international host name is written in its `xn--` form), with no control,
right-to-left or zero-width characters, and no percent-escape in the host, so a
look-alike host cannot be passed off as another. When a host on the consent page has an `xn--` label, the page
shows a warning.

**Dynamic client registration (DCR).** Older clients have no document and
instead register themselves first (RFC 7591). Rackbook keeps this minimal: only
public clients (no secret), only the redirect addresses `https://`,
`http://localhost`, `http://127.0.0.1` and `http://[::1]`, and the private-use
scheme of a desktop application such as `cursor://` (plain ASCII only, as above);
at most 10 per client and 100 registrations stored. Registering the same thing
again returns the existing client and costs nothing. A new registration counts
against the caller's address, 30 per 10 minutes (the same client-address
detection as the API-token limit, so set `--trusted-proxy` behind a proxy). When
the 100 are full, the oldest registration that never got a grant is dropped to
make room; if every registration is in use, new ones are refused until one is
freed. Registrations nobody used are removed after a day, and those whose grants
are all gone after 30 days. It is on by default so existing clients work, and
`dynamic_registration: false` turns it off once your clients all use documents.
Whichever way a client is known, the redirect address of an authorization
request must be **exactly** one it declared; there is no pattern matching, and
`localhost` and `127.0.0.1` are different addresses.

**The consent page.** Every authorization shows the consent page: who is asking
(the client's name and ID), where the result will be sent, as which user, and
what it may do: read, or also write. What is shown is the person's role limited
by the scopes, so a viewer is never told "read and write". Nothing is remembered
between requests, so a client that asks again has to be approved again. A request
for a scope the server does not have (anything but the configured read and write
scopes) is answered `invalid_scope`; a request with no scope gets all of them.
Writes through MCP still become pull requests unless `auth.mcp.direct_push` says
otherwise.

**Refresh rotation and reuse.** An access token lasts 10 minutes. The client
renews it with a *refresh token*, a random value that Rackbook stores only as a
hash. A grant has exactly one refresh token that works. Using it gives a new
access token and a new refresh token, and the old one is retired (the last eight
retired ones are remembered, as hashes). Everything that could refuse the request
(wrong client, wrong `resource`, a scope wider than the grant, a person without a
role, a client no longer in `allowed_clients`) is checked first, so a refused
request never uses the token up; and a person without a role, or a client that
is no longer allowed, ends the grant. If a retired token is presented again after
the grace window, a copy of it exists somewhere it should not, and Rackbook ends
the whole grant and logs it (without any token in the log). The client and the
thief are both locked out and the person has to approve again. A token Rackbook
does not know at all is just refused and changes nothing, so guessing cannot end
anyone's grant.

**The grace window.** A rotation can fail in the middle: Rackbook sends the new
tokens, the connection drops, and the client still holds only the old one. Two
requests can also arrive with the same token at the same moment. So for 60
seconds (`refresh_reuse_grace`) after a rotation, presenting the retired token
again simply gets **the same answer as the first time** (the same access token
and the same refresh token). Nothing changes on disk. Concurrent requests are
handled one at a time, so the second one gets the answer the first one made. The
answers are kept only in memory, for those 60 seconds, and are dropped when the
grant is revoked. This means the window cannot tell a retry from a thief who
copied the old token within the same minute: both get the same answer, which is
the price of surviving a lost response (RFC 9700 allows it; some identity
providers call it a reuse interval or grace period). After the 60 seconds the
retired token ends the grant. If Rackbook restarts inside the window the answers
are gone: the old token is then refused (`invalid_grant`) but the grant is *not*
ended, and the client either holds the newer token already or signs in again.

**The state file and the lock.** Grants, registered clients and the hashes of
refresh tokens are kept in `<state-dir>/oauth-grants.json`, the one thing
Rackbook stores outside Git. It never contains a token. It is written by writing
a temporary file, flushing it to disk, renaming it over the old one and flushing
the directory, and the new hash is on disk *before* the new token is sent. The
file has mode 0600 and the directory 0700. `serve` holds a lock on
`<state-dir>/rackbook.lock` while it runs, so a second server on the same
directory stops with an error instead of overwriting the first's changes.
Authorization codes (valid 60 seconds, usable once), pending consent requests
and fetched client documents are only in memory. If the file is lost, clients
simply have to be approved again; a damaged file stops the server from starting
rather than silently forgetting everyone.

**The signing key and rotation.** Access tokens are signed with an ES256 (P-256)
key. On first start Rackbook generates one at
`<state-dir>/oauth-signing-key.pem` (mode 0600). To use your own, point
`signing_key_file` at a PEM file, set `RACKBOOK_OAUTH_SIGNING_KEY` to its text,
or give systemd a credential (`LoadCredential=oauth-signing-key:/etc/rackbook/key.pem`).
Make one with `openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt`.
Only Rackbook checks these tokens, inside the same process, so the published key
list (`/oauth/jwks`) holds just the current key and no old one is kept. To
**rotate**: replace the file (or delete the generated one) and restart. Access
tokens signed with the old key stop working at once, which is harmless: clients
get a new one by refreshing, with no browser step, because refresh tokens are not
signed and do not depend on the key.

**Grant lifetime.** A grant lasts until it is revoked, until its person no longer
has a role, or until it has gone `idle_expiry` (90 days) without being refreshed.
The time is counted from the last refresh, so a client in regular use never has
to sign in again, and there is no absolute limit. A person revokes their own
grants on their account page, and an administrator revokes anyone's on the
admin page (`已授权客户端`); the client's access token stops working at once, not
after 10 minutes. If the change cannot be saved (for example the disk is
read-only) the request fails with an error and the grant stays in force; it is
never reported as revoked when it is not. The role is re-evaluated from `auth.roles` on every request
and on every refresh, so removing someone from the roles ends their MCP access
immediately and ends the grant at the next refresh. The groups used for
`group:` role entries are the ones the person had when they approved, and they
are not refreshed until they approve again.

## Endpoints

| Endpoint | Who | Purpose |
|---|---|---|
| `GET /.well-known/oauth-authorization-server` | anyone | RFC 8414 metadata |
| `GET /oauth/authorize` | signed-in person | checks the request, then sends the browser to the consent page |
| `GET /oauth/consent` | signed-in person | the console page that asks for approval |
| `POST /oauth/token` | client | `authorization_code` and `refresh_token` grants, public clients only |
| `POST /oauth/register` | client | RFC 7591 registration (when `dynamic_registration` is on) |
| `GET /oauth/jwks` | anyone | the public signing key |

Only the metadata, token, registration and JWKS endpoints answer requests from
other origins (browser-based clients need that); none of them takes cookies.
There is no token revocation endpoint (RFC 7009) in this version: revoke
grants in the console.

## Limits of this version

- Public clients only; no client secrets, no other grant types.
- Redirect addresses must match exactly; there is no loopback port wildcard.
- The groups of a grant are not refreshed (see above).
- Not covered: RFC 7009 revocation, token exchange, DPoP.
