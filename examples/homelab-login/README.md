# homelab with login

The `homelab` example plus an `auth:` block for the built-in login. Use it to try
Microsoft Entra ID sign-in and passkeys on your own machine.

1. Edit `auth.roles` in `rackbook.yml`: put the account you sign in with (its UPN) under
   `admin`, for example `admin: [you@yourdomain.com]`. Nobody without an entry gets in.
2. Make a local certificate for `localhost` (for example with
   `openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 -keyout localhost.key -out localhost.crt`)
   and trust it in your browser, or use mkcert.
3. In the Entra app registration, the redirect URI must be exactly
   `https://localhost:18443/auth/oidc/callback` (platform: Web) and a client secret must exist.
4. Copy this directory (the server edits and commits in it) and start it:

```sh
cp -R examples/homelab-login /tmp/ledger && cd /tmp/ledger && git init -b main && git add . && git commit -m seed
export RACKBOOK_OIDC_CLIENT_SECRET='<client secret value>'   # never commit it
export RACKBOOK_SESSION_KEY="$(openssl rand -base64 32)"
rackbook serve --listen 127.0.0.1:18443 --base-url https://localhost:18443 \
  --tls-cert localhost.crt --tls-key localhost.key
```

Open <https://localhost:18443>. Without a remote, passkeys and edits are committed to the local
repository only. Rotating `RACKBOOK_SESSION_KEY` logs everyone out.
