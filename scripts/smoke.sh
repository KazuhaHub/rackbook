#!/usr/bin/env bash
# Smoke test of a built rackbook binary: scripts/smoke.sh <path-to-binary> [config]
# Runs on Linux, macOS and Windows (Git Bash). Needs curl.
set -euo pipefail

bin=${1:?usage: smoke.sh <binary> [config]}
cfg=${2:-examples/homelab/rackbook.yml}
port=${SMOKE_PORT:-18080}
tmp=$(mktemp -d)
pid=
cleanup() { [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; rm -rf "$tmp"; }
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }

step "version"
"$bin" version | tee "$tmp/v"
grep -q '^rackbook ' "$tmp/v"
step "--version"
"$bin" --version | tee "$tmp/v"
grep -q '^rackbook ' "$tmp/v"

step "check"
"$bin" check --config "$cfg"

step "export"
"$bin" export --config "$cfg" --format json -o "$tmp/ledger.json"
test -s "$tmp/ledger.json"
"$bin" export --config "$cfg" --format llms -o "$tmp/llms.txt"
head -n 3 "$tmp/llms.txt"

step "mcp (stdio initialize)"
# The server stops at end of input, so keep stdin open until it has answered.
{ printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'; sleep 3; } \
  | "$bin" mcp --config "$cfg" > "$tmp/mcp.out"
grep -q '"serverInfo"' "$tmp/mcp.out"

step "serve (console and API)"
"$bin" serve --config "$cfg" --no-git --listen "127.0.0.1:$port" > "$tmp/serve.log" 2>&1 &
pid=$!
ok=
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$port/api/meta" -o "$tmp/meta.json" 2>/dev/null; then ok=1; break; fi
  sleep 0.5
done
if [ -z "$ok" ]; then echo "serve did not come up"; cat "$tmp/serve.log"; exit 1; fi
grep -q '"collections"' "$tmp/meta.json"
curl -fsS "http://127.0.0.1:$port/api/check" > /dev/null
curl -fsS "http://127.0.0.1:$port/llms.txt" -o "$tmp/llms-served.txt"
head -n 1 "$tmp/llms-served.txt"
curl -fsS "http://127.0.0.1:$port/" -o "$tmp/index.html"
grep -qi '<html' "$tmp/index.html"   # the console is embedded in the binary
echo "smoke ok"
