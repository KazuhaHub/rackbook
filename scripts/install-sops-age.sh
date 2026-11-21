#!/usr/bin/env bash
# Installs the pinned sops and age (age-keygen) for the tests of the infra
# secrets editor (linux/amd64 runners). The versions and SHA-256 digests match
# the Dockerfile; bump them together. Usage: install-sops-age.sh [bin-dir]
set -euo pipefail

SOPS_VERSION=3.13.3
SOPS_SHA256=e5bec3346a873ae91d871550f3e698c1aad962aff462a080e40f25fde17fef6b
AGE_VERSION=1.3.2
AGE_SHA256=cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10

bin="${1:-$HOME/.local/bin}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$bin"

curl -fsSL -o "$tmp/sops" "https://github.com/getsops/sops/releases/download/v${SOPS_VERSION}/sops-v${SOPS_VERSION}.linux.amd64"
echo "${SOPS_SHA256}  $tmp/sops" | sha256sum -c -
curl -fsSL -o "$tmp/age.tgz" "https://github.com/FiloSottile/age/releases/download/v${AGE_VERSION}/age-v${AGE_VERSION}-linux-amd64.tar.gz"
echo "${AGE_SHA256}  $tmp/age.tgz" | sha256sum -c -
tar -xzf "$tmp/age.tgz" -C "$tmp" age/age age/age-keygen
install -m 0755 "$tmp/sops" "$tmp/age/age" "$tmp/age/age-keygen" "$bin/"
"$bin/sops" --version --disable-version-check
"$bin/age-keygen" --version
