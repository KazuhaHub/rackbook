#!/usr/bin/env bash
# Decides which CI jobs a pull request needs, from the files it changes.
#
#   git -c core.quotePath=false diff --no-renames --name-only BASE HEAD | scripts/ci-changes.sh
#
# Reads the changed paths on stdin (the working tree is HEAD, for the content
# checks) and prints go=, web=, fuzz=, cross= and docker= lines (true/false)
# for $GITHUB_OUTPUT. A path it does not recognise runs the Go jobs; a change to
# CI itself (this script, ci.yml, the Makefile) runs everything; an empty list
# runs everything too. Pushes to main do not use it: they run every job.
#
#   go     gofmt, vet, staticcheck, actionlint, go test -race, govulncheck
#   web    the console checks and the i18n DOM check
#   fuzz   the secret scanner fuzz run
#   cross  every release target built with CGO_ENABLED=0, plus a smoke run
#   docker the multi-arch image build
set -euo pipefail

go=false web=false fuzz=false cross=false docker=false
all() { go=true web=true fuzz=true cross=true docker=true; }

# A Go file whose build depends on the platform: a GOOS/GOARCH file name
# suffix, a build constraint, or code that differs by platform, or any file in a
# package that has such a file (a platform file may use what it declares).
# Cross-compiling is what catches these; other Go code builds the same on every
# target.
platform_file() {
	local f=$1
	[[ $f =~ _(aix|android|darwin|dragonfly|freebsd|illumos|ios|js|linux|netbsd|openbsd|plan9|solaris|wasip1|windows|unix|other|386|amd64|arm|arm64|loong64|mips|mips64|mips64le|mipsle|ppc64|ppc64le|riscv64|s390x|wasm)(_test)?\.go$ ]] && return 0
	# a deleted file cannot be read: assume it mattered
	[[ -f $f ]] || return 0
	grep -qE '^//go:build|^// \+build|"syscall"|"golang.org/x/sys/|runtime\.GOOS|runtime\.GOARCH|"unsafe"|"os/signal"|"os/user"' "$f"
}
platform_specific() {
	local f=$1 d
	platform_file "$f" && return 0
	d=$(dirname "$f")
	for g in "$d"/*.go; do
		[[ -f $g ]] && platform_file "$g" && return 0
	done
	return 1
}

n=0
while IFS= read -r f; do
	[[ -n $f ]] || continue
	n=$((n + 1))
	case $f in
	.github/workflows/ci.yml | Makefile | scripts/ci-changes.sh | scripts/install-sops-age.sh)
		all
		;;
	go.mod | go.sum)
		go=true fuzz=true cross=true docker=true
		;;
	Dockerfile | .dockerignore)
		docker=true
		;;
	web/package.json | web/package-lock.json)
		web=true docker=true
		;;
	web/*.go)
		go=true
		;;
	# read by Go: the country list test, and the embedded dist directory
	web/src/lib/countries.ts | web/dist/*)
		go=true web=true
		;;
	web/*)
		web=true
		;;
	# the mock API serves examples/homelab; Go tests check the examples too
	examples/*)
		go=true web=true
		;;
	internal/secretscan/*)
		go=true fuzz=true
		platform_specific "$f" && cross=true
		;;
	*.go)
		go=true
		platform_specific "$f" && cross=true
		;;
	# prose only: no job reads the top-level Markdown files, docs/*.md or the
	# licence (Markdown deeper down, in examples or testdata, is ledger content)
	LICENSE) ;;
	*.md)
		if [[ $f == */*/* || ( $f == */* && $f != docs/* ) ]]; then go=true; fi
		;;
	# other workflows are checked by actionlint; anything else may be read by a Go test
	*)
		go=true
		;;
	esac
done

[[ $n -gt 0 ]] || all

printf 'go=%s\nweb=%s\nfuzz=%s\ncross=%s\ndocker=%s\n' "$go" "$web" "$fuzz" "$cross" "$docker"
