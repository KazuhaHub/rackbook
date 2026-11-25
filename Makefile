# Ignore any go.work in a parent directory; this module builds on its own.
export GOWORK := off

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
# Every Go package of the module. Not ./...: that would also pick up a Go
# package inside web/node_modules once npm has installed the console.
# make pkgs-check (part of go-lint) fails when a package is missing here.
GOPKGS  := ./cmd/... ./internal/... ./modules/... ./modsettings/... ./web

# The checks CI runs (.github/workflows/ci.yml calls these same targets).
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2
ACTIONLINT  := github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
# CI adds -count=1 so a run never reuses cached results.
TESTFLAGS ?=

.PHONY: build web go-build test test-shard vet pkgs-check smoke-build fmt-check staticcheck actionlint go-lint web-check web-i18n-dom ci check smoke run docker clean

# Full build: console first (it is embedded into the binary), then the binary.
build: web go-build

web:
	npm --prefix web ci
	npm --prefix web run build

go-build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o rackbook ./cmd/rackbook
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o rackbook-entra ./cmd/rackbook-entra
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o rackbook-notify ./cmd/rackbook-notify

vet:
	go vet $(GOPKGS)

# Every Go file git tracks or would track (node_modules is ignored).
fmt-check:
	@out="$$(git ls-files -z -co --exclude-standard '*.go' | xargs -0 gofmt -l)" || exit 1; if [ -n "$$out" ]; then echo "These files are not gofmt-formatted:"; echo "$$out"; exit 1; fi

staticcheck:
	go run $(STATICCHECK) $(GOPKGS)

# Checks the workflow files themselves: expressions, job wiring, inputs.
actionlint:
	go run $(ACTIONLINT)

# Fails when the module has a package that GOPKGS leaves out (and so would go
# untested and unchecked).
pkgs-check:
	@all="$$(go list ./...)" && listed="$$(go list $(GOPKGS))" \
	  && missing="$$(printf '%s\n' "$$all" | grep -v /node_modules/ | grep -vxF -e "$$listed" || true)" \
	  && if [ -n "$$missing" ]; then echo "packages missing from GOPKGS in the Makefile:"; echo "$$missing"; exit 1; fi

# Builds the three binaries as releases are built (static, -trimpath) and runs
# each once (CI job go-lint, and cross-compile for every target).
smoke-build:
	CGO_ENABLED=0 go build -trimpath -o rackbook ./cmd/rackbook
	./rackbook version
	./rackbook check --config examples/homelab/rackbook.yml
	CGO_ENABLED=0 go build -trimpath -o rackbook-entra ./cmd/rackbook-entra
	CGO_ENABLED=0 go build -trimpath -o rackbook-notify ./cmd/rackbook-notify
	./rackbook-entra --version
	./rackbook-notify --version

# The Go checks other than the tests (CI job go-lint).
go-lint: pkgs-check fmt-check vet staticcheck actionlint smoke-build

# With sops and age on PATH the secrets editor is tested against them; without
# them those tests skip, unless RACKBOOK_REQUIRE_SOPS=1 (set in CI) makes them fail.
test:
	go test -race $(TESTFLAGS) $(GOPKGS)

# CI runs the tests in three jobs at once (make test-shard SHARD=1..3). Shards 1
# and 2 name the slowest packages (measured); shard 3 is every other package, so
# a new package always lands in a shard. Together they are exactly make test.
SHARD_1 := ./internal/api ./internal/oauthserver
SHARD_2 := ./internal/gitstore ./internal/mcpauth ./internal/mcpserver
test-shard:
	@case "$(SHARD)" in \
	  1) pkgs="$(SHARD_1)" ;; \
	  2) pkgs="$(SHARD_2)" ;; \
	  3) named="$$(go list $(SHARD_1) $(SHARD_2))" && all="$$(go list $(GOPKGS))" && \
	     pkgs="$$(printf '%s\n' "$$all" | grep -vxF -e "$$named")" && [ -n "$$pkgs" ] ;; \
	  *) echo "SHARD must be 1, 2 or 3"; exit 2 ;; \
	esac && echo go test -race $(TESTFLAGS) $$pkgs && go test -race $(TESTFLAGS) $$pkgs

# The console checks (CI job web-check); run npm --prefix web ci first.
web-check:
	npm --prefix web run lint
	npm --prefix web run typecheck
	npm --prefix web run check:formats
	npm --prefix web run check:record-urls
	npm --prefix web run check:console-logic
	npm --prefix web run check:stale-chunk
	npm --prefix web run check:modules
	npm --prefix web run check:i18n
	npm --prefix web run build

# Loads each page in each language pair in headless Chrome against the mock API
# (CI job web-i18n-dom). Needs google-chrome, or CHROME=<path>.
web-i18n-dom:
	npm --prefix web run check:i18n-dom

# Everything CI checks, in one go (after npm --prefix web ci).
ci: go-lint test web-check web-i18n-dom

# Validate the example ledger with the freshly built binary.
check: go-build
	./rackbook check --config examples/homelab/rackbook.yml

# Smoke-test the built binary: version, check, export, mcp and serve.
smoke: go-build
	bash scripts/smoke.sh ./rackbook examples/homelab/rackbook.yml

run: go-build
	./rackbook serve --config examples/homelab/rackbook.yml --no-git

docker:
	docker build --build-arg VERSION=$(VERSION) -t rackbook:$(VERSION) .

clean:
	rm -rf rackbook rackbook-entra rackbook-notify dist
