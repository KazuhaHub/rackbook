# Ignore any go.work in a parent directory; this module builds on its own.
export GOWORK := off

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOPKGS  := ./cmd/... ./internal/... ./web

.PHONY: build web go-build test vet check smoke run docker clean

# Full build: console first (it is embedded into the binary), then the binary.
build: web go-build

web:
	npm --prefix web ci
	npm --prefix web run build

go-build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o rackbook ./cmd/rackbook

vet:
	go vet $(GOPKGS)

test:
	go test -race $(GOPKGS)

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
	rm -rf rackbook dist
