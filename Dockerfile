# syntax=docker/dockerfile:1

# 1. Console
FROM --platform=$BUILDPLATFORM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# 2. Static binary with the console embedded
# Pinned by digest to the same Go patch release as go.mod; bump both together.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
# The modules (docs/modules.md) are separate binaries in the same image.
RUN for cmd in rackbook rackbook-entra rackbook-notify; do \
      CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
      go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/$cmd ./cmd/$cmd || exit 1; \
    done

# 3. sops and age, for the infra secrets editor (docs/design.md decision 25).
# Pinned by version and verified by SHA-256 at build time: the sops digests are
# the ones in the release's sops-v3.13.3.checksums.txt, the age ones are the
# digests of the release tarballs. Bump the version and the digests together.
FROM --platform=$BUILDPLATFORM alpine:3.22 AS tools
ARG TARGETARCH
ARG SOPS_VERSION=3.13.3
ARG SOPS_SHA256_AMD64=e5bec3346a873ae91d871550f3e698c1aad962aff462a080e40f25fde17fef6b
ARG SOPS_SHA256_ARM64=53b0abacd38ef1b12a66d6c100956691b9cefce018d91f81e73ddf7438b94d77
ARG AGE_VERSION=1.3.2
ARG AGE_SHA256_AMD64=cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10
ARG AGE_SHA256_ARM64=6b8dc4333c53a5a57c9e5834e3a48f92605d7154014cd07269ff3327db5d37f4
RUN apk add --no-cache ca-certificates curl \
 && case "$TARGETARCH" in \
      amd64) sops_sha=$SOPS_SHA256_AMD64; age_sha=$AGE_SHA256_AMD64 ;; \
      arm64) sops_sha=$SOPS_SHA256_ARM64; age_sha=$AGE_SHA256_ARM64 ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac \
 && mkdir /out && cd /tmp \
 && curl -fsSL -o sops "https://github.com/getsops/sops/releases/download/v${SOPS_VERSION}/sops-v${SOPS_VERSION}.linux.${TARGETARCH}" \
 && echo "${sops_sha}  sops" | sha256sum -c - \
 && curl -fsSL -o age.tgz "https://github.com/FiloSottile/age/releases/download/v${AGE_VERSION}/age-v${AGE_VERSION}-linux-${TARGETARCH}.tar.gz" \
 && echo "${age_sha}  age.tgz" | sha256sum -c - \
 && tar -xzf age.tgz age/age-keygen age/age \
 && install -m 0755 sops age/age age/age-keygen /out/

# 4. Runtime: git and ssh are needed to pull and push the data repository
FROM alpine:3.22
RUN apk add --no-cache git openssh-client ca-certificates \
 && adduser -D -u 10001 rackbook \
 && mkdir /data && chown rackbook /data
COPY --from=build /out/rackbook /out/rackbook-entra /out/rackbook-notify /usr/local/bin/
COPY --from=tools /out/sops /out/age /out/age-keygen /usr/local/bin/
USER rackbook
WORKDIR /data
VOLUME /data
EXPOSE 8080
# The container listens on 0.0.0.0, so the server refuses to start without
# authentication. Pass `--auth cloudflare-access --cf-team ... --cf-aud ...`
# (or RACKBOOK_AUTH / RACKBOOK_CF_TEAM / RACKBOOK_CF_AUD), or, for a throwaway
# local demo only, `--insecure-no-auth` (RACKBOOK_INSECURE_NO_AUTH=true).
ENTRYPOINT ["rackbook"]
CMD ["serve", "--listen", "0.0.0.0:8080"]
