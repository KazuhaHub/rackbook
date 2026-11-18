# syntax=docker/dockerfile:1

# 1. Console
FROM --platform=$BUILDPLATFORM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# 2. Static binary with the console embedded
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/rackbook ./cmd/rackbook

# 3. Runtime: git and ssh are needed to pull and push the data repository
FROM alpine:3.22
RUN apk add --no-cache git openssh-client ca-certificates \
 && adduser -D -u 10001 rackbook \
 && mkdir /data && chown rackbook /data
COPY --from=build /out/rackbook /usr/local/bin/rackbook
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
