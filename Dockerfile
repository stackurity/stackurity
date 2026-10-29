# syntax=docker/dockerfile:1

# The web and Go stages run on the build machine and cross-compile; only the
# final stage is per target platform, so arm64 images need no emulation.
FROM --platform=$BUILDPLATFORM node:26.12.1-alpine3.24 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run build

# The licensed edition's files. Empty for Community; the ee image is built
# with --build-context pro=PATH-TO-stackurity-pro --build-arg EDITION=ee;
# EE_TAGS adds build tags an edition built on it needs (default "ee").
FROM scratch AS pro

FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
ARG VERSION=dev
ARG EDITION=community
ARG EE_TAGS=ee
ARG TARGETARCH
RUN --mount=type=bind,from=pro,target=/pro set -e; FLAGS=""; \
    if [ "$EDITION" = ee ]; then go run ./tools/eeoverlay -pro /pro > /tmp/ee.json; FLAGS="-tags $EE_TAGS -overlay /tmp/ee.json"; fi; \
    export GOOS=linux GOARCH=${TARGETARCH:-amd64}; \
    CGO_ENABLED=0 go build $FLAGS -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/stackurity ./cmd/stackurity; \
    for p in aws-managed kubernetes; do \
      CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/plugins/$p ./plugins/$p; \
    done; \
    # Agent builds the server hands to new hosts (Assets > Add server).
    mkdir -p /out/agents; for arch in amd64 arm64; do \
      CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build $FLAGS -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/agents/stackurity-linux-$arch ./cmd/stackurity; \
      (cd /out/agents && sha256sum stackurity-linux-$arch > stackurity-linux-$arch.sha256); \
    done

FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS syft
# Syft generates container image SBOMs from registries (no container runtime).
# Built from source with this toolchain rather than taking the release
# binary: Syft's own builds lag Go security releases. SYFT_DEPS raises
# modules whose fixes Syft has not picked up yet; drop an entry once Syft's
# go.mod has it. Modules come from the Go proxy and are verified against the
# checksum database. The image scan in CI fails on anything fixable left.
ARG SYFT_VERSION=1.55.0
ARG SYFT_DEPS="github.com/go-jose/go-jose/v4@v4.1.6 golang.org/x/net@v0.62.0"
ARG TARGETARCH
WORKDIR /syft
RUN go mod init syft-build \
 && go get github.com/anchore/syft/cmd/syft@v${SYFT_VERSION} ${SYFT_DEPS} \
 && CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build -trimpath \
      -ldflags "-s -w -X main.version=${SYFT_VERSION}" -o /usr/local/bin/syft github.com/anchore/syft/cmd/syft

FROM alpine:3.24
# git: shallow clones for repository scanning (data only, never executed).
RUN apk add --no-cache ca-certificates git tzdata \
 && adduser -D -H -u 10001 stackurity \
 && mkdir -p /var/lib/stackurity && chown stackurity /var/lib/stackurity
COPY --from=build /out/stackurity /usr/local/bin/stackurity
# First-party plugins, root-owned so the server user cannot modify them.
COPY --from=build --chmod=0755 /out/plugins/ /usr/local/lib/stackurity/plugins/
COPY --from=syft /usr/local/bin/syft /usr/local/bin/syft
COPY --from=build --chmod=0755 /out/agents/ /usr/local/lib/stackurity/agents/
USER 10001
ENV STACKURITY_DATA_DIR=/var/lib/stackurity STACKURITY_LISTEN=:8080 STACKURITY_PLUGIN_DIR=/usr/local/lib/stackurity/plugins \
    STACKURITY_AGENT_DIR=/usr/local/lib/stackurity/agents
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/readyz || exit 1
ENTRYPOINT ["stackurity"]
CMD ["server"]
