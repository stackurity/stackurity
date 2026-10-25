# syntax=docker/dockerfile:1

# The web and Go stages run on the build machine and cross-compile; only the
# final stage is per target platform, so arm64 images need no emulation.
FROM --platform=$BUILDPLATFORM node:22.11.0-alpine3.20 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run build

# The licensed edition's files. Empty for Community; the ee image is built
# with --build-context pro=PATH-TO-stackurity-pro --build-arg EDITION=ee.
FROM scratch AS pro

FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
ARG VERSION=dev
ARG EDITION=community
ARG TARGETARCH
RUN --mount=type=bind,from=pro,target=/pro set -e; FLAGS=""; \
    if [ "$EDITION" = ee ]; then go run ./tools/eeoverlay -pro /pro > /tmp/ee.json; FLAGS="-tags ee -overlay /tmp/ee.json"; fi; \
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

FROM --platform=$BUILDPLATFORM alpine:3.22 AS syft
# Syft generates container image SBOMs from registries (no container runtime).
ARG SYFT_VERSION=1.54.1
ARG TARGETARCH
RUN apk add --no-cache curl \
 && case "$TARGETARCH" in \
      amd64) sum=c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47 ;; \
      arm64) sum=dfdf0537610113edbefe1f1fc6548bc957b2d77439636ec824fcf0e10d46d054 ;; \
      *) echo "unsupported arch $TARGETARCH" && exit 1 ;; \
    esac \
 && curl -fsSLo /tmp/syft.tgz "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz" \
 && echo "$sum  /tmp/syft.tgz" | sha256sum -c - \
 && tar -xzf /tmp/syft.tgz -C /usr/local/bin syft

FROM alpine:3.22
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
