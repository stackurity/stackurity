VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# Checkout of the private stackurity-pro repository, for the licensed edition.
PRO ?= ../stackurity-pro
# Build tags of the licensed edition; an edition built on it adds its own
# (EE_TAGS=ee,NAME).
EE_TAGS ?= ee
EE_FLAGS = -tags $(EE_TAGS) -overlay ee-overlay.json

# First-party plugins, built next to the server and shipped in the image.
PLUGINS = aws-managed kubernetes

.PHONY: build plugins web test lint image clean ee-overlay build-ee test-ee image-ee

build: web plugins
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/stackurity ./cmd/stackurity

plugins:
	for p in $(PLUGINS); do CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/plugins/$$p ./plugins/$$p || exit 1; done

web:
	cd web && npm ci --ignore-scripts && npm run build

test:
	go test ./...

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...

image:
	docker build --build-arg VERSION=$(VERSION) -t stackurity:$(VERSION) .

# --- licensed edition (needs access to stackurity-pro; see docs/design/open-core.md)

ee-overlay:
	go run ./tools/eeoverlay -pro $(PRO) > ee-overlay.json

build-ee: web ee-overlay
	CGO_ENABLED=0 go build $(EE_FLAGS) -trimpath -ldflags "-s -w -X main.version=$(VERSION)-ee" -o bin/stackurity-ee ./cmd/stackurity

# The API package alone runs close to go test's default 10 minutes in the
# licensed and cloud builds on CI runners.
TEST_TIMEOUT ?= 25m

test-ee: ee-overlay
	go test $(EE_FLAGS) -timeout $(TEST_TIMEOUT) ./...

image-ee:
	docker build --build-context pro=$(PRO) --build-arg EDITION=ee --build-arg EE_TAGS=$(EE_TAGS) --build-arg VERSION=$(VERSION) -t stackurity-ee:$(VERSION) .

clean:
	rm -rf bin web/dist/assets web/dist/index.html
