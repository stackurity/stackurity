VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# Checkout of the private stackurity-pro repository, for the licensed edition.
PRO ?= ../stackurity-pro
EE_FLAGS = -tags ee -overlay ee-overlay.json

.PHONY: build web test lint image clean ee-overlay build-ee test-ee image-ee

build: web
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/stackurity ./cmd/stackurity

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

test-ee: ee-overlay
	go test $(EE_FLAGS) ./...

image-ee:
	docker build --build-context pro=$(PRO) --build-arg EDITION=ee --build-arg VERSION=$(VERSION) -t stackurity-ee:$(VERSION) .

clean:
	rm -rf bin web/dist/assets web/dist/index.html
