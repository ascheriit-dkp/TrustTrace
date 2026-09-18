GO ?= go
CLANG ?= clang
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
ARCH ?= $(shell $(GO) env GOARCH)
BPF_FLAGS = -target bpfel -O2 -g -Wall -Werror -ffile-prefix-map=$(CURDIR)=.
GO_FLAGS = -trimpath -buildvcs=false -ldflags='-s -w -buildid= -X main.version=$(VERSION) -X main.commit=$(COMMIT)'

.PHONY: all build generate fmt vet test integration check release clean
all: build

# Both objects are embedded, so release builds require no compiler at runtime.
generate:
	$(CLANG) $(BPF_FLAGS) -D__TARGET_ARCH_x86 -c internal/collector/bpf/trace.bpf.c -o internal/collector/trace_amd64.o
	$(CLANG) $(BPF_FLAGS) -D__TARGET_ARCH_arm64 -c internal/collector/bpf/trace.bpf.c -o internal/collector/trace_arm64.o

build:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) $(GO) build $(GO_FLAGS) -o bin/trusttrace ./cmd/trusttrace

fmt:
	gofmt -w cmd internal

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

integration: build
	if [ "$(ARCH)" = amd64 ]; then $(CLANG) -m32 -nostdlib -static -Wl,--build-id=none testdata/compat32.S -o bin/compat32; fi
	$(GO) test -c -o bin/collector.test ./internal/collector
	sudo env TRUSTTRACE_INTEGRATION=1 TRUSTTRACE_COMPAT_FIXTURE="$$(pwd)/bin/compat32" ./bin/collector.test -test.v -test.timeout=180s
	$(GO) test -c -o bin/cli.test ./cmd/trusttrace
	sudo env TRUSTTRACE_INTEGRATION=1 ./bin/cli.test -test.v -test.timeout=180s
	python3 scripts/cli-smoke.py ./bin/trusttrace

check: vet test
	test -z "$$(gofmt -l cmd internal)"

release: generate
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GO_FLAGS) -o dist/trusttrace-linux-amd64 ./cmd/trusttrace
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(GO_FLAGS) -o dist/trusttrace-linux-arm64 ./cmd/trusttrace
	cp LICENSE THIRD_PARTY_NOTICES.md dist/
	cd dist && sha256sum trusttrace-linux-amd64 trusttrace-linux-arm64 LICENSE THIRD_PARTY_NOTICES.md > SHA256SUMS
	python3 scripts/verify-release.py dist

clean:
	rm -rf bin dist coverage.out
