VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: test build run fmt vet clean help

## test: run all tests
test:
	go test ./...

## build: build the aggregator
build:
	go build -ldflags="$(LDFLAGS)" -o aggregator .

## run: build and run against the built-in sources
run: build
	ulimit -n 65535 && ./aggregator

## fmt: format all Go files
fmt:
	gofmt -w .

## vet: run go vet
vet:
	go vet ./...

## clean: remove the binary (never touches published output)
clean:
	rm -f aggregator

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
