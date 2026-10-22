BINARY_NAME := php2shell-check
BIN_DIR     := bin
VERSION     ?= 0.1.0-dev
COMMIT      ?= none
DATE        ?= unknown

export GOTOOLCHAIN ?= go1.25.7

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

ifeq ($(OS),Windows_NT)
	BINARY_EXT := .exe
else
	BINARY_EXT :=
endif

.PHONY: all build test lint vet clean

all: vet lint test build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)$(BINARY_EXT) ./cmd/php2shell-check
ifeq ($(OS),Windows_NT)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/php2shell-check
endif

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

clean:
	go clean -testcache
	rm -rf $(BIN_DIR)
