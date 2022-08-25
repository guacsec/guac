VERSION=$(shell git describe --tags --always)
COMMIT=$(shell git rev-parse HEAD)
BUILD=$(shell date +%FT%T%z)
PKG=github.com/guacsec/guac

LDFLAGS="-X $(PKG).version=$(VERSION) -X $(PKG).commit=$(COMMIT) -X $(PKG).date=$(BUILD)"

.PHONY: all
all: setup test cover fmt lint ci build
    
.PHONY: setup
setup: ## TODO Install all the build and lint dependencies
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.49.0


.PHONY: test
test: ## Run all the tests
	echo 'mode: atomic' > coverage.txt && go test -covermode=atomic -coverprofile=coverage.txt -v -race -timeout=30s ./...


.PHONY: cover
cover: test ## Run all the tests and opens the coverage report
	go tool cover -html=coverage.txt

.PHONY: fmt
fmt: ## Run goimports on all go files
	find . -name '*.go' -not -wholename './vendor/*' -exec goimports -w {} \;

.PHONY: lint
lint: ## TODO Run all the linters
	golangci-lint run ./...

.PHONY: ci
ci: lint test ## Run all the tests and code checks

.PHONY: build
build: ## Build a version
	go build -ldflags ${LDFLAGS} -o bin/ingestor cmd/ingestor/main.go

.PHONY: clean
clean: ## Remove temporary files
	go clean

# Absolutely awesome: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := build
