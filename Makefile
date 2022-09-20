VERSION=$(shell git describe --tags --always)
COMMIT=$(shell git rev-parse HEAD)
BUILD=$(shell date +%FT%T%z)
PKG=github.com/guacsec/guac

LDFLAGS="-X $(PKG).version=$(VERSION) -X $(PKG).commit=$(COMMIT) -X $(PKG).date=$(BUILD)"

.DEFAULT_GOAL := build

.PHONY: all
all: test cover fmt lint ci build

.PHONY: test
test: ## Run the unit tests
	echo 'mode: atomic' > coverage.txt && go test -covermode=atomic -coverprofile=coverage.txt -v -race -timeout=30s ./...

.PHONY: integration-test
integration-test: ## Run the integration tests
	go test -tags=integration ./...

.PHONY: cover
cover: test ## Run all the tests and opens the coverage report
	go tool cover -html=coverage.txt

.PHONY: fmt
fmt: ## Check the formatting
	test -z "$(shell goimports -l -e .)"
	test -z "$(shell find . -name '*.go' -not -wholename './vendor/*' -exec .github/scripts/copywrite.sh {} \;)"

.PHONY: lint
lint: ## Run all the linters
	golangci-lint run ./...

.PHONY: ci
ci: fmt lint test ## Run all the tests and code checks

.PHONY: build
build: ## Build a version
	go build -ldflags ${LDFLAGS} -o bin/collector cmd/collector/main.go
	go build -ldflags ${LDFLAGS} -o bin/ingest cmd/ingest/main.go
	go build -ldflags ${LDFLAGS} -o bin/guacone cmd/guacone/main.go

.PHONY: clean
clean: ## Remove temporary files
	go clean

# Absolutely awesome: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

