VERSION=$(shell git describe --tags --always)
COMMIT=$(shell git rev-parse HEAD)
BUILD=$(shell date +%FT%T%z)
PKG=github.com/guacsec/guac

LDFLAGS="-X $(PKG).version=$(VERSION) -X $(PKG).commit=$(COMMIT) -X $(PKG).date=$(BUILD)"

.DEFAULT_GOAL := build

.PHONY: all
all: test cover fmt lint ci build generate

.PHONY: test
test: generate ## Run the unit tests
	echo 'mode: atomic' > coverage.txt && go test -covermode=atomic -coverprofile=coverage.txt -v -race -timeout=30s ./...

.PHONY: integration-test
integration-test: generate ## Run the integration tests
	go test -tags=integration ./...

.PHONY: cover
cover: test ## Run all the tests and opens the coverage report
	go tool cover -html=coverage.txt

.PHONY: fmt
fmt: ## Check the formatting
	test -z "$(shell find . -name '*.go' -not -wholename './vendor/*' -not -name '*.pb.go' -exec goimports -l -e {} \;)"
	test -z "$(shell find . -name '*.go' -not -wholename './vendor/*' -not -name '*.pb.go' -exec .github/scripts/copyright.sh {} \;)"

.PHONY: lint
lint: ## Run all the linters
	golangci-lint run ./...

.PHONY: ci
ci: fmt lint test ## Run all the tests and code checks

.PHONY: build
build: generate ## Build a version
	go build -ldflags ${LDFLAGS} -o bin/collector cmd/collector/main.go
	go build -ldflags ${LDFLAGS} -o bin/ingest cmd/ingest/main.go
	go build -ldflags ${LDFLAGS} -o bin/guacone cmd/guacone/main.go
	go build -ldflags ${LDFLAGS} -o bin/pubsub_test cmd/pubsub_test/main.go

.PHONY: proto
proto: pkg/collectsub/collectsub/collectsub.proto
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$^

.PHONY: clean
clean: ## Remove temporary files
	go clean

# Absolutely awesome: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'


.PHONY:format fmt-md
format: fmt-md ##  Run all the formatting tasks
fmt-md: ## Format all the markdown files
	npx --yes prettier --write --prose-wrap always **/*.md

.PHONY: generate # generate code from autogen tools (gqlgen, genqlclient)
generate:
	go generate ./...
