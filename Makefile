VERSION=$(shell git describe --tags --always)
COMMIT=$(shell git rev-parse HEAD)
BUILD=$(shell date +%FT%T%z)
PKG=github.com/guacsec/guac

LDFLAGS="-X $(PKG).version=$(VERSION) -X $(PKG).commit=$(COMMIT) -X $(PKG).date=$(BUILD)"

.DEFAULT_GOAL := build

.PHONY: all
all: test cover fmt lint build generate

# Run the unit tests
.PHONY: test
test: generate
	echo 'mode: atomic' > coverage.txt && go test -covermode=atomic -coverprofile=coverage.txt -v -race -timeout=30s ./...

# Run the integration tests. Requires github token for scorecard (GITHUB_AUTH_TOKEN=<your token>)
.PHONY: integration-test
integration-test: generate check-env
	go test -tags=integration ./...

.PHONY: check-env
ifndef GITHUB_AUTH_TOKEN
	$(error GITHUB_AUTH_TOKEN is not set)
endif

# Run all the tests and opens the coverage report
.PHONY: cover
cover: test
	go tool cover -html=coverage.txt

# Check the formatting
.PHONY: fmt
fmt:
	@echo "Testing formatting and imports"
	test -z "$(shell find . -name '*.go' -not -wholename './vendor/*' -not -name '*.pb.go' -exec goimports -l -e {} \;)"
	@echo "Testing copyright notice"
	test -z "$(shell find . -name '*.go' -not -wholename './vendor/*' -not -name '*.pb.go' -exec .github/scripts/copyright.sh {} \;)"

# Check that generated files are up to date
.PHONY: generated_up_to_date
generated_up_to_date: generate
	test -z "$(shell git status -s)"

# Run all the linters
.PHONY: lint
lint: check-golangci-lint-tool-check
	golangci-lint run ./...

# Build a version
.PHONY: build
build: generate
	go build -ldflags ${LDFLAGS} -o bin/collector cmd/collector/main.go
	go build -ldflags ${LDFLAGS} -o bin/ingest cmd/ingest/main.go
	go build -ldflags ${LDFLAGS} -o bin/guacone cmd/guacone/main.go
	go build -ldflags ${LDFLAGS} -o bin/pubsub_test cmd/pubsub_test/main.go
	go build -ldflags ${LDFLAGS} -o bin/guacgql cmd/guacgql/main.go

.PHONY: proto
proto: 
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		pkg/collectsub/collectsub/collectsub.proto
	protoc --go_out=. --go_opt=paths=source_relative \
	    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
		pkg/handler/collector/deps_dev/internal/api.proto

# Remove temporary files
.PHONY: clean
clean:
	go clean

# Absolutely awesome: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

#  Run all the formatting tasks
.PHONY: format
format: fmt-md

# Format all the markdown files
.PHONY: fmt-md
fmt-md:
	npx --yes prettier --write --prose-wrap always **/*.md

# generate code from autogen tools (gqlgen, genqlclient, mockgen)
.PHONY: generate
generate:
	go generate ./...

.PHONY: container
container: check-docker-tool-check
	docker build -f dockerfiles/Dockerfile.guac-cont -t local-organic-guac .
	docker build -f dockerfiles/Dockerfile.healthcheck -t local-healthcheck .


# To run the service, run `make container` and then `make service`
# making the container is a longer process and thus not a dependency of service.
.PHONY: start-service
start-service:
	# requires force recreate since docker compose reuses containers and neo4j does
	# not handle that well.
	#
	# if container images are missing, run `make container` first
	docker compose up --force-recreate	

# to flush state, service-stop must be used else state is taken from old containers
.PHONY: stop-service
stop-service:
	docker compose down

.PHONY: check-docker-tool-check
check-docker-tool-check:
	@if ! command -v docker &> /dev/null; then \
		echo "Docker is not installed. Please install Docker and try again."; \
		exit 1; \
	fi

# Check that protoc is installed.
.PHONY: check-protoc-tool-check
check-protoc-tool-check:
	@if ! command -v protoc &> /dev/null; then \
		echo "Protoc is not installed. Please install Protoc and try again."; \
		exit 1; \
	fi

# Check that golangci-lint is installed.
.PHONY: check-golangci-lint-tool-check
check-golangci-lint-tool-check:
	@if ! command -v golangci-lint &> /dev/null; then \
		echo "Golangci-lint is not installed. Please install Golangci-lint and try again."; \
		exit 1; \
	fi

# Check that mockgen is installed.
.PHONY: check-mockgen-tool-check
check-mockgen-tool-check:
	@if ! command -v mockgen &> /dev/null; then \
		echo "mockgen is not installed. Please install mockgen and try again."; \
		exit 1; \
	fi

# Check that all the tools are installed.
.PHONY: check-tools
check-tools: check-docker-tool-check check-protoc-tool-check check-golangci-lint-tool-check check-mockgen-tool-check
