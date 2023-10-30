VERSION=$(shell git describe --tags --always)
COMMIT=$(shell git rev-parse HEAD)
BUILD=$(shell date +%FT%T%z)
PKG=github.com/guacsec/guac/pkg/version
LDFLAGS="-X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(BUILD)"

CONTAINER ?= docker
CPUTYPE=$(shell uname -m | sed 's/x86_64/amd64/')
GITHUB_REPOSITORY ?= guacsec/guac
LOCAL_IMAGE_NAME ?= local-organic-guac

.DEFAULT_GOAL := build

.PHONY: all
all: test cover fmt lint build generate

# Run the unit tests
.PHONY: test
test: generate
	echo 'mode: atomic' > coverage.txt && go test -covermode=atomic -coverprofile=coverage.txt -v -race -timeout=30s ./...

# Run the integration tests. Requires github token for scorecard (GITHUB_AUTH_TOKEN=<your token>)
# To run it locally you can run the following command: make start-integration-service
.PHONY: integration-test
integration-test: generate check-env
	go test -tags=integration ./...

# Runs the integration tests locally using docker-compose to start the dependencies and cleans up after itself.
.PHONY: integration-test-local
integration-test-local: generate check-env start-integration-service
	# wait for the service to start which is a http server at 8080 port
	@echo "Waiting for the service to start"
	@counter=0; \
	while [ $$counter -lt 15 ] && ! curl --silent --head --output /dev/null --fail http://localhost:8080; do \
		printf '.'; \
		sleep 1; \
		counter=$$((counter+1)); \
	done; \
	[ $$counter -eq 15 ] && { echo "Service did not start in time"; exit 1; } || echo "Service is up!"
	ENT_TEST_DATABASE_URL='postgresql://guac:guac@localhost/guac?sslmode=disable' go test -tags=integration ./...
	$(CONTAINER) compose down

.PHONY: integration-merge-test
integration-merge-test: generate check-env
	go test -tags=integrationMerge ./...

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
	test -z "$(shell find . -name '*.go' -not -path './.git/*' -not -wholename './vendor/*' -not -name '*.pb.go' -exec goimports -l -e {} \;)"
	@echo "Testing copyright notice"
	test -z "$(shell find . -name '*.go' -not -path './.git/*' -not -wholename './vendor/*' -not -name '*.pb.go' -exec .github/scripts/copyright.sh {} \;)"


# Check that generated files are up to date
.PHONY: generated_up_to_date
generated_up_to_date: generate
	test -z "$(shell git status -s)"

# Run all the linters
.PHONY: lint
lint: check-golangci-lint-tool-check
	golangci-lint run ./...

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

# generate code from autogen tools (gqlgen, genqlclient, mockgen, ent)
.PHONY: generate
generate:
	go generate ./...

# build bins for goos/goarch of current host
.PHONY: build_bins
build_bins:
	goreleaser build --clean --snapshot --single-target

# Build bins and copy to ./bin to align with docs
# Separate build_bins as its own target to ensure (workaround) goreleaser finish writing dist/artifacts.json
.PHONY: build
build: check-goreleaser-tool-check build_bins
	@mkdir -p bin
	@echo "$(shell cat dist/artifacts.json | jq '.[]| { path: .path, name: .extra.ID } | join(" ")' -r)" | xargs -n 2 sh -c 'cp $$0 ./bin/$$1'
	@echo "\nThe guac bins are available in ./bin"

.PHONY: build_local_container
build_local_container: GORELEASER_CURRENT_TAG ?= v0.0.0-$(LOCAL_IMAGE_NAME)
build_local_container:
    # docker CLI options are inconsistent across platforms; had to use the pretty print output here to extract the current context
	GITHUB_REPOSITORY=$(GITHUB_REPOSITORY) \
	GORELEASER_CURRENT_TAG=$(GORELEASER_CURRENT_TAG) \
	DOCKER_CONTEXT=$(shell docker context ls | grep '*' | awk '{print $$1}') \
	goreleaser release --clean --snapshot --skip-sign --skip-sbom

# Build and package a guac container for local testing
# Separate build_container as its own target to ensure (workaround) goreleaser finish writing dist/artifacts.json
.PHONY: container
container: check-docker-tool-check check-docker-buildx-tool-check check-goreleaser-tool-check build_local_container
    # tag/name the image according to current docs to avoid changes
	@$(CONTAINER) tag \
	"$(shell cat dist/artifacts.json | jq --raw-output '.[] | select( .type =="Docker Image" ) | select( .goarch =="$(CPUTYPE)" ).name')" \
	$(LOCAL_IMAGE_NAME)
	@echo "\nThe guac container image is tagged locally as $(LOCAL_IMAGE_NAME)"

# To run the service, run `make container` and then `make service`
# making the container is a longer process and thus not a dependency of service.
.PHONY: start-service
start-service: check-docker-compose-tool-check
	# requires force recreate since docker compose reuses containers and neo4j does
	# not handle that well.
	#
	# if container images are missing, run `make container` first
	$(CONTAINER) compose -f docker-compose.yml -f container_files/mem.yaml up --force-recreate

# to flush state, service-stop must be used else state is taken from old containers
.PHONY: stop-service
stop-service:
	$(CONTAINER) compose down

# This is a helper target to run the integration tests locally. 
.PHONY: start-integration-service
start-integration-service: check-docker-compose-tool-check
	$(CONTAINER) compose -f integration.docker-compose.yaml up 	--force-recreate -d

.PHONY: check-docker-tool-check
check-docker-tool-check:
	@if ! command -v $(CONTAINER) >/dev/null 2>&1; then \
		echo "'$(CONTAINER)' is not installed. Please install '$(CONTAINER)' and try again. Or set the CONTAINER variable to a different container runtime engine."; \
		exit 1; \
	fi

# Check that docker buildx is installed.
.PHONY: check-docker-buildx-tool-check
check-docker-buildx-tool-check:
	@if ! $(CONTAINER) buildx >/dev/null 2>&1; then \
		echo "'$(CONTAINER)' buildx is not installed. Please install '$(CONTAINER)' buildx and try again."; \
		exit 1; \
	fi

# Check that docker compose is installed.
.PHONY: check-docker-compose-tool-check
check-docker-compose-tool-check:
	@if ! $(CONTAINER) compose >/dev/null 2>&1; then \
		echo "'$(CONTAINER)' compose is not installed or not correctly linked to. Please install '$(CONTAINER)' compose or link it as a plugin and try again."; \
		exit 1; \
	fi

# Check that protoc is installed.
.PHONY: check-protoc-tool-check
check-protoc-tool-check:
	@if ! command -v protoc >/dev/null 2>&1; then \
		echo "Protoc is not installed. Please install Protoc and try again."; \
		exit 1; \
	fi

# Check that golangci-lint is installed.
.PHONY: check-golangci-lint-tool-check
check-golangci-lint-tool-check:
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Golangci-lint is not installed. Please install Golangci-lint and try again."; \
		exit 1; \
	fi

# Check that mockgen is installed.
.PHONY: check-mockgen-tool-check
check-mockgen-tool-check:
	@if ! command -v mockgen >/dev/null 2>&1; then \
		echo "mockgen is not installed. Please install mockgen and try again."; \
		exit 1; \
	fi

.PHONY: check-goreleaser-tool-check
check-goreleaser-tool-check:
	@if ! command -v goreleaser >/dev/null 2>&1; then \
		echo "goreleaser is not installed. Please install goreleaser and try again."; \
		exit 1; \
	fi

# Check that all the tools are installed.
.PHONY: check-tools
check-tools: check-docker-tool-check check-docker-buildx-tool-check check-docker-compose-tool-check check-protoc-tool-check check-golangci-lint-tool-check check-mockgen-tool-check check-goreleaser-tool-check
