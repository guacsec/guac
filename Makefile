VERSION=$(shell git describe --tags --always)
COMMIT=$(shell git rev-parse HEAD)
BUILD=$(shell date +%FT%T%z)
PKG=github.com/guacsec/guac

LDFLAGS="-X $(PKG).version=$(VERSION) -X $(PKG).commit=$(COMMIT) -X $(PKG).date=$(BUILD)"

.DEFAULT_GOAL := build

.PHONY: all
all: test cover fmt lint ci build generate

# Run the unit tests
.PHONY: test
test: generate
	echo 'mode: atomic' > coverage.txt && go test -covermode=atomic -coverprofile=coverage.txt -v -race -timeout=30s ./...

# Run the integration tests
.PHONY: integration-test
integration-test: generate
	go test -tags=integration ./...

check-env:
ifndef GITHUB_AUTH_TOKEN
	$(error GITHUB_AUTH_TOKEN is not set)
endif

# Run the end to end tests and requires GITHUB_AUTH_TOKEN to be set. If not the tests will fail.
# Not included in integration tests because it requires a github token.
# To run the tests locally, run `GITHUB_AUTH_TOKEN=<your token> make e2e-test`
# https://github.com/ossf/scorecard#authentication
.PHONY: e2e-test
e2e-test: generate check-env
	go test -tags=e2e ./...

# Run all the tests and opens the coverage report
.PHONY: cover
cover: test
	go tool cover -html=coverage.txt

# Check the formatting
.PHONY: fmt
fmt:
	test -z "$(shell find . -name '*.go' -not -wholename './vendor/*' -not -name '*.pb.go' -exec goimports -l -e {} \;)"
	test -z "$(shell find . -name '*.go' -not -wholename './vendor/*' -not -name '*.pb.go' -exec .github/scripts/copyright.sh {} \;)"

# Check that generated files are up to date
.PHONY: generated_up_to_date
generated_up_to_date: generate
	test -z "$(git status -s)"

# Run all the linters
.PHONY: lint
lint:
	golangci-lint run ./...

# Run all the tests and code checks
.PHONY: ci
ci: fmt lint test generated_up_to_date

# Build a version
.PHONY: build
build: generate
	go build -ldflags ${LDFLAGS} -o bin/collector cmd/collector/main.go
	go build -ldflags ${LDFLAGS} -o bin/ingest cmd/ingest/main.go
	go build -ldflags ${LDFLAGS} -o bin/guacone cmd/guacone/main.go
	go build -ldflags ${LDFLAGS} -o bin/pubsub_test cmd/pubsub_test/main.go

.PHONY: proto
proto: pkg/collectsub/collectsub/collectsub.proto
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$^

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

# generate code from autogen tools (gqlgen, genqlclient)
.PHONY: generate
generate:
	go generate ./...

.PHONY: container
container:
	docker build -f dockerfiles/Dockerfile.guac-cont -t local-organic-guac .
	docker build -f dockerfiles/Dockerfile.healthcheck -t local-healthcheck .


# To run the service, run `make container` and then `make service`
# making the container is a longer process and thus not a dependency of service.
.PHONY: service
service:
	# requires force recreate since docker compose reuses containers and neo4j does
	# not handle that well.
	#
	# if container images are missing, run `make container` first
	docker compose up --force-recreate	
