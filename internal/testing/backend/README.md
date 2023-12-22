# GUAC Backend Acceptance Test Suite

## How to run

Run all the backend containers using the compose yaml and then run the tests:

```shell
cd internal/testing/backend
docker-compose up -d
go test -v --tags=integration .
```

Also, these tests run in CI. See the "CI for integration tests" job in
[ci.yaml](/.github/workflows/ci.yaml)

All the files here must use the `//go:build integration` tag, so they are not
run with normal unit tests.

## Writing more tests

* Write normal go test functions. For example
  `func TestMytestname(t *testing.T) {`. These will be executed multiple times,
  once for each backend.

* Tests should receive a `backends.Backend` object by calling
  `setupTest(t)`. All testing is done on the received backend.

* Use `github.com/google/go-cmp/cmp` to compare expected and recieved
  values. The `commonOpts` global is used for any `Diff()` calls to that
  library. Add any needed options to that global in `setupOpts()`.

* Use `/internal/testing/testdata` for any test node data.

* Put any simple test data in `helpers_test.go` for reuse, such as `curTime`.

## Adding a backend

* Create a new `<name>_test.go` file and implement the `backend` interface.

* In [main_test.go](main_test.go):

  * Add a new global string to name the backend.

  * Add the backend to the `testBackends` map, with a constructor for the
    `backend` interface.

  * Add any needed skips to the `skipMatrix` map, if the new backend does not
    support all the node types yet.

* Before submitting, update this [docker-compose.yaml](docker-compose.yaml) to start any
  external dependencies needed.
