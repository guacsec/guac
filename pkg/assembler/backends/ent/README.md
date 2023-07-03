# Ent Backend

This contains the RDMS backend powered by Ent.

## Developing

Adding new nodes:

```shell
go run -mod=mod entgo.io/ent/cmd/ent new --target pkg/assembler/backends/ent/schema <NodeName>
```

Generating the schema:

```shell
go generate pkg/assembler/backends/ent/generate.go
```

## Testing

This package requires a real Postgres db to test against, so it is not included in the normal test suite. To run the tests, you must have a Postgres db running locally and set the `ENT_TEST_DATABASE_URL` environment variable to the connection string for that db, or use the default: `postgresql://localhost/guac_test?sslmode=disable`.

For example:

```shell
createdb guac_test
go test ./pkg/assembler/backends/ent/backend/
```

All tests run within a transaction, so they should not leave any data in the db, and each run should start with a clean slate.

## Future Work

### Supporting other databases

This backend uses Ent, which is compatible with a wide array of SQL database engines, including MySQL/Aurora, Sqlite, Postres, TiDB, etc.

This implementation is currently built against Postgres, but it should be possible to support other databases by adding support for their specific handling of indexes, and compiling in the necessary drivers. https://github.com/ivanvanderbyl/guac/blob/8fcfccf5bc4145a31fac6e8dc50e7e01e006292a/pkg/assembler/backends/ent/backend/backend.go#L12
