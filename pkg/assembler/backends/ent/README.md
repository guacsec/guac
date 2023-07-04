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

### Bulk Upserting Trees

Both Package and Source trees use multiple tables, which means it would be impossible to upsert using standard upsert semantics.

Here are a few ways we could solve this for performance:

1. Denormalize the entire tree to single table with nulls for the columns that aren't present, allowing us to upsert all layers of the tree in a single upsert request. This has one limitation that we'd need to know the primary keys which is impossible to return using batch upserts.
2. Do a presence query first before inserting the nodes that are missing. This isn't strictly an upsert since it's done at the application layer and would require locking other writers.
3. Generate the primary keys client side using UUIDs (v7 preferrably) and upsert each layer of the tree using `BulkCreate()` — NOTE: This will break Global Unique IDs unless we prefix everything, which will further complicate DB Indexes. This is only strictly needed to Node/Nodes queries.

Option 3 is probably the easiest to adopt, but we'd need to make that schema change before merging this in, or drop the DB and recreate it with the new schema since there's really no simple way to migrate from ints to uuids.
