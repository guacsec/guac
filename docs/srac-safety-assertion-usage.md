# Safety assertion ingestion and queries

This first implementation stores externally authored assertions through GUAC's
GraphQL and backend interfaces, using Ent/PostgreSQL. Assertions retain
declared, versioned PURLs even when no corresponding packages have been
ingested. GUAC does not infer or approve the supplied decision.

## Ingest an assertion

Send this mutation to a GUAC GraphQL server configured with the Ent backend:

```graphql
mutation {
  ingestSafetyAssertion(
    assertion: {
      assertionId: "product-a-library-2"
      safetyRelevance: SAFETY_RELATED
      rationale: "Externally authored assessment for product A"
      decisionStatus: DRAFT
      assertedAt: "2026-10-12T12:00:00Z"
      productPurl: "pkg:generic/product-a@1.0"
      componentPurl: "pkg:generic/library@2.0"
      evidence: [
        { evidenceId: "assessment", uri: "https://example.org/assessment" }
      ]
      origin: "https://example.org/assertions"
      collector: "example"
      documentRef: "blob:example-document"
      documentDigestAlgorithm: "sha256"
      documentDigest: "abababababababababababababababababababababababababababababababab"
    }
  )
}
```

The digest above is synthetic. A producer must supply the actual digest of the
received document. The API checks digest syntax; it cannot verify bytes that it
has not received. Supported algorithms are `sha256`, `sha384`, and `sha512`.

A retry with identical normalized input returns the same ID, including when
evidence order, digest letter case, or timestamp timezone differs. Reusing a
document digest and assertion ID with different content returns an error.
Document provenance is immutable: another observation with a different origin,
collector, document reference, or source authority currently returns a conflict.
A revised external decision must be supplied as a new source document.

`REVIEWED`, `APPROVED`, and `REJECTED` require a reviewer. Classification scheme
and value must be supplied together. Evidence IDs must be unique within the
assertion, and evidence URIs must be absolute. Optional digests require both an
algorithm and a correctly sized hexadecimal value. Product and component PURLs
must include a version; name-only identities are rejected.

## Query product-specific safety context

```graphql
query {
  SafetyAssertionList(
    safetyAssertionSpec: {
      componentPurl: "pkg:generic/library@2.0"
      safetyRelevance: SAFETY_RELATED
    }
    first: 20
  ) {
    totalCount
    pageInfo {
      hasNextPage
      endCursor
    }
    edges {
      cursor
      node {
        id
        assertionId
        decisionStatus
        rationale
        target {
          productPurl
          componentPurl
          correlationStatus
        }
        evidence {
          evidenceId
          uri
        }
        origin
        documentRef
      }
    }
  }
}
```

Pass `pageInfo.endCursor` as `after` for the next page. PURL filters use the
complete declared identity, including version, qualifiers, and subpath. They do
not query resolved graph bindings. Every correlation state is `PENDING` until
the follow-up certifier and binding implementation is available.

## Validation

Run unit validation and resolver tests:

```sh
go test ./pkg/assembler/backends/helper ./pkg/assembler/graphql/resolvers
```

Run PostgreSQL persistence and GraphQL round-trip tests with a PostgreSQL role
that can create temporary databases:

```sh
ENT_TEST_DATABASE_URL='postgresql://guac:guac@localhost/postgres?sslmode=disable' \
  go test -v ./pkg/assembler/backends/ent/backend -run TestSafetyAssertionPostgres
```

The integration test creates and drops an isolated database. It covers missing
packages, idempotent and concurrent retries, immutable content and provenance,
two products with opposite relevance for one component, version-specific
queries, pagination, invalid cursors, and GraphQL ingestion/retrieval. Without
`ENT_TEST_DATABASE_URL`, the PostgreSQL test is skipped explicitly.
