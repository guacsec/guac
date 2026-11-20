# Safety assertion ingestion and queries

This implementation ingests SRAC documents and stores externally authored
assertions through GUAC's GraphQL and backend interfaces, using Ent/PostgreSQL.
Assertions retain declared, versioned PURLs even when no corresponding packages
have been ingested. GUAC does not infer or approve the supplied decision.

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
          correlationReason
          lastEvaluatedAt
        }
        binding {
          product {
            type
            namespaces {
              namespace
              names {
                name
                versions {
                  id
                  version
                }
              }
            }
          }
          component {
            type
            namespaces {
              namespace
              names {
                name
                versions {
                  id
                  version
                }
              }
            }
          }
          matchedBy
          resolvedAt
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
not substitute another version when a declared version is missing. `binding`
returns the resolved graph endpoints after reconciliation succeeds.

## Ingest SRAC documents and reconcile

The normal document ingestion pipeline recognizes SRAC `0.2-draft` JSON. The
fixture `docs/examples/srac/product-context.srac.json` demonstrates one
component in two products with opposite safety relevance. The parser emits
dedicated assertions, computes SHA-256 over the exact received bytes, and
preserves source authority, ingestion provenance, evidence, and the authored
decision. It does not ingest packages or generate scan requests from unresolved
declarations.

`assertedAt` is optional in the draft carrier and defaults to `generatedAt`.
`validUntil` and `classificationScheme` are optional additions. For legacy
`classification` strings without a scheme, the parser uses `unspecified` and
retains the value verbatim; it does not infer a safety standard from the value.
Without configured blob storage, the parser uses a `urn:sha256:` content
identity as the document reference, which is not a claim that a blob was
uploaded.

The current target contract carries one component digest. SRAC inputs with
multiple component digests or product digests are rejected explicitly, so no
supplied digest constraint is silently discarded. Unmodeled draft metadata
remains available in the original source document when blob storage is
configured.

After ingesting assertions and the relevant SBOMs, run:

```sh
guacone certifier safety-assertions --gql-addr http://localhost:8080/query
```

For repeated reconciliation as later SBOMs arrive:

```sh
guacone certifier safety-assertions --gql-addr http://localhost:8080/query \
  --poll --interval 5m --page-size 100
```

The command uses the existing `--header-file` authentication option and supports
cancellation. Each pass paginates through all assertions, including earlier
matches, to re-evaluate expiry and new digest evidence. Query and mutation
errors are returned to the caller. The same backend evaluation can be invoked
for one assertion with `reconcileSafetyAssertion(id: ...)`.

| State       | Meaning                                                                                                            |
| ----------- | ------------------------------------------------------------------------------------------------------------------ |
| `PENDING`   | A declared version or required digest observation is missing.                                                      |
| `MATCHED`   | Both versioned identities resolve uniquely and any declared component digest is consistent with graph occurrences. |
| `AMBIGUOUS` | An exact identity has multiple candidate package versions.                                                         |
| `INVALID`   | An identity is unsupported or a component digest conflicts.                                                        |
| `STALE`     | The assertion has expired.                                                                                         |

Only `MATCHED` exposes an active binding. A missing digest observation remains
pending, while a conflicting digest invalidates the binding. Repeated runs
preserve `resolvedAt` for an unchanged binding. Correlation never changes
`decisionStatus`, reviewer, relevance, or the authored rationale.

## Validation

Run unit validation and resolver tests:

```sh
go test ./pkg/srac ./pkg/ingestor/parser/srac ./pkg/certifier/safetyassertion \
  ./pkg/handler/processor/guesser ./pkg/assembler/graphql/resolvers
```

Run PostgreSQL persistence and GraphQL round-trip tests with a PostgreSQL role
that can create temporary databases:

```sh
ENT_TEST_DATABASE_URL='postgresql://guac:guac@localhost/postgres?sslmode=disable' \
  go test -v ./pkg/assembler/backends/ent/backend -run TestSafety
```

The integration test creates and drops an isolated database. It covers missing
packages, idempotent and concurrent retries, immutable content and provenance,
two products with opposite relevance for one component, version-specific
queries, pagination, invalid cursors, full SRAC/SBOM ingestion in both orders,
later product versions, digest mismatch, missing digest observations, ambiguity,
expiry, concurrent reconciliation, and typed GraphQL bindings. Without
`ENT_TEST_DATABASE_URL`, the PostgreSQL test is skipped explicitly.
