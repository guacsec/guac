# Experimental SRAC ingestion

This prototype ingests externally authored Safety Relevance Assertion Capability
(SRAC) documents as read-only, product-scoped GUAC metadata. It is intended to
validate the use case in #3256 without committing GUAC to a new ontology type.

The safety lifecycle remains authoritative. GUAC validates, preserves, and
correlates supplied context; it does not infer safety relevance or approve a
safety decision.

## Correlation contract

The adapter requires exact product and component package URLs. An optional
component BOM reference and digest further constrain a match. Package names
alone are never accepted. Correlation results are explicit: `matched`,
`unmatched`, `ambiguous`, or `invalid` (including digest mismatch).

Parsed assertions become `HasMetadata` predicates on the product package with
the key `srac.safety-relevance`. The JSON value preserves the component target,
classification, rationale, evidence, review state, source authority, and the
SHA-256 digest of the received SRAC document.

This representation is deliberately experimental. Maintainer feedback will
determine whether a future implementation should use an existing GUAC evidence
model or a dedicated ontology predicate.

## Example query

The existing `HasMetadata` query can retrieve all ingested SRAC assertions:

```graphql
query SafetyRelevantProducts {
  HasMetadata(hasMetadataSpec: { key: "srac.safety-relevance" }) {
    subject {
      ... on Package {
        type
        namespaces {
          namespace
          names {
            name
            versions {
              purl
            }
          }
        }
      }
    }
    value
    origin
    documentRef
  }
}
```

Consumers parse `value` and select assertions whose `safetyRelevance` is
`safety-related` and whose component matches the vulnerability under
investigation. The example fixture shows the same component in two products with
different externally authored safety contexts.
