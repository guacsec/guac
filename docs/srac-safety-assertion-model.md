# Dedicated safety-assertion model proposal

Status: draft for maintainer review

Related work:

- Use case: [#3256](https://github.com/guacsec/guac/issues/3256)
- Experimental standalone parser: [#3271](https://github.com/guacsec/guac/pull/3271)

## Goal

Represent an externally authored, product-specific safety-relevance assertion
as a first-class GUAC predicate connecting a product package version to a
component package version.

The model must support both ingestion paths identified in #3256:

1. a standalone SRAC document parser; and
2. future SPDX and CycloneDX parsers that map native safety fields into the
   same internal predicate.

GUAC stores, correlates, and exposes the supplied assertion. It does not infer
safety relevance, approve an assertion, or replace the originating safety
lifecycle.

## Why a dedicated predicate

The parser prototype in #3271 uses product-scoped `HasMetadata` to validate the
workflow without changing the ontology. That representation is not intended as
the permanent model because it:

- stores the product/component relationship inside a JSON value;
- cannot filter safety fields efficiently;
- does not provide a typed graph edge between product and component; and
- makes native SPDX and CycloneDX mapping harder to query consistently.

A dedicated predicate makes product context explicit while preserving multiple
assertions about the same component in different products.

## Proposed graph relationship

```text
Product PackageVersion
        |
        | SafetyAssertion
        v
Component PackageVersion
```

Both endpoints are specific package versions. Name-only matching is not
permitted. A BOM reference or component digest can be preserved as additional
correlation evidence, but does not replace the package identity.

## Proposed fields

| Field | Purpose |
| --- | --- |
| `assertionId` | Stable identifier assigned by the originating safety lifecycle |
| `safetyRelevance` | `SAFETY_RELATED`, `NOT_SAFETY_RELATED`, or `UNDETERMINED` |
| `classificationScheme` | Domain scheme such as ISO 26262, IEC 61508, IEC 62304, or DO-178C |
| `classificationValue` | Scheme-specific value such as ASIL-B, SIL-2, Class-C, or DAL-B |
| `rationale` | Externally authored explanation for the assertion |
| `status` | `DRAFT`, `REVIEWED`, `APPROVED`, or `REJECTED` |
| `reviewer` | Safety reviewer or authority supplied by the source record |
| `evidence` | Structured references to supporting evidence and optional digests |
| `componentBomRef` | Optional source-SBOM component reference |
| `componentDigest` | Optional algorithm and digest used during correlation |
| `assertedAt` | Assertion timestamp |
| `sourceAuthority` | Organization or authority that authored the assertion |
| `origin` | Original safety document URI |
| `collector` | GUAC collector that supplied the document |
| `documentRef` | Reference to the received document in configured blob storage |
| `documentDigest` | SHA-256 of the received assertion document |

The classification is represented as a scheme/value pair rather than an ASIL-
or SIL-specific enum so that the predicate works across safety domains.

## Proposed GraphQL contract

The following schema is illustrative. Names and nullability should be confirmed
before code generation and backend implementation.

```graphql
enum SafetyRelevance {
  SAFETY_RELATED
  NOT_SAFETY_RELATED
  UNDETERMINED
}

enum SafetyAssertionStatus {
  DRAFT
  REVIEWED
  APPROVED
  REJECTED
}

type SafetyEvidenceReference {
  id: String!
  uri: String!
  digestAlgorithm: String
  digest: String
}

input SafetyEvidenceReferenceInput {
  id: String!
  uri: String!
  digestAlgorithm: String
  digest: String
}

type SafetyAssertion {
  id: ID!
  product: Package!
  component: Package!
  assertionId: String!
  safetyRelevance: SafetyRelevance!
  classificationScheme: String
  classificationValue: String
  rationale: String!
  status: SafetyAssertionStatus!
  reviewer: String
  evidence: [SafetyEvidenceReference!]!
  componentBomRef: String
  componentDigestAlgorithm: String
  componentDigest: String
  assertedAt: Time!
  sourceAuthority: String
  origin: String!
  collector: String!
  documentRef: String!
  documentDigest: String!
}

input SafetyAssertionInputSpec {
  assertionId: String!
  safetyRelevance: SafetyRelevance!
  classificationScheme: String
  classificationValue: String
  rationale: String!
  status: SafetyAssertionStatus!
  reviewer: String
  evidence: [SafetyEvidenceReferenceInput!]!
  componentBomRef: String
  componentDigestAlgorithm: String
  componentDigest: String
  assertedAt: Time!
  sourceAuthority: String
  origin: String!
  collector: String!
  documentRef: String!
  documentDigest: String!
}

input SafetyAssertionSpec {
  id: ID
  product: PkgSpec
  component: PkgSpec
  assertionId: String
  safetyRelevance: SafetyRelevance
  classificationScheme: String
  classificationValue: String
  status: SafetyAssertionStatus
  sourceAuthority: String
  origin: String
  documentDigest: String
}

type SafetyAssertionEdge {
  cursor: ID!
  node: SafetyAssertion!
}

type SafetyAssertionConnection {
  totalCount: Int!
  pageInfo: PageInfo!
  edges: [SafetyAssertionEdge!]!
}

extend type Mutation {
  ingestSafetyAssertion(
    product: IDorPkgInput!
    component: IDorPkgInput!
    assertion: SafetyAssertionInputSpec!
  ): ID!
}

extend type Query {
  SafetyAssertion(safetyAssertionSpec: SafetyAssertionSpec!): [SafetyAssertion!]!
  SafetyAssertionList(
    safetyAssertionSpec: SafetyAssertionSpec!
    after: ID
    first: Int
  ): SafetyAssertionConnection
}
```

The query filter should support, at minimum, product, component, safety
relevance, classification scheme/value, lifecycle status, source authority,
origin, and document digest.

## Example query

The core use case is:

> Which products use a vulnerable component in an asserted safety-relevant
> context, and what evidence supports each assertion?

The vulnerability-to-component portion uses GUAC's existing graph. The new
predicate supplies the component-to-product safety context and evidence.

## Implementation slices

1. Confirm predicate name, endpoint types, fields, and nullability.
2. Add GraphQL schema, generated models, assembler input, and client operations.
3. Add database schema/migration and backend implementations required by GUAC.
4. Add GraphQL ingestion, filtering, pagination, and resolver tests.
5. Change the standalone SRAC parser to emit the new predicate instead of
   `HasMetadata`.
6. Add a synthetic end-to-end fixture with two products containing the same
   component but different safety relevance.
7. Later, map native SPDX and CycloneDX safety data into the same predicate.
8. Add REST only when a concrete endpoint and response contract are agreed.

## Validation rules

- Product and component must resolve to specific package versions.
- Name-only matching is rejected.
- A supplied digest mismatch produces an invalid correlation, not a fallback.
- Reviewed, approved, or rejected assertions require a reviewer.
- Evidence references require stable IDs and URIs; supplied digests are
  validated.
- The originating assertion, provenance, and lifecycle status are preserved.
- GUAC never promotes `DRAFT` to `APPROVED` or otherwise creates a safety
  decision.

## Open questions

1. Should the predicate be named `SafetyAssertion`, `HasSafetyContext`, or
   something else consistent with GUAC ontology conventions?
2. Should evidence references be normalized as separate nodes or initially
   stored as structured predicate fields?
3. Which storage backends must be implemented in the first code PR?
4. Is GraphQL sufficient for the MVP, leaving REST for a follow-up?
5. Should #3271 be rebased onto the model implementation, or should its parser
   remain a separate follow-up PR?
