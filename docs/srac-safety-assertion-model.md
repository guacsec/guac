# Dedicated safety-assertion graph model proposal

Status: draft for maintainer review

Related work:

- Use case: [#3256](https://github.com/guacsec/guac/issues/3256)
- Standalone parser prototype: [#3271](https://github.com/guacsec/guac/pull/3271)
- GUAC certifier framework: [`pkg/certifier`](../pkg/certifier)

## Goal

Represent externally authored, product-specific safety-relevance assertions as
first-class GUAC data. The model must retain an assertion even when its
referenced product or component has not yet been ingested, and later create
typed graph bindings when those package versions become available.

The model supports both ingestion paths identified in #3256:

1. a standalone SRAC document parser; and
2. SPDX and CycloneDX parsers that map safety fields into the same internal
   predicate.

GUAC stores, correlates, and exposes the supplied assertion. It does not infer
safety relevance, approve an assertion, or replace the originating safety
lifecycle.

## Maintainer-meeting direction

The 12 October 2026 GUAC maintainer discussion identified four design
requirements for the next iteration:

1. define the ontology and the client queries before adding generated code;
2. introduce first-class safety-assertion nouns and relationships rather than
   keeping the permanent model in `HasMetadata`;
3. use a certifier to resolve assertions when documents arrive out of order;
   and
4. implement through GUAC's GraphQL and backend abstractions, with PostgreSQL
   as the first persistence target rather than parser-owned SQL.

This document records that proposed interpretation for maintainer confirmation.
It does not claim that the names, schema, or implementation sequence have been
approved.

## Why a dedicated predicate

The parser prototype in #3271 uses product-scoped `HasMetadata` to validate the
workflow without changing the ontology. That representation is not intended as
the permanent model because it:

- stores the product/component relationship inside a JSON value;
- cannot filter safety fields efficiently;
- cannot represent an unresolved declared target separately from a resolved
  graph binding;
- does not provide typed graph relationships among an assertion, product, and
  component; and
- makes native SPDX and CycloneDX mapping harder to query consistently.

A dedicated model makes product context explicit while preserving multiple
assertions about the same component in different products.

## Proposed graph model

Ingestion and graph resolution are separate stages:

```text
SafetyAssertionDocument
        |
        | contains
        v
SafetyAssertion ---- supportedBy ----> SafetyEvidenceReference
        |
        | declares
        v
SafetyAssertionTarget
  product identity + component identity + optional BOM reference/digest
        |
        | resolved by certifier when both endpoints exist
        v
SafetyAssertionBinding
  Product PackageVersion ---- assertion ----> Component PackageVersion
```

`SafetyAssertionTarget` preserves the identities supplied by the author even
if either `PackageVersion` is absent. `SafetyAssertionBinding` is created only
after deterministic resolution. This avoids dropping an assertion or creating
a placeholder package solely because documents arrived in a different order.

Both resolved endpoints are specific package versions. Name-only matching is
not permitted. A BOM reference or component digest can be preserved as
correlation evidence, but does not replace package identity.

## Proposed storage entities

The names below describe responsibilities, not final SQL table names. Ent and
the GUAC backend interfaces should own persistence and migrations.

### SafetyAssertionDocument

Represents the received source document and its provenance.

| Field             | Purpose                                              |
| ----------------- | ---------------------------------------------------- |
| `id`              | GUAC UUIDv7 identity                                 |
| `documentDigest`  | Algorithm and digest of the exact received document  |
| `documentRef`     | Reference to the document in configured blob storage |
| `origin`          | Original document URI                                |
| `collector`       | GUAC collector that supplied the document            |
| `sourceAuthority` | Organization or authority that authored it           |
| `receivedAt`      | Ingestion timestamp                                  |

The digest algorithm and value should be unique together for idempotent
ingestion. The complete source document remains in configured blob storage;
the graph retains the queryable, provenance-bearing subset.

### SafetyAssertion

Represents the externally authored safety decision or lifecycle state.

| Field                  | Purpose                                                           |
| ---------------------- | ----------------------------------------------------------------- |
| `id`                   | GUAC UUIDv7 identity                                              |
| `documentId`           | Source `SafetyAssertionDocument`                                  |
| `assertionId`          | Stable identifier assigned by the originating lifecycle           |
| `safetyRelevance`      | `SAFETY_RELATED`, `NOT_SAFETY_RELATED`, or `UNDETERMINED`         |
| `classificationScheme` | Domain scheme such as ISO 26262, IEC 61508, IEC 62304, or DO-178C |
| `classificationValue`  | Scheme-specific value such as ASIL-B, SIL-2, Class-C, or DAL-B    |
| `rationale`            | Externally authored explanation                                   |
| `decisionStatus`       | `DRAFT`, `REVIEWED`, `APPROVED`, or `REJECTED`                    |
| `reviewer`             | Reviewer or authority supplied by the source                      |
| `assertedAt`           | Assertion timestamp                                               |
| `validUntil`           | Optional expiry or reevaluation time                              |

`documentId` plus `assertionId` should be unique. The classification is a
scheme/value pair rather than an ASIL- or SIL-specific enum so the model works
across safety domains.

### SafetyAssertionTarget

Retains the declared product and component identities before graph resolution.

| Field               | Purpose                                                  |
| ------------------- | -------------------------------------------------------- |
| `assertionId`       | Owning `SafetyAssertion`                                 |
| `productPurl`       | Required product package identity and version            |
| `componentPurl`     | Required component package identity and version          |
| `componentBomRef`   | Optional source-SBOM component reference                 |
| `componentDigest`   | Optional algorithm and digest used for correlation       |
| `correlationStatus` | `PENDING`, `MATCHED`, `AMBIGUOUS`, `INVALID`, or `STALE` |
| `correlationReason` | Machine-readable and human-readable resolution detail    |
| `lastEvaluatedAt`   | Last certifier evaluation time                           |

### SafetyAssertionBinding

Represents the typed, resolved graph relationship.

| Field                       | Purpose                                            |
| --------------------------- | -------------------------------------------------- |
| `assertionId`               | Source `SafetyAssertion`                           |
| `productPackageVersionId`   | Resolved product package version                   |
| `componentPackageVersionId` | Resolved component package version                 |
| `matchedBy`                 | Identity evidence used for the deterministic match |
| `resolvedAt`                | Resolution timestamp                               |

The assertion/product/component tuple should be unique so certifier reruns are
idempotent.

### SafetyEvidenceReference

Represents evidence cited by an assertion.

| Field         | Purpose                                              |
| ------------- | ---------------------------------------------------- |
| `assertionId` | Owning `SafetyAssertion`                             |
| `evidenceId`  | Stable evidence identifier from the source lifecycle |
| `uri`         | Evidence reference                                   |
| `digest`      | Optional algorithm and digest                        |

Whether evidence becomes a reusable GUAC node or remains normalized under the
assertion is an open ontology decision.

## Two independent state machines

The model must not combine the author's safety decision with GUAC's correlation
result:

- `decisionStatus` records the externally authored lifecycle state. GUAC never
  promotes or approves it.
- `correlationStatus` records whether GUAC can bind the declared identities to
  graph nodes.

For example, an `APPROVED` assertion can remain `PENDING` because its product
version has not been ingested. Conversely, a `MATCHED` binding says nothing
about whether the safety decision is approved.

## Certifier reconciliation

The parser stores the document, assertion, target identities, evidence, and
provenance. It does not require both package nodes to exist and does not write
database tables directly.

A safety-assertion certifier should:

1. query targets in `PENDING` or `STALE` state;
2. resolve product and component package versions using deterministic identity
   data, never name-only matching;
3. create or refresh `SafetyAssertionBinding` records for unique matches;
4. mark multiple candidates `AMBIGUOUS` without choosing one;
5. mark malformed identities or digest mismatches `INVALID`;
6. keep missing endpoints `PENDING`; and
7. be safe to run periodically, on demand, or after relevant package ingestion.

When a new product version appears, existing assertions are not silently
rebound to it. A new or updated assertion, or an explicit reevaluation rule,
must identify the intended version.

## Proposed GraphQL contract

The following contract is illustrative. Names and nullability should be
confirmed before code generation and backend implementation.

```graphql
enum SafetyRelevance {
  SAFETY_RELATED
  NOT_SAFETY_RELATED
  UNDETERMINED
}

enum SafetyDecisionStatus {
  DRAFT
  REVIEWED
  APPROVED
  REJECTED
}

enum SafetyCorrelationStatus {
  PENDING
  MATCHED
  AMBIGUOUS
  INVALID
  STALE
}

type SafetyAssertionTarget {
  productPurl: String!
  componentPurl: String!
  componentBomRef: String
  componentDigestAlgorithm: String
  componentDigest: String
  correlationStatus: SafetyCorrelationStatus!
  correlationReason: String
  lastEvaluatedAt: Time
}

type SafetyAssertionBinding {
  product: Package!
  component: Package!
  matchedBy: String!
  resolvedAt: Time!
}

type SafetyEvidenceReference {
  evidenceId: String!
  uri: String!
  digestAlgorithm: String
  digest: String
}

input SafetyEvidenceReferenceInput {
  evidenceId: String!
  uri: String!
  digestAlgorithm: String
  digest: String
}

type SafetyAssertion {
  id: ID!
  assertionId: String!
  safetyRelevance: SafetyRelevance!
  classificationScheme: String
  classificationValue: String
  rationale: String!
  decisionStatus: SafetyDecisionStatus!
  reviewer: String
  assertedAt: Time!
  validUntil: Time
  target: SafetyAssertionTarget!
  binding: SafetyAssertionBinding
  evidence: [SafetyEvidenceReference!]!
  sourceAuthority: String
  origin: String!
  collector: String!
  documentRef: String!
  documentDigestAlgorithm: String!
  documentDigest: String!
}

input SafetyAssertionInputSpec {
  assertionId: String!
  safetyRelevance: SafetyRelevance!
  classificationScheme: String
  classificationValue: String
  rationale: String!
  decisionStatus: SafetyDecisionStatus!
  reviewer: String
  assertedAt: Time!
  validUntil: Time
  productPurl: String!
  componentPurl: String!
  componentBomRef: String
  componentDigestAlgorithm: String
  componentDigest: String
  evidence: [SafetyEvidenceReferenceInput!]!
  sourceAuthority: String
  origin: String!
  collector: String!
  documentRef: String!
  documentDigestAlgorithm: String!
  documentDigest: String!
}

input SafetyAssertionSpec {
  id: ID
  assertionId: String
  product: PkgSpec
  component: PkgSpec
  safetyRelevance: SafetyRelevance
  classificationScheme: String
  classificationValue: String
  decisionStatus: SafetyDecisionStatus
  correlationStatus: SafetyCorrelationStatus
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
  ingestSafetyAssertion(assertion: SafetyAssertionInputSpec!): ID!
}

extend type Query {
  SafetyAssertion(
    safetyAssertionSpec: SafetyAssertionSpec!
  ): [SafetyAssertion!]!
  SafetyAssertionList(
    safetyAssertionSpec: SafetyAssertionSpec!
    after: ID
    first: Int
  ): SafetyAssertionConnection
}
```

The input intentionally carries declared identities instead of requiring
existing GUAC node IDs. The query filter should support product, component,
safety relevance, classification scheme/value, decision status, correlation
status, source authority, origin, and document digest.

## Maintainer-facing query

The core use case is:

> Which products use a vulnerable component in an asserted safety-relevant
> context, and what evidence supports each assertion?

The vulnerability-to-component portion uses GUAC's existing graph. The new
model supplies product-specific safety context and evidence. A synthetic demo
should show the same component in two products, with `SAFETY_RELATED` in one
and `NOT_SAFETY_RELATED` in the other.

## Implementation slices

1. Confirm ontology names, entity boundaries, fields, nullability, and queries.
2. Add GraphQL types, inputs, mutations, filters, pagination, and generated
   client operations.
3. Add backend interface methods and Ent/PostgreSQL schemas, indexes, and
   migrations through GUAC's existing abstractions.
4. Add ingestion and resolver tests, including idempotent document ingestion.
5. Change #3271 to emit the first-class assertion input instead of
   `HasMetadata`.
6. Add the safety-assertion certifier and idempotent binding tests.
7. Add the two-product end-to-end fixture and maintainer-facing query.
8. Map SPDX and CycloneDX safety data into the same model when supported input
   fields are available.
9. Add REST only if a concrete endpoint and response contract are agreed.

Keeping the ontology/persistence, parser, and certifier in reviewable slices
avoids coupling parser approval to generated database and GraphQL code.

## Validation and acceptance cases

- The assertion is retained when the product, component, or both are absent.
- Ingesting the same document and assertion twice is idempotent.
- Product and component bind only to specific package versions.
- Name-only matching is rejected.
- A unique deterministic match produces one binding.
- Multiple valid candidates produce `AMBIGUOUS`, with no arbitrary binding.
- A digest mismatch produces `INVALID`, not a fallback match.
- A later package ingestion allows a `PENDING` assertion to become `MATCHED`.
- Repeated certifier runs do not duplicate bindings.
- Reviewed, approved, or rejected assertions require a reviewer.
- Evidence references require stable IDs and URIs; supplied digests are
  validated.
- The source assertion, provenance, decision state, and correlation state are
  preserved and independently queryable.
- GUAC never promotes `DRAFT` to `APPROVED` or otherwise creates a safety
  decision.

## Open questions for maintainers

1. Should the first-class noun be named `SafetyAssertion`,
   `HasSafetyContext`, or something else consistent with GUAC ontology
   conventions?
2. Is the document -> assertion -> declared target -> resolved binding split
   the preferred representation for out-of-order ingestion?
3. Should evidence references be reusable graph nodes or initially normalized
   under the assertion?
4. Is PostgreSQL/Ent sufficient for the first implementation if all access is
   kept behind GUAC's backend interfaces?
5. Should one assertion bind to exactly one product/component version pair, or
   may one assertion intentionally cover multiple versions?
6. Is GraphQL sufficient for the first implementation, leaving REST for a
   follow-up?
7. Should #3271 be rebased onto the model implementation, or should its parser
   remain a separate follow-up PR?
