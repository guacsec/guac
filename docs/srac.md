# SRAC document ingestion and reconciliation

GUAC validates and ingests the externally authored Safety Relevance Assertion
Capability (SRAC) interchange document used by the product-context example in
#3256.

SRAC documents are recognized by the document guesser and processed through the
normal parser and assembler pipeline. They create dedicated safety assertions
connecting declared product/component identities, evidence, provenance, and
review state. They do not create package placeholders or `HasMetadata`
projections.

The Ent/PostgreSQL implementation and GraphQL API support out-of-order
resolution with `guacone certifier safety-assertions`, once or with
`--poll --interval 5m`. See
[usage, supported draft fields, and tests](srac-safety-assertion-usage.md).

## Validation performed here

The `pkg/srac` package:

- accepts the `0.2-draft` JSON document shape;
- requires a document identity, generation time, source URI, and at least one
  assertion;
- requires exact product and component pURLs and canonicalizes them with the
  package-url library;
- rejects name-only component matching;
- validates safety-relevance and decision-status values;
- requires a reviewer for reviewed, approved, or rejected assertions;
- validates SHA-256 evidence digests and SHA-256/384/512 subject digests; and
- rejects duplicate assertion identifiers within a document.

The synthetic fixture in `docs/examples/srac/product-context.srac.json` shows
the same component used in two products with different externally authored
safety contexts.

## Resolution

The resolution flow is:

```text
SRAC document -> declared assertion target -> certifier resolution -> typed
product/assertion/component graph binding
```

The certifier resolves complete package identities, including qualifiers and
subpaths. Missing endpoints or digest observations remain `PENDING`; unique
matches produce a typed `MATCHED` binding. Ambiguous identities, conflicting
digests, and expired assertions remain visible without an active binding.
Repeated runs preserve one binding and do not retarget a later product version.

GUAC preserves and exposes externally authored assertions. It does not infer
safety relevance or approve safety decisions.
