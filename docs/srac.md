# SRAC document validation foundation

This change defines and validates the externally authored Safety Relevance
Assertion Capability (SRAC) interchange document used by the product-context
example in #3256.

The current slice deliberately stops before graph ingestion. In particular, it
does not project safety assertions into `HasMetadata`. The maintainer review of
#3271 confirmed that the permanent implementation requires a dedicated,
queryable safety-assertion ontology connecting the product, component,
evidence, provenance, and review state.

The proposed ontology and out-of-order resolution lifecycle are tracked in
#3272. After maintainers approve that contract, the GUAC document guesser,
processor, parser, backend, GraphQL API, and certifier can be wired to the same
first-class predicate.

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
- validates supplied SHA-256 evidence and component digests; and
- rejects duplicate assertion identifiers within a document.

The synthetic fixture in `docs/examples/srac/product-context.srac.json` shows
the same component used in two products with different externally authored
safety contexts.

## Follow-up implementation boundary

The accepted ontology must provide queryable fields rather than an opaque JSON
value. The planned resolution flow is:

```text
SRAC document -> declared assertion target -> certifier resolution -> typed
product/assertion/component graph binding
```

The certifier will own correlation after the ontology exists. It will normalize
pURLs before comparison, preserve missing endpoints as pending or unmatched,
distinguish missing digest data from a conflicting digest, and avoid creating
placeholder package nodes solely because an assertion arrived first.

GUAC will preserve and expose externally authored assertions. It will not infer
safety relevance or approve safety decisions.
