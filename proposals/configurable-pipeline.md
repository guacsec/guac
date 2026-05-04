# Configurable Collector-Certifier-Queryer Pipeline

**Author:** Community Contribution  
**State:** Work in Progress  
**Issue:** [#1093](https://github.com/guacsec/guac/issues/1093)

---

## Background

GUAC aggregates software security metadata into a high-fidelity graph through
Collectors, Certifiers, and a GraphQL Queryer. After hearing feedback from users
deploying GUAC at scale, two recurring concerns have come up.

### Problem 1 — Operational complexity of multiple binaries

GUAC currently follows the "do one thing well" Unix philosophy. Each collector
or certifier runs as its own separate binary or process:

```
guaccollect osv
guaccollect deps_dev
guaccollect scorecard
guaccollect files
guacone certifier osv
guacone certifier scorecard
guacgql
guaccsub
```

While this is architecturally clean, it creates real operational friction:

- Every collector/certifier needs its own process, container, or Kubernetes pod.
- Operators have to manage lifecycle (start, stop, health checks) across many
  separate services.
- Correlating logs across multiple processes when debugging is painful.
- Adding or removing a collector means changing Helm charts or Docker Compose
  files, not just a config flag.

For teams new to GUAC, this is a steep ramp just to get started.

### Problem 2 — No unified, declarative configuration

The `guac.yaml` file is a flat list of key-value pairs, and the flag registry in
`pkg/cli/store.go` treats all flags for every component at the same level:

```yaml
gql-backend: keyvalue
gql-listen-port: 8080
certifier-batch-size: 60000
interval: 20m
add-vuln-on-ingest: false
```

There is no way for an operator to look at the config and understand what
components are running. There is no concept of "enable the OSV certifier" as a
configuration choice — you have to know to run a separate binary. Enabling or
disabling a component means changing how you invoke processes, not editing a
config file.

---

## Proposal

Introduce a `pipeline:` configuration block in `guac.yaml` that lets users
declare which collectors, certifiers, and server components should be active.
The idea is that a single `guacone run` (or similar) command could read this
block and start all enabled components in one process.

A rough sketch of what this could look like:

```yaml
pipeline:
  collectors:
    - type: deps_dev
      enabled: true
      poll: true
      retrieve-dependencies: true

    - type: scorecard
      enabled: true
      poll: true

    - type: files
      enabled: false

  certifiers:
    - type: osv
      enabled: true
      interval: 10m
      batch-size: 60000
      last-scan: 4

    - type: clearlydefined
      enabled: true
      interval: 10m

    - type: scorecard
      enabled: false

  server:
    gql-backend: keyvalue
    gql-listen-port: 8080
    rest-api-server-port: 8081

  infrastructure:
    pubsub-addr: nats://localhost:4222
    blob-addr: file:///tmp/blobstore?no_tmp_dir=true
    csub-addr: localhost:2782
    use-csub: true

  ingestion:
    add-vuln-on-ingest: false
    add-license-on-ingest: false
    add-eol-on-ingest: false
    add-depsdev-on-ingest: false

  observability:
    log-level: Info
    enable-prometheus: false
    enable-otel: false
```

The existing flat keys and all current CLI subcommands (`guaccollect osv`,
`guacone certifier osv`, etc.) would continue to work exactly as before — this
`pipeline:` block would be entirely opt-in.

### How it would work (rough sketch)

A new `guacone run` subcommand would:

1. Read the `pipeline:` block from `guac.yaml`.
2. For each enabled collector, call `collector.RegisterDocumentCollector(...)`.
3. For each enabled certifier, call `certify.RegisterCertifier(...)`.
4. Start the GQL server if configured.
5. Run all components concurrently under a shared context with unified signal
   handling for graceful shutdown.

Override precedence (highest to lowest) would be:

```
CLI flags > GUAC_* env vars > pipeline: block > top-level guac.yaml defaults
```

### Implementation notes (things to think through)

- Typed Go structs for `PipelineConfig`, `CollectorConfig`, `CertifierConfig`
  would need to live somewhere — possibly a new `pkg/config/pipeline.go`.
- All enabled components would share the same ingestor, GQL transport, and
  collectsub client.
- A component failure probably shouldn't crash the whole process — but that
  behavior could be configurable.

---

## Open questions

- Should this be a new `guacone run` subcommand, a separate `guacpipeline`
  binary, or something else?
- If one certifier fails, should the rest keep running?
- Should the pipeline support config hot-reload via `SIGHUP`?
- With multiple certifiers in one process, how do Prometheus metrics stay
  distinguishable?
- What is the minimum viable set of collectors/certifiers for a first
  implementation?

---

## References

- [GUAC how it works](https://docs.guac.sh/how-guac-works/)
- [`pkg/cli/store.go`](../pkg/cli/store.go) — current flag registry
- [`cmd/guacone/cmd/`](../cmd/guacone/cmd/) — certifier commands
- [`cmd/guaccollect/cmd/`](../cmd/guaccollect/cmd/) — collector commands
- [`guac.yaml`](../guac.yaml) — current config file
- [Original discussion (Google Doc)](https://docs.google.com/document/d/1gyoXic3-UcLj8spgbux4aNDfiEBANikKFN30NDlx-yY/edit?usp=sharing)
