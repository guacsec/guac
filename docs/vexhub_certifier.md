# VEX Hub Certifier

The VEX Hub certifier queries VEX (Vulnerability Exploitability eXchange)
repositories conforming to the
[VEX Repository Specification](https://github.com/openvex/vex-repo-spec) to
discover VEX statements affecting software packages ingested into GUAC.

## Overview

The certifier downloads and indexes VEX repositories to match package URLs
(PURLs) against known VEX statements, outputting OpenVEX documents to GUAC
processors.

## Configuration & Flags

The certifier can be configured via CLI flags or configuration files:

- `--vexhub-manifest-url`: URL of the VEX repository manifest (defaults to
  `https://raw.githubusercontent.com/aquasecurity/vexhub/main/vex-repository.json`).
- `--certifier-batch-size`: Number of package nodes certified per batch query
  (defaults to 1000).
- `--interval`: Duration between polling runs when polling is enabled.
- `--poll` / `--service-poll`: Enables continuous polling mode for periodic VEX
  synchronization.

## Manifest and Repository Layout

A VEX repository follows the VEX Repo Spec layout:

1. **Repository Manifest (`vex-repository.json`)**: Contains metadata about the
   repository, supported specification versions (`spec_version: "0.1"`), archive
   mirror locations, and an optional `update_interval` (e.g., `"1h"`, `"24h"`).
   Subdirectory paths within an archive may be denoted using a `//` delimiter in
   the location URL (e.g., `https://example.com/archive.tar.gz//subdir-name`).

2. **Index (`index.json`)**: Located inside the archive root or specified
   subdirectory. Maps PURL identifiers to the relative path of their
   corresponding VEX document and specifies document format.

3. **VEX Documents**: Individual VEX files stored at paths designated in
   `index.json`.

## Supported Formats

- **OpenVEX**: Fully supported (`format: "openvex"` or unspecified/empty format
  for backward compatibility).
- Non-OpenVEX formats (such as CSAF) listed in `index.json` are skipped by the
  certifier.

## Caching and Performance

- **Shared Instance**: The certifier is constructed once and reused for every
  component batch. The cache and deduplication state live on that instance, so
  registering a factory that builds a new certifier per batch would discard both
  and re-download the archive on every batch.
- **Document Caching**: The indexed archive is held in memory as a
  canonical-PURL to document map.
- **Cache TTL**: The cache TTL is derived from the manifest's `update_interval`
  field (defaulting to 1 hour when absent or unparseable).
- **Two-Pass Extraction**: Archives are buffered to temporary files and read
  using two streaming passes to extract only referenced documents, protecting
  against unbounded memory consumption and tar-bombs. Individual entries larger
  than 32 MiB are rejected rather than truncated.
- **Deduplication**: Emitted documents are tracked by document digest rather
  than by PURL, so an unchanged document is never re-sent, while a statement
  revised upstream is picked up on the next refresh.

## Error Handling

- A manifest that declares no locations for the supported spec version, or whose
  every location fails the reachability probe, returns an error. An unreachable
  hub is therefore distinguishable from a hub with nothing to report.
- The reachability probe uses HEAD but treats only a transport error or a
  definitive `404`/`410` as disqualifying, since many object stores and CDNs
  answer `403`/`405` to HEAD while serving the same URL over GET.
