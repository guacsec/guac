# VEX Hub Certifier

The VEX Hub certifier queries VEX (Vulnerability Exploitability eXchange) repositories conforming to the [VEX Repository Specification](https://github.com/openvex/vex-repo-spec) to discover VEX statements affecting software packages ingested into GUAC.

## Overview

The certifier downloads and indexes VEX repositories to match package URLs (PURLs) against known VEX statements, outputting OpenVEX documents to GUAC processors.

## Configuration & Flags

The certifier can be configured via CLI flags or configuration files:

- `--vexhub-manifest-url`: URL of the VEX repository manifest (defaults to `https://raw.githubusercontent.com/aquasecurity/vexhub/main/vex-repository.json`).
- `--certifier-batch-size`: Number of package nodes certified per batch query (defaults to 1000).
- `--interval`: Duration between polling runs when polling is enabled.
- `--poll` / `--service-poll`: Enables continuous polling mode for periodic VEX synchronization.

## Manifest and Repository Layout

A VEX repository follows the VEX Repo Spec layout:

1. **Repository Manifest (`vex-repository.json`)**:
   Contains metadata about the repository, supported specification versions (`spec_version: "0.1"`), archive mirror locations, and an optional `update_interval` (e.g., `"1h"`, `"24h"`).
   Subdirectory paths within an archive may be denoted using a `//` delimiter in the location URL (e.g., `https://example.com/archive.tar.gz//subdir-name`).

2. **Index (`index.json`)**:
   Located inside the archive root or specified subdirectory. Maps PURL identifiers to the relative path of their corresponding VEX document and specifies document format.

3. **VEX Documents**:
   Individual VEX files stored at paths designated in `index.json`.

## Supported Formats

- **OpenVEX**: Fully supported (`format: "openvex"` or unspecified/empty format for backward compatibility).
- Non-OpenVEX formats (such as CSAF) listed in `index.json` are skipped by the certifier.

## Caching and Performance

- **Manifest & Document Caching**: The certifier caches parsed manifests and VEX document maps in-memory, keyed by the manifest URL.
- **Cache TTL**: The cache TTL is dynamically derived from the manifest's `update_interval` field (defaulting to 1 hour if not specified).
- **Two-Pass Extraction**: Archives are buffered to temporary files and read using two streaming passes to extract only referenced documents, protecting against unbounded memory consumption and tar-bombs.
- **Cross-Batch Deduplication**: Documents that have already been emitted are tracked across batch queries to prevent redundant ingestions.
