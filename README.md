# GUAC: Graph for Understanding Artifact Composition

<p align="center">
  <img src="https://user-images.githubusercontent.com/3060102/204297133-9bf702c6-b4e2-46df-a029-42b5060b19a4.png">
</p>

[![build](https://github.com/guacsec/guac/workflows/release/badge.svg)](https://github.com/guacsec/guac/actions?query=workflow%3Arelease) [![PkgGoDev](https://pkg.go.dev/badge/github.com/guacsec/guac)](https://pkg.go.dev/github.com/guacsec/guac) [![Go Report Card](https://goreportcard.com/badge/github.com/guacsec/guac)](https://goreportcard.com/report/github.com/guacsec/guac)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/guacsec/guac/badge)](https://api.securityscorecards.dev/projects/github.com/guacsec/guac)

**Note:** GUAC is under active development - if you are interested in
contributing, please look at [contributor guide](CONTRIBUTING.md). GUAC is an
[OpenSSF](https://openssf.org) incubating project under the
[Supply Chain Integrity WG](https://github.com/ossf/wg-supply-chain-integrity).

[Graph for Understanding Artifact Composition (GUAC)](https://guac.sh/)
aggregates software security metadata into a high fidelity graph
database—normalizing entity identities and mapping standard relationships
between them. Querying this graph can drive higher-level organizational outcomes
such as audit, policy, risk management, and even developer assistance.

Conceptually, GUAC occupies the “aggregation and synthesis” layer of the
software supply chain transparency logical model:

![image](https://user-images.githubusercontent.com/3060102/196563695-a1cdc8bd-9946-482f-873a-937bf75891dc.png)

A few examples of questions answered by GUAC include:

![image](https://user-images.githubusercontent.com/3060102/182689788-70acefc1-6d69-4972-abbf-3e60c0d4c014.png)

## Quickstart

Our [documentation](https://docs.guac.sh/) is a good place to get started.

We have various [demos use cases](https://docs.guac.sh/guac-use-cases/) that you
can take a look.

Starting the GUAC services with our
[docker compose quickstart](https://docs.guac.sh/setup/).

## Docs

All documentation for GUAC lives on [docs.guac.sh](https://docs.guac.sh), backed
by the following [docs github repository](https://github.com/guacsec/guac-docs).

## Architecture

Here is an overview of the architecture of GUAC:

![guac_api](https://github.com/guacsec/guac/assets/42319948/db573e4e-f493-4df5-b1bb-fec6307643dd)

For an in-depth view and explanation of components of the GUAC Beta, please
refer to [how GUAC works](https://docs.guac.sh/how-guac-works/).

## Supported input documents

- [CycloneDX](https://github.com/CycloneDX/specification)
- [Dead Simple Signing Envelope](https://github.com/secure-systems-lab/dsse)
- [Deps.dev API](https://deps.dev/)
- [In-toto ITE6](https://github.com/in-toto/attestation)
- [OpenSSF Scorecard](https://github.com/ossf/scorecard)
- [OSV](https://osv.dev/)
- [SLSA](https://github.com/slsa-framework/slsa)
- [SPDX](https://spdx.dev/specifications/)
- [CSAF/CSAF VEX](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html)
- [OpenVEX](https://github.com/openvex)

Note that GUAC uses software identifiers standards to help link metadata
together. However, these identifiers are not always available and heuristics
need to be used to link them. Therefore, there may be unhandled edge cases and
errors occurring when ingesting data. We appreciate it if you could create a
[data quality issue](https://github.com/guacsec/guac/issues/new?assignees=&labels=bug%2C+data-sources%2C+data-quality&projects=&template=bug_report_ingestion.md&title=%5Bingestion%2Fdata-quality+issue%5D+FILL+THIS+IN)
if you encounter any errors or bugs with ingestion.

## GraphQL backends

GUAC supports multiple [backends](pkg/assembler/backends) behind a software
abstraction layer. The GraphQL API is always the same and clients should be
unaffected by which backend is in use. The backends are categorized into:

1. Supported/Unsupported: Supported backends are those which the GUAC project
   is committed to actively maintain. Unsupported backends are not actively
   maintained but will accept community contributions.

2. Complete/Incomplete: Complete backends support all mandatory GraphQL
   APIs. Incomplete backends support a subset of those APIs and may not be
   feature complete.

3. Optimized: The backend has gone through a level of optimization to help
   improve performance.

The two backend that are Supported, Complete, and Optimized are:

- [keyvalue (supported, complete,
  optimized)](https://github.com/guacsec/guac/tree/main/pkg/assembler/backends/keyvalue):
  a non-persistent in-memory backend that doesn't require any additional
  infrastructure. Also acts as a conformance backend for API
  implementations. We recommend starting with this if you're just starting with
  GUAC!

- [ent (supported, complete
  optimized)](https://github.com/guacsec/guac/tree/main/pkg/assembler/backends/ent)
  with [PostgreSQL](https://www.postgresql.org/): a persistent backend based on
  [Entity Framework for Go](https://entgo.io/) that can run on various SQL
  backends. GUAC only supports ent with PostgreSQL. Other ent backends such as
  [MySQL](https://www.mysql.com/) and
  [SQLite](https://www.sqlite.org/index.html) are unsupported.

The other backends are:

- [arangoDB (unsupported, incomplete,
  optimized)](https://github.com/guacsec/guac/tree/main/pkg/assembler/backends/arangodb):
  a persistent backend based on [ArangoDB](https://arangodb.com/)

- [neo4j/openCypher (unsupported,
  incomplete)](https://github.com/guacsec/guac/tree/main/pkg/assembler/backends/neo4j):
  a persistent backend based on [neo4j](https://neo4j.com/) and
  [openCypher](https://opencypher.org/). This backend should work with any
  database that supported openCypher queries.

- [keyvalue: Redis (experimental, complete)](/pkg/assembler/kv/redis): The
  default keyvalue backend, but using Redis as storage.

- [keyvalue: TiKV (experimental, complete)](/pkg/assembler/kv/tikv): The
  default keyvalue backend, but using [TiKV](https://tikv.org/) as storage.

## Additional References

- [GUAC use cases](use-cases.md)
- [GUAC presentation at OSS NA 2023](https://sched.co/1K5Hn)
- [GUAC 2023 Q1 Maintainer Summit Notes](https://docs.google.com/document/d/15Kb3I3SWhq-9_R7WYhSjsIxn_FykYgPyFlQWlLgF4fA/edit)
- [GUAC presentation at KubeCon NA 2022](https://www.youtube.com/watch?v=xFRNgIEzbkA)
- [GUAC Intro Slides](https://docs.google.com/presentation/d/1WF4dsJiwR6URWPgn1aiHAE3iLVl-oGP4SJRWFpcOlao/edit#slide=id.p)
- [GUAC Design Doc](https://docs.google.com/document/d/1N5x0HErb-kmCPgG9M8TwBEOGIVU54clqp_X4KhtNJI8/edit)

## Communication

For more information on how to get involved in the community, mailing lists and
meetings, please refer to our [community page](https://guac.sh/community/)

For security issues or code of conduct concerns, an e-mail should be sent to
GUAC-Maintainers@lists.openssf.org.

## Governance

Information about governance can be found [here](GOVERNANCE.md).
