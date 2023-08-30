# GUAC: Graph for Understanding Artifact Composition

<p align="center">
  <img src="https://user-images.githubusercontent.com/3060102/204297133-9bf702c6-b4e2-46df-a029-42b5060b19a4.png">
</p>

**Note:** GUAC is under active development - if you are interested in
contributing, please look at [contributor guide](CONTRIBUTING.md).

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

![image](https://user-images.githubusercontent.com/3060102/235186368-995784eb-7ef2-43e6-b560-17d6014553ca.png)

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

Note that GUAC uses software identifiers standards to help link metadata
together. However, these identifiers are not always available and heuristics
need to be used to link them. Therefore, there may be unhandled edge cases and
errors occurring when ingesting data. We appreciate it if you could create a
[data quality issue](https://github.com/guacsec/guac/issues/new?assignees=&labels=bug%2C+data-sources%2C+data-quality&projects=&template=bug_report_ingestion.md&title=%5Bingestion%2Fdata-quality+issue%5D+FILL+THIS+IN)
if you encounter any errors or bugs with ingestion.

## GraphQL backends

The following are [GraphQL backends](pkg/assembler/backends) that are implemented for GUAC. The backends are categorized into:

1. Supported/Unsupported: Supported backends are those that will be maintained by the project. Unsupported backends are not actively maintained by the project but will accept community contributions.
2. Complete/Incomplete: Complete backends support all mandatory GraphQL APIs. Incomplete backends support a subset of those APIs and may not be feature complete.
3. Optimized: The backend has gone through a level of optimization to help improve performance.

The enumerated backends are:
- [inmem (supported, complete, optimized)](https://github.com/guacsec/guac/tree/main/pkg/assembler/backends/inmem): a non-persistent in-memory backend that doesn't require any additional infrastructure. Also acts as a conformance backend for API implementations. We recommend starting with this if you're just starting with GUAC!
- [arangoDB (supported, incomplete, optimized)](https://github.com/guacsec/guac/tree/main/pkg/assembler/backends/arangodb): a persistent backend based on [ArangoDB](https://arangodb.com/)
- [ent (supported, incomplete)](https://github.com/guacsec/guac/tree/main/pkg/assembler/backends/ent): a persistent backend based on [ent](https://entgo.io/) that can run on various SQL backends such as [PostgreSQL](https://www.postgresql.org/), [MySQL](https://www.mysql.com/) and [SQLite](https://www.sqlite.org/index.html).
- [neo4j/openCypher (unsupported, incomplete)](https://github.com/guacsec/guac/tree/main/pkg/assembler/backends/neo4j): a persistent backend based on [neo4j](https://neo4j.com/) and [openCypher](https://opencypher.org/). This backend should work with any database that supported openCypher queries.

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
guac-maintainers@googlegroups.com.

## Governance

Information about governance can be found [here](GOVERNANCE.md).
