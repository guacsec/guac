# GUAC: Graph for Understanding Artifact Composition

<p align="center">
  <img src="https://user-images.githubusercontent.com/3060102/204297133-9bf702c6-b4e2-46df-a029-42b5060b19a4.png">
</p>

> :warning: **GUAC is being re-architected to support GraphQL**: the main branch
> has breaking changes. Please use
> [release v0.0.1](https://github.com/guacsec/guac/releases/tag/v0.0.1) until
> work is complete!

**Note:** GUAC is under active development - if you are interested in
contributing, please look at [contributor guide](CONTRIBUTING.md) and the
["express interest" issue](https://github.com/guacsec/guac/issues/1)

Graph for Understanding Artifact Composition (GUAC) aggregates software security
metadata into a high fidelity graph database—normalizing entity identities and
mapping standard relationships between them. Querying this graph can drive
higher-level organizational outcomes such as audit, policy, risk management, and
even developer assistance.

Conceptually, GUAC occupies the “aggregation and synthesis” layer of the
software supply chain transparency logical model:

![image](https://user-images.githubusercontent.com/3060102/196563695-a1cdc8bd-9946-482f-873a-937bf75891dc.png)

A few examples of questions answered by GUAC include:

![image](https://user-images.githubusercontent.com/3060102/182689788-70acefc1-6d69-4972-abbf-3e60c0d4c014.png)

## Quickstart

Refer to the [Setup + Demo](./SETUP.md) document to learn how to prepare your
environment and try GUAC out!

## Architecture

Here is an overview of the architecture of GUAC:

![image](https://user-images.githubusercontent.com/3060102/182689908-477f4770-1142-4c18-8fa9-16d93dcf84b4.png)

## Supported input formats

- [CycloneDX](https://github.com/CycloneDX/specification)
- [Dead Simple Signing Envelope](https://github.com/secure-systems-lab/dsse)
- [In-toto ITE6](https://github.com/in-toto/attestation)
- [OpenSSF Scorecard](https://github.com/ossf/scorecard)
- [SLSA](https://github.com/slsa-framework/slsa)
- [SPDX](https://spdx.dev/specifications/)

Note that GUAC uses software identifiers standards to help link metadata
together. However, these identifiers are not always available and heuristics
need to be used to link them. Therefore, there may be unhandled edge cases and
errors occuring when ingesting data. We appreciate if a comment can be made on
the [metadata quality issue](https://github.com/guacsec/guac/issues/169).

## Additional References

- [GUAC Intro Slides](https://docs.google.com/presentation/d/1WF4dsJiwR6URWPgn1aiHAE3iLVl-oGP4SJRWFpcOlao/edit#slide=id.p)
- [GUAC Design Doc](https://docs.google.com/document/d/1N5x0HErb-kmCPgG9M8TwBEOGIVU54clqp_X4KhtNJI8/edit)
- [GUAC 2023 Q1 Maintainer Summit Notes](https://docs.google.com/document/d/15Kb3I3SWhq-9_R7WYhSjsIxn_FykYgPyFlQWlLgF4fA/edit)

## Communication

We encourage discussions to be done on github issues. We also have a
[public slack channel](https://openssf.slack.com/archives/C03U677QD46) on the
OpenSSF slack.

For future updates, announcements, and community meetings, join our
[GUAC community google group](https://groups.google.com/forum/#!forum/guac-community/join).

We host monthly community calls available for all to join
([Calendar Invite](https://calendar.google.com/calendar/event?action=TEMPLATE&tmeid=NTRsazR2cWUxaHVkYXVlOGt1dDNwZDBhNGdfMjAyMzAyMTZUMTgwMDAwWiBjXzg0ZjFmY2FhZGVhMmM0NTZlYTBkNWQ2OTljMzIwZWU5ZDc1NzY0ODQ0NzRlYmVmY2U1N2M0N2QxZWFlYjAyZDZAZw&tmsrc=c_84f1fcaadea2c456ea0d5d699c320ee9d7576484474ebefce57c47d1eaeb02d6%40group.calendar.google.com&scp=ALL)).

For security issues or code of conduct concerns, an e-mail should be sent to
guac-maintainers@googlegroups.com.

## Governance

Information about governance can be found [here](GOVERNANCE.md).
