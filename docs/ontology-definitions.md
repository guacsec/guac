# GUAC Ontology Definition

This document provides some insights into how the GUAC ontology was defined.

For a comprehensive and up-to-date listing of the GUAC ontology, please refer to
the
[GraphQL documentation](https://github.com/guacsec/guac/blob/main/docs/GraphQL.md).

## Overview

Based on the [GUAC Onlotogy](./ontology.md) design document, the 3 structures
were defined. These are the software tree, evidence tree, and finally the actor
tree.

- **Software Tree:** A factual structure that describes software entities. They
  communicate both physical (e.g. artifact and hashes) and logical (e.g. PURL)
  view, and is an extension of the idea of factual software identifiers nodes as
  described in
  [GUAC Identity Problem Design Doc [Shared Externally] ](https://docs.google.com/document/d/1BUEi7q2i-KXlAhsh1adYvL1fkWN-q8FrgLyEre7c5kg/edit?resourcekey=0-02sC5-9IbTfwJckze_CDQw)(Issue
  [#217](https://github.com/guacsec/guac/issues/217))
- **Evidence Tree:** A structure to communicate claims about nodes in a software
  tree and ties them to the actor tree. All claims are considered skeptical and
  need to be evaluated based on observing their evidence (through linking with
  the actor tree)
- **Actor Tree:** A structure to model trust and trust relationships

## GUAC Software Tree

We first have to define the software tree and components. This can be broken
into, PURL, source, artifact, builder, OSV, GHSA, and CVE.

For a comprehensive and up-to-date listing of the GUAC ontology, please refer to
the
[GraphQL documentation](https://github.com/guacsec/guac/blob/main/docs/GraphQL.md).

1.  Package (Pkg) (based on the
    [purl-spec](https://github.com/package-url/purl-spec)) is defined as the
    following: **scheme:type/namespace/name@version?qualifiers#subpath**. The
    definition for each component is:

    1.  **scheme**: this is the URL scheme with the constant value of "pkg". One
        of the primary reason for this single scheme is to facilitate the future
        official registration of the "pkg" scheme for package URLs. Required.
    1.  **type**: the package "type" or package "protocol" such as maven, npm,
        nuget, gem, pypi, etc. Required.
    1.  **namespace**: some name prefix such as a Maven groupid, a Docker image
        owner, a GitHub user or an organization. Optional and type-specific.
    1.  **name**: the name of the package. Required.
    1.  **version**: the version of the package. Optional.
    1.  **qualifiers**: extra qualifying data for a package such as an OS,
        architecture, a distro, etc. Optional and type-specific.
    1.  **subpath**: extra subpath within a package, relative to the package
        root. Optional.
    1.  The question arises if the pkg/PURL software tree should eventually
        extend to have artifacts as leaves. It was decided that mapping to
        hashes as leaf nodes should not be part of the software tree and should
        be linked via an attestation/evidence tree. This is due to the fact that
        saying a package has an occurrence of an artifact with hash is an
        opinion, and software trees need to remain factual. For example, an SBOM
        may contain an entry that says "pkg://abc" has hash "sha256:def",
        however, this may be incorrect - and thus GUAC providing the ability to
        raise counterfactuals becomes important IF there is a conflict of two
        trusted document metadata.

2.  Source to define the location of the software artifact. Similar to the purl
    spec this is defined:
    1.  **type:**: version control system type (git/svn/cvs)
    1.  **namespace**: location of the repo (github/gitlab/bitbucket)
    1.  **name**: URL to the repo
    1.  **qualifier**: tag or commit
3.  Artifact contains the hash of the software component
4.  Builder is the component that built the artifact (for example GitHub
    actions, FRSCA). This contains the URI of the builder.
5.  [OSV](https://osv.dev/) or Open Source Vulnerability contains the OSV ID
    that can be mapped to a GHSA or CVE
6.  GHSA - GitHub Security Advisory contains a GHSA ID that maps to the
    [GitHub Advisory Database](https://github.com/advisories)
7.  CVE - Common Vulnerabilities and Exposures contains a CVE ID

A visualization of some of the above software trees would look like:

![guacontologyde--caxvto8ogd](https://user-images.githubusercontent.com/3060102/233416367-2eab415e-7a79-4e58-b43c-6f590f60b916.png)

## GUAC Evidence Tree

An evidence tree would then create attestations/actions against nodes of a
software tree and link them to each other and to nodes in the actor tree. We
note that attestations/actions represented as evidence trees can be overlaid not
only on leaf nodes. For example, an attestation may be on all software versions,
and thus may be applied upon the software tree representation of the PURL:
pkg://pypi/requests, instead of doing it on a particular version number. This
also applies to the representation of the source where the name and qualifier
(containing the tag/commit) may be used for the attestation.

An example of a predicate is:

**IsDependency:**

- **Description**: attestation that the package has the following dependencies
  (pkg) based on a justification

- **Subject**:
  - pkg
- **Object**:
  - depends_on ( pkg ) (**pkgName**)
- **Properties**:
  - justification ( string )
  - version_range ( string )
  - source ( string )
  - collector ( string )

For a list of all predicates, please refer to the
[GraphQL documentation](https://github.com/guacsec/guac/blob/main/docs/GraphQL.md).

## GUAC Actor Tree (Not in v0.1 BETA)

The structure of the trust ontology being one of either delegation (e.g.
certificate authorities), or one of a web of trust (e.g. pgp). These were the
two topologies of trust that encapsulates the most common trust models.

The reasoning/verification of actions and the corresponding trust backed by it.
We determined there to be 3 different dimensions of trust of action, they are:

- The identity: Do I trust verification of who is the entity that has made this
  claim is?
- The capability: Do I trust the entity to assert that claim?
- The subject: Do I trust the entity is an authority to such a claim?

To start, we decided to start with the following:

- Structure: Only interested in the leaf nodes of a trust ontology.
- Reasoning: We only care about the identity for the GUAC beta, and capabilities
  as far as intrinsic protocols allow the expressiveness of (x509 expiry and key
  capabilities)

The way to do this is to have identity nodes as part of the "Actor Tree" be just
singletons represented by a URI and whether or not they've been verified. These
URIs would be validated with the root of trust via trust oracle, which would use
a trust config per GUAC instance to verify the signatures and provide a URI that
can be used to make trust decisions. This is building upon the proposal as in
the "Trust Policy" section of this document:
[GUAC Identity Problem Design Doc [Shared Externally] ](https://docs.google.com/document/d/1BUEi7q2i-KXlAhsh1adYvL1fkWN-q8FrgLyEre7c5kg/edit?resourcekey=0-02sC5-9IbTfwJckze_CDQw#heading=h.h9kfextfhlqn),
and discussed as part of
[this issue](https://github.com/guacsec/guac/issues/75).

This would look like the following from a topological perspective. However,
since they are singleton nodes, they can be stored as URIs in each evidence node
and can be de-normalized if there is a need to optimize queries.

![guacontologyde--lnkzgnmkpw](https://user-images.githubusercontent.com/3060102/233416389-e655067a-5b73-4616-b834-80473fbe913f.png)
