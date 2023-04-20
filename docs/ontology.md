# GUAC Ontology

## Problem Statement

Software supply chain is becoming more sophisticated than ever, as well as its
compromises. With this comes the availability and popularity of various efforts
around software metadata such as SLSA/In-toto and SBOM. To better understand the
security posture of a software, we need to know software supply chain properties
about each used artifact. To solve this problem, we propose building a software
supply chain knowledge graph, GUAC (Graph for Understanding Artifact
Composition). GUAC should allow us to efficiently query information about
software supply chain properties and efficiently update the state of the supply
chain.

## Distilling an Ontology for GUAC

At a low level, a software supply chain is a series of _actions_ carried out by
_actors_ to produce _artifacts._ Generally speaking, determining the quality
properties of an artifact boils down to how much we trust actors, what
information can we glean from their actions and how artifacts relate to each
other.

By building a universal graph, we are able to answer questions such as:

- Is this _artifact_ affected by this _vulnerability_ as _reported_ by this
  _scan_?
- Has this _artifact_ been _reviewed_ by a _trusted individual_
- Was this _artifact_ _involved_ in this security _incident_?

We posit that, in order to be able to answer these questions, we just need to
appropriate collect the following information:

- Evidence collection about actions
- Actors and actions
- Software and its lineage

With this, we are able to transform any informational query into one that
involves the triple (artifacts, actors, actions).

## Mapping the three elements of supply chains to a universal graph

A first finding is that all these three elements can be collected for public
information and used to construct a _semantic_ _tree_ about their respective
element. This not only allows us to turn the collector functions into a
_bijection_, and as such prevent the loss of data during the collection process.

We develop these bijections in the collector to build trees of evidence, trees
of actions and trees of software lineage that then we can connect to each other
to build the graph

### The evidence tree

The first tree of information is that of the evidence tree. That is, for each
piece of evidence collected we are able to build a tree of the following
elements by following the **ITE-6 processing model**:

1. DSSE layer: creates an edge between an actor (identity) and an action
1. Subject layer: creates an edge between an action and a software instance
   (e.g., identified by a purl and a hash)
1. Predicate layer: creates an edge between a collection of software instances
   and an action (e.g., a series of packages and environmental tools)

<img width="940" alt="1" src="https://user-images.githubusercontent.com/3060102/233409097-638d7ec8-9422-43c5-949a-e9753c6617f6.png">

These trees can be decomposed to further separate actions and evidence. For
example, an SBOM using SPDX can be decomposed into a series of evidentiary
information that separates each relationship information with a separate one.

### The actor tree

The actor tree attempts to model the trust relationships between actors, as well
as the provenance information between actors and claims. At an ideal level, this
portion of the graph allows us to model such trust relationships between actors
as a separate operation. While there are many standards for trust models (e.g.,
PKIx and PGP), the fundamental property of trust is that it can be either
provided de-facto (i.e., by a policy mechanism) or it can be compounded (i.e.,
it can be computed as a function of a collection of the former type).

For example, an X509 certificate allows us to build an identity tree of the
following nature:

1. A certificate represent an identity
1. A certificate chain represents a path of trust between a series of identities

This tree can be collected from public identity sources (e.g., a certificate
transparency log, or a pgp keyserver) and used to create a collection of trust
trees.

### The software tree

FInally, the software tree represents a series of software properties that
relate to their logical collection up to their "physical instantiations". This
can be easily modeled using a pURL semantic, which describes a software
artifact. Take for example the following purl pkg:pypi/django@1.11.1, it can be
used to model software relationships with the following properties:

1. A software type (pkg)
1. A software repository (pypi)
1. A software name (django)
1. A version (1.11.1)

<img width="688" alt="2" src="https://user-images.githubusercontent.com/3060102/233409099-27ca189f-a6ad-47b5-bb0d-0d99e1f74e52.png">

### Combining Trees for more expressive search Query:

The three trees combine as following :

- The hash in the software tree is the artifact in the evidence tree.
- The identity in the evidence tree is the signature in the actor tree.

<img width="919" alt="3" src="https://user-images.githubusercontent.com/3060102/233409102-6a53112e-dace-4dbe-91c1-63fd53497e72.png">

With this in mind, GUAC queries can be defined as:

- Network structure tests (e.g., reachability)
- Node property and tes

## Use Cases

### Use Case: Identifying Connected Components\*\*

**Description:**  
Given a starting node, retrieve the entire connected component of it.

**Example diagram**

An Organization wants to dumb all the metadata and assertions related to an
artifact.

**_Query_:** connected component given start node artifact C  
**_Approach_:** starting from artifact C, get all first neighbor evidence nodes
, then get the connected component of each evidence, the result subgraph is the
connected component starting artifact C  
**_Result_:**

<img width="940" alt="4" src="https://user-images.githubusercontent.com/3060102/233409103-e22b1d0e-966d-45ea-aaad-7e15aa7d68ce.png">

### Use Case: Reachability

**Description:**

An Organization wants to check if it is software affected by a recently
published vulnerability with an assigned CVE number, signed by a specific
vulnerability database .

- Query the GUAC Graph such that based on the artifact nodes of the software,
  Can you reach the CVE evidence, then the vulnerability database ? If yes, then
  the software is vulnerable to it.

**Example diagram**

**_Query_:** Is artifact C affected by CVE#2 and that report has been done by
the national vulnerability database ?  
**_Approach_:** From Identity tree, determine which nodes belong to that class
of identities, is there a path from the artifact -> CVE -> any node in the class
of identities.  
**_Result_:** From identity tree, NVD identities are NVD#Root, NVD#2,NVD#3.  
Walk the path (artifact C -> SLSA evidence -> Artifact A -> CVE#2 evidence->
identity NVD#3 )

<img width="1000" alt="5" src="https://user-images.githubusercontent.com/3060102/233409106-703b9e41-346c-4f94-b3bf-e7677012525f.png">

However, this does not cover a case in which two different reports describe the
same artifact and do **not** agree in the security posture of an artifact

### Use Case: Counterfactual (not part of v0.1 BETA)

GUAC should be able to raise counterfactuals to show conflicts of two trusted
documents metadata, e.g.,conflicting SLSA attestation.

**Description:**

An Organization wants to check the vulnerabilities that affect its software.

- Query the GUAC Graph such that based on the artifact nodes of the software, do
  they have any neighbor CVE evidence?

**Example diagram**

**_Query_:** Is artifact C affected by any vulnerability ?  
**_Approach_:** Using first neighbor search, is there any neighbor CVE evidence
for artifact C?  
**_Result_:** Using first neighbor search, Bob signed CVE#4 evidence, while Sam
signed CVE#5 evidence, conflicting information, Bob and Sam disagree about the
CVEs affecting artifact C.

Conflicting information should be flagged as something to be analyzed further.  
Speculative vs Factual

<img width="897" alt="6" src="https://user-images.githubusercontent.com/3060102/233409111-f9f669be-4e8a-44e4-9e4e-4db201fa5b97.png">

## Use Case: Hypergraph Semantics (not part of v0.1 BETA)

A hypergraph is a graph in which hyperedges can connect to a subset of nodes
rather than two nodes. Hyperedges can be used to do logical grouping for nodes
that represent the same thing, and they may appear in GUAC in couple of ways:

- **Artifacts:** identical artifacts or packages, for example : a SLSA document
  describing an artifact with multiple hashes makes the implicit claim that
  these hashes describe the same content. These hashes of the same artifact
  could be grouped together in a hypergraph.
- **Identities:** the same identity has multiple public keys, or multiple people
  represents an identity.

**How is it useful to use them in GUAC?**

With that explained, we note that this is future work not covered in guac beta,
and may be covered in future releases.

**Agreement over same CVE evidence**

<img width="899" alt="7" src="https://user-images.githubusercontent.com/3060102/233409112-87a0ed55-ea66-4d43-9949-50d3c00d6392.png">
