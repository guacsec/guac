# Reacting to a supply chain incident

The next log4shell type vulnerability has landed. How should you react to it?
How do you discover which of my products and software is vulnerable? And how
should you go about in my organization to remediate the problem? What is the
patch plan?

GUAC's GraphQL API exposes the necessary information to be able to discover how
an organization's software catalog is affected, and provide ability to remediate
against large scale security incidents in a timely manner.

In this demo, we will simulate the discovery of a brand new vulnerability, which
doesn't even have a CVE, and show how you can discover what software needs to be
reviewed or patched.

## Requirements

- go
- git
- web browser
- npm
- docker

### Setup the GUAC service infrastructure and binaries

If you haven't already set one up, start a fresh copy of the GUAC service
infrastructure through docker compose with [this tutorial](/docs/Compose.md).

### Setting up the organization's software catalog

For this demo, we will simulate ingesting an organization's software catalog. To
do this, we will ingest a collection of SBOMs.

```bash
bin/guacone files ../guac-data/docs/
```

This will ingest a collection of SBOMs and SLSA attestations into GUAC.

Once ingested we will see the following message (the number of documents may
vary):

```bash
{"level":"info","ts":1681864775.1161852,"caller":"cmd/files.go:201","msg":"completed ingesting 67 documents of 67"}
```

### Setting up the experimental GUAC Visualizer

To start up the GUAC visualizer, follow
[this guide](https://github.com/guacsec/guac-visualizer/tree/main/docs/setup.md).

## New security incident!

A new security incident has occurred, and there's no CVE or report for it yet,
but listening on various communities, we know that a particular package is
affected, more specifically the package "golang/github.com/dougm/pretty" has
been found to have a vulnerability.

The first step we can take is to mark this packages as bad. We can do this by
using the `guacone certify` command with the `-good=false` flag which asserts
that it is a negative certification (instead of a positive one), as well as a
`justification` flag to indicate why it is bad. In this cause it is a new
undisclosed vulnerability.

```bash
bin/guacone certify --good=false -n --justification="pretty bad undisclosed vuln" --type package pkg:golang/github.com/dougm/pretty
```

## Are you affected?

To answer the question of "are you affected?", you can utilize one of our
experimental GUAC tools, the guac-visualizer. The GUAC visualizer provides a
utility to do some basic analysis and exploration of the software supply chain,
which is a great way to get a sense of the size of the problem and to help in
developing prototype utilities and queries with GUAC (very much like the
[vulnerability CLI](/demo/query_vuln.md)).

## Exploring bad packages

We start by navigating to the GUAC visualizer in a browser. If you are using the
stadard setup, this should be http://localhost:3000. We can see that there is an
option to browse different packages, as well as a drop down indicating
"CertifyBad Entities". Since this is what we'd like to find out more about,
let's use that drop down and select the bad package.

<img width="1264" alt="1" src="https://user-images.githubusercontent.com/3060102/233170909-ae42af31-c387-449e-b1ec-715f9c13649f.png">

Doing this will result in a graph appearing, showing the definition of the
package within the graph.

<img width="1224" alt="2" src="https://user-images.githubusercontent.com/3060102/233170940-1a7c07bc-50c1-4870-9e5c-d64554d7ecef.png">

This doesn't show much, since we have not yet expanded the graph. To expand the
graph to find its dependents (packages that use it), we can utilize the expand
dependents feature in the UI. Be sure to select "Expand Dependents" options, set
the exploration depth (defaults to 3) and hit "Expand".

<img width="1260" alt="3" src="https://user-images.githubusercontent.com/3060102/233170956-af80325e-b756-4c28-bc6b-af0b2d2a5ec6.png">

This will end up giving up an expanded graph of depedencies. Note that if you
don't see depedencies expanded here, it is possible that additional open source
insights is still being ingested from GUAC's external sources (such as
Deps.dev). Therefore, if you are seeing less than what is shown here, you may
want to check back again in a few minutes!

<img width="1064" alt="4" src="https://user-images.githubusercontent.com/3060102/233170971-5573b807-da1a-43f2-9feb-950a6633958b.png">

From here, we can tell from this small example (arranging the graph a little)
that the bad library is being used by the "vic" package, which is then used by
go library `go-discover`, which are used by the vault and consul docker
containers. From this we can tell which software needs to be patched and
rebuilt. In this case, once the `pretty` package is patched, `vic` and
`go-discover` needs to be updated, followed by the containers `vault` and
`consul` re-built.

Alternatively, if the `vic` package can be analyzed to check if it is affected
by the use of the component and a VEX statement can be produced for the new
issue (linking to it when a CVE or vulnerability identifier is released).

## Bigger example

Th above example is a fairly simple one. However, taking a more popularly used
library, we can use the same flow, but with additional capabilities in the UI.
This is an illustration based on our experimental visualizer, and we are working
towards automating some of this in the `guacone` CLI.

In this next example, we will simulate a github repo getting compromised and do
the same analysis.

```bash
bin/guacone certify --good=false -n --justification="github repo compromised" --type package pkg:golang/github.com/pmezard/go-difflib
```

We perform the same actions, but now we see that as we expand the graph, we no
longer see the visual graph component. This is because having a graph of a large
size isn't very helpful in understanding what's going on. However, we can still
do some analysis of the data! By using the node expander, we can specify that we
want to find all paths to other packages (through the "PackageName" node).

<img width="1267" alt="6" src="https://user-images.githubusercontent.com/3060102/233170988-643b5e46-d6ec-449b-86b1-25c1dc1200d1.png">

We can then hit "find path", which will then list all the dependent paths on the
bad package. We gather from this list all the packages that are affected in our
software catalog.

<img width="1270" alt="7" src="https://user-images.githubusercontent.com/3060102/233170989-24c71faf-d846-4583-84fa-be098799e77d.png">

We can click on the "[Click here to Visualize]" text to open up that path in
visual format, which will provide us the ability to develop a patch plan. One of
the potential next areas of work for the project is to create a CLI to do patch
planning for the organization. Given a set of packages that need to be updated,
what is the order of operations that need to be done in order to perform
remediation.

<img width="1267" alt="8" src="https://user-images.githubusercontent.com/3060102/233170991-f5dfe23f-8530-496b-8686-ccb3bc9d432e.png">

## Building more advanced patch planning capability

In order to build something like that we can further leverage the GraphQL Query
API that GUAC provides, to get started with that you may take a look at the
[GraphQL demo](/demo/GraphQL.md).
