# Reacting to a supply chain incident

The next high-profile vulnerability has landed. How should you react to it? How
do you discover which of my products and software is vulnerable? And how should
you go about in my organization to remediate the problem? What is the patch
plan?

GUAC's GraphQL API exposes the necessary information to be able to discover how
an organization's software catalog is affected and provides the ability to
remediate against large-scale security incidents in a timely manner.

In this demo, we will simulate the discovery of a high-profile vulnerability and
show how you can discover what software needs to be reviewed or patched.
CertifyBad/CertifyGood in the future will be similar to a binary authorization,
where certain checks or policies have determined that an artifact should be
utilized or not.

## Requirements

- go
- git
- web browser
- npm
- docker

### Setup the GUAC service infrastructure and binaries

If you haven't already set one up, start a fresh copy of the GUAC service
infrastructure through docker compose with [this tutorial](/docs/Compose.md).

## Clone GUAC

If you haven't already, clone GUAC to a local directory:

```bash
git clone https://github.com/guacsec/guac.git
```

Also, clone GUAC data, this is used as test data for this demo.

```bash
git clone https://github.com/guacsec/guac-data.git
```

The rest of the demo will assume you are in the GUAC directory

```bash
cd guac
```

## Building the GUAC binaries

Build the GUAC binaries using the `make` command.

```bash
make
```

### Setting up the organization's software catalog

For this demo, we will simulate ingesting an organization's software catalog. To
do this, we will ingest a collection of SBOMs.

```bash
bin/guacone collect files ../guac-data/docs/
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

## New security incident

A new security incident has occurred and listening on various communities, we
know that a particular package is affected, more specifically the debian package
"tzdata" has been found to have a critical vulnerability (yikes!). We know the
package and the specific version that is vulnerable. Can we be proactive with
this information and quickly find where this package is being used?

The first step we can take is to mark this package as bad. We can do this by
using the `guacone certify` command which defaults to assert a negative
certification (instead of a positive one), as well as a `justification` to
indicate why it is bad. In this case, it is a critical vulnerability.

```bash
./bin/guacone certify package "compromised version of tzdata" "pkg:deb/debian/tzdata@2021a-1+deb11u5?arch=all&distro=debian-11"
```

an output will contain the following meaning that we have successfully added
"CertifyBad":

```bash
{"level":"info","ts":1683130083.9894989,"caller":"helpers/assembler.go:69","msg":"assembling CertifyBad: 1"}
```

## Are you affected?

To answer the question of "Are you affected by this?" or "What do I need to
patch", you can utilize one of our experimental GUAC tools, the guac-visualizer.
The GUAC visualizer provides a utility to do some basic analysis and exploration
of the software supply chain, which is a great way to get a sense of the size of
the problem and to help in developing prototype utilities and queries with GUAC
(very much like the [vulnerability CLI](/demo/query_vuln.md)).

## Exploring bad packages

To start exploring all the "certifyBad" items (can be a package, source or
artifact), we can start by running the "query Bad" CLI.

To do this, run:

```bash
./bin/guacone query bad
```

This query will automatically search the database and find the list of
"certifyBad" that are present. For example, an output will look like the
following:

```bash
Use the arrow keys to navigate: ↓ ↑ → ←
? Select CertifyBad to Query:
  ▸ pkg:golang/github.com/kr/pretty (pretty bad undisclosed vuln)
    git+https://github.com/googleapis/google-cloud-go (github repo compromised)
    pkg:golang/github.com/pmezard/go-difflib (github repo compromised)
    pkg:maven/org.apache.logging.log4j/log4j-core@2.8.1 (never use this version of log4j)
↓   pkg:golang/github.com/prometheus/client_golang@v1.11.1 (undisclosed vuln)
```

Select the package, source, or artifact from the list and a visualizer URL will
be generated to view all the packages/artifacts that are dependents (packages
that use it). Further iterations of the same CLI tool (or another) could be used
to give a step-by-step guide to remediation!

From the list, select
`pkg:maven/org.apache.logging.log4j/log4j-core (never use this version of log4j)`
we created earlier:

```bash
Use the arrow keys to navigate: ↓ ↑ → ←
? Select CertifyBad to Query:
    pkg:golang/k8s.io/release/images/build/go-runner@%28devel%29 (compromised go-runner)
  ▸ pkg:deb/debian/tzdata@2021a-1+deb11u5 (compromised version of tzdata)
```

Doing so will produce a output similar to this:

```bash
✔ pkg:deb/debian/tzdata@2021a-1+deb11u5 (compromised version of tzdata)
Visualizer url: http://localhost:3000/?path=142605,44614,1372,1305,1304,127547,127527,127526,36248,2,125455,125358,125357,123291,123287,123286,121220,121216,121215,119149,119145,119144,117075,117074,117073,115010,115006,115005,112939,112935,112934,110299,110283,110282,107515,107453,107452,68077,67990,67989,65923,65745,65744,63678,63674,63673,61607,61603,61602,59536,59532,59531,57463,57461,57460,55393,55390,55389,53320,53319,53318,51236,51113,51112,49048,48779,48778,46714,46713,46712,44615,44610,44609,42533,42528,42527,40466,40462,40461,38397,38393,38392,36252,36250,36249,15392,15337,15336,15335,4155,4125,4124,3,3182,2865,2864,2667,2633,2632,2501,2419,2418,2413,2312,2311,2190,2150,2149,2092,2048,2047,1374,1303,1302
```

Navigating to the URL to visualize the output. This will show us an expanded
graph of dependencies. Note that if you don't see dependencies expanded here, it
is possible that additional open-source insights are still being ingested from
GUAC's external sources (such as Deps.dev). Therefore, if you are seeing less
than what is shown here, you may want to check back again by re-running the CLI
in a few minutes!

<img width="1267" alt="6" src="https://github.com/guacsec/guac/assets/88045217/bd73a5fe-ea6c-46c1-8c56-c52de6c8a567">

From here, we can tell from this example (arranging the graph a little) the bad
debian package (used for timezone information) is commonly used throughout a
bunch of dependant container images! All are a cause for concern as they are
notable images for kubernetes, redis, nginx and python. We need to remediate
these right away! This always us to quickly figure out what needs to be updated,
so we are not scrambling to first scan and determine where `tzdata` might be
used.

## Exploring bad source repos and their packages

In the above example, we look at a specific package. This time, we know of a git
repo that is producing a bunch of bad packages. We want to mark that repo as
compromised and learn what the packages are that are linked to this particular
repo and figure out where they could be used. For example, let's take the
`googleapis/google-cloud-go` git repo. We will begin by certifying it bad by
running:

```bash
bin/guacone certify source "github repo compromised" "git+https://github.com/googleapis/google-cloud-go"
```

Once again, you will see an output similar to the above confirming that it has
been added to the database:

```bash
{"level":"info","ts":1683130083.9894989,"caller":"helpers/assembler.go:69","msg":"assembling CertifyBad: 1"}
```

We perform the same actions by running the CLI but this time selecting the new
compromised source repo:

```bash
? Select CertifyBad to Query:
    pkg:golang/github.com/prometheus/client_golang@v1.4.0 (undisclosed vuln)
    pkg:golang/github.com/dougm/pretty (pretty bad undisclosed vuln)
    pkg:golang/github.com/kr/pretty (pretty bad undisclosed vuln)
  ▸ git+https://github.com/googleapis/google-cloud-go (github repo compromised)
↓   pkg:golang/github.com/pmezard/go-difflib (github repo compromised)
```

Selecting the
`gitt+https://github.com/googleapis/google-cloud-go (github repo compromised)`

will output the following. (the IDs path could be different)

```bash
✔ git+https://github.com/googleapis/google-cloud-go (github repo compromised)
Visualizer url: http://localhost:3000/?path=130726,1001,1000,97,130727,130629,4501,130728,130632,130729,130635,130730,4611,131477,4930,131478,131469,131468,133884,5380,133898,5188,133918,4502,133976,5425,134985,134417,134986,134542,138434,130615,130614,5435
```

We can now follow the url to see the following graph:

<img width="1267" alt="6" src="https://user-images.githubusercontent.com/88045217/236021344-82be9de7-1f9f-486d-b360-59588f967a9d.png">

From this view, we can see that this particular repo is being used by a bunch of
package, specifically:

| Packages                                        |
| ----------------------------------------------- |
| pkg:golang/cloud.google.com/go                  |
| pkg:golang/cloud.google.com/go/bigquery         |
| pkg:golang/cloud.google.com/go/datastore        |
| pkg:golang/cloud.google.com/go/pubsub           |
| pkg:golang/cloud.google.com/go/storage          |
| pkg:golang/cloud.google.com/go/compute          |
| pkg:golang/cloud.google.com/go/compute/metadata |
| pkg:golang/cloud.google.com/go/iam              |
| pkg:golang/cloud.google.com/go/kms              |
| pkg:golang/cloud.google.com/go/monitoring       |
| pkg:golang/cloud.google.com/go/spanner          |
| pkg:golang/cloud.google.com/go/logging          |
| pkg:golang/cloud.google.com/go/longrunning      |

From here we can investigate further and determine which packages are dependent
on these compromised packages and be able to remediate them quickly. One of the
potential next areas of work for the project is to create a CLI to do patch
planning for the organization. Given a set of packages that need to be updated,
what is the order of operations that need to be done in order to perform
remediation.

## Building more advanced patch planning capability

In order to build something like that we can further leverage the GraphQL Query
API that GUAC provides, to get started with that you may take a look at the
[GraphQL demo](/demo/GraphQL.md).
