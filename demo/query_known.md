# What is Known and Unknown about your Software Supply Chain

<img width="1260" alt="3" src="https://user-images.githubusercontent.com/88045217/235365392-39923864-10e3-48f8-ba39-93c138507b82.jpg">

The software supply chain is like a rabbit hole that could be very deep and
could hold a bunch of twists and turns. It's hard to track where the different
tunnels may lead. With SBOMs, SLSA attestations, scorecards, VEX, and other
in-toto ITE-6 attestations, the list of metadata associated with an artifact is
growing. The common questions that are asked are “Where do I store my SBOMs,
SLSA attestations, and other metadata documents?”, “Can I find these documents
quickly?”, and “What do I know (and don’t know) about my supply chain?”

GUAC has the ability to ingest and link these documents together into a complete
picture of the software supply chain! This can allow the user to easily
determine and answer the question of what are the “known, knowns” “what is
known, unknowns” and finally “unknown, unknowns”. Let's take a look at this in
more detail.

In the [workflow demo](./workflow/workflow.md), we went through the process of
ingesting an SBOM and letting GUAC expand our horizons on what we know about our
environment autonomously! In this demo, based on the documents ingested and the
information GUAC was able to pull for us, we will determine what we know but
also as equally important, what we don’t know about the artifacts.

## Requirements

- go
- Kubernetes 1.19+ ([k3s](https://github.com/k3s-io/k3s/),
  [minikube](https://github.com/kubernetes/minikube) or
  [colima](https://github.com/abiosoft/colima) (or another k8s service of your
  choice))
- [Helm v3.9.4+](https://helm.sh/)

**NOTE**: There is also a docker-compose deployment to get GUAC running if you
don't want to use Kubernetes. Follow the
[docker compose deployment](../../docs/Compose.md) to get started!

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

## Installing GUAC via Helm Chart/Docker Compose

Please refer to the GUAC Helm Install Guide<INSERT LINK HERE> or
[docker compose deployment](../../docs/Compose.md) to have a running instance.

## Ingesting Vault’s SBOM

As this demo builds off [workflow demo](./workflow/workflow.md) please follow
the steps for ingesting
[Vault’s SBOM](https://github.com/guacsec/guac-data/blob/main/top-dh-sboms/vault.json)
and letting GUAC find additional information about the dependencies.

## Running the query to find the knowns and unknowns

Now that we have the data ingested from the
[workflow demo](./workflow/workflow.md), let's run some queries on the data.

GAUC (at the time of the beta release) can store various metadata about an
artifact. In the context of query CLI, the evidence nodes have the following
definitions:

| Evidence Nodes | Description                                                                  |
| -------------- | ---------------------------------------------------------------------------- |
| `hashEquals`   | when two artifacts are equal                                                 |
| `scorecards`   | the OpenSSF scorecard associated with the source repo                        |
| `occurrences`  | a package is associated with an artifact (digest) (or vice-versa)            |
| `hasSrcAt`     | a package has a source repo at the following location                        |
| `hasSBOMs`     | a package/artifact has an SBOM stored in a downloadable location             |
| `hasSLSAs`     | the artifact has an SLSA attestation stored in a downloadable location       |
| `certifyVulns` | the package has been scanned (currently via OSV) and the results of the scan |
| `vexLinks`     | a VEX document associated with the Vulnerability                             |
| `badLinks`     | list of CertifyBad associated with the package, source or artifact           |
| `goodLinks`    | list of CertifyGood associated with the package, source or artifact          |
| `pkgEquals`    | two packages (with different purls) are equal                                |

For more information on these please refer to the
[grapQL documentation](../docs/GraphQL.md) along with the
[ontology definitions](../docs/ontology-definitions.md).

Utilizing the CLI and GUAC Visualizer, we quickly determine the location of
SBOMs, SLSA attestations, and scorecard information but also determine what
information we are missing.

## Query Known/Unknown

We will utilize the “query known” CLI. This CLI has the ability to search a
package via [PURL](https://github.com/package-url/purl-spec), source URL
following the definition of VCS uri from the
[SPDX documentation](https://spdx.github.io/spdx-spec/v2.3/package-information/#771-description)
`<vcs_tool>+<transport>://<host_name>[/<path_to_repository>][@<revision_tag_or_branch>][#<sub_path>])`
and a artifact (algorithm:digest).

First, we will look at if a package (vault) to see if it has an SBOM associated
with and where it can be found:

**Note**: `--type "package"` flag is specified that we are querying a PURL

```bash
./bin/guacone query known --type "package" "pkg:guac/spdx/docker.io/library/vault-latest"
```

The output will look similar to this:

```bash
+------------------------------------------------+
| Package Name Nodes                             |
+-----------+-----------+------------------------+
| NODE TYPE | NODE ID   | ADDITIONAL INFORMATION |
+-----------+-----------+------------------------+
+-----------+-----------+------------------------+
Visualizer url: http://localhost:3000/?path=4,3,2
+----------------------------------------------------------------------------------------------+
| Package Version Nodes                                                                        |
+-----------+-----------+----------------------------------------------------------------------+
| NODE TYPE | NODE ID   | ADDITIONAL INFORMATION                                               |
+-----------+-----------+----------------------------------------------------------------------+
| hasSBOM   | 6964      | SBOM Download Location: file:///../guac-data/top-dh-sboms/vault.json |
+-----------+-----------+----------------------------------------------------------------------+
Visualizer url: http://localhost:3000/?path=5,4,3,2,6964

```

This output is two separate tables, one for the “package name level” and the
other at the “package version level”. Evidence/metadata nodes at the “package
name level” mean that they apply to all the versions that come below it.
“Package version level”, on the other hand, means that it only applies to the
version specified. By default, if a version is not specified during ingestion,
it defaults to an empty version string.

The “package name level” does not have any nodes associated with it, but the
“package version level” does have the “hasSBOM” node associated with it. This
shows us that this package has an SBOM associated with it and can be downloaded
at the following location. Future work with GUAC is to have an evidence store
with GUAC to store SBOM and SLSA attestations for quick access. For now, we can
quickly locate the SBOM but we also learn that we are missing `hasSLSA`
attestations for this package.

Next, we will run the query on the Prometheus package we were working on within
the workflow demo:

```bash
./bin/guacone query_known --type
"package" "pkg:golang/github.com/prometheus/client_golang@v1.11.1"
```

The Output should be similar to this:

```bash
+---------------------------------------------------------------------------------+
| Package Name Nodes                                                              |
+-----------+-----------+---------------------------------------------------------+
| NODE TYPE | NODE ID   | ADDITIONAL INFORMATION                                  |
+-----------+-----------+---------------------------------------------------------+
| hasSrcAt  | 7647      | Source: git+https://github.com/prometheus/client_golang |
+-----------+-----------+---------------------------------------------------------+
Visualizer url: http://localhost:3000/?path=578,327,6,7647
+----------------------------------------------------+
| Package Version Nodes                              |
+-------------+-----------+--------------------------+
| NODE TYPE   | NODE ID   | ADDITIONAL INFORMATION   |
+-------------+-----------+--------------------------+
| certifyVuln | 13469     | vulnerability ID: NoVuln |
+-------------+-----------+--------------------------+
Visualizer url: http://localhost:3000/?path=579,578,327,6,13469

```

In this example, the “package name level” has the “hasSrcAt” node that shows us
that the “prometheus/client_golang” source repo is located at
“<https://github.com/prometheus/client_golang>”

The “Package Version Nodes” shows us that the specific package with the purl
`pkg:golang/github.com/prometheus/client_golang@v1.11.1` was scanned and did not
contain any vulnerabilities associated with it.

**NOTE**: this is just the vulnerability associated with this specific package
(not taking into account dependencies). For a full in-depth vulnerability search
please follow the [Query Vulnerability demo](./query_vuln.md)

We also see that in this case, we did not get a `hasSBOM` associated with it.
Meaning that we do not have any SBOM information related to this package. We
also see there are no nodes for the SLSA attestations, but we could query the
source for more information about it and its scorecard information.

But before we do that, we will look at another version of the
“prometheus/client_golang” package with the purl
"pkg:golang/github.com/prometheus/client_golang@v1.4.0". Note the version is now
v1.4.0.

Using the CLI to query this:

```bash
./bin/guacone query_known --type "package" "pkg:golang/github.com/prometheus/client_golang@v1.4.0"
```

```bash
+---------------------------------------------------------------------------------+
| Package Name Nodes                                                              |
+-----------+-----------+---------------------------------------------------------+
| NODE TYPE | NODE ID   | ADDITIONAL INFORMATION                                  |
+-----------+-----------+---------------------------------------------------------+
| hasSrcAt  | 7647      | Source: git+https://github.com/prometheus/client_golang |
+-----------+-----------+---------------------------------------------------------+
Visualizer url: http://localhost:3000/?path=578,327,6,7647
+-----------------------------------------------------------------+
| Package Version Nodes                                           |
+-------------+-----------+---------------------------------------+
| NODE TYPE   | NODE ID   | ADDITIONAL INFORMATION                |
+-------------+-----------+---------------------------------------+
| certifyVuln | 13471     | vulnerability ID: ghsa-cg3q-j54f-5p7p |
| certifyVuln | 13473     | vulnerability ID: go-2022-0322        |
+-------------+-----------+---------------------------------------+
Visualizer url: http://localhost:3000/?path=7600,578,327,6,13471,13473
```

We once again see that at the “package name level” we have the same source repo
associated with it. But at the “package version level” (at v1.4.0) there are
some vulnerabilities that are associated with it! The newer version of the same
“prometheus/client_golang” did not have these vulnerabilities. We could do
further investigation via the GUAC visualizer (and other upcoming tools) to
determine which packages are dependent on these and need to be updated to a
newer version. For example, from the workflow demo, we know that
github.com/armon/go-metrics version 0.3.10 depends on this package and should be
immediately updated!

```bash
     {
        "id": "7624",
        "justification": "dependency data collected via deps.dev",
        "package": {
          "id": "6",
          "type": "golang",
          "namespaces": [
            {
              "id": "279",
              "namespace": "github.com/armon",
              "names": [
                {
                  "id": "280",
                  "name": "go-metrics",
                  "versions": [
                    {
                      "id": "281",
                      "version": "v0.3.10",
                      "qualifiers": [],
                      "subpath": ""
                    }
                  ]
                }
              ]
            }
          ]
        },
        "dependentPackage": {
          "id": "6",
          "type": "golang",
          "namespaces": [
            {
              "id": "396",
              "namespace": "github.com/prometheus",
              "names": [
                {
                  "id": "397",
                  "name": "client_golang",
                  "versions": []
                }
              ]
            }
          ]
        },
        "versionRange": "v1.4.0",
        "origin": "deps.dev",
        "collector": "deps.dev"
      }
```

Next, let's take a closer look at the source repo for the
prometheus/client_golang package:

We can run the query:

**Note**: `--type "source"` flag is specified that we are querying a source repo

```bash
./bin/guacone query_known --type "source" git+https://github.com/prometheus/client_golang
```

```bash
+-----------+-----------+--------------------------------------------------------------------+
| NODE TYPE | NODE ID   | ADDITIONAL INFORMATION                                             |
+-----------+-----------+--------------------------------------------------------------------+
| hasSrcAt  | 7647      | Source for Package: pkg:golang/github.com/prometheus/client_golang |
+-----------+-----------+--------------------------------------------------------------------+
| scorecard | 7583      | Overall Score: 6.600000                                            |
+-----------+-----------+--------------------------------------------------------------------+
Visualizer url: http://localhost:3000/?path=7582,7581,6965,7647,7583
```

From this output, we see the reverse of what we saw when we queried the package.
This time, we see that this source is related to the prometheus/client_golang
package we queried for above but also we see that there is an OpenSSF scorecard
associated.

Finally, let’s query for another source repo:

```bash
./bin/guacone query_known --type "source" "git+https://github.com/googleapis/google-cloud-go"
```

The output should be similar to:

```bash
+-----------+-----------+---------------------------------------------------------------------+
| NODE TYPE | NODE ID   | ADDITIONAL INFORMATION                                              |
+-----------+-----------+---------------------------------------------------------------------+
| hasSrcAt  | 7074      | Source for Package: pkg:golang/cloud.google.com/go                  |
| hasSrcAt  | 7075      | Source for Package: pkg:golang/cloud.google.com/go/storage          |
| hasSrcAt  | 7156      | Source for Package: pkg:golang/cloud.google.com/go/spanner          |
| hasSrcAt  | 8948      | Source for Package: pkg:golang/cloud.google.com/go/compute/metadata |
| hasSrcAt  | 8949      | Source for Package: pkg:golang/cloud.google.com/go/logging          |
| hasSrcAt  | 8950      | Source for Package: pkg:golang/cloud.google.com/go/longrunning      |
+-----------+-----------+---------------------------------------------------------------------+
| scorecard | 6968      | Overall Score: 8.300000                                             |
+-----------+-----------+---------------------------------------------------------------------+
Visualizer url: http://localhost:3000/?path=6967,6966,6965,7074,7075,7156,8948,8949,8950,6968
```

Here we see that this specific source repo is associated with various different
packages (go, storage, spanner…etc), and again we see that it does have a
scorecard associated with a score of 8.3

## Knowing the unknown

Based on the information gathered above, we know what we have about the various
artifacts (either ingested or determine by the services of GUAC). We can quickly
locate an SBOM, an SLSA attestation (other ITE-6 attestations), OpenSSF
scorecard information, and other metadata quickly. At the same time, we
determined what “we don’t know”. For example, some packages did not have an SBOM
or SLSA attestation associated, there may have been source repositories that
might not have been scanned by OpenSSF Scorecard.

Finally, we found out information that we didn’t even know that we “needed to
know”. For example, the vulnerable version of prometheus/client_golang (the
older version) is being used in our software supply chain and needs to be
immediately updated. Knowing the unknown is the first key step in securing the
supply chain. If the security teams and developers have no knowledge of these,
how can we keep shifting left effectively?
