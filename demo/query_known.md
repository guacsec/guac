# What is Known and Unknown about your software supply chain

<img width="1260" alt="3" src="https://user-images.githubusercontent.com/88045217/235365392-39923864-10e3-48f8-ba39-93c138507b82.jpg">

The software supply chain is like a rabbit hole that could be very deep and it's
hard to track where the different tunnels may lead. With SBOMs, SLSA
attestations, scorecard, VEX, and other in-toto ITE-6 attestations, the list of
metadata associated with an artifact is growing. The common questions that are
asked are “Where do I store my SBOMs, SLSA attestations, and other metadata
documents?”, “Can I find these documents quickly?”, and “What do I know (and
don’t know) about my supply chain?”

GUAC has the ability to ingest and link these documents together into a complete
picture of the software supply chain! This can allow the user to easily
determine and answer the question of what are the “known, knowns” “what is
known, unknowns” and finally “unknown, unknowns”. Let's take a look at this in
more detail.

In the [workflow demo](./workflow/workflow.md), we went through the process
of ingesting an SBOM and letting GUAC expand our horizons on what we know about
our environment autonomously! In this demo, based on the documents ingested and
the information GUAC was able to pull for us, we will determine what we know but
also as equally important, what we don’t know about the artifacts.

## Requirements

- go
- Kubernetes 1.19+ ([k3s](https://github.com/k3s-io/k3s/),
  [minikube](https://github.com/kubernetes/minikube) or
  [colima](https://github.com/abiosoft/colima) (or another k8s service of your
  choice))
- [Helm v3.9.4+](https://helm.sh/)

**NOTE**: There is also a docker compose deployment to get GUAC running if you
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

## Installing GUAC via Helm Chart/Docker compose

Please refer to the <GUAC Helm Install Guide> or [docker compose deployment](../../docs/Compose.md)  to have a running instance.

## Ingesting Vault’s SBOM

As this demo builds off
[docker compose deployment](../../docs/Compose.md)
please follow the steps of ingesting
[Vault’s SBOM](https://github.com/guacsec/guac-data/blob/main/top-dh-sboms/vault.json)
and letting GUAC find additional information about the dependencies.

## Running the query to find the knowns and unknowns

Now that we have the data ingested from the
[docker compose deployment](../../docs/Compose.md),
let's run some queries on the data.

GAUC (at the time of the beta release) can store various metadata about an
artifact. In context of the query CLI the evidence nodes have the following meaning:

| Evidence Nodes | Description                                                                  |
|----------------|------------------------------------------------------------------------------|
| `hashEquals`   | when two artifacts are equal                                                 |
| `scorecards`   | the OpenSSF scorecard associated with the source repo                        |
| `occurrences`  | a package is associated with an artifact (digest)                            |
| `hasSrcAt`     | a package has a source repo at the following location                        |
| `hasSBOMs`     | a package/artifact has an SBOM stored in a downloadable location             |
| `hasSLSAs`     | the artifact has an SLSA attestation stored in a downloadable location       |
| `certifyVulns` | the package has been scanned (currently via OSV) and the results of the scan |
| `vexLinks`     | a VEX document associated with the Vulnerability                             |
| `badLinks`     | list of CertifyBad associated with the package, source or artifact           |
| `goodLinks`    | list of CertifyGood associated with the package, source or artifact          |
| `pkgEquals`    | two packages (with different purls) are equal                                |

For more information on these please refer to the
[grapQL documentation](../docs/GraphQL.md)
along with the
[ontology definitions](../docs/ontology-definitions.md)
Utilizing the CLI and GUAC Visualizer, we quickly determine the location of
SBOMs, SLSA attestations, and scorecard information but also determine what
information we are missing.

## Query Known/Unknown

We will utilize the “query known” CLI:

First, we will look at if a package (vault) has an SBOM associated with and
where it can be found:

```bash
./bin/guacone query_known --type "package" "pkg:guac/spdx/docker.io/library/vault-latest"
```

The output will look similar to this:

```bash
{"level":"info","ts":1682866911.5851321,"caller":"cli/init.go:53","msg":"Using config file: /Users/parth/Documents/pxp928/artifact-ff/guac.yaml"}
+-----------+-----------+----------------------------------------------------------------------+
| NODE TYPE | NODE ID   | ADDITIONAL INFORMATION                                               |
+-----------+-----------+----------------------------------------------------------------------+
| hasSBOM   | 6964      | SBOM Download Location: file:///../guac-data/top-dh-sboms/vault.json |
+-----------+-----------+----------------------------------------------------------------------+
Visualizer url: http://localhost:3000/visualize?path=[5,4,3,2,6964]
```

```bash
➜  artifact-ff git:(unknown-known-demo) ✗ ./bin/guacone query_known --type "package" "pkg:guac/spdx/docker.io/library/vault-latest"
{"level":"info","ts":1682866911.5851321,"caller":"cli/init.go:53","msg":"Using config file: /Users/parth/Documents/pxp928/artifact-ff/guac.yaml"}
+-----------+-----------+----------------------------------------------------------------------+
| NODE TYPE | NODE ID   | ADDITIONAL INFORMATION                                               |
+-----------+-----------+----------------------------------------------------------------------+
| hasSBOM   | 6964      | SBOM Download Location: file:///../guac-data/top-dh-sboms/vault.json |
+-----------+-----------+----------------------------------------------------------------------+
Visualizer url: http://localhost:3000/visualize?path=[5,4,3,2,6964]
```

➜ artifact-ff git:(unknown-known-demo) ✗ ./bin/guacone query_known --type
"package" "pkg:golang/github.com/prometheus/client_golang@v1.11.1"

```bash
{"level":"info","ts":1682866825.0184278,"caller":"cli/init.go:53","msg":"Using config file: /Users/parth/Documents/pxp928/artifact-ff/guac.yaml"}
+-------------+-----------+--------------------------+
| NODE TYPE   | NODE ID   | ADDITIONAL INFORMATION   |
+-------------+-----------+--------------------------+
| certifyVuln | 13469     | vulnerability ID: NoVuln |
+-------------+-----------+--------------------------+
```

```bash
➜  artifact-ff git:(unknown-known-demo) ✗ go run ./cmd/guacone query_known --type "source" "git+https://github.com/googleapis/google-cloud-go"
{"level":"info","ts":1682866506.0761201,"caller":"cli/init.go:53","msg":"Using config file: /Users/parth/Documents/pxp928/artifact-ff/guac.yaml"}
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
Visualizer url: http://localhost:3000/visualize?path=[6967,6966,6965,7074,7075,7156,8948,8949,8950,6968]
```

```bash
➜  artifact-ff git:(unknown-known-demo) ✗ ./bin/guacone query_known --type "package" "pkg:golang/github.com/prometheus/client_golang@v1.4.0"
{"level":"info","ts":1682870962.001216,"caller":"cli/init.go:53","msg":"Using config file: /Users/parth/Documents/pxp928/artifact-ff/guac.yaml"}
+-------------+-----------+---------------------------------------+
| NODE TYPE   | NODE ID   | ADDITIONAL INFORMATION                |
+-------------+-----------+---------------------------------------+
| certifyVuln | 13471     | vulnerability ID: ghsa-cg3q-j54f-5p7p |
| certifyVuln | 13473     | vulnerability ID: go-2022-0322        |
+-------------+-----------+---------------------------------------+
Visualizer url: http://localhost:3000/visualize?path=[7600,578,327,6,13471,13473]
```
