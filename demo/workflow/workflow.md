# Expanding your view of the software supply chain

### **Bruce Wayne** : You're just SBOMs.

<img width="1260" alt="3" src="https://user-images.githubusercontent.com/88045217/233477844-8f4f1743-654d-4c53-a6ff-23e0bcf3a6eb.jpg">

### **Henri Ducard (Ra's al Ghul)** : No, no, no. An SBOM is just a document lost in the scramble for its own importance. It can be misplaced or underutilized. But if you make the SBOM more than just a document, you devote the SBOM to be utilized properly to secure your software supply chain, and if the attackers cannot get to you via supply chain attacks, then the SBOM becomes something else entirely.

<img width="1260" alt="3" src="https://user-images.githubusercontent.com/88045217/233478647-a62fccb0-1e87-4542-b089-2091155c553c.png">

### **Bruce Wayne** : Which is?

<img width="1260" alt="3" src="https://user-images.githubusercontent.com/88045217/233477213-f6d99be5-f669-4344-8c1e-123f063db3de.png">

### **Henri Ducard (Ra's al Ghul)** : Legend, Mr. Wayne!

<img width="1260" alt="3" src="https://user-images.githubusercontent.com/88045217/233479006-9fa20a7e-1a13-41d1-9f97-2345fcd85c69.png">

Ra’s al Ghul understands that an SBOM alone can be forgotten but if you combine
it with GUAC, you can start to get a greater understanding of your own software
supply chain environment.

In this demo, we will go through the process of ingesting an SBOM and letting
GUAC expand our horizons on what we know about our environment autonomously!

## Requirements

- go
- Kubernetes 1.19+ ([k3s](https://github.com/k3s-io/k3s/),
  [minikube](https://github.com/kubernetes/minikube) or
  [colima](https://github.com/abiosoft/colima) (or another k8s service of your
  choice))
- [Helm v3.9.4+](https://helm.sh/)

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

## Installing GUAC via Helm Chart

Please refer to the [INSERT GUAC Helm Install Guide] to have a running instance.

Once that process is completed, you will see the following pods running (the pod
names are auto-generated so they might differ):

```bash
default       osv-certifier-c7c67d89d-f5ndx             1/1     Running     0             11m
default       guac-nats-box-774449cffc-vdkmx            1/1     Running     0             11m
default       collectsub-855c4578f6-69nfx               1/1     Running     0             11m
default       graphql-server-589c77fdb4-hvprm           1/1     Running     0             11m
default       guac-nats-0                               3/3     Running     0             11m
default       depsdev-collector-8698956798-x74vr        1/1     Running     2 (11m ago)   11m
default       oci-collector-7ff77d9b7-k24zk             1/1     Running     2 (11m ago)   11m
default       ingestor-5c75564464-s5v2s                 1/1     Running     2 (11m ago)   11m
default       ingest-guac-data-98rfq                    0/2     Completed   1             11m
```

## Ingesting Vault’s SBOM

For demo purposes, let's ingest Vault’s SBOM. To do this, we will use the help
of the `guacone` file command

Run the following command:

```bash
./bin/collector files ../guac-data/top-dh-sboms/vault.json
```

File collector

```bash
{"level":"info","ts":1681994359.2474601,"caller":"cmd/files.go:112","msg":"collector ended gracefully"}
```

## Checking the ingestion logs

We can pull the logs from Kubernetes to see the progress of the ingestion:

**NOTE**: the name of the pod will be different per instantiation, please use
the name from your cluster

```bash
kubectl logs ingestor-<IDENTIFIER>
```

The results for the Vault SBOM ingestion will look like the following:

```bash
{"level":"info","ts":1681992933.3817039,"caller":"emitter/nats_emitter.go:121","msg":"creating stream \"DOCUMENTS\" and subjects \"DOCUMENTS.*\""}
{"level":"info","ts":1681994359.306624,"caller":"process/process.go:97","msg":"[processor: 856ef1f5-1627-4ec9-b9e1-507b7bdee58f] docTree Processed: {Collector:FileCollector Source:file:///../guac-data/top-dh-sboms/vault.json}"}
{"level":"info","ts":1681994359.31475,"caller":"parser/parser.go:128","msg":"parsing document tree with root type: SPDX"}
{"level":"info","ts":1681994359.3263202,"caller":"helpers/assembler.go:34","msg":"assembling CertifyScorecard: 0"}
{"level":"info","ts":1681994359.32635,"caller":"helpers/assembler.go:39","msg":"assembling IsDependency: 2260"}
{"level":"info","ts":1681994359.7843368,"caller":"helpers/assembler.go:44","msg":"assembling IsOccurence: 963"}
{"level":"info","ts":1681994359.954613,"caller":"helpers/assembler.go:49","msg":"assembling HasSLSA: 0"}
{"level":"info","ts":1681994359.954643,"caller":"helpers/assembler.go:54","msg":"assembling CertifyVuln: 0"}
{"level":"info","ts":1681994359.954647,"caller":"helpers/assembler.go:59","msg":"assembling IsVuln: 0"}
{"level":"info","ts":1681994359.954649,"caller":"helpers/assembler.go:64","msg":"assembling HasSourceAt: 0"}
{"level":"info","ts":1681994359.9546518,"caller":"helpers/assembler.go:69","msg":"assembling CertifyBad: 0"}
{"level":"info","ts":1681994359.954654,"caller":"helpers/assembler.go:74","msg":"assembling CertifyGood: 0"}
{"level":"info","ts":1681994359.9546711,"caller":"cmd/ingest.go:118","msg":"got collect entries to add: 349"}
{"level":"info","ts":1681994359.9560268,"caller":"parser/parser.go:110","msg":"[ingestor: 04462d2a-a2c7-4aa9-95eb-2183cb5f249d] ingested docTree: {Collector:FileCollector Source:file:///../guac-data/top-dh-sboms/vault.json}"}
```

## Automated query for more information

As the ingestion process occurs, the collector subscriber service of GUAC
collects purls, OCI strings, and others to determine if there is more
information available to be pulled into the graph DB.

As the SBOM is ingested, it collects the PURLs of its dependency packages and
queries the deps.dev database automatically to grab the source, OpenSSF
scorecard, and its dependency information and links this back to the original
top-level artifact of the SBOM. This process is recursive, meaning that the
PURLs that the dependency relies on will also be queried!

We can pull the logs from Kubernetes to see which packages deps.dev collector
found:

**NOTE**: the name of the pod will be different per instantiation, please use
the name from your cluster

```bash
kubectl logs depsdev-collector--<IDENTIFIER>
```

The results from the deps.dev collector pod will look like the following:

```bash
{"level":"info","ts":1681994369.748968,"caller":"deps_dev/deps_dev.go:217","msg":"obtained additional metadata for package: pkg:golang/cloud.google.com/go@v0.65.0"}
{"level":"info","ts":1681994372.493675,"caller":"deps_dev/deps_dev.go:217","msg":"obtained additional metadata for package: pkg:golang/cloud.google.com/go/spanner@v1.5.1"}
{"level":"info","ts":1681994375.3482509,"caller":"deps_dev/deps_dev.go:217","msg":"obtained additional metadata for package: pkg:golang/cloud.google.com/go/storage@v1.10.0"}
{"level":"info","ts":1681994376.722956,"caller":"deps_dev/deps_dev.go:217","msg":"obtained additional metadata for package: pkg:golang/code.cloudfoundry.org/gofileutils@v0.0.0-20170111115228-4d0c80011a0f"}
{"level":"info","ts":1681994377.476279,"caller":"deps_dev/deps_dev.go:217","msg":"obtained additional metadata for package: pkg:golang/github.com/Azure/azure-pipeline-go@v0.2.3"}
{"level":"info","ts":1681994380.7538428,"caller":"deps_dev/deps_dev.go:217","msg":"obtained additional metadata for package: pkg:golang/github.com/Azure/azure-sdk-for-go@v61.4.0+incompatible"}
{"level":"info","ts":1681994382.8232992,"caller":"deps_dev/deps_dev.go:217","msg":"obtained additional metadata for package: pkg:golang/github.com/Azure/azure-storage-blob-go@v0.14.0"}
```

If we go back to the ingestor logs, we will see deps.dev documents being
ingested.

```bash
kubectl logs ingestor-<IDENTIFIER>
```

These logs will show the following with the collector and source being from
deps.dev.

```bash
{"level":"info","ts":1681994398.146413,"caller":"parser/parser.go:128","msg":"parsing document tree with root type: DEPS_DEV"}
{"level":"info","ts":1681994398.146731,"caller":"helpers/assembler.go:34","msg":"assembling CertifyScorecard: 1"}
{"level":"info","ts":1681994398.148156,"caller":"helpers/assembler.go:39","msg":"assembling IsDependency: 12"}
{"level":"info","ts":1681994398.156023,"caller":"helpers/assembler.go:44","msg":"assembling IsOccurence: 0"}
{"level":"info","ts":1681994398.156051,"caller":"helpers/assembler.go:49","msg":"assembling HasSLSA: 0"}
{"level":"info","ts":1681994398.1560571,"caller":"helpers/assembler.go:54","msg":"assembling CertifyVuln: 0"}
{"level":"info","ts":1681994398.156063,"caller":"helpers/assembler.go:59","msg":"assembling IsVuln: 0"}
{"level":"info","ts":1681994398.156069,"caller":"helpers/assembler.go:64","msg":"assembling HasSourceAt: 4"}
{"level":"info","ts":1681994398.157971,"caller":"helpers/assembler.go:69","msg":"assembling CertifyBad: 0"}
{"level":"info","ts":1681994398.1579862,"caller":"helpers/assembler.go:74","msg":"assembling CertifyGood: 0"}
{"level":"info","ts":1681994398.157998,"caller":"cmd/ingest.go:118","msg":"got collect entries to add: 12"}
{"level":"info","ts":1681994398.158665,"caller":"parser/parser.go:110","msg":"[ingestor: 04462d2a-a2c7-4aa9-95eb-2183cb5f249d] ingested docTree: {Collector:deps.dev Source:deps.dev}"}
```

From the logs we see that `CertifyScorecard`, `IsDependency` and `HasSourceAt`
are being ingested. We will further inspect this information in the coming
sections.

## Automated query for vulnerabilities

As we saw in the section above, GUAC automatically looks for more information
for an ingested SBOM. What about vulnerabilities?

The certifier (currently utilizing the OSV database, with more integrations to
come) is configured to run and query the vulnerability database to determine if
a package has a vulnerability

We can pull the logs from kubernetes to see the OSV certifier in action.

**NOTE**: the name of the pod will be different per instantiation, please use
the name from your cluster

```bash
kubectl logs osv-certifier-<IDENTIFIER>
```

The results from the osv certifier pod will look like the following:

```bash
{"level":"info","ts":1681994498.498469,"caller":"cmd/osv.go:115","msg":"[209.458µs] completed doc {Collector:guac Source:guac}"}
{"level":"info","ts":1681994498.4986901,"caller":"cmd/osv.go:115","msg":"[216µs] completed doc {Collector:guac Source:guac}"}
{"level":"info","ts":1681994498.4989061,"caller":"cmd/osv.go:115","msg":"[211.042µs] completed doc {Collector:guac Source:guac}"}
{"level":"info","ts":1681994498.498911,"caller":"cmd/osv.go:122","msg":"certifier ended gracefully"}
```

We will further inspect these vulnerabilities in the following section.

## Examining the information collected

To understand what was collected, we will utilize the graphQL playground. To
access, we must first port-forward from kubernetes cluster.

Run the following command to port-forward:

```bash
kubectl port-forward svc/graphql-server 8080:8080
```

The playground will be accessible via: `http://localhost:8080/graphql`

From graphQL Playground, we can use the provided
[graphQL queries](/demo/workflow/queries.gql) and paste that into the left
column that defines the queries

### IsDepdendency

First, we will run the `IsDepdendency` query by clicking the red play button and
selecting the `IsDepdendency`.

The query:

```bash
IsDependency(
    isDependencySpec: {dependentPackage: {namespace: "github.com/prometheus", name: "client_golang"}}
  )
```

The query will search all the `IsDepdendency` nodes and find the one that
depends on the following package:
`pkg:golang/github.com/prometheus/client_golang`.

This will output the following:

```bash
{
  "data": {
    "IsDependency": [
      {
        "id": "399",
        "justification": "top-level package GUAC heuristic connecting to each file/package",
        "package": {
          "id": "2",
          "type": "guac",
          "namespaces": [
            {
              "id": "3",
              "namespace": "spdx/docker.io/library",
              "names": [
                {
                  "id": "4",
                  "name": "vault-latest",
                  "versions": [
                    {
                      "id": "5",
                      "version": "",
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
        "versionRange": "v1.11.1",
        "origin": "file:///../guac-data/top-dh-sboms/vault.json",
        "collector": "FileCollector"
      },
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
      },
      {
        "id": "8508",
        "justification": "dependency data collected via deps.dev",
        "package": {
          "id": "6",
          "type": "golang",
          "namespaces": [
            {
              "id": "503",
              "namespace": "github.com/docker",
              "names": [
                {
                  "id": "504",
                  "name": "docker",
                  "versions": [
                    {
                      "id": "505",
                      "version": "v20.10.10+incompatible",
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
        "versionRange": "v1.15.0",
        "origin": "deps.dev",
        "collector": "deps.dev"
      }
    ]
  }
}
```

From the output, we can see that prometheus/client_golang is used by a bunch of
packages. The first one shows the origin being the document that we ingest at
the beginning (related to vault). The other entries all come from deps.dev that
show that other packages `github.com/armon/go-metrics` also depend on
`prometheus/client_golang`. Meaning that `prometheus/client_golang` is both a
direct and transitive dependency for the Vault image SBOM we ingested!

### HasSourceAt

Next we will run the `HasSourceAt` query by clicking the red play button and
selecting the `HasSourceAt`.

The query:

```bash
  HasSourceAt(
    hasSourceAtSpec: {package: {namespace: "cloud.google.com", name: "go"}}
  )
```

The query will search all the `HasSourceAt` nodes and find the one related to
the package specified above.

This will output the following:

```bash
    "HasSourceAt": [
      {
        "id": "7046",
        "justification": "collected via deps.dev",
        "knownSince": "2023-04-20T12:39:26.823782Z",
        "package": {
          "id": "6",
          "type": "golang",
          "namespaces": [
            {
              "id": "1075",
              "namespace": "cloud.google.com",
              "names": [
                {
                  "id": "1076",
                  "name": "go",
                  "versions": []
                }
              ]
            }
          ]
        },
        "source": {
          "id": "6964",
          "type": "git",
          "namespaces": [
            {
              "id": "6965",
              "namespace": "github.com/googleapis",
              "names": [
                {
                  "id": "6966",
                  "name": "google-cloud-go",
                  "tag": "",
                  "commit": ""
                }
              ]
            }
          ]
        },
        "origin": "deps.dev",
        "collector": "deps.dev"
      },
```

From this, we can see that as the collector subscriber and deps.dev collector
captured that the `pkg:golang/cloud.google.com/go` has a source repo at
`github.com/googleapis/google-cloud-go`. This information shows the origin being
deps.dev.

### OpenSSF Scorecard

Next, we will run the `Scorecard` query by clicking the red play button and
selecting the `Scorecard`.

The query:

```bash
scorecards(
    scorecardSpec: {source: {namespace: "github.com/googleapis", name: "google-cloud-go"}}
  )
```

The query will search all the `scorecard` nodes and find the one related to the
source specified above.

This will output the following:

```bash
"scorecards": [
      {
        "id": "6967",
        "source": {
          "id": "6964",
          "type": "git",
          "namespaces": [
            {
              "id": "6965",
              "namespace": "github.com/googleapis",
              "names": [
                {
                  "id": "6966",
                  "name": "google-cloud-go",
                  "tag": "",
                  "commit": ""
                }
              ]
            }
          ]
        },
        "scorecard": {
          "timeScanned": "2023-04-10T00:00:00Z",
          "aggregateScore": 8.300000190734863,
          "checks": [
            {
              "check": "License",
              "score": 10
            },
            {
              "check": "Signed-Releases",
              "score": -1
            },
            {
              "check": "Dangerous-Workflow",
              "score": 10
            },
            {
              "check": "Token-Permissions",
              "score": 0
            },
            {
              "check": "Maintained",
              "score": 10
            },
            {
              "check": "Branch-Protection",
              "score": -1
            },
            {
              "check": "Packaging",
              "score": -1
            },
            {
              "check": "Security-Policy",
              "score": 10
            },
            {
              "check": "Fuzzing",
              "score": 10
            },
            {
              "check": "Binary-Artifacts",
              "score": 10
            },
            {
              "check": "Pinned-Dependencies",
              "score": 7
            },
            {
              "check": "Vulnerabilities",
              "score": 10
            },
            {
              "check": "CII-Best-Practices",
              "score": 0
            }
          ],
          "scorecardVersion": "v4.10.5-30-gfade79b",
          "scorecardCommit": "fade79ba6b60232f6ac38070f9f4a388f7580d90",
          "origin": "deps.dev",
          "collector": "deps.dev"
        }
      },
```

The above source repo we found at `github.com/googleapis/google-cloud-go` now
has the following scorecard attached to it with a timestamp on when the OpenSSF
scorecard was taken. Once again we see that we collected this information
automatically from deps.dev!

### Certify Vulnerability

Finally we will run the `CertifyVuln` query by clicking the red play button and
selecting the `CertifyVuln`.

The query:

```bash
  CertifyVuln(
    certifyVulnSpec: {vulnerability: {osv: {osvId: "ghsa-cg3q-j54f-5p7p"}}}
  )
```

The query will search all the `CertifyVuln` nodes and find the one that relates
to the OSV ID specified above.

This will output the following:

```bash
{
  "data": {
    "CertifyVuln": [
      {
        "id": "9699",
        "package": {
          "id": "6",
          "type": "golang",
          "namespaces": [
            {
              "id": "191",
              "namespace": "github.com/prometheus",
              "names": [
                {
                  "id": "192",
                  "name": "client_golang",
                  "versions": [
                    {
                      "id": "7623",
                      "version": "v1.4.0",
                      "qualifiers": [],
                      "subpath": ""
                    }
                  ]
                }
              ]
            }
          ]
        },
        "vulnerability": {
          "__typename": "OSV",
          "id": "9698",
          "osvId": "ghsa-cg3q-j54f-5p7p"
        },
        "metadata": {
          "dbUri": "",
          "dbVersion": "",
          "scannerUri": "osv.dev",
          "scannerVersion": "0.0.14",
          "timeScanned": "2023-04-20T12:41:38.272364Z",
          "origin": "guac",
          "collector": "guac"
        }
      },
      {
        "id": "14527",
        "package": {
          "id": "6",
          "type": "golang",
          "namespaces": [
            {
              "id": "191",
              "namespace": "github.com/prometheus",
              "names": [
                {
                  "id": "192",
                  "name": "client_golang",
                  "versions": [
                    {
                      "id": "14106",
                      "version": "v1.7.1",
                      "qualifiers": [],
                      "subpath": ""
                    }
                  ]
                }
              ]
            }
          ]
        },
        "vulnerability": {
          "__typename": "OSV",
          "id": "9698",
          "osvId": "ghsa-cg3q-j54f-5p7p"
        },
        "metadata": {
          "dbUri": "",
          "dbVersion": "",
          "scannerUri": "osv.dev",
          "scannerVersion": "0.0.14",
          "timeScanned": "2023-04-20T12:46:46.985135Z",
          "origin": "guac",
          "collector": "guac"
        }
      }
    ]
  }
}

```

This information came from the OSV certifier service that is constantly running
within GUAC. From this, we can see that two versions of
`github.com/prometheus/client_golang` contain the same `ghsa-cg3q-j54f-5p7p`. In
the vulnerability CLI demo (LINK TO DEMO) we can use this information to
determine if there is a path (there is based on the `isDepdendency` we saw
above) between this and the version of Vault we are using. Here is a quick look
at what the visualization would look like for that:

<img width="1260" alt="3" src="https://user-images.githubusercontent.com/88045217/233479721-318cc19a-ea39-4524-adfe-890e4b2ddbd5.png">

## Expanded your view of the software supply chain

Through this demo, we learned that GUAC services are designed to extract as much
information as possible about an SBOM that it ingests. Utilizing this
information, we can quickly make up-to-date policy decisions or even integrate
it into an IDE to provide information on if a package should not be used due to
a low OpenSSF scorecard score or may contain a critical vulnerability!
