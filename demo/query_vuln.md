# Query Vulnerability via CLI Demo

GUAC's GraphQL API allows us to integrate the knowledge graph into various
applications. In the other examples, we saw how it can be used to visualize and
query the graph from a React UI and even a small Python application to query for
paths between nodes. In this demo, we will utilize a Go CLI that will allow us
to query if a purl (package URL) has any vulnerabilities based on its direct and
indirect dependencies. We will so see if a purl is affected by a specific
vulnerability and which dependencies need to be updated to remediate that
particular vulnerability.

## Setup

To get started, please follow the [docker compose setup](../docs/Compose.md) to
get setup and started.

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

## Running the GUAC Visualizer

To get the GUAC visualizer up and running please follow the
[GUAC visualizer setup](https://github.com/guacsec/guac-visualizer/blob/main/docs/setup.md).
This will be used in this demo to show the various paths from package to
vulnerability.

## Ingesting a vulnerability SPDX SBOM

For demo purposes, let's ingest a known bad SPDX SBOM that contains a bunch of
vulnerabilities. To do this, we will use the help of the `guacone` command,
which is an all-in-one utility that can take a collection of files and ingest
them into the GUAC graph.

In your terminal window, run:

```bash
./bin/guacone collect files ../guac-data/docs/spdx/spdx_vuln.json
```

This will ingest the vulnerable SPDX SBOM into GUAC so that various insights can
be easily queried.

Once ingested you will see the following message:

```bash
{"level":"info","ts":1681821120.162612,"caller":"cmd/files.go:181","msg":"[2.158961542s] completed doc {Collector:FileCollector Source:file:///../guac-data/docs/spdx/spdx_vuln.json}"}
{"level":"info","ts":1681821120.162633,"caller":"cmd/files.go:188","msg":"collector ended gracefully"}
{"level":"info","ts":1681821120.1626382,"caller":"cmd/files.go:201","msg":"completed ingesting 1 documents of 1"}
```

## Drawing further insight from OSV.dev

One of the benefits of GUAC is that it’s not a static database, it is constantly
evolving and trying to find more information on the artifacts ingested. To
demonstrate this, we will utilize one of the components of GUAC known as a
“certifier”. The role of the certifier is to continuously run and query for
additional information from various sources (such as osv.dev and scorecard to
start with) and keep the information specified up-to-date within GUAC.

The certifier can be run in two modes, polling (for continuous updates on the
information) or non-polling (run once and collect the data). For this demo, the
polling version of the osv certifier is already running as part of the docker
compose.

The OSV certifier will query osv.dev and determine if the various components
that make up our images have vulnerabilities we should be worried about.

Switch back to the compose window and you will soon see that the OSV certifier
recognized the new packages and is looking up vulnerability information for
them.

**NOTE**: The OSV certifier is set to run at a five minute interval
(configurable by the user). If the quires below return an error you can either
wait for the OSV certifier to re-scan or force it to run manually via:

```bash
./bin/guacone certifier osv -p=false
```

Once the OSV certifier has completed running and you will see the following
message:

```bash
{"level":"info","ts":1681821205.06338,"caller":"cmd/osv.go:122","msg":"certifier ended gracefully"}
```

In a running instance of GUAC, as you are ingesting new SBOMs and artifacts, the
certifier will automatically query OSV for the latest information and populate
GUAC. After a set period of time (set by the user), it will re-query the
information to ensure that it's always up to date. For demo purposes, we ran it
just once.

## Running the Query Vulnerability CLI

Now that we have our GUAC instance up and running with up-to-date information on
the vulnerable image that we ingest, we will now look at how we can utilize this
data effectively.

### Query PURL to determine vulnerabilities

In this first example, we will query if our image has any vulnerabilities
(either directly or indirectly).

We will start off by running the following command:

```bash
./bin/guacone query vuln "pkg:guac/spdx/ghcr.io/guacsec/vul-image-latest"
```

**Note**: if you see the following error:

```bash
{"level":"fatal","ts":1681822176.390916,"caller":"cmd/query_vulnerability.go:179","msg":"error searching dependency packages match: error querying neighbor: error certify vulnerability node not found, incomplete data. Please ensure certifier has run"}
```

This error message is a check that all dependent packages have been scanned for
vulnerabilities via the certifier (either OSV or some other) to ensure that
there is no incomplete data or a false sense of security from a lack of
information.

The OSV certifier may not have completed the scan for all the packages (set to a
five minute interval to keep re-scanning for any new packages in GUAC). To force
the scan to occur immediately please run:

```bash
./bin/guacone certifier osv -p=false
```

Successful output will show the following:

```bash
+-------------+-----------+---------------------------------------+
| NODE TYPE   | NODE ID   | ADDITIONAL INFORMATION                |
+-------------+-----------+---------------------------------------+
| certifyVuln | 138477    | vulnerability ID: ghsa-599f-7c49-w659 |
| certifyVuln | 138449    | vulnerability ID: ghsa-7rjr-3q55-vv33 |
| certifyVuln | 138451    | vulnerability ID: ghsa-8489-44mv-ggj8 |
| certifyVuln | 138453    | vulnerability ID: ghsa-fxph-q3j8-mv87 |
| certifyVuln | 138455    | vulnerability ID: ghsa-jfh8-c2jp-5v3q |
| certifyVuln | 138457    | vulnerability ID: ghsa-p6xc-xr62-6r2g |
| certifyVuln | 138459    | vulnerability ID: ghsa-vwqq-5vrc-xw9h |
+-------------+-----------+---------------------------------------+
Visualizer url: http://localhost:3000/?path=15337,15336,15335,2,15432,15431,15430,15340,2509,138477,138478,15574,15573,15572,15515,138449,138450,138451,138452,138453,138454,138455,138456,138457,138458,138459,138460
```

From the output, you can see that there are vulnerabilities associated with the
image we ingested. This information can be output into a JSON format that we can
use elsewhere to make policy decisions or to visualize the issue, we can use the
GUAC visualizer to explore the vulnerabilities quickly. Copying the provided URL
and pasting it into a browser will show the following:

<p align="center">
  <img src="https://user-images.githubusercontent.com/88045217/232806365-3c68a9b3-10f5-4c98-b072-55dadab8abde.png">
</p>

From the visualizer, we can determine that the image we are working with is
vulnerable to both log4j and text4shell vulnerabilities. These packages need to
be updated to remove these critical vulnerabilities.

### Query PURL and Vulnerability ID to determine if path exists

In this example, we will query our image to determine if it is affected by a
particular vulnerability. If it is, return a path to said vulnerability such
that we can remediate the culprit.

**Note**: This query will return all paths by default. If you want to only
return a certain number, you can use the `--path` flag to specify the number.

To do this we will run the following:

```bash
./bin/guacone query_vuln --purl "pkg:guac/spdx/ghcr.io/guacsec/vul-image-latest" --vulnerabilityID "ghsa-7rjr-3q55-vv33"
```

**Note**: if you see the following:

```bash
Failed to identify vulnerability as cve or ghsa and no results found for OSV
No path to vulnerability ID found!
```

This means that the vulnerability node was not found within GUAC.

```bash
{"level":"fatal","ts":1681822176.390916,"caller":"cmd/query_vulnerability.go:179","msg":"error searching dependency packages match: error querying neighbor: error certify vulnerability node not found, incomplete data. Please ensure certifier has run"}
```

As above, there may be incomplete data from the certifier not being run
successfully to provide accurate results.

Successful output will show the following:

```bash
+-----------+-----------+---------------------------------------+
| NODE TYPE | NODE ID   | ADDITIONAL INFORMATION                |
+-----------+-----------+---------------------------------------+
| osv       | 138449    | vulnerability ID: ghsa-7rjr-3q55-vv33 |
+-----------+-----------+---------------------------------------+
Visualizer url: http://localhost:3000/?path=138449,138450,15573,15572,15515,2509,15574,15337,15336,15335,2
```

Based on the output we see that there is a path to the vulnerability, we can use
the GUAC visualizer to inspect in more detail. Copying the provided URL and
pasting it into a browser will show the following:

<p align="center">
  <img src="https://user-images.githubusercontent.com/88045217/232806473-ea50ca96-7d32-482e-8955-6ff089d9094b.png">
</p>

From this, we can see that the Apache logging library, log4j, is the culprit and
needs to be remediated immediately!

## Utilization of GUAC Data

From this demo, we learned how we can quickly analyze the GUAC data to find if a
specific PURL we are interested in contains a direct or in-direct vulnerability.
We also learned that this is just one of many utilizations of GUAC’s graphQL API
to create more tools such as these quickly and easily!

## Cleanup

To delete the all the GUAC components run:

```bash
docker-compose down
```
