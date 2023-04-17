# Running GUAC with Docker Compose

This tutorial introduces the full GUAC components deployment and how to deploy
it with the included Docker Compose configuration.

## GUAC Services

In previous demos, you may have had a closer look into a subset of these
components. For example, the [GUAC GraphQL demo](graphql-demo.md) showcases the
graphQL server in isolation.

However, that's just one component of GUAC! In order to get the most value out
of GUAC (for example, augmenting documents with aditional data), we need to take
advantage of the additional components of GUAC!

The full GUAC component deployment is a set of asynchronous services that
combine to form a robust and scaleable pipeline. This is represented by the area
in green in the diagrom below. In some of our [demos](demos/), you may have seen
these components work in concert! This document explains a little more of what
goes on behind the hood!

## GUAC Components

![Guac Diagram](GUAC-diagram.svg)

### GraphQL Server

The GraphQL server serves the GUAC defined nodes through GraphQL queries. It is
an abstraction layer for GUAC integrations and other GUAC components. This
tutorial uses the built-in in-memory backend for the server. Currently the
server also supports a Neo4j backend. Any future backend database support added
to GUAC will not affect the GraphQL interface that the server provides.

### Ingestion Pipeline

| Name       | Short Description                                                                  |
| ---------- | ---------------------------------------------------------------------------------- |
| Collector  | Reads or watches locations for new documents and collects them when found          |
| Ingestor   | Takes documents (ex: SBOMs) and parses them into the GUAC data model/ontology      |
| Assembler  | Takes GUAC objects and puts them in a datastore queryable by the GraphQL server    |
| CollectSub | Takes identifiers of interest, and creates a subscription for collectors to follow |

#### Collectors / Certifiers

Collectors are meant to gather data from various sources, both internally within
the organization, public sources (like open source) as well as third party
vendors. There are different collectors for the different types of locations
that GUAC can watch: files, storage buckets, git repositories, etc.

Collectors are able to be configured to use a CollectSub service to know which
data sources are of interest. For example, a git collector may subscribe to the
CollectSub service to know which git repositories it should get its data from.
This is a way in which one can, at a glance get an idea of what data sources the
instance of GUAC is looking at!

Collectors and certifiers then take the documents and pass them on to the
ingestor via [Nats](https://nats.io/),

##### Certifiers

Another class of GUAC collector components are certifiers. Certifiers run
outside the server, but are not part of the ingestion pipeline. They watch the
server for new nodes in the server, and then try to add additional information
attached to those nodes.

For example, the [OSV](https://ossf.github.io/osv-schema/) certifier will watch
GUAC for new packages, then try to discover OSV vulnerabilities for those
packages. If any vulnerabilities are found, the certifier will attach a
"CertifyVuln" node to the package that signifies that the package is connected
to the OSV vulnerability.

#### Ingestor

Ingestors take in documents and parse them into the GUAC data model/ontology.
The process extracts meaning from documents and translates to a common reasoning
model (GUAC ontology). In the process, it also finds identifiers of interest in
which it passes to the CollectSub service to request additional information for.

Today, GUAC can understand multiple data formats such as: SPDX, CycloneDX, SLSA,
etc. The ingestor listens for documents to parse via [Nats](https://nats.io/),
and talks to the Assembler via a GraphQL API.

#### Assembler

The assembler takes the parsed GUAC ontology objects from the Ingestor and
creates entries within a database which is used as a source of truth for GUAC
queries.

The assembler exposes a set of GraphQL mutate interfaces (and is physically part
of the GraphQL server, but logically part of ingestion).

#### CollectSub

The collect subcriber service provides a way to express a want for a datasource
to be used, or indication that more data about a software identifier is desired.
For example, in parsing an SBOM, if it sees the use of a package with a PURL,
the ingestor creates and entry to the CollectSub service to indicate more
information about the PURL is desired (via gRPC).

The collectors all subscribe to this service and will automatically retrieve
more information about the PURL (or other identifier/datasource) if it knows how
to handle it. For example, the deps.dev collector would know how to handle
PURLs, and then retrieve more information about the PURL entries created from
the ingestor parsing the SBOM.

## Prerequisites

- Docker
- Docker Compose
- Git
- Go (optional)
- Make (optional)

## Clone GUAC

If you haven't already, clone GUAC to a local directory:

```bash
git clone https://github.com/guacsec/guac.git
```

Optional: Also clone GUAC data, this is used as test data.

```bash
git clone https://github.com/guacsec/guac-data.git
```

The rest of the tutorial will assume you are in the GUAC directory

```bash
cd guac
```

## Build the containers

The `Makefile` contains the `docker build` commands:

```bash
make container
```

> Note: you may also run the `docker build` command directly without `make`.

## Start GUAC

In another terminal, start up GUAC.

```bash
docker-compose up
```

The full GUAC deployment is now running. The GraphQL server is listening on port
`8080`. You may visit [http://localhost:8080](http://localhost:8080) to see the
GraphQL playground. GraphQL queries are served at the `/query` endpoint.

Nats is listening on port `4222`, this is where any collectors that you run will
need to connect to push any docs they find. The GUAC `collector` command
defaults to `nats://127.0.0.1:4222` for the Nats address, so this will work
automatically.

Once it is up, you should be able to verify that its running

```bash
docker compose ls --filter "name=guac"
```

with expected output:

```bash
NAME                STATUS              CONFIG FILES
guac                running(7)          /Users/lumb/go/src/github.com/guacsec/guac/docker-compose.yml
```

### Note

If you are running into trouble getting the server started up, you can try
runnning `docker-compose down` first. Because docker compose caches the
containers used, the unclean state can cause issues.

## Start Ingesting Data

Now you can run the `guacone files` ingestion command to load data into your
GUAC deployment. For example we can ingest the sample `guac-data` data. However,
you may ingest what you wish to here instead.

```bash
pushd ../guac-data/docs
docker run --rm -v $PWD:/data --network guac_default local-organic-guac:latest /opt/guac/guacone files /data --gql-endpoint http://guac-graphql:8080/query
popd
```

Switch back to the compose window and you will soon see that the OSV certifier
recognized the new packages and is looking up vulnerability information for
them.

This command uses the `guacone` GUAC binary from the `local-organic-guac`
container we built earlier. Because containers don't have access to localhost by
default, we connect to the existing compose network (`--network guac_default`)
and use the `guac-graphql` container name to connect to it. The command uses a
volume mount to mout the `guac-data` into the container for collecting
(`-v $PWD:/data`).

Alternatively, you may build the GUAC binaries for your local machine and run
them natively.

```bash
make build
./bin/guacone files ../guac-data/docs
```

## Query GraphQL Endpoint

You may now query the GraphQL endpoint to ensure the data is ingested, and
everything is running.

```bash
curl 'http://localhost:8080/query' -s -X POST -H 'content-type: application/json' \
  --data '{
    "query": "{ packages(pkgSpec: {}) { type } }"
  }' | jq
```

You should see the types of all the packages ingested

```json
{
  "data": {
    "packages": [
      {
        "type": "oci"
      },
...
```

Congratulations, you are now running a full GUAC deployment!

## What is running?

Taking a look at the `docker-compose.yaml` we can see what is actually running:

- **Nats**: Nats is used for communication between the GUAC components. It is
  available on port `4222`.

- **Collector-Subscriber**: This component helps communicate to the collectors
  when additional information is needed.

- **GraphQL Server**: Serving GUAC GraphQL queries and storing the data. As the
  in-memory backend is used, no separate backend is needed behind the server.

- **Ingestor**: The ingestor listens for things to ingest through Nats, then
  pushes to the GraphQL Server. The ingestor also runs the assembler and parser
  internally.

- **Image Collector**: This collector can pull OCI image metadata (SBOMs and
  attestations) from registries for further inspection.

- **Deps.dev Collector**: This collector gathers further information from
  [Deps.dev](https://deps.dev/) for supported packages.

- **OSV Certifier**: This certifier gathers OSV vulnerability information from
  [osv.dev](https://osv.dev/) about packages.

## Next steps

The compose configuration is suitable to leave running in an environment that is
accessible to your environment for further GUAC ingestion, discovery, analysis,
and evaluation. Keep in mind that the in-memory backend is not persistent.

Explore the types of collectors available in the `collector` binary and see what
will work for your build, ingestion, and SBOM workflow. These collectors can be
run as another service that watches a location for new documents to ingest.
