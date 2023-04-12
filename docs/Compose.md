# Running GUAC with Docker Compose

This tutorial introduces the full GUAC ingestion pipeline and how to deploy it
with the included Docker Compose configuration.

## Demo GUAC Ingestion

The GUAC demonstrations use the full GUAC GraphQL server, but use a demo-level
all-in-one ingestion command `guacone files`. This command runs the GUAC
collector, parser, assembler, and ingestor components all at once. These
components are designed to be run as separate asynchronous services that combine
to form a robust and scalable ingestion pipeline.

## GUAC Components

### Server

The GraphQL server serves the GUAC defined nodes through GraphQL queries. It is
an abstraction layer for GUAC integrations and other GUAC components. This
tutorial uses the built-in in-memory backend for the server. Currently the
server also supports a Neo4j backend. Any future backend database support added
to GUAC will not affect the GraphQL interface that the server provides.

### Ingestion

| Name      | Short Description                                                                 |
| --------- | --------------------------------------------------------------------------------- |
| Ingestor  | Takes completed GUAC objects and performs GraphQL mutation queries to add to GUAC |
| Assembler | Takes parsed document objects and assembles GUAC objects                          |
| Parser    | Takes documents (ex: SBOMs) and parses the objects inside them                    |
| Collector | Reads or watches locations for new documents and collects them when found         |

There are different collectors for the different types of locations that GUAC
can watch: files, storage buckets, git repositories, etc. There are different
types of Parser/Assemblers for the different document types that GUAC can
understand: SPDX, CycloneDX, etc. GUAC uses [Nats](https://nats.io/) for
communication between components.

### Certifiers

Another class GUAC components are certifiers. Certifiers run outside the server,
but are not part of the ingestion pipeline. They watch the server for new nodes
in the server, and then try to add additional information attached to those
nodes.

For example, the [OSV](https://ossf.github.io/osv-schema/) certifier will watch
GUAC for new packages, then try to discover OSV vulnerabilities for those
packages. If any vulnerabilities are found, the certifier will attach a
"CertifyVuln" node to the package that signifies that the package is connected
to the OSV vulnerability.

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

The rest of the demo will assume you are in the GUAC directory

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
need to connect to push any files they find. The GUAC `collector` command
defaults to `nats://127.0.0.1:4222` for the Nats address, so this will work
automatically.

## Start Ingesting Data

Now you can run any GUAC collector and push data to the running ingestion
pipeline. For example we can ingest the sample `guac-data` data. However, you
may ingest what you wish to here instead.

```bash
pushd ../guac-data/docs
docker run --rm -v $PWD:/data --network guac_default local-organic-guac:latest /opt/guac/collector files /data --natsaddr nats:4222
popd
```

Notice how the collectors run and complete quickly. If you have run the
`guacone files` command in a previous demo, you know that that is a slower
process. In this case the collector completes quickly because the parsing,
computation, and ingesting is happening within the ingestion pipeline services
that are running.

Switch back to the compose window and you can see the ingestor logging the
activity. Shortly after that you will see that the OSV certifier recognized the
new packages and is looking up vulnerability information for them.

This command uses the `collector` GUAC binary from the container we built
earlier. Because containers don't have access to localhost by default, we
connect to the compose network and use the `nats` container name to connect to
it.

Alternatively, you may build the GUAC binaries for your local machine and run
them natively.

```bash
make build
./bin/collector files ../guac-data/docs
```

or

```bash
go run ./cmd/collector files ../guac-data/docs
```

## What is running?

Taking a look at the `docker-compose.yaml` we can see what is actually running:

- **Nats**: Nats is used for communication between the ingestion components. It
  is available on port `4222`.

- **Collector-Subscriber**: This component (help here).

- **GraphQL Server**: Serving GUAC GraphQL queries and storing the data. As the
  in-memory backend is used, no separate backend is needed behind the server.

- **Ingestor**: The ingestor listens for things to ingest through Nats, then
  pushes to the GraphQL Server. The ingestor also runs the assembler and parser
  internally.

- **Image Collector**: This collector can pull OCI images from registries for
  further inspection.

- **Deps.dev Collector**: This collector gathers further information from
  [Deps.dev](https://deps.dev/) for supported packages.

- **OSV Certifier**: This certifier gathers OSV vulnerability information about
  packages.

## Next steps

The compose configuration is suitable to leave running in an environment that is
accessible to your environment for further GUAC ingestion, discovery, analysis,
and evaluation. Keep in mind that the in-memory backend is not persistent.

Explore the types of collectors available in the `collector` binary and see what
will work for your build, ingestion, and SBOM workflow. These collectors can be
run as another service that watches a location for new documents to ingest.
