# Setup

## Requirements

- make
- [npm] (some makefile tasks use [npx])
- [docker]
- [golang] 1.18+

## Prepare the working directories

The directories are expected to be located in the same folder, as they depend on
each other. These environment variables are provided to simplify the setup
process. If you do not want to use them as is, you will need to adjust them
according to your case.

```bash
# Export the variable(s).
export GUACSEC_HOME="${HOME}/projects/guacsec"

# Create the folders.
mkdir -p ${GUACSEC_HOME}
cd ${GUACSEC_HOME}

# Clone the Guacsec repositories.
git clone git@github.com:guacsec/guac-data.git
git clone git@github.com:guacsec/guac.git
```

## Setup Neo4j

GUAC uses Neo4j as a graph database. Neo4j provides and maintain official Docker
images.

```bash
docker run --rm \
  -p7474:7474 \
  -p7687:7687 \
  -e NEO4J_AUTH=neo4j/s3cr3t \
  neo4j:4.4.9-community
```

## Run Guacone

Compile the binaries:

```bash
cd guac
make build
```

and use the `guacone` client:

```bash
bin/guacone files --creds neo4j:s3cr3t ${GUACSEC_HOME}/guac-data/top-dh-sboms
```

Once it is done, the data can be accessed either in the web browser at
<http://localhost:7474/>, either using a fat client client like [Neo4j Desktop],
or by using any [Neo4j drivers] of your choice.

[docker]: https://www.docker.com/get-started/
[golang]: https://go.dev/doc/install
[neo4j desktop]: https://neo4j.com/docs/desktop-manual/current/
[neo4j drivers]: https://neo4j.com/docs/drivers-apis/
[npm]: https://docs.npmjs.com/downloading-and-installing-node-js-and-npm
[npx]: https://docs.npmjs.com/cli/v7/commands/npx
