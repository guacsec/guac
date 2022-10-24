# Setup + Demo

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
export GUACSEC_HOME="$(go env GOPATH)/src/github.com/guacsec"

# Create the folders.
mkdir -p ${GUACSEC_HOME}
cd ${GUACSEC_HOME}

# Clone the Guacsec repositories.
git clone git@github.com:guacsec/guac-data.git
git clone git@github.com:guacsec/guac.git
```

## Setup Neo4j

GUAC uses Neo4j as a graph database. We can run one using the docker image
provided by the Neo4j community.

```bash
docker run --rm \
  -p7474:7474 \
  -p7687:7687 \
  -e NEO4J_AUTH=neo4j/s3cr3t \
  -e NEO4J_apoc_export_file_enabled=true \
  -e NEO4J_apoc_import_file_enabled=true \
  -e NEO4J_apoc_import_file_use__neo4j__config=true \
  -e NEO4JLABS_PLUGINS=\[\"apoc\"\] \
  neo4j:4.4.9-community
```

Once it is done, the Neo4j console can be accessed either in the web browser at
<http://localhost:7474/>, either using a client like [Neo4j Desktop],
or by using any [Neo4j drivers] of your choice.

To login, use the credentials set above: `neo4j/s3cr3t`.

The environment variables containing `*apoc*` are needed to enable the [apoc]
Neo4j stored procedures add-on which can be used for more advanced queries.

### Create Neo4j DB Index

With the Neo4j Console, you want to first create the indexes before ingesting
the data. This can be done through running the following query:

```
CREATE INDEX IF NOT EXISTS FOR (n:Artifact) on n.digest;
CREATE INDEX IF NOT EXISTS FOR (n:Artifact) on n.name;
CREATE INDEX IF NOT EXISTS FOR (n:Package) on n.purl;
CREATE INDEX IF NOT EXISTS FOR (n:Package) on n.name;
CREATE INDEX IF NOT EXISTS FOR (n:Metadata) on n.id;
CREATE INDEX IF NOT EXISTS FOR (n:Attestation) on n.digest;
```

You can validate the indices have been created by using the command:

```
:schema
```

## Ingesting the data

To ingest the data, we will use the help of the guacone binary, which is an
all-in-one utility that can take a collection of files and ingest them into
the neo4j database.

We build it by first going into the guac project folder and running `make build`:
```bash
cd guac
make build
```

Once compiled, use the `guacone` client on the set of downloaded documents:

```bash
bin/guacone files --creds neo4j:s3cr3t ${GUACSEC_HOME}/guac-data/docs
```

This will take a couple minutes (should not be more than 5 minutes - if so, please
make sure that you created the database indices as mentioned above). This dataset
consists of a set of document types:
- SLSA attestations for kubernetes
- Scorecard data for kubernetes repos
- SPDX SBOMs for kubernetes containers
- CycloneDX SBOMs for some latest DockerHub images


## Observing the data

You can take a look at the ingested data through a simple match query:

```
MATCH (n) RETURN n LIMIT 25;
```

![image](https://user-images.githubusercontent.com/3060102/196476203-3e288fa7-241e-4520-aacb-8ebb9a8e442e.png)

**Note:** The neo4j client has multiple views of the data, for the demo, we
will be going between different views of the data to aid visual understanding.

**Note:** Each node has a different color depending on the label it has, these colors
may be different on your neo4j instance.

**Note:** If you make a mistake and want to reset the data, you can perform a [cleanup]

## Example 1: Exploring Kubernetes Containers

In this first example, we want to take a look at the kubernetes containers, and
see what metadata/attestations can be connected to it.

We first start by looking up the `kube-controller-manager` containers.
```
MATCH (n:Package)
WHERE n.purl CONTAINS "kube-controller-manager"
AND "CONTAINER" in n.tags
RETURN n;
```

![image](https://user-images.githubusercontent.com/3060102/196477253-7ede9ec5-a995-4e59-aab7-8acb35dc56cf.png)

We'll pick a specific version, for now we'll choose `v1.24.6`.

In this next query we want to ask what are all the binaries in this container, and
for each of them, is there any metadata tied to them?

```
MATCH p=((n:Package{purl: "pkg:oci/kube-controller-manager-v1.24.6?repository_url=k8s.gcr.io"})-[:DependsOn|Contains*1..5]->(a))
WHERE "BINARY" in a.tags
WITH a,p
OPTIONAL MATCH pp=((a)-[:DependsOn|Contains*0..5]->()<-[:MetadataFor|Attestation]-(k))
RETURN a AS DEPEDENCY, collect(k) AS METADATA, p AS PATH, collect(pp) AS METADATA_PATH;
```

Graphical view:
![image](https://user-images.githubusercontent.com/3060102/196477712-af3407e4-04a7-4219-b8b6-b5af0c18a1c7.png)

Text/Table view:
![image](https://user-images.githubusercontent.com/3060102/196480219-ff3ed225-65f6-401e-a58a-f8b823e69475.png)

In the returned sub-graph result, we can observe the following:

- We can see the kubernetes container package (red) has two binaries
  `/go-runner` and `/usr/local/bin/kube-controller-manager`.
- We can see we have a SLSA attestation (orange) for kube binary,
  but no attestations for the `/go-runner`.
- We also notice that there is scorecards metadata for the kube binary, which was
  derived through understanding that the kube binary was built from (through SLSA)
  the kubernetes source repo/commit, which has a scorecard information.
- We can view the scorecards information in the panel on the right.

This gives us an understanding of the security metadata of a container, and also provides
addition insight that we are lacking attestations for `/go-runner`.

# Example 2: Debian container overlaps

In this example, we have a container image, and we want to find out which other
containers potentially use it as a base image - for use statistics or security
incident response.

We first view the debian image we are looking to compare against.
```
MATCH (n:Package)
WHERE "CONTAINER" in n.tags
AND n.name CONTAINS "debian"
RETURN n;
```

Text output:
![image](https://user-images.githubusercontent.com/3060102/197051068-ac22ecd1-16ae-44f1-8c1f-44c049a4627e.png)


We then run the following commands that finds other containers that share dependencies
with the debian image, and counts the number of shared dependencies in descending order.

```
MATCH (n:Package{purl:"pkg:oci/debian:latest?repository_url=docker.io/library"}) -[:Contains|DependsOn*1..5]->(d)<-[*1..3]-(o:Package)
where "CONTAINER" in o.tags
WITH o.purl AS target, collect(d.name) as shared_dep
RETURN target, SIZE(shared_dep) as num_deps, shared_dep
ORDER BY num_deps desc;
```

The result of that is a list of containers that share dependencies with debian.
We can see the top matches which have a lot of shared packages/files.

![image](https://user-images.githubusercontent.com/3060102/197051119-31ebf12d-2b6a-4f0d-b188-f5194956e626.png)

Going down the list, we see other containers which do not have many shared
packages/files, and thus probably don't use the debian image.

![image](https://user-images.githubusercontent.com/3060102/197051163-47db6eb1-af3b-41df-a0dc-8fd7c5d582b8.png)

## Clean-up

If you'd like to delete the nodes in your database, you execute the query:
```
MATCH (n) DETACH DELETE n;
```


[docker]: https://www.docker.com/get-started/
[golang]: https://go.dev/doc/install
[neo4j desktop]: https://neo4j.com/docs/desktop-manual/current/
[neo4j drivers]: https://neo4j.com/docs/drivers-apis/
[npm]: https://docs.npmjs.com/downloading-and-installing-node-js-and-npm
[npx]: https://docs.npmjs.com/cli/v7/commands/npx
[cleanup]: #Clean-up
[apoc]: https://neo4j.com/labs/apoc/
