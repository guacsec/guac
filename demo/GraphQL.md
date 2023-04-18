# GraphQL Demo

This demo introduces the GUAC GraphQL API. It covers the basic node "noun" and
"verb" types and what they contain. Also, it explores the server-side `path`
query and demonstrates a client-side search program.

## Requirements

- go
- pip (optional)
- jq (optional)

## Clone GUAC

If you haven't already, clone GUAC to a local directory:

```bash
git clone https://github.com/guacsec/guac.git
```

Also clone GUAC data, this is used as test data for this demo.

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

## Running the GUAC Server

The GUAC server can be run in different ways. For this demo, we will use the
`guacone gql-server` command with the `--debug` flag command, which sets up a
GraphQL endpoint and playground, and runs an in-memory backend to store the GUAC
graph.

Run this command in a separate terminal (in the same path) and keep it running
throughout the demo.

```bash
bin/guacone gql-server --gql-debug
```

Note: As the data is stored in-memory, whenever you restart the server, the
graph will be empty.

## Ingesting the data

To ingest the data, we will use the help of the `guacone` command, which is an
all-in-one utility that can take a collection of files and ingest them into the
GUAC graph.

In your original window, run:

```bash
bin/guacone files ../guac-data/docs/
```

This can take a minute or two. This dataset consists of a set of document types:

- SLSA attestations for kubernetes
- Scorecard data for kubernetes repos
- SPDX SBOMs for kubernetes containers
- CycloneDX SBOMs for some popular DockerHub images

## Running Queries

The queries for this demo are stored in the `demo/queries.gql` file. Running the
demo queries can be done graphically by opening the GraphQL Playground in a web
browser, or using the command line.

The remainder of the demo will have cli commands. If you would like to use the
GraphQL Playground instead, use these steps:

1. Open the GraphQL Playground by visiting `http://localhost:8080/` in your web
   browser.

1. Open `demo/queries.gql` in a text editor and copy the full contents.

1. Paste the contents in the left pane of the Playground

1. The "Play" button in the top center of the Playground can be used to select
   which query to run.

To use the command line to run queries, install the `gql-cli` tool with `pip`,
run:

```bash
pip install gql[all]
```

Note:

- if you are using a shell like `zsh` it will not be able to run the command
  above properly. Instead, use a `bash` or `sh` shell.
- in your system, if you are using pyhton3, you may need to use the `pip3`
  command instead.

## GraphQL

The GUAC graph is queryable using GraphQL. GraphQL is a query language for APIs
and a runtime for fulfilling those queries with your existing data.

> For some background reading, visit https://graphql.org/learn/ . Also, the full
> GUAC schema can be saved with this command:
>
> ```bash
> gql-cli http://localhost:8080/query --print-schema > schema.graphql
> ```

## A Simple Query

A primary type of node in GUAC is a Package. Packages are stored in hierarchical
nodes by Type -> Namespace -> Name -> Version. First we will run the below
query:

```
{
  packages(pkgSpec: {}) {
    type
  }
}
```

This query has an empty `pkgSpec`, that means it will match and return all
packages. However we are only requesting the `type` field, and not any nested
nodes. Therefore, we will only receive the top-level Type nodes.

```bash
cat demo/queries.gql | gql-cli http://localhost:8080/query -o PkgQ1 | jq
```

If you are using the GraphQL playground for the rest of the demo, you would run
the query with the name at the end of the command. In this case, it is "PkgQ1".

We receive:

```json
{
  "packages": [
    {
      "type": "alpine"
    },
    {
      "type": "golang"
    },
    {
      "type": "pypi"
    },
    {
      "type": "deb"
    },
    {
      "type": "maven"
    },
    {
      "type": "guac"
    }
  ]
}
```

These are the top level Types of all the packages we ingested from the
`guac-data` repository.

### Query Namespaces

Going one level deeper, let us query for all the Namespaces under the "oci"
Type. The query looks like this:

```
{
  packages(pkgSpec: { type: "deb" }) {
    type
    namespaces {
      namespace
    }
  }
}
```

Run it with:

```bash
cat demo/queries.gql | gql-cli http://localhost:8080/query -o PkgQ2 | jq
```

Output:

```json
{
  "data": {
    "packages": [
      {
        "type": "deb",
        "namespaces": [
          {
            "namespace": "ubuntu"
          },
          {
            "namespace": "debian"
          }
        ]
      }
    ]
  }
}
```

### Full package data

Run `PkgQ3` to get full package data on any package with `name: "libp11-kit0"`.

```bash
cat demo/queries.gql | gql-cli http://localhost:8080/query -o PkgQ3 | jq
```

```json
{
  "packages": [
    {
      "id": "1785",
      "type": "deb",
      "namespaces": [
        {
          "id": "1786",
          "namespace": "debian",
          "names": [
            {
              "id": "1935",
              "name": "libp11-kit0",
              "versions": [
                {
                  "id": "1936",
                  "version": "0.23.22-1",
                  "qualifiers": [
                    {
                      "key": "distro",
                      "value": "debian-11"
                    },
                    {
                      "key": "arch",
                      "value": "amd64"
                    },
                    {
                      "key": "upstream",
                      "value": "p11-kit"
                    }
                  ],
                  "subpath": ""
                },
                {
                  "id": "12712",
                  "version": "0.23.22-1",
                  "qualifiers": [
                    {
                      "key": "arch",
                      "value": "arm64"
                    },
                    {
                      "key": "upstream",
                      "value": "p11-kit"
                    },
                    {
                      "key": "distro",
                      "value": "debian-11"
                    }
                  ],
                  "subpath": ""
                }
              ]
            }
          ]
        },
        {
          "id": "4859",
          "namespace": "ubuntu",
          "names": [
            {
              "id": "5124",
              "name": "libp11-kit0",
              "versions": [
                {
                  "id": "5125",
                  "version": "0.23.20-1ubuntu0.1",
                  "qualifiers": [
                    {
                      "key": "arch",
                      "value": "amd64"
                    },
                    {
                      "key": "upstream",
                      "value": "p11-kit"
                    },
                    {
                      "key": "distro",
                      "value": "ubuntu-20.04"
                    }
                  ],
                  "subpath": ""
                },
                {
                  "id": "5406",
                  "version": "0.24.0-6build1",
                  "qualifiers": [
                    {
                      "key": "arch",
                      "value": "amd64"
                    },
                    {
                      "key": "upstream",
                      "value": "p11-kit"
                    },
                    {
                      "key": "distro",
                      "value": "ubuntu-22.04"
                    }
                  ],
                  "subpath": ""
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

Here you can see the package is a `deb` type and found under both the `debian`
and `ubuntu` namespaces. Of the two Name nodes found, there are two Version
nodes underneath.

If you take a look at the query in the `demo/queries.gql` file, you will see
that it uses the `allPkgTree` fragment. This fragment specifies all the possible
fields in a GUAC package. Fragments can be used to avoid duplicating long lists
of attributes.

## Dependencies

We have explored Package nodes, which are called "nouns" in GUAC. Now let's
explore nodes that are called "verbs". `IsDependency` is a node that links two
packages, signifying that one package depends on the other. First take look at
the Package node for the `consul` container image:

```bash
cat demo/queries.gql | gql-cli http://localhost:8080/query -o PkgQ4 | jq
```

```json
{
  "packages": [
    {
      "id": "4",
      "type": "oci",
      "namespaces": [
        {
          "id": "5",
          "namespace": "docker.io/library",
          "names": [
            {
              "id": "6",
              "name": "consul",
              "versions": [
                {
                  "id": "7",
                  "version": "sha256:22ab19cf1326abbfaafec6a14eb68f96e899e88ffe9ce26fa36affcf8ffb582c",
                  "qualifiers": [
                    {
                      "key": "tag",
                      "value": "latest"
                    }
                  ],
                  "subpath": ""
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

Now we will use a query on `IsDependency` to find all the packages that the
`consul` container image depends on. The query is looks like this:

```
{
  IsDependency(isDependencySpec: { package: { type: "oci", namespace: "docker.io/library", name: "consul" }}) {
    dependentPackage {
      type
      namespaces {
        namespace
        names {
          name
        }
      }
    }
  }
}
```

```bash
cat demo/queries.gql | gql-cli http://localhost:8080/query -o IsDependencyQ1 | jq
```

```json
{
  "IsDependency": [
    {
      "dependentPackage": {
        "type": "golang",
        "namespaces": [
          {
            "namespace": "github.com/azure",
            "names": [
              {
                "name": "azure-sdk-for-go"
              }
            ]
          }
        ]
      }
    },
    {
      "dependentPackage": {
        "type": "alpine",
        "namespaces": [
          {
            "namespace": "",
            "names": [
              {
                "name": "libcurl"
              }
            ]
          }
        ]
      }
    },
    {
      "dependentPackage": {
        "type": "golang",
        "namespaces": [
          {
            "namespace": "github.com/sirupsen",
            "names": [
              {
                "name": "logrus"
              }
            ]
          }
        ]
      }
    },
... many more
```

We see that the `consul` image depends on the `logrus` Go package. We can query
the full details of that link as so:

```
{
  IsDependency(isDependencySpec: {
    package: { type: "oci", namespace: "docker.io/library", name: "consul" }
    dependentPackage: { type: "golang", namespace: "github.com/sirupsen", name: "logrus" }
  }) {
    ...allIsDependencyTree
  }
}
```

```bash
cat demo/queries.gql | gql-cli http://localhost:8080/query -o IsDependencyQ2 | jq
```

```json
{
  "IsDependency": [
    {
      "id": "903",
      "justification": "top-level package GUAC heuristic connecting to each file/package",
      "versionRange": "",
      "package": {
        "id": "4",
        "type": "oci",
        "namespaces": [
          {
            "id": "5",
            "namespace": "docker.io/library",
            "names": [
              {
                "id": "6",
                "name": "consul",
                "versions": [
                  {
                    "id": "7",
                    "version": "sha256:22ab19cf1326abbfaafec6a14eb68f96e899e88ffe9ce26fa36affcf8ffb582c",
                    "qualifiers": [
                      {
                        "key": "tag",
                        "value": "latest"
                      }
                    ],
                    "subpath": ""
                  }
                ]
              }
            ]
          }
        ]
      },
      "dependentPackage": {
        "id": "11",
        "type": "golang",
        "namespaces": [
          {
            "id": "900",
            "namespace": "github.com/sirupsen",
            "names": [
              {
                "id": "901",
                "name": "logrus",
                "versions": []
              }
            ]
          }
        ]
      },
      "origin": "file:///../guac-data/docs/cyclonedx/syft-cyclonedx-docker.io-library-consul:latest.json",
      "collector": "FileCollector"
    }
  ]
}
```

Here are the full details of the dependency link, including the SBOM that
declared it.

## Finding paths

GUAC has a `path` query to find the shortest path between any two nodes. To use
this, we will need to pay attention to the `id` field of the nodes we want to
query. For this example we will pick the `etcd/client` and `etcd/api` Go
packages. Run these two queries to find the `id` of the packages.

```bash
cat demo/queries.gql | gql-cli http://localhost:8080/query -o PkgQ5 | jq
cat demo/queries.gql | gql-cli http://localhost:8080/query -o PkgQ6 | jq
```

Make a note the two `id`s printed. The path query will look like this:

```
{
  path(subject: 5809, target: 6721, maxPathLength: 10) {
    __typename
    ... on Package{
        ...allPkgTree
    }
    ... on IsDependency {
        ...allIsDependencyTree
    }
  }
}
```

However, the query saved in `demo/queries.gql` is parameterized so you may pass
in the two ids you found, which may be different. Replace `5809` and `6721` with
the numbers you found.

```bash
cat demo/queries.gql | gql-cli http://localhost:8080/query -o PathQ1 -V subject:5809 target:6721 | jq
```

> Note: in the "Playground" there is a section at the bottom to specify
> "Variables".

Here we see a long output with a chain of nodes from the `etcd/client` package
to `etcd/api`. First is the `client` package node. Then an `IsDependency` node
which describes the dependency from the `vault` container image to the `client`
package. Next is the `Package` node for the `vault` container image. Then
another `IsDependency` node which describes the dependency from the `vault`
container image to the `api` package. Finally is the `Package` node for the
`api` package.

What we have learned is that the `vault` container image depends on both the
`client` and `api` package. This is maybe not the dependency relationship we
were hoping to find.

It is important to understand the limitations of the path GraphQL query in
isolation and understand how to use client-side processing to get the desired
results. An example of how to do this is in the section below.

## Vulnerabilities

The data we have ingested in GUAC is based on the SBOM files in the `guac-data`
repo, but does not contain any vulnerability information. GUAC has built-in
"certifiers" which can search the ingested data and attach vulnerability data to
them. The OSV certifier will search for OSV vulnerability information. To run
the OSV certifiers, run:

```bash
bin/guacone osv --poll=false
```

The certifier will take a few minutes to run. A vulnerability "noun" node may be
queried with a query like this:

```
{
  osv(osvSpec: {osvId: "ghsa-jfh8-c2jp-5v3q"}) {
    ...allOSVTree
  }
}
```

```bash
cat demo/queries.gql | gql-cli http://localhost:8080/query -o OSVQ1 | jq
```

```json
{
  "osv": [
    {
      "id": "131666",
      "osvId": "ghsa-jfh8-c2jp-5v3q"
    }
  ]
}
```

GUAC doesn't store a lot of information here, just the OSV ID which can be
easily cross-referenced.

The "verb" node type that links packages to vulnerabilities is `CertifyVuln`. We
can query to see all of these nodes that link packages to the above
vulnerability like so:

```
{
  CertifyVuln(certifyVulnSpec: {vulnerability: {osv: {osvId: "ghsa-jfh8-c2jp-5v3q"}}}) {
    ...allCertifyVulnTree
  }
}
```

```bash
cat demo/queries.gql | gql-cli http://localhost:8080/query -o CertifyVulnQ1 | jq
```

```json
{
  "CertifyVuln": [
    {
      "id": "131684",
      "package": {
        "id": "3197",
        "type": "maven",
        "namespaces": [
          {
            "id": "12486",
            "namespace": "org.apache.logging.log4j",
            "names": [
              {
                "id": "12487",
                "name": "log4j-core",
                "versions": [
                  {
                    "id": "12488",
                    "version": "2.8.1",
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
        "id": "131666",
        "osvId": "ghsa-jfh8-c2jp-5v3q"
      },
      "metadata": {
        "dbUri": "",
        "dbVersion": "",
        "scannerUri": "osv.dev",
        "scannerVersion": "0.0.14",
        "timeScanned": "2023-04-03T16:28:44.835711634Z",
        "origin": "guac",
        "collector": "guac"
      }
    }
  ]
}
```

This node has the package and vulnerability nodes along with the metadata that
records how this link was found.

## Client-side search

All of the above examples use a single GraphQL query. However, the query results
are all easily parsed `json` that can be interpreted to build powerful scripts.
GUAC has a `neighbors` query that will return all the nodes with a relationship
to the specified node. This can be used to search through relationships, finding
the specific type of path you are looking for. The neighbor query also take in a
set of edge filters of which to traverse. However, we are not using that field
in this query.

The neighbors query looks like this:

```
{
  neighbors(node: $nodeId, usingOnly: []) {
    __typename
    ... on Package{
      ...allPkgTree
    }
    ... on IsDependency {
      ...allIsDependencyTree
    }
  }
}
```

The `demo/path.py` file contains a simple Python program to do a breadth-first
search of GUAC nodes, similar to the `path` server-side query. However, in
`path.py` we have defined a `filter()` function that filters the types and
direction of links that are searched. This filter has been written in an attempt
to find "downward" dependency relationships.

```python
# filter is used by bfs to decide weather to search a node or not. In this
# implementation we try to find dependency links between packages
def filter(fromID, fromNode, neighbor):
    if neighbor['__typename'] == 'Package':
        # From Package -> Package, only search downwards
        if fromNode['__typename'] == 'Package':
            return containsID(neighbor, fromID)
        # From other node type -> Package is ok.
        return True
    # Only allow IsDependency where the fromID is in the subject package
    if neighbor['__typename'] == 'IsDependency':
        return containsID(neighbor['package'], fromID)
    # Otherwise don't follow path
    return False
```

For `Package`->`Package` links, they are only followed downward, "PackageName"
-> "PackageVersion". For `Package`->`IsDependency` links, they are only followed
if the Package is the "Subject" and not the "Object", ie: if the previous
Package node is the one that depends on the newly found Package in the link.

First, run with the previous two ids from the `etcd/client` and `etcd/api`
packages found above.

```bash
./demo/path.py 5809 6721
```

```
[]
[]
```

Nothing is found. Before, we saw dependency links from the `vault` image to both
of these packages, but now with the filter we have in place, we don't follow the
dependency link "up" to the `vault` image. We would normally expect to find a
dependency link between an api and a client of that api, but we simply haven't
ingested an SBOM that contains that link. In this case, only the `vault` SBOM
was ingested which referenced both packages.

Now let's explore two more packages, the `python` container image, and the
`libsqlite3-dev` debian package. Run these queries and node the `id`s.

```bash
cat demo/queries.gql | gql-cli http://localhost:8080/query -o PkgQ7 | jq
cat demo/queries.gql | gql-cli http://localhost:8080/query -o PkgQ8 | jq
```

Now find the path, your `id`s may be different

```bash
./demo/path.py 3616 4422
```

```
['3616', '3617', '4424', '4422']
[
  {
    "__typename": "Package",
...
```

A path is found. The program prints the ids of the path, then the nodes. The
`python` "PackageName" is linked to the "PackageVersion", which is a specific
tag of the image. Then, an `IsDependency` link has the `python` "PackageVersion"
as the "subject" of the link, and the "object" `dependentPackage` is the
"PackageName" node of the `libsqlite3-dev` package. The last node in the path is
the "PackageName" node of `libsqlite3-dev`.

## Exploring

Now you have the knowledge and tools to import data, query nodes an
relationships and find interesting discoveries. Share your novel queries and
usecases with the [community](README.md#communication)!
