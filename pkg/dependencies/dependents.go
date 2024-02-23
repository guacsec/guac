//
// Copyright 2024 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dependencies

import (
	"context"
	"fmt"
	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/cmd/guacone/cmd"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/handler/collector/deps_dev"
	"sort"
)

type dependencyNode struct {
	dependents map[string]bool // map of the Name of the dependent to whether it is a dependent of the current node
}

type PackageName struct {
	Name           string
	DependentCount int
}

type Dependencies interface {
	GetSortedDependents() ([]PackageName, error)
}

type dependencies struct {
	ctx       context.Context
	gqlClient graphql.Client
}

func New(ctx context.Context, gqlClient graphql.Client) Dependencies {
	return &dependencies{
		gqlClient: gqlClient,
		ctx:       ctx,
	}
}

func (deps *dependencies) GetSortedDependents() ([]PackageName, error) {
	packages, err := findAllDependents(deps.gqlClient)

	if err != nil {
		return nil, fmt.Errorf("failed to get dependents: %v", err)
	}

	var packagesArr []PackageName

	for n, d := range packages {
		packagesArr = append(packagesArr, PackageName{Name: n, DependentCount: len(d.dependents)})
	}

	sort.Slice(packagesArr, func(i, j int) bool {
		return packagesArr[i].DependentCount > packagesArr[j].DependentCount
	})
	return packagesArr, nil
}

// findAllDependents queries a GraphQL endpoint to find all dependencies and constructs a map of dependencyNode.
func findAllDependents(gqlClient graphql.Client) (map[string]dependencyNode, error) {
	ctx := context.Background()

	// Initialize a map to hold package names mapped to their dependency nodes. This will be the returned map
	packages := map[string]dependencyNode{}

	// Initialize maps to hold dependency and dependent edges.
	// dependentEdges maps a package ID to the IDs of packages that depend on it (DepPkg to Pkg).
	// dependencyEdges maps a package ID to the IDs of its dependencies (Pkg to DepPkg).
	dependentEdges := make(map[string][]string)  // id -> dependents ids
	dependencyEdges := make(map[string][]string) // id -> dependency ids

	// Initialize a map to convert package IDs to their names.
	idToName := make(map[string]string)

	sboms, err := model.HasSBOMs(ctx, gqlClient, model.HasSBOMSpec{})

	if err != nil {
		return nil, fmt.Errorf("error getting dependencies: %v", err)
	}

	for _, resp := range sboms.HasSBOM {
		// Skip entries from "deps.dev" because they are inconsistent.
		if resp.Origin == deps_dev.DepsCollector {
			continue
		}
		// Iterate through the included dependencies of each SBOM.
		for _, dependency := range resp.IncludedDependencies {
			// Construct unique names for the dependency package and the package itself.
			// TODO: Make the names actually unique, not just add "_".
			depPkgName := dependency.DependencyPackage.Type + "_" + dependency.DependencyPackage.Namespaces[0].Namespace + "_" + dependency.DependencyPackage.Namespaces[0].Names[0].Name
			pkgName := dependency.Package.Type + "_" + dependency.Package.Namespaces[0].Namespace + "_" + dependency.Package.Namespaces[0].Names[0].Name

			var depPkgIds []string
			pkgId := dependency.Package.Namespaces[0].Names[0].Versions[0].Id

			if len(dependency.DependencyPackage.Namespaces[0].Names[0].Versions) == 0 {
				findMatchingDepPkgVersionIDs, err := cmd.FindDepPkgVersionIDs(ctx, gqlClient, dependency.DependencyPackage.Type,
					dependency.DependencyPackage.Namespaces[0].Namespace,
					dependency.DependencyPackage.Namespaces[0].Names[0].Name, dependency.VersionRange)
				if err != nil {
					return nil, fmt.Errorf("error from FindMatchingDepPkgVersionIDs:%w", err)
				}
				depPkgIds = append(depPkgIds, findMatchingDepPkgVersionIDs...)
			} else {
				depPkgIds = append(depPkgIds, dependency.DependencyPackage.Namespaces[0].Names[0].Versions[0].Id)
			}

			for _, depPkgId := range depPkgIds {
				// Map the IDs to their names.
				idToName[depPkgId] = depPkgName
				idToName[pkgId] = pkgName

				// Skip "guac" files.
				if dependency.DependencyPackage.Type == "guac" && dependency.DependencyPackage.Namespaces[0].Namespace == "files" {
					continue
				}

				// First we need to find all the packages that have pkgName as a dependency

				// Initialize a visited map and a queue for BFS to find all packages that have pkgName as a dependency.
				visited := map[string]bool{}
				queue := []string{depPkgId}

				// Perform BFS to mark visited nodes.
				for len(queue) > 0 {
					n := len(queue)

					for i := 0; i < n; i++ {
						node := queue[0]
						queue = queue[1:]

						if _, ok := visited[node]; ok {
							continue
						}
						visited[node] = true

						// Add dependency nodes of node to the queue.
						queue = append(queue, dependencyEdges[node]...)
					}
				}

				// Next we want to find all the packages that are dependencies of pkgName.
				// We need to add them all to the dependencies of all nodes that have pkgName as a dependency.

				// Reset the queue to find all packages that are dependencies of pkgName.
				queue = []string{pkgId}

				// Perform BFS to add pkgName and dependencies of it to all nodes that have pkgName as a dependency.
				for len(queue) > 0 {
					n := len(queue)

					for i := 0; i < n; i++ { // go through the entire row
						nodeId := queue[0]
						queue = queue[1:]

						node := idToName[nodeId]

						for depPkgNodeId := range visited {
							depPkgNode := idToName[depPkgNodeId]
							if _, ok := packages[depPkgNode]; !ok {
								packages[depPkgNode] = dependencyNode{dependents: map[string]bool{}}
							}

							// Mark the node as a dependent.
							packages[depPkgNode].dependents[node] = true
						}

						// Add dependent nodes to the queue.
						queue = append(queue, dependentEdges[nodeId]...)
					}
				}

				// Update the edges with pkgId and depPkgId.
				dependentEdges[depPkgId] = append(dependentEdges[depPkgId], pkgId) // pkgId is dependent on depPkgId
				dependencyEdges[pkgId] = append(dependencyEdges[pkgId], depPkgId)  // depPkgId is a dependency of pkgId
			}
		}
	}

	return packages, nil
}
