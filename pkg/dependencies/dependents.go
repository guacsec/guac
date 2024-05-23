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
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"sort"

	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/handler/collector/deps_dev"
	"github.com/guacsec/guac/pkg/misc/depversion"

	"github.com/Khan/genqlient/graphql"
)

type dependencyNode struct {
	dependents map[string]bool // map of the Name of the dependent to whether it is a dependent of the current node
}

type PackageName struct {
	Name           string
	DependentCount int
}

// GetDependenciesBySortedDependentCnt retrieves all dependents for each package and returns a sorted list of
// PackageName, where each PackageName contains the name of the package and the number of its dependents.
// The list is sorted in descending order based on the DependentCount, so packages with the most dependents come first.
// This function leverages the findDependentsOfDependencies function to construct a map of all packages and their dependents,
// then processes this map to create a slice of PackageName, which is then sorted.
//
// Returns:
// - A slice of PackageName, sorted by DependentCount in descending order.
// - An error
func GetDependenciesBySortedDependentCnt(ctx context.Context, gqlClient graphql.Client) ([]PackageName, error) {
	packages, err := findDependentsOfDependencies(ctx, gqlClient)

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

// findDependentsOfDependencies queries the GraphQL endpoint to retrieve all SBOMs and constructs
// a map of dependencyNode, where each node represents a package and its dependents. This function is designed to
// identify and map out the relationships between packages based on the SBOM data. It filters out inconsistent data
// from "deps.dev" and handles packages with and without specific version IDs. The function employs a breadth-first search
// (BFS) algorithm to traverse the dependency graph and populate the map with packages and their respective dependents.
//
// Returns:
//   - A map where the key is a string representing the package name, and the value is a dependencyNode containing
//     the dependents of the package.
//   - An error
func findDependentsOfDependencies(ctx context.Context, gqlClient graphql.Client) (map[string]dependencyNode, error) {
	// Initialize a map to hold package names mapped to their dependency nodes. This will be the returned map
	packages := make(map[string]dependencyNode)

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
		for _, isDependency := range resp.IncludedDependencies {
			// Construct unique names for the dependency package and the package itself.
			depPkgName := helpers.PkgToPurl(isDependency.DependencyPackage.Type, isDependency.DependencyPackage.Namespaces[0].Namespace, isDependency.DependencyPackage.Namespaces[0].Names[0].Name, "", "", []string{})
			pkgName := helpers.PkgToPurl(isDependency.Package.Type, isDependency.Package.Namespaces[0].Namespace, isDependency.Package.Namespaces[0].Names[0].Name, "", "", []string{})

			var depPkgIds []string
			pkgId := isDependency.Package.Namespaces[0].Names[0].Versions[0].Id

			if len(isDependency.DependencyPackage.Namespaces[0].Names[0].Versions) == 0 {
				findMatchingDepPkgVersionIDs, err := FindDepPkgVersionIDs(ctx, gqlClient, isDependency.DependencyPackage.Type,
					isDependency.DependencyPackage.Namespaces[0].Namespace,
					isDependency.DependencyPackage.Namespaces[0].Names[0].Name, isDependency.VersionRange)
				if err != nil {
					return nil, fmt.Errorf("error from FindMatchingDepPkgVersionIDs:%w", err)
				}
				depPkgIds = append(depPkgIds, findMatchingDepPkgVersionIDs...)
			} else {
				depPkgIds = append(depPkgIds, isDependency.DependencyPackage.Namespaces[0].Names[0].Versions[0].Id)
			}

			for _, depPkgId := range depPkgIds {
				// Skip "guac" files.
				if isDependency.DependencyPackage.Type == "guac" && isDependency.DependencyPackage.Namespaces[0].Namespace == "files" {
					continue
				}

				// Inside the loop where you iterate through dependencies
				updatePackagesAndNames(idToName, packages, depPkgId, pkgId, depPkgName, pkgName, dependencyEdges, dependentEdges)

				// Update the edges with pkgId and depPkgId.
				dependentEdges[depPkgId] = append(dependentEdges[depPkgId], pkgId) // pkgId is dependent on depPkgId
				dependencyEdges[pkgId] = append(dependencyEdges[pkgId], depPkgId)  // depPkgId is a dependency of pkgId
			}
		}
	}

	return packages, nil
}

// updatePackagesAndNames updates the mapping of package IDs to their names, and constructs the dependency graph.
// It takes a set of parameters including maps for ID to name conversion, packages, dependency and dependent edges,
// and information about the package and its dependency such as their IDs, names, types, and namespaces.
// This function skips processing for "guac" files in the "files" namespace and updates the provided maps with
// the relationships between packages and their dependencies. It leverages traverseGraph to find all packages
// that are either dependencies of or dependents on the given package, and updates the packages map accordingly.
func updatePackagesAndNames(idToName map[string]string, packages map[string]dependencyNode, depPkgId, pkgId, depPkgName, pkgName string, dependencyEdges, dependentEdges map[string][]string) {
	// Map the IDs to their names.
	idToName[depPkgId] = depPkgName
	idToName[pkgId] = pkgName

	// First, we need to find all the packages that are dependencies of pkgName.
	// We need to add them all to the dependencies of all nodes that have pkgName as a dependent.
	// Note that we are only searching for dependencies of pkgName from the edges that have scanned so far
	dependencyPackages := traverseGraph(depPkgId, dependencyEdges)

	// Next we want to find all the packages that have pkgName as a dependency.
	// Note that we are only searching of packages with pkgName as a dependency from the edges that have scanned so far.
	// This dependentPackages map finds all packages that have pkgName as a dependency out of our pre-scanned packages.
	dependentPackages := traverseGraph(pkgId, dependentEdges)

	for depPkgNodeId := range dependencyPackages {
		depPkgNode := idToName[depPkgNodeId]
		if _, ok := packages[depPkgNode]; !ok {
			packages[depPkgNode] = dependencyNode{dependents: make(map[string]bool)}
		}

		for node := range dependentPackages {
			packages[depPkgNode].dependents[node] = true
		}
	}
}

// traverseGraph performs a breadth-first search (BFS) on the dependency graph starting from a given node.
// It takes a startNode ID and a map of edges (either dependencyEdges or dependentEdges) and returns a map
// of visited nodes. This function is used to find all packages that are either dependencies of or dependents
// on a given package by traversing the graph and marking nodes as visited.
func traverseGraph(startNode string, edges map[string][]string) map[string]bool {
	visited := make(map[string]bool)
	queue := []string{startNode}

	// Perform BFS to mark visited nodes.
	for len(queue) > 0 {
		currentNode := queue[0]
		queue = queue[1:]

		if visited[currentNode] {
			continue // Skip already visited nodes
		}
		visited[currentNode] = true // Mark current node as visited

		// Enqueue all adjacent nodes that haven't been visited yet
		for _, adjacentNode := range edges[currentNode] {
			if !visited[adjacentNode] {
				queue = append(queue, adjacentNode)
			}
		}
	}

	return visited
}

// FindDepPkgVersionIDs queries for packages matching the specified filters (type, namespace, name) and version range.
// It returns a slice of version IDs that match the given version range criteria.
// This function returns:
// - A slice of matching dependent package version IDs.
// - An error
func FindDepPkgVersionIDs(ctx context.Context, gqlclient graphql.Client, depPkgType string, depPkgNameSpace string, depPkgName string, versionRange string) ([]string, error) {
	var matchingDepPkgVersionIDs []string

	depPkgFilter := &model.PkgSpec{
		Type:      &depPkgType,
		Namespace: &depPkgNameSpace,
		Name:      &depPkgName,
	}

	depPkgResponse, err := model.Packages(ctx, gqlclient, *depPkgFilter)
	if err != nil {
		return nil, fmt.Errorf("error querying for dependent package: %w", err)
	}

	depPkgVersionsMap := make(map[string]string)
	var depPkgVersions []string
	for _, depPkgVersion := range depPkgResponse.Packages[0].Namespaces[0].Names[0].Versions {
		depPkgVersions = append(depPkgVersions, depPkgVersion.Version)
		depPkgVersionsMap[depPkgVersion.Version] = depPkgVersion.Id
	}

	matchingDepPkgVersions, err := depversion.WhichVersionMatches(depPkgVersions, versionRange)
	if err != nil {
		// TODO(jeffmendoza): depversion is not handling all/new possible
		// version ranges from deps.dev. Continue here to report possible
		// vulns even if some paths cannot be followed.
		matchingDepPkgVersions = nil
		//return nil, nil, fmt.Errorf("error determining dependent version matches: %w", err)
	}

	for matchingDepPkgVersion := range matchingDepPkgVersions {
		matchingDepPkgVersionIDs = append(matchingDepPkgVersionIDs, depPkgVersionsMap[matchingDepPkgVersion])
	}
	return matchingDepPkgVersionIDs, nil
}
