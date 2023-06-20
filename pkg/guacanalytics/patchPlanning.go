//
// Copyright 2023 The GUAC Authors.
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

package guacanalytics

import (
	"context"
	"fmt"

	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/misc/depversion"
)

type DfsNode struct {
	expanded     bool // true once all node neighbors are added to queue
	parent       string
	isDependency *model.NeighborsNeighborsIsDependency
	depth        int
	neighbors    []DfsNode
}

// TODO: make more robust usuing predicates
func searchDependenciesFromStartNode(ctx context.Context, gqlclient graphql.Client, startID string, stopID string, maxDepth int) ([]string, map[string]DfsNode, error) {
	startNode, err := model.Node(ctx, gqlclient, startID)
	fmt.Println(startNode.GetNode())

	if err != nil {
		return nil, nil, fmt.Errorf("failed getting intial node with given ID:%v", err)
	}

	start, ok := startNode.Node.(*model.NodeNodePackage)

	if !ok {
		return nil, nil, fmt.Errorf("Not a package")
	}

	var collectedIDs []string
	queue := make([]string, 0) // the queue of nodes in bfs

	collectedIDs = append(collectedIDs, startID)
	nodeMap := map[string]DfsNode{}
	nodeMap[startID] = DfsNode{
		expanded: false,
		depth:    0,
	}
	queue = append(queue, startID)
	found := false
	nowNode := DfsNode{}
	totalNodes := 1

	for len(queue) > 0 {
		now := queue[0]
		queue = queue[1:]
		nowNode = nodeMap[now]

		pkgNameResponses, err := model.Neighbors(ctx, gqlclient, now, []model.Edge{})
		if err != nil {
			return nil, nil, fmt.Errorf("failed getting package parent:%v", err)
		}

		if maxDepth != 0 && nowNode.depth >= maxDepth {
			break
		}

		for _, neighbor := range pkgNameResponses.Neighbors {
			if pkgName, ok := neighbor.(*model.NeighborsNeighborsPackage); ok {
				if len(pkgName.Namespaces) == 0 {
					continue
				}

				isDependencyNeighborResponses, err := model.Neighbors(ctx, gqlclient, pkgName.Namespaces[0].Names[0].Id, []model.Edge{model.EdgePackageIsDependency})
				if err != nil {
					return nil, nil, fmt.Errorf("failed getting package parent:%v", err)
				}
				for _, neighbor := range isDependencyNeighborResponses.Neighbors {
					if isDependency, ok := neighbor.(*model.NeighborsNeighborsIsDependency); ok {
						fmt.Println(isDependency)
						doesRangeInclude, err :=
							depversion.DoesRangeInclude([]string{start.Namespaces[0].Names[0].Versions[0].Version}, isDependency.VersionRange)

						if err == nil && !doesRangeInclude {
							fmt.Println("breaking")
							break
						}

						dfsN, seen := nodeMap[isDependency.Package.Namespaces[0].Names[0].Versions[0].Id]
						if stopID == isDependency.Package.Namespaces[0].Names[0].Versions[0].Id {
							found = true
						}

						if !seen {
							dfsN = DfsNode{
								expanded:     false,
								parent:       now,
								isDependency: isDependency,
								depth:        nowNode.depth + 1,
							}
							nodeMap[isDependency.Package.Namespaces[0].Names[0].Versions[0].Id] = dfsN
							totalNodes = totalNodes + 1
						}

						if !dfsN.expanded {
							queue = append(queue, isDependency.Package.Namespaces[0].Names[0].Versions[0].Id)
							collectedIDs = append(collectedIDs, isDependency.Package.Namespaces[0].Names[0].Versions[0].Id)
						}
					}
				}

			}
		}

		if found {
			break
		}

		nowNode.expanded = true
		nodeMap[now] = nowNode
	}

	if stopID != "" && !found {
		return nil, nil, fmt.Errorf("No path found up to specified stop node")
	}

	var path []string
	var now string

	// construct a path of nodes to return for visualizer purposes
	if stopID != "" {
		now = stopID
		for now != startID {
			fmt.Printf(nodeMap[now].isDependency.Id)
			path = append(path, nodeMap[now].isDependency.Id, nodeMap[now].isDependency.DependentPackage.Namespaces[0].Names[0].Id,
				nodeMap[now].isDependency.DependentPackage.Namespaces[0].Id, nodeMap[now].isDependency.DependentPackage.Id,
				nodeMap[now].isDependency.Package.Namespaces[0].Names[0].Versions[0].Id,
				nodeMap[now].isDependency.Package.Namespaces[0].Names[0].Id, nodeMap[now].isDependency.Package.Namespaces[0].Id,
				nodeMap[now].isDependency.Package.Id)
			now = nodeMap[now].parent
		}
		return path, nodeMap, nil
	} else {
		fmt.Println(collectedIDs)
		for i := len(collectedIDs) - 1; i >= 0; i-- {
			if nodeMap[collectedIDs[i]].isDependency != nil {
				path = append(path, nodeMap[collectedIDs[i]].isDependency.Id, nodeMap[collectedIDs[i]].isDependency.DependentPackage.Namespaces[0].Names[0].Id,
					nodeMap[collectedIDs[i]].isDependency.DependentPackage.Namespaces[0].Id, nodeMap[collectedIDs[i]].isDependency.DependentPackage.Id,
					nodeMap[collectedIDs[i]].isDependency.Package.Namespaces[0].Names[0].Versions[0].Id,
					nodeMap[collectedIDs[i]].isDependency.Package.Namespaces[0].Names[0].Id, nodeMap[collectedIDs[i]].isDependency.Package.Namespaces[0].Id,
					nodeMap[collectedIDs[i]].isDependency.Package.Id)
			}
		}
		return path, nodeMap, nil
	}

}
