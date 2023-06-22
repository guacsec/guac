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
	expanded bool // true once all node neighbors are added to queue
	Parent   string
	depth    int
}

var path []string
var nodeMap map[string]DfsNode
var now string
var nowNode DfsNode
var queue []string

// TODO: make more robust usuing predicates
func SearchDependenciesFromStartNode(ctx context.Context, gqlclient graphql.Client, startID string, stopID string, maxDepth int) (map[string]DfsNode, error) {
	startNode, err := model.Node(ctx, gqlclient, startID)

	if err != nil {
		return nil, fmt.Errorf("failed getting intial node with given ID:%v", err)
	}

	_, ok := startNode.Node.(*model.NodeNodePackage)

	if !ok {
		return nil, fmt.Errorf("Not a package")
	}
	queue = make([]string, 0) // the queue of nodes in bfs

	nodeMap = map[string]DfsNode{}

	nodeMap[startID] = DfsNode{}
	queue = append(queue, startID)

	for len(queue) > 0 {
		now = queue[0]
		queue = queue[1:]
		nowNode = nodeMap[now]

		if stopID == now {
			break
		}

		if maxDepth != 0 && nowNode.depth >= maxDepth {
			break
		}

		nodes := map[string]model.NeighborsResponse{}

		isDependencyNeighborResponses, err := model.Neighbors(ctx, gqlclient, now, []model.Edge{model.EdgePackageIsDependency})
		if err != nil {
			return nil, fmt.Errorf("failed getting package parent:%w", err)
		}

		nodes["isDep"] = *isDependencyNeighborResponses

		for predicateType, response := range nodes {
			switch predicateType {
			case "isDep":
				err := exploreIsDependency(response, ctx, gqlclient)

				if err != nil {
					return nil, err
				}
			}
		}

		nowNode.expanded = true
		nodeMap[now] = nowNode
	}

	return nodeMap, nil

}

func exploreIsDependency(isDependencyNeighborResponses model.NeighborsResponse, ctx context.Context, gqlclient graphql.Client) error {
	for _, neighbor := range isDependencyNeighborResponses.Neighbors {
		if isDependency, ok := neighbor.(*model.NeighborsNeighborsIsDependency); ok {
			dependentPkgFilter := &model.PkgSpec{
				Type:      &isDependency.DependentPackage.Type,
				Namespace: &isDependency.DependentPackage.Namespaces[0].Namespace,
				Name:      &isDependency.DependentPackage.Namespaces[0].Names[0].Name,
			}

			depPkgResponse, err := model.Packages(ctx, gqlclient, dependentPkgFilter)
			if err != nil {
				return fmt.Errorf("error querying for dependent package: %w", err)
			}

			depPkgVersionsMap := map[string]string{}
			depPkgVersions := []string{}
			for _, depPkgVersion := range depPkgResponse.Packages[0].Namespaces[0].Names[0].Versions {
				depPkgVersions = append(depPkgVersions, depPkgVersion.Version)
				depPkgVersionsMap[depPkgVersion.Version] = depPkgVersion.Id
			}

			matchingDepPkgVersions, err := depversion.WhichVersionMatches(depPkgVersions, isDependency.VersionRange)
			if err != nil {
				return fmt.Errorf("error determining dependent version matches: %w", err)
			}

			for matchingDepPkgVersion := range matchingDepPkgVersions {
				matchingDepPkgVersionID := depPkgVersionsMap[matchingDepPkgVersion]
				if err != nil {
					return fmt.Errorf("error querying neighbor: %w", err)
				}

				path = append(path, isDependency.Id, matchingDepPkgVersionID,
					depPkgResponse.Packages[0].Namespaces[0].Names[0].Id, depPkgResponse.Packages[0].Namespaces[0].Id,
					depPkgResponse.Packages[0].Id)

				dfsN, seen := nodeMap[matchingDepPkgVersionID]
				if !seen {
					dfsN = DfsNode{
						Parent: now,
						depth:  nowNode.depth + 1,
					}
					nodeMap[matchingDepPkgVersionID] = dfsN
				}
				if !dfsN.expanded {
					queue = append(queue, matchingDepPkgVersionID)
				}
			}
		}
	}
	return nil
}
