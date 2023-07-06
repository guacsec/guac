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
	nodeType string // packageName, packageVersion
}

var path []string
var nodeMap map[string]DfsNode
var now string
var nowNode DfsNode
var queue []string

// TODO: make more robust using predicates
func SearchDependenciesFromStartNode(ctx context.Context, gqlclient graphql.Client, startID string, stopID string, startType string, maxDepth int) (map[string]DfsNode, error) {
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

	nodeMap[startID] = DfsNode{
		nodeType: startType,
	}
	queue = append(queue, startID)

	for len(queue) > 0 {
		now = queue[0]
		queue = queue[1:]
		nowNode = nodeMap[now]

		if stopID == now {
			break
		}

		if nowNode.depth >= maxDepth {
			break
		}

		neighborsResponse, err := model.Neighbors(ctx, gqlclient, now, []model.Edge{})

		if err != nil {
			return nil, fmt.Errorf("failed getting neighbors:%w", err)
		}

		for _, neighbor := range neighborsResponse.Neighbors {
			err = caseOnPredicates(neighbor, nowNode, ctx, gqlclient)

			if err != nil {
				return nil, err
			}
		}

		nowNode.expanded = true
		nodeMap[now] = nowNode
	}

	return nodeMap, nil

}

func caseOnPredicates(neighbor model.NeighborsNeighborsNode, nowNode DfsNode, ctx context.Context, gqlclient graphql.Client) error {
	// case on predicates and nodeType
	switch nowNode.nodeType {
	case "packageVersion":
		if isDependency, ok := neighbor.(*model.NeighborsNeighborsIsDependency); ok {
			err := exploreIsDependency(*isDependency, ctx, gqlclient)

			if err != nil {
				return err
			}
		}

		if isOccurrence, ok := neighbor.(*model.NeighborsNeighborsIsOccurrence); ok {
			err := exploreIsOccurrence(*isOccurrence, ctx, gqlclient)

			if err != nil {
				return err
			}
		}
	}

	return nil
}

func exploreIsDependency(isDependency model.NeighborsNeighborsIsDependency, ctx context.Context, gqlclient graphql.Client) error {
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
	var depPkgVersions []string
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

		dfsNVersion, seenVersion := nodeMap[matchingDepPkgVersionID]
		dfsNName, seenName := nodeMap[depPkgResponse.Packages[0].Namespaces[0].Names[0].Id]
		if !seenName {
			dfsNName = DfsNode{
				Parent:   now,
				depth:    nowNode.depth + 1,
				nodeType: "packageName",
			}
			nodeMap[depPkgResponse.Packages[0].Namespaces[0].Names[0].Id] = dfsNName
		}
		if !seenVersion {
			dfsNVersion = DfsNode{
				Parent:   depPkgResponse.Packages[0].Namespaces[0].Names[0].Id,
				depth:    nowNode.depth + 1,
				nodeType: "packageVersion",
			}
			nodeMap[matchingDepPkgVersionID] = dfsNVersion
		}
		if !dfsNName.expanded {
			queue = append(queue, depPkgResponse.Packages[0].Namespaces[0].Names[0].Id)
		}
		if !dfsNVersion.expanded {
			queue = append(queue, matchingDepPkgVersionID)
		}
	}
	return nil
}

func exploreIsOccurrence(isOccurrence model.NeighborsNeighborsIsOccurrence, ctx context.Context, gqlclient graphql.Client) error {
	artifactFilter := &model.ArtifactSpec{
		Id:        &isOccurrence.Artifact.Id,
		Algorithm: &isOccurrence.Artifact.Algorithm,
		Digest:    &isOccurrence.Artifact.Digest,
	}
	artifactResponse, err := model.Artifacts(ctx, gqlclient, artifactFilter)
	if err != nil {
		return fmt.Errorf("error querying for built from artifacts: %w", err)
	}

	if len(artifactResponse.Artifacts) != 1 {
		return fmt.Errorf("error querying for built from artifacts")
	}
	neighborResponseHasSLSA, err := model.Neighbors(ctx, gqlclient, artifactResponse.Artifacts[0].Id, []model.Edge{model.EdgeArtifactHasSlsa})
	if err != nil {
		return fmt.Errorf("error querying for hasSLSA responses")
	} else {
		for _, neighborHasSLSA := range neighborResponseHasSLSA.Neighbors {
			if hasSLSA, ok := neighborHasSLSA.(*model.NeighborsNeighborsHasSLSA); ok {
				isOccurrenceFilter := model.
					hasSLSA.Subject
			}
		}
	}
	return nil
}
