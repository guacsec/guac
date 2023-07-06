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
	"github.com/jedib0t/go-pretty/v6/table"
)

type DfsNode struct {
	expanded bool // true once all node neighbors are added to queue
	Parent   string
	depth    int
	nodeType string // packageName, packageVersion
}

type queueValues struct {
	path    []string
	nodeMap map[string]DfsNode
	now     string
	nowNode DfsNode
	queue   []string
}

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

	q := queueValues{
		queue:   make([]string, 0), // the queue of nodes in bfs
		nodeMap: map[string]DfsNode{},
	}

	q.nodeMap[startID] = DfsNode{
		nodeType: startType,
	}

	q.queue = append(q.queue, startID)

	for len(q.queue) > 0 {
		q.now = q.queue[0]
		q.queue = q.queue[1:]
		q.nowNode = q.nodeMap[q.now]

		if stopID == q.now {
			break
		}

		if q.nowNode.depth >= maxDepth {
			break
		}

		neighborsResponse, err := model.Neighbors(ctx, gqlclient, q.now, []model.Edge{})

		if err != nil {
			return nil, fmt.Errorf("failed getting neighbors:%w", err)
		}

		for _, neighbor := range neighborsResponse.Neighbors {
			q, err = caseOnPredicates(ctx, gqlclient, &q, neighbor)

			if err != nil {
				return nil, err
			}
		}

		q.nowNode.expanded = true
		q.nodeMap[q.now] = q.nowNode
	}

	return q.nodeMap, nil

}

func caseOnPredicates(ctx context.Context, gqlclient graphql.Client, q *queueValues, neighbor model.NeighborsNeighborsNode) (queueValues, error) {
	// case on predicates and nodeType
	switch q.nowNode.nodeType {
	case "packageVersion":
		switch neighbor := neighbor.(type) {
		case *model.NeighborsNeighborsIsDependency:
			q, err := exploreIsDependency(ctx, gqlclient, q, *neighbor)

			if err != nil {
				return q, err
			}
		case *model.NeighborsNeighborsIsOccurrence:
			q, err := exploreIsOccurrence(ctx, gqlclient, q, *neighbor)

			if err != nil {
				return q, err
			}
		}
	}

	return *q, nil
}

func exploreIsDependency(ctx context.Context, gqlclient graphql.Client, q *queueValues, isDependency model.NeighborsNeighborsIsDependency) (queueValues, error) {
	dependentPkgFilter := &model.PkgSpec{
		Type:      &isDependency.DependentPackage.Type,
		Namespace: &isDependency.DependentPackage.Namespaces[0].Namespace,
		Name:      &isDependency.DependentPackage.Namespaces[0].Names[0].Name,
	}

	depPkgResponse, err := model.Packages(ctx, gqlclient, dependentPkgFilter)
	if err != nil {
		return *q, fmt.Errorf("error querying for dependent package: %w", err)
	}

	depPkgVersionsMap := map[string]string{}
	var depPkgVersions []string
	for _, depPkgVersion := range depPkgResponse.Packages[0].Namespaces[0].Names[0].Versions {
		depPkgVersions = append(depPkgVersions, depPkgVersion.Version)
		depPkgVersionsMap[depPkgVersion.Version] = depPkgVersion.Id
	}

	matchingDepPkgVersions, err := depversion.WhichVersionMatches(depPkgVersions, isDependency.VersionRange)
	if err != nil {
		return *q, fmt.Errorf("error determining dependent version matches: %w", err)
	}

	for matchingDepPkgVersion := range matchingDepPkgVersions {
		matchingDepPkgVersionID := depPkgVersionsMap[matchingDepPkgVersion]
		if err != nil {
			return *q, fmt.Errorf("error querying neighbor: %w", err)
		}

		q.path = append(q.path, isDependency.Id, matchingDepPkgVersionID,
			depPkgResponse.Packages[0].Namespaces[0].Names[0].Id, depPkgResponse.Packages[0].Namespaces[0].Id,
			depPkgResponse.Packages[0].Id)

		dfsNVersion, seenVersion := q.nodeMap[matchingDepPkgVersionID]
		dfsNName, seenName := q.nodeMap[depPkgResponse.Packages[0].Namespaces[0].Names[0].Id]
		if !seenName {
			dfsNName = DfsNode{
				Parent:   q.now,
				depth:    q.nowNode.depth + 1,
				nodeType: "packageName",
			}
			q.nodeMap[depPkgResponse.Packages[0].Namespaces[0].Names[0].Id] = dfsNName
		}
		if !seenVersion {
			dfsNVersion = DfsNode{
				Parent:   depPkgResponse.Packages[0].Namespaces[0].Names[0].Id,
				depth:    q.nowNode.depth + 1,
				nodeType: "packageVersion",
			}
			q.nodeMap[matchingDepPkgVersionID] = dfsNVersion
		}
		if !dfsNName.expanded {
			q.queue = append(q.queue, depPkgResponse.Packages[0].Namespaces[0].Names[0].Id)
		}
		if !dfsNVersion.expanded {
			q.queue = append(q.queue, matchingDepPkgVersionID)
		}
	}
	return *q, nil
}

func exploreIsOccurrence(ctx context.Context, gqlclient graphql.Client, q *queueValues, isOccurrence model.NeighborsNeighborsIsOccurrence) (queueValues, error) {
	artifactFilter := &model.ArtifactSpec{
		Id:        &isOccurrence.Artifact.Id,
		Algorithm: &isOccurrence.Artifact.Algorithm,
		Digest:    &isOccurrence.Artifact.Digest,
	}
	artifactResponse, err := model.Artifacts(ctx, gqlclient, artifactFilter)
	if err != nil {
		return *q, fmt.Errorf("error querying for built from artifacts: %w", err)
	}

	if len(artifactResponse.Artifacts) != 1 {
		return *q, fmt.Errorf("error querying for built from artifacts")
	}
	neighborResponseHasSLSA, err := model.Neighbors(ctx, gqlclient, artifactResponse.Artifacts[0].Id, []model.Edge{model.EdgeArtifactHasSlsa})
	if err != nil {
		return *q, fmt.Errorf("error querying for hasSLSA responses")
	} else {
		for _, neighborHasSLSA := range neighborResponseHasSLSA.Neighbors {
			if hasSLSA, ok := neighborHasSLSA.(*model.NeighborsNeighborsHasSLSA); ok {
				tableRows = append(tableRows, table.Row{hasSLSAStr, hasSLSA.Id, "SLSA Attestation Location: " + hasSLSA.Slsa.Origin})
			}
		}
	}
	return *q, nil
}
