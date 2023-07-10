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
	Expanded     bool // true once all node neighbors are added to queue
	Parent       string
	Depth        int
	NodeType     string   // packageName, packageVersion
	nodeVersions []string // for a packageName, what was the packageVersion associated with this version
}

type queueValues struct {
	nodeMap map[string]DfsNode
	now     string
	nowNode DfsNode
	queue   []string
}

// TODO: make more robust using predicates
func SearchDependenciesFromStartNode(ctx context.Context, gqlclient graphql.Client, startID string, stopID *string, maxDepth int) (map[string]DfsNode, error) {
	startNode, err := model.Node(ctx, gqlclient, startID)

	if err != nil {
		return nil, fmt.Errorf("failed getting intial node with given ID:%w", err)
	}

	nodePkg, ok := startNode.Node.(*model.NodeNodePackage)

	if !ok {
		return nil, fmt.Errorf("Not a package")
	}

	q := queueValues{
		queue:   make([]string, 0), // the queue of nodes in bfs
		nodeMap: map[string]DfsNode{},
	}

	// TODO: add functionality to start with other nodes?
	if len(nodePkg.AllPkgTree.Namespaces) < 1 {
		return nil, fmt.Errorf("Start by inputting a packageName or packageVerion node")
	}

	if len(nodePkg.AllPkgTree.Namespaces[0].Names) < 1 {
		return nil, fmt.Errorf("Start by inputting a packageName or packageVerion node")
	}

	if len(nodePkg.AllPkgTree.Namespaces[0].Names[0].Versions) < 1 {
		// TODO: handle case where there are circular depedencies that introduce more versions to the version list on a node that requires revisiting
		var versionsList []string
		for _, versionEntry := range nodePkg.AllPkgTree.Namespaces[0].Names[0].Versions {
			versionsList = append(versionsList, versionEntry.Version)
		}
		q.nodeMap[startID] = DfsNode{
			NodeType:     "packageName",
			nodeVersions: versionsList,
		}
	} else {
		q.nodeMap[startID] = DfsNode{
			NodeType: "packageVersion",
		}

		// Add packageName node to the frontier as well
		q.queue = append(q.queue, nodePkg.AllPkgTree.Namespaces[0].Names[0].Id)

		var versionsList []string
		versionsList = append(versionsList, nodePkg.AllPkgTree.Namespaces[0].Names[0].Versions[0].Version)
		q.nodeMap[nodePkg.AllPkgTree.Namespaces[0].Names[0].Id] = DfsNode{
			NodeType:     "packageName",
			nodeVersions: versionsList,
		}
	}

	q.queue = append(q.queue, startID)

	for len(q.queue) > 0 {
		q.now = q.queue[0]
		q.queue = q.queue[1:]
		q.nowNode = q.nodeMap[q.now]

		if stopID != nil && *stopID == q.now {
			break
		}

		if q.nowNode.Depth >= maxDepth {
			break
		}

		neighborsResponse, err := model.Neighbors(ctx, gqlclient, q.now, []model.Edge{})

		if err != nil {
			return nil, fmt.Errorf("failed getting neighbors:%w", err)
		}

		for _, neighbor := range neighborsResponse.Neighbors {
			err = caseOnPredicates(ctx, gqlclient, &q, neighbor, q.nowNode.NodeType)

			if err != nil {
				return nil, err
			}
		}

		q.nowNode.Expanded = true
		q.nodeMap[q.now] = q.nowNode
	}

	return q.nodeMap, nil

}

func caseOnPredicates(ctx context.Context, gqlclient graphql.Client, q *queueValues, neighbor model.NeighborsNeighborsNode, nodeType string) error {
	// case on predicates and nodeType
	switch nodeType {
	case "packageName":
		switch neighbor := neighbor.(type) {
		case *model.NeighborsNeighborsIsDependency:
			err := exploreIsDependencyFromDepPkg(ctx, gqlclient, q, *neighbor)

			if err != nil {
				return err
			}
		}
	// two cases one after the other work like an OR statement
	case "packageVersion":
	case "sourceName":
		switch neighbor := neighbor.(type) {
		case *model.NeighborsNeighborsIsOccurrence:
			err := exploreIsOccurrence(ctx, gqlclient, q, *neighbor)

			if err != nil {
				return err
			}
		}
	}
	return nil
}

func exploreIsDependencyFromDepPkg(ctx context.Context, gqlclient graphql.Client, q *queueValues, isDependency model.NeighborsNeighborsIsDependency) error {
	doesRangeInclude, err := depversion.DoesRangeInclude(q.nowNode.nodeVersions, isDependency.VersionRange)

	if err != nil {
		return err
	}

	if !doesRangeInclude {
		return nil
	}

	dfsNVersion, seenVersion := q.nodeMap[isDependency.Package.Namespaces[0].Names[0].Versions[0].Id]
	dfsNName, seenName := q.nodeMap[isDependency.Package.Namespaces[0].Names[0].Id]

	if !seenVersion {
		dfsNVersion = DfsNode{
			Parent:   q.now,
			Depth:    q.nowNode.Depth + 1,
			NodeType: "packageVersion",
		}
		q.nodeMap[isDependency.Package.Namespaces[0].Names[0].Versions[0].Id] = dfsNVersion
	}

	if !seenName {
		dfsNName = DfsNode{
			Parent:       q.now,
			Depth:        q.nowNode.Depth + 1,
			NodeType:     "packageName",
			nodeVersions: []string{isDependency.Package.Namespaces[0].Names[0].Versions[0].Version},
		}
		q.nodeMap[isDependency.Package.Namespaces[0].Names[0].Id] = dfsNName
	}

	if !dfsNVersion.Expanded {
		q.queue = append(q.queue, isDependency.Package.Namespaces[0].Names[0].Versions[0].Id)
	}

	if !dfsNName.Expanded {
		q.queue = append(q.queue, isDependency.Package.Namespaces[0].Names[0].Id)
	}

	return nil
}

// TODO: impelement this functions
func exploreIsOccurrence(ctx context.Context, gqlclient graphql.Client, q *queueValues, isOccurrence model.NeighborsNeighborsIsOccurrence) error {
	// Step 1: Find Artifact attached to package through IsOccurence
	// -> call .Artifact on isOccurrence

	// Step 2: Find HasSLSA where Artifact is the builtFrom
	// -> call .Neighbors on the artifact id with the edge type specified as HasSLSAArtifact and loop through results

	// Step 3: Find Artifact that is the subject of the HasSLSA
	// -> call .Subject on HasSLSA result of .Neighbors call

	// Step 4: Find isOccurrence attached to that Artifact
	// -> call .Neighbors with edge type specified as IsOccurrence

	// Step 5: Find packageVersion attached to the isOccurrence
	// -> call .Subject on isOccurrence return value from previous step

	// Step 6: Case on if subject returned is a source or a package
	// Step 6a: (IF PACKAGE) Add packageVersion and packageName to the queue
	// -> done the same way as in exploreIsDependencyFromDepPkg (perhaps abstract out to a helper)

	// Step 6b: (IF SOURCE) Add sourceName to the queue
	return fmt.Errorf("unimplemeted")
}
