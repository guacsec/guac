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

type NodeType int

const (
	PackageName NodeType = iota
	PackageVersion
	SourceName
	Artifact
)

type DfsNode struct {
	Expanded     bool // true once all node neighbors are added to queue
	Parent       string
	Depth        int
	Type         NodeType
	nodeVersions []string // for a packageName, what was the packageVersion associated with this version.  For a packageVersion, what is the version.
	slsaSubject  bool     // for an artifact, was it added from a SLSA subject
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
		return nil, fmt.Errorf("failed getting initial node with given ID:%w", err)
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
		return nil, fmt.Errorf("Start by inputting a packageName or packageVersion node")
	}

	if len(nodePkg.AllPkgTree.Namespaces[0].Names) < 1 {
		return nil, fmt.Errorf("Start by inputting a packageName or packageVersion node")
	}

	if len(nodePkg.AllPkgTree.Namespaces[0].Names[0].Versions) < 1 {
		// TODO: handle case where there are circular dependencies that introduce more versions to the version list on a node that requires revisiting
		var versionsList []string
		for _, versionEntry := range nodePkg.AllPkgTree.Namespaces[0].Names[0].Versions {
			versionsList = append(versionsList, versionEntry.Version)
		}
		q.nodeMap[startID] = DfsNode{
			Type:         PackageName,
			nodeVersions: versionsList,
		}
	} else {
		q.queue = append(q.queue, nodePkg.AllPkgTree.Namespaces[0].Names[0].Id)

		var versionsList []string
		versionsList = append(versionsList, nodePkg.AllPkgTree.Namespaces[0].Names[0].Versions[0].Version)
		q.nodeMap[startID] = DfsNode{
			Type:         PackageVersion,
			nodeVersions: versionsList,
		}

		q.nodeMap[nodePkg.AllPkgTree.Namespaces[0].Names[0].Id] = DfsNode{
			Type:         PackageName,
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
			err = caseOnPredicates(ctx, gqlclient, &q, neighbor, q.nowNode.Type)

			if err != nil {
				return nil, err
			}
		}

		q.nowNode.Expanded = true
		q.nodeMap[q.now] = q.nowNode
	}

	return q.nodeMap, nil

}

func caseOnPredicates(ctx context.Context, gqlclient graphql.Client, q *queueValues, neighbor model.NeighborsNeighborsNode, Type NodeType) error {
	// case on predicates and nodeType
	switch Type {
	case PackageName:
		switch neighbor := neighbor.(type) {
		case *model.NeighborsNeighborsIsDependency:
			err := exploreIsDependencyFromDepPkg(ctx, gqlclient, q, *neighbor)

			if err != nil {
				return err
			}
		}
	case PackageVersion, SourceName:
		switch neighbor := neighbor.(type) {
		case *model.NeighborsNeighborsIsOccurrence:
			exploreIsOccurrenceFromSubject(ctx, gqlclient, q, *neighbor)
		}
	case Artifact:
		switch neighbor := neighbor.(type) {
		case *model.NeighborsNeighborsHasSLSA:
			exploreHasSLSAFromArtifact(ctx, gqlclient, q, *neighbor)
		case *model.NeighborsNeighborsIsOccurrence:
			exploreIsOccurrenceFromArtifact(ctx, gqlclient, q, *neighbor)
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

	addNodeToQueue(q, q.now, q.nowNode.Depth, PackageVersion, false, nil, isDependency.Package.Namespaces[0].Names[0].Versions[0].Id)
	addNodeToQueue(q, q.now, q.nowNode.Depth, PackageName, false, []string{isDependency.Package.Namespaces[0].Names[0].Versions[0].Version}, isDependency.Package.Namespaces[0].Names[0].Id)

	return nil
}

func exploreIsOccurrenceFromSubject(ctx context.Context, gqlclient graphql.Client, q *queueValues, isOccurrence model.NeighborsNeighborsIsOccurrence) {
	addNodeToQueue(q, q.now, q.nowNode.Depth, Artifact, false, nil, isOccurrence.Artifact.Id)
}

func exploreHasSLSAFromArtifact(ctx context.Context, gqlclient graphql.Client, q *queueValues, hasSLSA model.NeighborsNeighborsHasSLSA) {
	// Check that the subject is not the node inputted itself and being re-added to the queue unnecessarily
	if q.now != hasSLSA.Subject.Id {
		addNodeToQueue(q, q.now, q.nowNode.Depth, Artifact, true, nil, hasSLSA.Subject.Id)
	}
}

func exploreIsOccurrenceFromArtifact(ctx context.Context, gqlclient graphql.Client, q *queueValues, isOccurrence model.NeighborsNeighborsIsOccurrence) {
	// TODO: take into account PkgEqual case where there is another alias of the artifact package that we don't know about
	// Right now we only explore isOccurrences if their artifact is from a HasSLSA
	if q.nowNode.slsaSubject {
		switch subject := isOccurrence.Subject.(type) {
		case *model.AllIsOccurrencesTreeSubjectPackage:
			addNodeToQueue(q, q.now, q.nowNode.Depth, PackageVersion, false, []string{subject.Namespaces[0].Names[0].Versions[0].Version}, subject.Namespaces[0].Names[0].Versions[0].Id)
			addNodeToQueue(q, q.now, q.nowNode.Depth, PackageName, false, []string{subject.Namespaces[0].Names[0].Versions[0].Version}, subject.Namespaces[0].Names[0].Id)
		case *model.AllIsOccurrencesTreeSubjectSource:
			addNodeToQueue(q, q.now, q.nowNode.Depth, SourceName, false, nil, subject.Namespaces[0].Names[0].Id)
		}
	}
}

func addNodeToQueue(q *queueValues, parent string, depth int, Type NodeType, slsa bool, versions []string, id string) {
	node, seen := q.nodeMap[id]

	if !seen {
		node = DfsNode{
			Parent:       parent,
			Depth:        depth + 1,
			Type:         Type,
			nodeVersions: versions,
			slsaSubject:  slsa,
		}
		q.nodeMap[id] = node
	}

	if !node.Expanded {
		q.queue = append(q.queue, id)
	}
}
