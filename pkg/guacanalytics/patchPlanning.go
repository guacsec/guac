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
	Expanded       bool   // true once all node neighbors are added to queue
	Parent         string // TODO: turn parent into a list in cause discovered twice from two different nodes
	Depth          int
	Type           NodeType
	nodeVersions   []string // for a packageName, what was the packageVersion associated with this version.  For a packageVersion, what is the version.
	PointOfContact model.PointOfContactInputSpec
}

type queueValues struct {
	nodeMap map[string]DfsNode
	now     string
	nowNode DfsNode
	queue   []string
}

func SearchDependenciesFromStartNode(ctx context.Context, gqlClient graphql.Client, startID string, stopID *string, maxDepth int) (map[string]DfsNode, error) {
	startNode, err := model.Node(ctx, gqlClient, startID)

	if err != nil {
		return nil, fmt.Errorf("failed getting initial node with given ID:%w", err)
	}

	nodePkg, ok := startNode.Node.(*model.NodeNodePackage)

	if !ok {
		return nil, fmt.Errorf("not a package")
	}

	q := queueValues{
		queue:   make([]string, 0), // the queue of nodes in bfs
		nodeMap: map[string]DfsNode{},
	}

	// TODO: add functionality to start with other nodes?
	if len(nodePkg.AllPkgTree.Namespaces) == 0 {
		return nil, fmt.Errorf("start by inputting a packageName or packageVersion node")
	}

	if len(nodePkg.AllPkgTree.Namespaces[0].Names) == 0 {
		return nil, fmt.Errorf("start by inputting a packageName or packageVersion node")
	}

	if len(nodePkg.AllPkgTree.Namespaces[0].Names[0].Versions) == 0 {
		// TODO: handle case where there are circular dependencies that introduce more versions to the version list on a node that requires revisiting
		err := q.addNodesToQueueFromPackageName(ctx, gqlClient, nodePkg.AllPkgTree.Type, nodePkg.AllPkgTree.Namespaces[0].Namespace, nodePkg.AllPkgTree.Namespaces[0].Names[0].Name, startID)

		if err != nil {
			return nil, err
		}
	} else {
		q.queue = append(q.queue, nodePkg.AllPkgTree.Namespaces[0].Names[0].Id)

		var versionsList []string
		versionsList = append(versionsList, nodePkg.AllPkgTree.Namespaces[0].Names[0].Versions[0].Version)
		q.nodeMap[startID] = DfsNode{
			Type: PackageVersion,
		}

		q.nodeMap[nodePkg.AllPkgTree.Namespaces[0].Names[0].Id] = DfsNode{
			Type:         PackageName,
			nodeVersions: versionsList,
		}
		q.queue = append(q.queue, startID)
	}

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

		neighborsResponse, err := model.Neighbors(ctx, gqlClient, q.now, []model.Edge{})

		if err != nil {
			return nil, fmt.Errorf("failed getting neighbors:%w", err)
		}

		for _, neighbor := range neighborsResponse.Neighbors {
			err = caseOnPredicates(ctx, gqlClient, &q, neighbor, q.nowNode.Type)

			if err != nil {
				return nil, err
			}
		}

		q.nowNode.Expanded = true
		q.nodeMap[q.now] = q.nowNode
	}

	return q.nodeMap, nil

}

func caseOnPredicates(ctx context.Context, gqlClient graphql.Client, q *queueValues, neighbor model.NeighborsNeighborsNode, nodeType NodeType) error {
	// case on predicates and nodeType
	switch nodeType {
	case PackageName:
		switch neighbor := neighbor.(type) {
		case *model.NeighborsNeighborsIsDependency:
			err := exploreIsDependencyFromDepPkg(ctx, gqlClient, q, *neighbor)

			if err != nil {
				return err
			}
		case *model.NeighborsNeighborsHasSourceAt:
			exploreHasSourceAtFromPackage(ctx, gqlClient, q, *neighbor)
		case *model.NeighborsNeighborsPointOfContact:
			explorePointOfContact(ctx, gqlClient, q, *neighbor)
		}
	case PackageVersion:
		switch neighbor := neighbor.(type) {
		case *model.NeighborsNeighborsIsOccurrence:
			exploreIsOccurrenceFromSubject(ctx, gqlClient, q, *neighbor)
		case *model.NeighborsNeighborsHasSourceAt:
			exploreHasSourceAtFromPackage(ctx, gqlClient, q, *neighbor)
		case *model.NeighborsNeighborsPkgEqual:
			explorePkgEqual(ctx, gqlClient, q, *neighbor)
		case *model.NeighborsNeighborsPointOfContact:
			explorePointOfContact(ctx, gqlClient, q, *neighbor)
		}
	case SourceName:
		switch neighbor := neighbor.(type) {
		case *model.NeighborsNeighborsIsOccurrence:
			exploreIsOccurrenceFromSubject(ctx, gqlClient, q, *neighbor)
		case *model.NeighborsNeighborsHasSourceAt:
			err := exploreHasSourceAtFromSource(ctx, gqlClient, q, *neighbor)

			if err != nil {
				return err
			}
		case *model.NeighborsNeighborsPointOfContact:
			explorePointOfContact(ctx, gqlClient, q, *neighbor)
		}
	case Artifact:
		switch neighbor := neighbor.(type) {
		case *model.NeighborsNeighborsHasSLSA:
			exploreHasSLSAFromArtifact(ctx, gqlClient, q, *neighbor)
		case *model.NeighborsNeighborsIsOccurrence:
			exploreIsOccurrenceFromArtifact(ctx, gqlClient, q, *neighbor)
		case *model.NeighborsNeighborsHashEqual:
			exploreHashEqual(ctx, gqlClient, q, *neighbor)
		case *model.NeighborsNeighborsPointOfContact:
			explorePointOfContact(ctx, gqlClient, q, *neighbor)
		}
	}
	return nil
}

func exploreIsDependencyFromDepPkg(ctx context.Context, gqlClient graphql.Client, q *queueValues, isDependency model.NeighborsNeighborsIsDependency) error {
	doesRangeInclude, err := depversion.DoesRangeInclude(q.nowNode.nodeVersions, isDependency.VersionRange)

	if err != nil {
		return err
	}

	if !doesRangeInclude {
		return nil
	}

	q.addNodeToQueue(PackageVersion, nil, isDependency.Package.Namespaces[0].Names[0].Versions[0].Id)
	q.addNodeToQueue(PackageName, []string{isDependency.Package.Namespaces[0].Names[0].Versions[0].Version}, isDependency.Package.Namespaces[0].Names[0].Id)

	return nil
}

func exploreIsOccurrenceFromSubject(ctx context.Context, gqlClient graphql.Client, q *queueValues, isOccurrence model.NeighborsNeighborsIsOccurrence) {
	q.addNodeToQueue(Artifact, nil, isOccurrence.Artifact.Id)
}

func exploreHasSLSAFromArtifact(ctx context.Context, gqlClient graphql.Client, q *queueValues, hasSLSA model.NeighborsNeighborsHasSLSA) {
	// Check that the subject is not the node inputted itself and being re-added to the queue unnecessarily
	if q.now != hasSLSA.Subject.Id {
		q.addNodeToQueue(Artifact, nil, hasSLSA.Subject.Id)
	}
}

func exploreIsOccurrenceFromArtifact(ctx context.Context, gqlClient graphql.Client, q *queueValues, isOccurrence model.NeighborsNeighborsIsOccurrence) {
	switch subject := isOccurrence.Subject.(type) {
	case *model.AllIsOccurrencesTreeSubjectPackage:
		q.addNodeToQueue(PackageVersion, []string{subject.Namespaces[0].Names[0].Versions[0].Version}, subject.Namespaces[0].Names[0].Versions[0].Id)
		q.addNodeToQueue(PackageName, []string{subject.Namespaces[0].Names[0].Versions[0].Version}, subject.Namespaces[0].Names[0].Id)
	case *model.AllIsOccurrencesTreeSubjectSource:
		q.addNodeToQueue(SourceName, nil, subject.Namespaces[0].Names[0].Id)
	}
}

func exploreHasSourceAtFromSource(ctx context.Context, gqlClient graphql.Client, q *queueValues, hasSourceAt model.NeighborsNeighborsHasSourceAt) error {
	if len(hasSourceAt.Package.Namespaces[0].Names[0].Versions) == 0 {
		err := q.addNodesToQueueFromPackageName(ctx, gqlClient, hasSourceAt.Package.Type, hasSourceAt.Package.Namespaces[0].Namespace, hasSourceAt.Package.Namespaces[0].Names[0].Name, hasSourceAt.Package.Namespaces[0].Names[0].Id)

		if err != nil {
			return err
		}
	} else {
		q.addNodeToQueue(PackageVersion, []string{hasSourceAt.Package.Namespaces[0].Names[0].Versions[0].Version}, hasSourceAt.Package.Namespaces[0].Names[0].Versions[0].Id)
		q.addNodeToQueue(PackageName, []string{hasSourceAt.Package.Namespaces[0].Names[0].Versions[0].Version}, hasSourceAt.Package.Namespaces[0].Names[0].Id)
	}
	return nil
}

// TODO: Expand to not just deal with packageVersions
func explorePkgEqual(ctx context.Context, gqlClient graphql.Client, q *queueValues, pkgEqual model.NeighborsNeighborsPkgEqual) {
	for _, pkg := range pkgEqual.Packages {
		if pkg.Namespaces[0].Names[0].Versions[0].Id != q.now {
			q.addNodeToQueue(PackageVersion, nil, pkg.Namespaces[0].Names[0].Versions[0].Id)
			q.addNodeToQueue(PackageName, []string{pkg.Namespaces[0].Names[0].Versions[0].Id}, pkg.Namespaces[0].Names[0].Id)
		}
	}
}

func exploreHashEqual(ctx context.Context, gqlClient graphql.Client, q *queueValues, hashEqual model.NeighborsNeighborsHashEqual) {
	for _, artifact := range hashEqual.Artifacts {
		if artifact.Id != q.now {
			q.addNodeToQueue(Artifact, nil, artifact.Id)
		}
	}
}

func exploreHasSourceAtFromPackage(ctx context.Context, gqlClient graphql.Client, q *queueValues, hasSourceAt model.NeighborsNeighborsHasSourceAt) {
	node, seen := q.nodeMap[hasSourceAt.Source.Namespaces[0].Names[0].Id]

	if !seen {
		node = DfsNode{
			Parent: q.now,
			Depth:  q.nowNode.Depth + 1,
			Type:   SourceName,
		}
	}

	q.nodeMap[hasSourceAt.Source.Namespaces[0].Names[0].Id] = node
}

// TODO: implement
func explorePointOfContact(ctx context.Context, gqlClient graphql.Client, q *queueValues, pointOfContact model.NeighborsNeighborsPointOfContact) {
	// Step 1: Add field to current node in nodeMap of this POC (may need to copy over old fields)
	// Step 2: If it is a packageName, add the POC to applicable versions (versions in the nodeVersions) but not the reverse
	// (i.e. for a version do not add POC to associated name as it may not be applicable)
}

func (q *queueValues) addNodesToQueueFromPackageName(ctx context.Context, gqlClient graphql.Client, pkgType string, pkgNamespace string, pkgName string, id string) error {
	pkgFilter := model.PkgSpec{
		Type:      &pkgType,
		Namespace: &pkgNamespace,
		Name:      &pkgName,
	}

	pkgResponse, err := model.Packages(ctx, gqlClient, &pkgFilter)

	if err != nil {
		return fmt.Errorf("error finding inputted node %s", err)
	}

	var versionsList []string
	for _, versionEntry := range pkgResponse.Packages[0].Namespaces[0].Names[0].Versions {
		versionsList = append(versionsList, versionEntry.Version)
		q.nodeMap[versionEntry.Id] = DfsNode{
			Parent: q.now,
			Depth:  q.nowNode.Depth + 1,
			Type:   PackageVersion,
		}

		q.queue = append(q.queue, versionEntry.Id)
	}

	q.nodeMap[id] = DfsNode{
		Parent:       q.now,
		Depth:        q.nowNode.Depth + 1,
		Type:         PackageName,
		nodeVersions: versionsList,
	}
	q.queue = append(q.queue, id)

	return nil
}

func (q *queueValues) addNodeToQueue(nodeType NodeType, versions []string, id string) {
	node, seen := q.nodeMap[id]

	if !seen {
		node = DfsNode{
			Parent:       q.now,
			Depth:        q.nowNode.Depth + 1,
			Type:         nodeType,
			nodeVersions: versions,
		}
		q.nodeMap[id] = node
	}

	if !node.Expanded {
		q.queue = append(q.queue, id)
	}
}
