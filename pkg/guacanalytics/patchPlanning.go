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

type BfsNode struct {
	Expanded         bool // true once all node neighbors are added to queue
	Parents          []string
	Depth            int
	Type             NodeType
	nodeVersions     []string // for a packageName, what was the packageVersion associated with this version.  For a packageVersion, what is the version.
	PointOfContact   model.AllPointOfContact
	NotInBlastRadius bool // true if it is solely an informational node, not to be included in the blast radius subgraph
}

type queueValues struct {
	nodeMap map[string]BfsNode
	now     string
	nowNode BfsNode
	queue   []string
}

func SearchDependenciesFromStartNode(ctx context.Context, gqlClient graphql.Client, startID string, stopID *string, maxDepth int) (map[string]BfsNode, error) {
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
		nodeMap: map[string]BfsNode{},
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
		q.nodeMap[startID] = BfsNode{
			Type:    PackageVersion,
			Parents: []string{},
		}

		q.nodeMap[nodePkg.AllPkgTree.Namespaces[0].Names[0].Id] = BfsNode{
			Type:         PackageName,
			nodeVersions: versionsList,
			Parents:      []string{},
		}
		q.queue = append(q.queue, startID)
	}

	bfsNodeMap, err := q.bfsOfDependencies(ctx, gqlClient, stopID, maxDepth)
	if err != nil {
		return bfsNodeMap, err
	}

	return q.nodeMap, nil

}

// bfsOfDependencies performs a breadth-first search on a graph to find dependencies
func (q *queueValues) bfsOfDependencies(ctx context.Context, gqlClient graphql.Client, stopID *string, maxDepth int) (map[string]BfsNode, error) {
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

		// model.Neighbors performs a GraphQL query to get the neighbor nodes of a given node.
		neighborsResponse, err := model.Neighbors(ctx, gqlClient, q.now, []model.Edge{})

		if err != nil {
			return nil, fmt.Errorf("failed getting neighbors:%w", err)
		}

		for _, neighbor := range neighborsResponse.Neighbors {
			err = caseOnPredicates(ctx, gqlClient, q, neighbor, q.nowNode.Type)

			if err != nil {
				return nil, err
			}
		}

		q.nowNode.Expanded = true
		q.nodeMap[q.now] = q.nowNode
	}
	return nil, nil
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
			err := exploreHasSourceAtFromPackage(ctx, gqlClient, q, *neighbor)

			if err != nil {
				return err
			}
		case *model.NeighborsNeighborsPointOfContact:
			err := explorePointOfContact(ctx, gqlClient, q, *neighbor)

			if err != nil {
				return err
			}
		}
	case PackageVersion:
		switch neighbor := neighbor.(type) {
		case *model.NeighborsNeighborsIsOccurrence:
			exploreIsOccurrenceFromSubject(ctx, gqlClient, q, *neighbor)
		case *model.NeighborsNeighborsHasSourceAt:
			err := exploreHasSourceAtFromPackage(ctx, gqlClient, q, *neighbor)

			if err != nil {
				return err
			}
		case *model.NeighborsNeighborsPkgEqual:
			explorePkgEqual(ctx, gqlClient, q, *neighbor)
		case *model.NeighborsNeighborsPointOfContact:
			err := explorePointOfContact(ctx, gqlClient, q, *neighbor)

			if err != nil {
				return err
			}
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
			err := explorePointOfContact(ctx, gqlClient, q, *neighbor)

			if err != nil {
				return err
			}
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
			err := explorePointOfContact(ctx, gqlClient, q, *neighbor)

			if err != nil {
				return err
			}
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
		q.addNodeToQueue(PackageVersion, nil, subject.Namespaces[0].Names[0].Versions[0].Id)
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
		q.addNodeToQueue(PackageVersion, nil, hasSourceAt.Package.Namespaces[0].Names[0].Versions[0].Id)
		q.addNodeToQueue(PackageName, []string{hasSourceAt.Package.Namespaces[0].Names[0].Versions[0].Version}, hasSourceAt.Package.Namespaces[0].Names[0].Id)
	}
	return nil
}

// TODO: Expand to not just deal with packageVersions
func explorePkgEqual(ctx context.Context, gqlClient graphql.Client, q *queueValues, pkgEqual model.NeighborsNeighborsPkgEqual) {
	for _, pkg := range pkgEqual.Packages {
		if pkg.Namespaces[0].Names[0].Versions[0].Id != q.now {
			q.addNodeToQueue(PackageVersion, nil, pkg.Namespaces[0].Names[0].Versions[0].Id)
			q.addNodeToQueue(PackageName, []string{pkg.Namespaces[0].Names[0].Versions[0].Version}, pkg.Namespaces[0].Names[0].Id)
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

func exploreHasSourceAtFromPackage(ctx context.Context, gqlClient graphql.Client, q *queueValues, hasSourceAt model.NeighborsNeighborsHasSourceAt) error {
	node, seen := q.nodeMap[hasSourceAt.Source.Namespaces[0].Names[0].Id]
	if !seen {
		node = BfsNode{
			Parents: []string{q.now},
			Depth:   q.nowNode.Depth + 1,
			Type:    SourceName,
		}

		// check if the Src has any POCs
		neighborsResponse, err := model.Neighbors(ctx, gqlClient, hasSourceAt.Source.Namespaces[0].Names[0].Id, []model.Edge{})

		if err != nil {
			return err
		}

		for _, neighbor := range neighborsResponse.Neighbors {
			switch neighbor := neighbor.(type) {
			case *model.NeighborsNeighborsPointOfContact:
				node = BfsNode{
					Parents:        []string{q.now},
					Depth:          q.nowNode.Depth + 1,
					Type:           SourceName,
					PointOfContact: neighbor.AllPointOfContact,
				}
			}
		}
	} else {
		node = BfsNode{
			Parents:          append(node.Parents, q.now),
			Depth:            node.Depth,
			Type:             node.Type,
			nodeVersions:     node.nodeVersions,
			PointOfContact:   node.PointOfContact,
			NotInBlastRadius: node.NotInBlastRadius,
			Expanded:         node.Expanded,
		}
	}

	q.nodeMap[hasSourceAt.Source.Namespaces[0].Names[0].Id] = node
	return nil
}

func explorePointOfContact(ctx context.Context, gqlClient graphql.Client, q *queueValues, pointOfContact model.NeighborsNeighborsPointOfContact) error {
	node := BfsNode{
		Parents:          q.nowNode.Parents,
		Depth:            q.nowNode.Depth,
		Type:             q.nowNode.Type,
		nodeVersions:     q.nowNode.nodeVersions,
		PointOfContact:   pointOfContact.AllPointOfContact,
		NotInBlastRadius: q.nowNode.NotInBlastRadius,
		Expanded:         q.nowNode.Expanded,
	}
	q.nodeMap[q.now] = node
	q.nowNode = node

	// If it is a packageName, add the POC to applicable versions (versions in the nodeVersions) but not the reverse
	if q.nowNode.Type != PackageName {
		return nil
	}

	switch poc := pointOfContact.Subject.(type) {
	case *model.AllPointOfContactSubjectPackage:
		pkgFilter := model.PkgSpec{
			Type:      &poc.Type,
			Namespace: &poc.Namespaces[0].Namespace,
			Name:      &poc.Namespaces[0].Names[0].Name,
		}

		pkgResponse, err := model.Packages(ctx, gqlClient, pkgFilter)

		if err != nil {
			return fmt.Errorf("error finding inputted node %s", err)
		}

		for _, versionEntry := range pkgResponse.Packages[0].Namespaces[0].Names[0].Versions {
			if node, seen := q.nodeMap[versionEntry.Id]; seen {
				node = BfsNode{
					Parents:          append(node.Parents, q.now),
					Depth:            node.Depth,
					Type:             node.Type,
					PointOfContact:   pointOfContact.AllPointOfContact,
					NotInBlastRadius: node.NotInBlastRadius,
					Expanded:         node.Expanded,
				}
			} else {
				node = BfsNode{
					Parents:          append(node.Parents, q.now),
					Depth:            q.nowNode.Depth + 1,
					Type:             PackageVersion,
					PointOfContact:   pointOfContact.AllPointOfContact,
					NotInBlastRadius: true,
				}
			}
			q.nodeMap[versionEntry.Id] = node
		}
	}

	return nil
}

func (q *queueValues) addNodesToQueueFromPackageName(ctx context.Context, gqlClient graphql.Client, pkgType string, pkgNamespace string, pkgName string, id string) error {
	if node, seen := q.nodeMap[id]; seen {
		if !q.nodeMap[id].Expanded {
			q.queue = append(q.queue, id)
		}
		q.nodeMap[id] = BfsNode{
			Parents:          append(node.Parents, q.now),
			Depth:            node.Depth,
			Type:             node.Type,
			PointOfContact:   node.PointOfContact,
			NotInBlastRadius: node.NotInBlastRadius,
			Expanded:         node.Expanded,
		}
		return nil
	}

	pkgFilter := model.PkgSpec{
		Type:      &pkgType,
		Namespace: &pkgNamespace,
		Name:      &pkgName,
	}

	pkgResponse, err := model.Packages(ctx, gqlClient, pkgFilter)

	if err != nil {
		return fmt.Errorf("error finding inputted node %s", err)
	}

	var versionsList []string
	for _, versionEntry := range pkgResponse.Packages[0].Namespaces[0].Names[0].Versions {
		versionsList = append(versionsList, versionEntry.Version)
		if versionNode, seen := q.nodeMap[versionEntry.Id]; seen {
			if !q.nodeMap[versionEntry.Id].Expanded {
				q.queue = append(q.queue, versionEntry.Id)
			}
			q.nodeMap[versionEntry.Id] = BfsNode{
				Parents:          append(versionNode.Parents, q.now),
				Depth:            q.nowNode.Depth + 1,
				Type:             PackageVersion,
				PointOfContact:   q.nowNode.PointOfContact,
				NotInBlastRadius: false,
			}
			break
		} else {
			q.nodeMap[versionEntry.Id] = BfsNode{
				Parents:          append(versionNode.Parents, q.now),
				Depth:            q.nowNode.Depth + 1,
				Type:             PackageVersion,
				PointOfContact:   q.nowNode.PointOfContact,
				NotInBlastRadius: false,
			}
		}
		q.queue = append(q.queue, versionEntry.Id)
	}

	q.nodeMap[id] = BfsNode{
		Parents:        []string{q.now},
		Depth:          q.nowNode.Depth + 1,
		Type:           PackageName,
		nodeVersions:   versionsList,
		PointOfContact: q.nowNode.PointOfContact,
	}

	q.queue = append(q.queue, id)

	return nil
}

func (q *queueValues) addNodeToQueue(nodeType NodeType, versions []string, id string) {
	node, seen := q.nodeMap[id]

	var notInBlastRadius bool
	if !seen || nodeType == PackageVersion {
		notInBlastRadius = false
	} else {
		notInBlastRadius = node.NotInBlastRadius
	}

	q.nodeMap[id] = BfsNode{
		Parents:          append(node.Parents, q.now),
		Depth:            q.nowNode.Depth + 1,
		Type:             nodeType,
		PointOfContact:   node.PointOfContact,
		nodeVersions:     versions,
		NotInBlastRadius: notInBlastRadius,
		Expanded:         node.Expanded,
	}

	if !node.Expanded && !node.NotInBlastRadius {
		q.queue = append(q.queue, id)
	}
}
