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

package testing

import (
	"context"
	"fmt"
	"log"
	"strconv"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// TODO: move this into a unit test for this file
func registerAllSources(client *demoClient) {
	ctx := context.Background()
	v12 := "v2.12.0"
	commit := "abcdef"

	inputs := []model.SourceInputSpec{{
		Type:      "git",
		Namespace: "github.com/tensorflow",
		Name:      "tensorflow",
	}, {
		Type:      "git",
		Namespace: "github.com/tensorflow",
		Name:      "build",
	}, {
		Type:      "git",
		Namespace: "github.com/tensorflow",
		Name:      "tensorflow",
		Tag:       &v12,
	}, {
		Type:      "git",
		Namespace: "github.com/tensorflow",
		Name:      "tensorflow",
		Commit:    &commit,
	}}

	for _, input := range inputs {
		_, err := client.IngestSource(ctx, input)
		if err != nil {
			log.Printf("Error in ingesting: %v\n", err)
		}
	}
}

// Internal data: Sources
type srcTypeMap map[string]*srcNamespaceStruct
type srcNamespaceStruct struct {
	id         nodeID
	typeKey    string
	namespaces srcNamespaceMap
}
type srcNamespaceMap map[string]*srcNameStruct
type srcNameStruct struct {
	id        nodeID
	parent    nodeID
	namespace string
	names     srcNameList
}
type srcNameList []*srcNameNode
type srcNameNode struct {
	id         nodeID
	parent     nodeID
	name       string
	tag        string
	commit     string
	srcMapLink nodeID
}

func (n *srcNamespaceStruct) getID() nodeID { return n.id }
func (n *srcNameStruct) getID() nodeID      { return n.id }
func (n *srcNameNode) getID() nodeID        { return n.id }

// Ingest Source

func (c *demoClient) IngestSource(ctx context.Context, input model.SourceInputSpec) (*model.Source, error) {
	namespacesStruct, hasNamespace := sources[input.Type]
	if !hasNamespace {
		namespacesStruct = &srcNamespaceStruct{
			id:         c.getNextID(),
			typeKey:    input.Type,
			namespaces: srcNamespaceMap{},
		}
		index[namespacesStruct.id] = namespacesStruct
	}
	namespaces := namespacesStruct.namespaces

	namesStruct, hasName := namespaces[input.Namespace]
	if !hasName {
		namesStruct = &srcNameStruct{
			id:        c.getNextID(),
			parent:    namespacesStruct.id,
			namespace: input.Namespace,
			names:     srcNameList{},
		}
		index[namesStruct.id] = namesStruct
	}
	names := namesStruct.names

	newSource := srcNameNode{
		id:     c.getNextID(),
		parent: namesStruct.id,
		name:   input.Name,
	}
	index[newSource.id] = &newSource
	if input.Tag != nil {
		newSource.tag = nilToEmpty(input.Tag)
	}
	if input.Commit != nil {
		newSource.commit = nilToEmpty(input.Commit)
	}

	// Don't insert duplicates
	duplicate := false
	for _, src := range names {
		if src.name != input.Name {
			continue
		}
		if noMatch(input.Tag, src.tag) {
			continue
		}
		if noMatch(input.Commit, src.commit) {
			continue
		}
		duplicate = true
		break
	}
	if !duplicate {
		namesStruct.names = append(names, &newSource)
		namespaces[input.Namespace] = namesStruct
		sources[input.Type] = namespacesStruct
	}

	// build return GraphQL type
	return buildSourceResponse(newSource.id, nil)
}

// Query Source

func (c *demoClient) Sources(ctx context.Context, filter *model.SourceSpec) ([]*model.Source, error) {
	if filter.ID != nil {
		id, err := strconv.Atoi(*filter.ID)
		if err != nil {
			return nil, err
		}
		s, err := buildSourceResponse(nodeID(id), filter)
		if err != nil {
			return nil, err
		}
		return []*model.Source{s}, nil
	}
	out := []*model.Source{}
	for dbType, namespaces := range sources {
		if noMatch(filter.Type, dbType) {
			continue
		}
		sNamespaces := []*model.SourceNamespace{}
		for namespace, names := range namespaces.namespaces {
			if noMatch(filter.Namespace, namespace) {
				continue
			}
			sns := []*model.SourceName{}
			for _, s := range names.names {
				if noMatch(filter.Name, s.name) {
					continue
				}
				if noMatch(filter.Tag, s.tag) {
					continue
				}
				if noMatch(filter.Commit, s.commit) {
					continue
				}
				sns = append(sns, &model.SourceName{
					ID:     fmt.Sprintf("%d", s.id),
					Name:   s.name,
					Tag:    &s.tag,
					Commit: &s.commit,
				})
			}
			if len(sns) > 0 {
				sNamespaces = append(sNamespaces, &model.SourceNamespace{
					ID:        fmt.Sprintf("%d", names.id),
					Namespace: namespace,
					Names:     sns,
				})
			}
		}
		if len(sNamespaces) > 0 {
			out = append(out, &model.Source{
				ID:         fmt.Sprintf("%d", namespaces.id),
				Type:       dbType,
				Namespaces: sNamespaces,
			})
		}
	}
	return out, nil
}

// Builds a model.Source to send as GraphQL response, starting from id.
// The optional filter allows restricting output (on selection operations).
func buildSourceResponse(id nodeID, filter *model.SourceSpec) (*model.Source, error) {
	if filter != nil && filter.ID != nil {
		filteredID, err := strconv.Atoi(*filter.ID)
		if err != nil {
			return nil, err
		}
		if nodeID(filteredID) != id {
			return nil, nil
		}
	}

	node, ok := index[id]
	if !ok {
		return nil, gqlerror.Errorf("ID does not match existing node")
	}

	snl := []*model.SourceName{}
	if nameNode, ok := node.(*srcNameNode); ok {
		if filter != nil && noMatch(filter.Name, nameNode.name) {
			return nil, nil
		}
		if filter != nil && noMatch(filter.Tag, nameNode.tag) {
			return nil, nil
		}
		if filter != nil && noMatch(filter.Commit, nameNode.commit) {
			return nil, nil
		}
		snl = append(snl, &model.SourceName{
			// IDs are generated as string even though we ask for integers
			// See https://github.com/99designs/gqlgen/issues/2561
			ID:     fmt.Sprintf("%d", nameNode.id),
			Name:   nameNode.name,
			Tag:    &nameNode.tag,
			Commit: &nameNode.commit,
		})
		node = index[nameNode.parent]
	}

	snsl := []*model.SourceNamespace{}
	if nameStruct, ok := node.(*srcNameStruct); ok {
		if filter != nil && noMatch(filter.Namespace, nameStruct.namespace) {
			return nil, nil
		}
		snsl = append(snsl, &model.SourceNamespace{
			ID:        fmt.Sprintf("%d", nameStruct.id),
			Namespace: nameStruct.namespace,
			Names:     snl,
		})
		node = index[nameStruct.parent]
	}

	namespaceStruct, ok := node.(*srcNamespaceStruct)
	if !ok {
		return nil, gqlerror.Errorf("ID does not match expected node type")
	}
	s := model.Source{
		ID:         fmt.Sprintf("%d", namespaceStruct.id),
		Type:       namespaceStruct.typeKey,
		Namespaces: snsl,
	}
	if filter != nil && noMatch(filter.Type, s.Type) {
		return nil, nil
	}
	return &s, nil
}

// TODO: remove these once the other components don't utilize it
func filterSourceNamespace(src *model.Source, sourceSpec *model.SourceSpec) (*model.Source, error) {
	var namespaces []*model.SourceNamespace
	for _, ns := range src.Namespaces {
		if sourceSpec.Namespace == nil || ns.Namespace == *sourceSpec.Namespace {
			newNs, err := filterSourceName(ns, sourceSpec)
			if err != nil {
				return nil, err
			}
			if newNs != nil {
				namespaces = append(namespaces, newNs)
			}
		}
	}
	if len(namespaces) == 0 {
		return nil, nil
	}
	return &model.Source{
		Type:       src.Type,
		Namespaces: namespaces,
	}, nil
}

// TODO: remove these once the other components don't utilize it
func filterSourceName(ns *model.SourceNamespace, sourceSpec *model.SourceSpec) (*model.SourceNamespace, error) {
	var names []*model.SourceName
	for _, n := range ns.Names {
		if sourceSpec.Name == nil || n.Name == *sourceSpec.Name {
			n, err := filterSourceTagCommit(n, sourceSpec)
			if err != nil {
				return nil, err
			}
			if n != nil {
				names = append(names, n)
			}
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	return &model.SourceNamespace{
		Namespace: ns.Namespace,
		Names:     names,
	}, nil
}

// TODO: remove these once the other components don't utilize it
func filterSourceTagCommit(n *model.SourceName, sourceSpec *model.SourceSpec) (*model.SourceName, error) {
	if sourceSpec.Commit != nil && sourceSpec.Tag != nil {
		if *sourceSpec.Commit != "" && *sourceSpec.Tag != "" {
			return nil, gqlerror.Errorf("Passing both commit and tag selectors is an error")
		}
	}

	if !matchInputSpecWithDBField(sourceSpec.Commit, n.Commit) {
		return nil, nil
	}

	if !matchInputSpecWithDBField(sourceSpec.Tag, n.Tag) {
		return nil, nil
	}

	return n, nil
}

// TODO: remove these once the other components don't utilize it
func matchInputSpecWithDBField(spec *string, dbField *string) bool {
	if spec == nil {
		return true
	}

	if *spec == "" {
		return (dbField == nil || *dbField == "")
	}

	return (dbField != nil && *dbField == *spec)
}
