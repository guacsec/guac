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
	"errors"
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
		Namespace: "github.com",
		Name:      "tensorflow",
	}, {
		Type:      "git",
		Namespace: "github.com",
		Name:      "build",
	}, {
		Type:      "git",
		Namespace: "github.com",
		Name:      "tensorflow",
		Tag:       &v12,
	}, {
		Type:      "git",
		Namespace: "github.com",
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
	id         uint32
	typeKey    string
	namespaces srcNamespaceMap
}
type srcNamespaceMap map[string]*srcNameStruct
type srcNameStruct struct {
	id        uint32
	parent    uint32
	namespace string
	names     srcNameList
}
type srcNameList []*srcNameNode
type srcNameNode struct {
	id             uint32
	parent         uint32
	name           string
	tag            string
	commit         string
	srcMapLinks    []uint32
	scorecardLinks []uint32
	occurrences    []uint32
	hasSBOMs       []uint32
	badLinks       []uint32
}

func (n *srcNamespaceStruct) getID() uint32 { return n.id }
func (n *srcNameStruct) getID() uint32      { return n.id }
func (n *srcNameNode) getID() uint32        { return n.id }

func (n *srcNamespaceStruct) neighbors() []uint32 {
	out := make([]uint32, 0, len(n.namespaces))
	for _, v := range n.namespaces {
		out = append(out, v.id)
	}
	return out
}
func (n *srcNameStruct) neighbors() []uint32 {
	out := make([]uint32, 0, 1+len(n.names))
	for _, v := range n.names {
		out = append(out, v.id)
	}
	out = append(out, n.parent)
	return out
}
func (n *srcNameNode) neighbors() []uint32 {
	out := make([]uint32, 0, 1+len(n.srcMapLinks)+len(n.scorecardLinks)+len(n.occurrences)+len(n.badLinks))
	out = append(out, n.srcMapLinks...)
	out = append(out, n.scorecardLinks...)
	out = append(out, n.occurrences...)
	out = append(out, n.badLinks...)
	out = append(out, n.parent)
	return out
}

func (n *srcNamespaceStruct) buildModelNode(c *demoClient) (model.Node, error) {
	return c.buildSourceResponse(n.id, nil)
}
func (n *srcNameStruct) buildModelNode(c *demoClient) (model.Node, error) {
	return c.buildSourceResponse(n.id, nil)
}
func (n *srcNameNode) buildModelNode(c *demoClient) (model.Node, error) {
	return c.buildSourceResponse(n.id, nil)
}

// hasSourceAt back edges
func (p *srcNameNode) setSrcMapLinks(id uint32) { p.srcMapLinks = append(p.srcMapLinks, id) }

// scorecard back edges
func (p *srcNameNode) setScorecardLinks(id uint32) { p.scorecardLinks = append(p.scorecardLinks, id) }

// occurrence back edges
func (p *srcNameNode) setOccurrenceLinks(id uint32) { p.occurrences = append(p.occurrences, id) }

func (p *srcNameNode) setHasSBOM(id uint32) { p.hasSBOMs = append(p.hasSBOMs, id) }
func (p *srcNameNode) getHasSBOM() []uint32 { return p.hasSBOMs }

// occurrence back edges
func (p *srcNameNode) setCertifyBadLinks(id uint32) { p.badLinks = append(p.badLinks, id) }

// Ingest Source
func (c *demoClient) IngestSource(ctx context.Context, input model.SourceInputSpec) (*model.Source, error) {
	namespacesStruct, hasNamespace := c.sources[input.Type]
	if !hasNamespace {
		namespacesStruct = &srcNamespaceStruct{
			id:         c.getNextID(),
			typeKey:    input.Type,
			namespaces: srcNamespaceMap{},
		}
		c.index[namespacesStruct.id] = namespacesStruct
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
		c.index[namesStruct.id] = namesStruct
	}
	names := namesStruct.names

	// Don't insert duplicates
	duplicate := false
	collectedSrcName := srcNameNode{}

	for _, src := range names {
		if src.name != input.Name {
			continue
		}
		if noMatchInput(input.Tag, src.tag) {
			continue
		}
		if noMatchInput(input.Commit, src.commit) {
			continue
		}
		collectedSrcName = *src
		duplicate = true
		break
	}
	if !duplicate {
		collectedSrcName = srcNameNode{
			id:     c.getNextID(),
			parent: namesStruct.id,
			name:   input.Name,
		}
		c.index[collectedSrcName.id] = &collectedSrcName
		if input.Tag != nil {
			collectedSrcName.tag = nilToEmpty(input.Tag)
		}
		if input.Commit != nil {
			collectedSrcName.commit = nilToEmpty(input.Commit)
		}
		namesStruct.names = append(names, &collectedSrcName)
		namespaces[input.Namespace] = namesStruct
		c.sources[input.Type] = namespacesStruct
	}

	// build return GraphQL type
	return c.buildSourceResponse(collectedSrcName.id, nil)
}

// Query Source

func (c *demoClient) Sources(ctx context.Context, filter *model.SourceSpec) ([]*model.Source, error) {
	if filter.Commit != nil && filter.Tag != nil {
		if *filter.Commit != "" && *filter.Tag != "" {
			return nil, gqlerror.Errorf("Passing both commit and tag selectors is an error")
		}
	}
	if filter != nil && filter.ID != nil {
		id, err := strconv.Atoi(*filter.ID)
		if err != nil {
			return nil, err
		}
		s, err := c.buildSourceResponse(uint32(id), filter)
		if err != nil {
			return nil, err
		}
		return []*model.Source{s}, nil
	}

	out := []*model.Source{}
	if filter != nil && filter.Type != nil {
		srcNamespaceStruct, ok := c.sources[*filter.Type]
		if ok {
			sNamespaces := buildSourceNamespace(srcNamespaceStruct, filter)
			if len(sNamespaces) > 0 {
				out = append(out, &model.Source{
					ID:         nodeID(srcNamespaceStruct.id),
					Type:       srcNamespaceStruct.typeKey,
					Namespaces: sNamespaces,
				})
			}
		}
	} else {
		for dbType, srcNamespaceStruct := range c.sources {
			sNamespaces := buildSourceNamespace(srcNamespaceStruct, filter)
			if len(sNamespaces) > 0 {
				out = append(out, &model.Source{
					ID:         nodeID(srcNamespaceStruct.id),
					Type:       dbType,
					Namespaces: sNamespaces,
				})
			}
		}
	}
	return out, nil
}

func buildSourceNamespace(srcNamespaceStruct *srcNamespaceStruct, filter *model.SourceSpec) []*model.SourceNamespace {
	sNamespaces := []*model.SourceNamespace{}
	if filter != nil && filter.Namespace != nil {
		srcNameStruct, ok := srcNamespaceStruct.namespaces[*filter.Namespace]
		if ok {
			sns := buildSourceName(srcNameStruct, filter)
			if len(sns) > 0 {
				sNamespaces = append(sNamespaces, &model.SourceNamespace{
					ID:        nodeID(srcNameStruct.id),
					Namespace: srcNameStruct.namespace,
					Names:     sns,
				})
			}
		}
	} else {
		for namespace, srcNameStruct := range srcNamespaceStruct.namespaces {
			sns := buildSourceName(srcNameStruct, filter)
			if len(sns) > 0 {
				sNamespaces = append(sNamespaces, &model.SourceNamespace{
					ID:        nodeID(srcNameStruct.id),
					Namespace: namespace,
					Names:     sns,
				})
			}
		}
	}
	return sNamespaces
}

func buildSourceName(srcNameStruct *srcNameStruct, filter *model.SourceSpec) []*model.SourceName {
	sns := []*model.SourceName{}
	for _, s := range srcNameStruct.names {
		if filter != nil && noMatch(filter.Name, s.name) {
			continue
		}
		if filter != nil && noMatch(filter.Tag, s.tag) {
			continue
		}
		if filter != nil && noMatch(filter.Commit, s.commit) {
			continue
		}
		sns = append(sns, &model.SourceName{
			ID:     nodeID(s.id),
			Name:   s.name,
			Tag:    &s.tag,
			Commit: &s.commit,
		})
	}
	return sns
}

// Builds a model.Source to send as GraphQL response, starting from id.
// The optional filter allows restricting output (on selection operations).
func (c *demoClient) buildSourceResponse(id uint32, filter *model.SourceSpec) (*model.Source, error) {
	if filter != nil && filter.ID != nil {
		filteredID, err := strconv.Atoi(*filter.ID)
		if err != nil {
			return nil, err
		}
		if uint32(filteredID) != id {
			return nil, nil
		}
	}

	node, ok := c.index[id]
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
			ID:     nodeID(nameNode.id),
			Name:   nameNode.name,
			Tag:    &nameNode.tag,
			Commit: &nameNode.commit,
		})
		node = c.index[nameNode.parent]
	}

	snsl := []*model.SourceNamespace{}
	if nameStruct, ok := node.(*srcNameStruct); ok {
		if filter != nil && noMatch(filter.Namespace, nameStruct.namespace) {
			return nil, nil
		}
		snsl = append(snsl, &model.SourceNamespace{
			ID:        nodeID(nameStruct.id),
			Namespace: nameStruct.namespace,
			Names:     snl,
		})
		node = c.index[nameStruct.parent]
	}

	namespaceStruct, ok := node.(*srcNamespaceStruct)
	if !ok {
		return nil, gqlerror.Errorf("ID does not match expected node type for source namespace")
	}
	s := model.Source{
		ID:         nodeID(namespaceStruct.id),
		Type:       namespaceStruct.typeKey,
		Namespaces: snsl,
	}
	if filter != nil && noMatch(filter.Type, s.Type) {
		return nil, nil
	}
	return &s, nil
}

func getSourceIDFromInput(c *demoClient, input model.SourceInputSpec) (uint32, error) {
	srcNamespace, srcHasNamespace := c.sources[input.Type]
	if !srcHasNamespace {
		return 0, gqlerror.Errorf("Source type \"%s\" not found", input.Type)
	}
	srcName, srcHasName := srcNamespace.namespaces[input.Namespace]
	if !srcHasName {
		return 0, gqlerror.Errorf("Source namespace \"%s\" not found", input.Namespace)
	}
	found := false
	var sourceID uint32
	for _, src := range srcName.names {
		if src.name != input.Name {
			continue
		}
		if noMatchInput(input.Tag, src.tag) {
			continue
		}
		if noMatchInput(input.Commit, src.commit) {
			continue
		}
		if found {
			return 0, gqlerror.Errorf("More than one source matches input")
		}
		sourceID = src.id
		found = true
	}
	if !found {
		return 0, gqlerror.Errorf("No source matches input")
	}
	return sourceID, nil
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

func (c *demoClient) sourceByID(id uint32) (*srcNameNode, error) {
	o, ok := c.index[id]
	if !ok {
		return nil, errors.New("could not find source")
	}
	a, ok := o.(*srcNameNode)
	if !ok {
		return nil, errors.New("not a source")
	}
	return a, nil
}
