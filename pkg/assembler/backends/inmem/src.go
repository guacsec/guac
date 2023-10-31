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

package inmem

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// TODO: move this into a unit test for this file
// func registerAllSources(client *demoClient) {
// 	ctx := context.Background()
// 	v12 := "v2.12.0"
// 	commit := "abcdef"

// 	inputs := []model.SourceInputSpec{{
// 		Type:      "git",
// 		Namespace: "github.com",
// 		Name:      "tensorflow",
// 	}, {
// 		Type:      "git",
// 		Namespace: "github.com",
// 		Name:      "build",
// 	}, {
// 		Type:      "git",
// 		Namespace: "github.com",
// 		Name:      "tensorflow",
// 		Tag:       &v12,
// 	}, {
// 		Type:      "git",
// 		Namespace: "github.com",
// 		Name:      "tensorflow",
// 		Commit:    &commit,
// 	}}

// 	for _, input := range inputs {
// 		_, err := client.IngestSource(ctx, input)
// 		if err != nil {
// 			log.Printf("Error in ingesting: %v\n", err)
// 		}
// 	}
// }

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
	id                  uint32
	parent              uint32
	name                string
	tag                 string
	commit              string
	srcMapLinks         []uint32
	scorecardLinks      []uint32
	occurrences         []uint32
	badLinks            []uint32
	goodLinks           []uint32
	hasMetadataLinks    []uint32
	pointOfContactLinks []uint32
	certifyLegals       []uint32
}

func (n *srcNamespaceStruct) ID() uint32 { return n.id }
func (n *srcNameStruct) ID() uint32      { return n.id }
func (n *srcNameNode) ID() uint32        { return n.id }

func (n *srcNamespaceStruct) Neighbors(allowedEdges edgeMap) []uint32 {
	var out []uint32
	if allowedEdges[model.EdgeSourceTypeSourceNamespace] {
		for _, v := range n.namespaces {
			out = append(out, v.id)
		}
	}
	return out
}
func (n *srcNameStruct) Neighbors(allowedEdges edgeMap) []uint32 {
	var out []uint32
	if allowedEdges[model.EdgeSourceNamespaceSourceName] {
		for _, v := range n.names {
			out = append(out, v.id)
		}
	}
	if allowedEdges[model.EdgeSourceNamespaceSourceType] {
		out = append(out, n.parent)
	}
	return out
}
func (n *srcNameNode) Neighbors(allowedEdges edgeMap) []uint32 {
	var out []uint32
	if allowedEdges[model.EdgeSourceNameSourceNamespace] {
		out = append(out, n.parent)
	}
	if allowedEdges[model.EdgeSourceHasSourceAt] {
		out = append(out, n.srcMapLinks...)
	}
	if allowedEdges[model.EdgeSourceCertifyScorecard] {
		out = append(out, n.scorecardLinks...)
	}
	if allowedEdges[model.EdgeSourceIsOccurrence] {
		out = append(out, n.occurrences...)
	}
	if allowedEdges[model.EdgeSourceCertifyBad] {
		out = append(out, n.badLinks...)
	}
	if allowedEdges[model.EdgeSourceCertifyGood] {
		out = append(out, n.goodLinks...)
	}
	if allowedEdges[model.EdgeSourceHasMetadata] {
		out = append(out, n.hasMetadataLinks...)
	}
	if allowedEdges[model.EdgeSourcePointOfContact] {
		out = append(out, n.pointOfContactLinks...)
	}
	if allowedEdges[model.EdgeSourceCertifyLegal] {
		out = append(out, n.certifyLegals...)
	}

	return out
}

func (n *srcNamespaceStruct) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildSourceResponse(n.id, nil)
}
func (n *srcNameStruct) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildSourceResponse(n.id, nil)
}
func (n *srcNameNode) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildSourceResponse(n.id, nil)
}

func (p *srcNameNode) setSrcMapLinks(id uint32)      { p.srcMapLinks = append(p.srcMapLinks, id) }
func (p *srcNameNode) setScorecardLinks(id uint32)   { p.scorecardLinks = append(p.scorecardLinks, id) }
func (p *srcNameNode) setOccurrenceLinks(id uint32)  { p.occurrences = append(p.occurrences, id) }
func (p *srcNameNode) setCertifyBadLinks(id uint32)  { p.badLinks = append(p.badLinks, id) }
func (p *srcNameNode) setCertifyGoodLinks(id uint32) { p.goodLinks = append(p.goodLinks, id) }
func (p *srcNameNode) setCertifyLegals(id uint32)    { p.certifyLegals = append(p.certifyLegals, id) }
func (p *srcNameNode) setHasMetadataLinks(id uint32) {
	p.hasMetadataLinks = append(p.hasMetadataLinks, id)
}
func (p *srcNameNode) setPointOfContactLinks(id uint32) {
	p.pointOfContactLinks = append(p.pointOfContactLinks, id)
}

// Ingest Source

func (c *demoClient) IngestSources(ctx context.Context, sources []*model.SourceInputSpec) ([]*model.Source, error) {
	var modelSources []*model.Source
	for _, src := range sources {
		modelSrc, err := c.IngestSource(ctx, *src)
		if err != nil {
			return nil, gqlerror.Errorf("IngestSources failed with err: %v", err)
		}
		modelSources = append(modelSources, modelSrc)
	}
	return modelSources, nil
}

func (c *demoClient) IngestSource(ctx context.Context, input model.SourceInputSpec) (*model.Source, error) {
	c.m.RLock()
	namespacesStruct, hasNamespace := c.sources[input.Type]
	c.m.RUnlock()
	if !hasNamespace {
		c.m.Lock()
		namespacesStruct, hasNamespace = c.sources[input.Type]
		if !hasNamespace {
			namespacesStruct = &srcNamespaceStruct{
				id:         c.getNextID(),
				typeKey:    input.Type,
				namespaces: srcNamespaceMap{},
			}
			c.index[namespacesStruct.id] = namespacesStruct
			c.sources[input.Type] = namespacesStruct
		}
		c.m.Unlock()
	}
	namespaces := namespacesStruct.namespaces

	c.m.RLock()
	namesStruct, hasName := namespaces[input.Namespace]
	c.m.RUnlock()
	if !hasName {
		c.m.Lock()
		namesStruct, hasName = namespaces[input.Namespace]
		if !hasName {
			namesStruct = &srcNameStruct{
				id:        c.getNextID(),
				parent:    namespacesStruct.id,
				namespace: input.Namespace,
				names:     srcNameList{},
			}
			c.index[namesStruct.id] = namesStruct
			namespaces[input.Namespace] = namesStruct
		}
		c.m.Unlock()
	}

	c.m.RLock()
	duplicate, collectedSrcName := duplicateSrcName(namesStruct.names, input)
	c.m.RUnlock()
	if !duplicate {
		c.m.Lock()
		duplicate, collectedSrcName = duplicateSrcName(namesStruct.names, input)
		if !duplicate {
			collectedSrcName = &srcNameNode{
				id:     c.getNextID(),
				parent: namesStruct.id,
				name:   input.Name,
			}
			c.index[collectedSrcName.id] = collectedSrcName
			if input.Tag != nil {
				collectedSrcName.tag = nilToEmpty(input.Tag)
			}
			if input.Commit != nil {
				collectedSrcName.commit = nilToEmpty(input.Commit)
			}
			namesStruct.names = append(namesStruct.names, collectedSrcName)
		}
		c.m.Unlock()
	}

	// build return GraphQL type
	c.m.RLock()
	defer c.m.RUnlock()
	return c.buildSourceResponse(collectedSrcName.id, nil)
}

func duplicateSrcName(names srcNameList, input model.SourceInputSpec) (bool, *srcNameNode) {
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
		return true, src
	}
	return false, nil
}

// Query Source

func (c *demoClient) Sources(ctx context.Context, filter *model.SourceSpec) ([]*model.Source, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	if filter != nil && filter.ID != nil {
		id, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, err
		}
		s, err := c.buildSourceResponse(uint32(id), filter)
		if err != nil {
			if errors.Is(err, errNotFound) {
				// not found
				return nil, nil
			}
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
		filteredID, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, err
		}
		if uint32(filteredID) != id {
			return nil, nil
		}
	}

	node, ok := c.index[id]
	if !ok {
		return nil, fmt.Errorf("%w : ID does not match existing node", errNotFound)
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
		node, ok = c.index[nameNode.parent]
		if !ok {
			return nil, fmt.Errorf("Internal ID does not match existing node")
		}
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
		node, ok = c.index[nameStruct.parent]
		if !ok {
			return nil, fmt.Errorf("Internal ID does not match existing node")
		}
	}

	namespaceStruct, ok := node.(*srcNamespaceStruct)
	if !ok {
		return nil, fmt.Errorf("%w: ID does not match expected node type for source namespace", errNotFound)
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

func (c *demoClient) exactSource(filter *model.SourceSpec) (*srcNameNode, error) {
	if filter == nil {
		return nil, nil
	}
	if filter.ID != nil {
		id64, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, err
		}
		id := uint32(id64)
		if node, ok := c.index[id]; ok {
			if s, ok := node.(*srcNameNode); ok {
				return s, nil
			}
		}
	}
	if filter.Type != nil && filter.Namespace != nil && filter.Name != nil && (filter.Tag != nil || filter.Commit != nil) {
		tp, ok := c.sources[*filter.Type]
		if !ok {
			return nil, nil
		}
		ns, ok := tp.namespaces[*filter.Namespace]
		if !ok {
			return nil, nil
		}
		for _, n := range ns.names {
			if *filter.Name != n.name ||
				noMatchInput(filter.Tag, n.tag) ||
				noMatchInput(filter.Commit, n.commit) {
				continue
			}
			return n, nil
		}
	}
	return nil, nil
}
