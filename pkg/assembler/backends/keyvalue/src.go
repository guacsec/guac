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

package keyvalue

import (
	"context"
	"errors"
	"fmt"

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
	id         string
	typeKey    string
	namespaces srcNamespaceMap
}
type srcNamespaceMap map[string]*srcNameStruct
type srcNameStruct struct {
	id        string
	parent    string
	namespace string
	names     srcNameList
}
type srcNameList []*srcNameNode
type srcNameNode struct {
	id                  string
	parent              string
	name                string
	tag                 string
	commit              string
	srcMapLinks         []string
	scorecardLinks      []string
	occurrences         []string
	badLinks            []string
	goodLinks           []string
	hasMetadataLinks    []string
	pointOfContactLinks []string
	certifyLegals       []string
}

func (n *srcNamespaceStruct) ID() string { return n.id }
func (n *srcNameStruct) ID() string      { return n.id }
func (n *srcNameNode) ID() string        { return n.id }

func (n *srcNamespaceStruct) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, len(n.namespaces))
	for _, v := range n.namespaces {
		out = append(out, v.id)
	}
	return out
}
func (n *srcNameStruct) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 1+len(n.names))
	for _, v := range n.names {
		out = append(out, v.id)
	}
	out = append(out, n.parent)
	return out
}
func (n *srcNameNode) Neighbors(allowedEdges edgeMap) []string {
	out := []string{n.parent}

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

func (n *srcNamespaceStruct) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildSourceResponse(n.id, nil)
}
func (n *srcNameStruct) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildSourceResponse(n.id, nil)
}
func (n *srcNameNode) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildSourceResponse(n.id, nil)
}

func (p *srcNameNode) setSrcMapLinks(id string)      { p.srcMapLinks = append(p.srcMapLinks, id) }
func (p *srcNameNode) setScorecardLinks(id string)   { p.scorecardLinks = append(p.scorecardLinks, id) }
func (p *srcNameNode) setOccurrenceLinks(id string)  { p.occurrences = append(p.occurrences, id) }
func (p *srcNameNode) setCertifyBadLinks(id string)  { p.badLinks = append(p.badLinks, id) }
func (p *srcNameNode) setCertifyGoodLinks(id string) { p.goodLinks = append(p.goodLinks, id) }
func (p *srcNameNode) setCertifyLegals(id string)    { p.certifyLegals = append(p.certifyLegals, id) }
func (p *srcNameNode) setHasMetadataLinks(id string) {
	p.hasMetadataLinks = append(p.hasMetadataLinks, id)
}
func (p *srcNameNode) setPointOfContactLinks(id string) {
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
		s, err := c.buildSourceResponse(*filter.ID, filter)
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
					ID:         srcNamespaceStruct.id,
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
					ID:         srcNamespaceStruct.id,
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
					ID:        srcNameStruct.id,
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
					ID:        srcNameStruct.id,
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
			ID:     s.id,
			Name:   s.name,
			Tag:    &s.tag,
			Commit: &s.commit,
		})
	}
	return sns
}

// Builds a model.Source to send as GraphQL response, starting from id.
// The optional filter allows restricting output (on selection operations).
func (c *demoClient) buildSourceResponse(id string, filter *model.SourceSpec) (*model.Source, error) {
	if filter != nil && filter.ID != nil && *filter.ID != id {
		return nil, nil
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
			ID:     nameNode.id,
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
			ID:        nameStruct.id,
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
		ID:         namespaceStruct.id,
		Type:       namespaceStruct.typeKey,
		Namespaces: snsl,
	}
	if filter != nil && noMatch(filter.Type, s.Type) {
		return nil, nil
	}
	return &s, nil
}

func getSourceIDFromInput(c *demoClient, input model.SourceInputSpec) (string, error) {
	srcNamespace, srcHasNamespace := c.sources[input.Type]
	if !srcHasNamespace {
		return "", gqlerror.Errorf("Source type \"%s\" not found", input.Type)
	}
	srcName, srcHasName := srcNamespace.namespaces[input.Namespace]
	if !srcHasName {
		return "", gqlerror.Errorf("Source namespace \"%s\" not found", input.Namespace)
	}
	found := false
	var sourceID string
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
			return "", gqlerror.Errorf("More than one source matches input")
		}
		sourceID = src.id
		found = true
	}
	if !found {
		return "", gqlerror.Errorf("No source matches input")
	}
	return sourceID, nil
}

func (c *demoClient) exactSource(filter *model.SourceSpec) (*srcNameNode, error) {
	if filter == nil {
		return nil, nil
	}
	if filter.ID != nil {
		if node, ok := c.index[*filter.ID]; ok {
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
