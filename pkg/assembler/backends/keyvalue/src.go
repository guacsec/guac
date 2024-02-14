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
	"strings"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
)

// Internal data: Sources
type srcType struct {
	ThisID     string
	Type       string
	Namespaces []string
}
type srcNamespace struct {
	ThisID    string
	Parent    string
	Namespace string
	Names     []string
}
type srcNameNode struct {
	ThisID              string
	Parent              string
	Name                string
	Tag                 string
	Commit              string
	SrcMapLinks         []string
	ScorecardLinks      []string
	Occurrences         []string
	BadLinks            []string
	GoodLinks           []string
	HasMetadataLinks    []string
	PointOfContactLinks []string
	CertifyLegals       []string
}

func (n *srcType) ID() string      { return n.ThisID }
func (n *srcNamespace) ID() string { return n.ThisID }
func (n *srcNameNode) ID() string  { return n.ThisID }

func (n *srcType) Key() string {
	return hashKey(n.Type)
}

func (n *srcNamespace) Key() string {
	return hashKey(strings.Join([]string{
		n.Parent,
		n.Namespace,
	}, ":"))
}

func (n *srcNameNode) Key() string {
	return hashKey(strings.Join([]string{
		n.Parent,
		n.Name,
		n.Tag,
		n.Commit,
	}, ":"))
}

func (n *srcType) Neighbors(allowedEdges edgeMap) []string {
	if allowedEdges[model.EdgeSourceTypeSourceNamespace] {
		return n.Namespaces
	}
	return nil
}
func (n *srcNamespace) Neighbors(allowedEdges edgeMap) []string {
	var out []string
	if allowedEdges[model.EdgeSourceNamespaceSourceName] {
		out = append(out, n.Names...)
	}
	if allowedEdges[model.EdgeSourceNamespaceSourceType] {
		out = append(out, n.Parent)
	}
	return out
}
func (n *srcNameNode) Neighbors(allowedEdges edgeMap) []string {
	var out []string

	if allowedEdges[model.EdgeSourceNameSourceNamespace] {
		out = append(out, n.Parent)
	}
	if allowedEdges[model.EdgeSourceHasSourceAt] {
		out = append(out, n.SrcMapLinks...)
	}
	if allowedEdges[model.EdgeSourceCertifyScorecard] {
		out = append(out, n.ScorecardLinks...)
	}
	if allowedEdges[model.EdgeSourceIsOccurrence] {
		out = append(out, n.Occurrences...)
	}
	if allowedEdges[model.EdgeSourceCertifyBad] {
		out = append(out, n.BadLinks...)
	}
	if allowedEdges[model.EdgeSourceCertifyGood] {
		out = append(out, n.GoodLinks...)
	}
	if allowedEdges[model.EdgeSourceHasMetadata] {
		out = append(out, n.HasMetadataLinks...)
	}
	if allowedEdges[model.EdgeSourcePointOfContact] {
		out = append(out, n.PointOfContactLinks...)
	}
	if allowedEdges[model.EdgeSourceCertifyLegal] {
		out = append(out, n.CertifyLegals...)
	}

	return out
}

func (n *srcType) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildSourceResponse(ctx, n.ThisID, nil)
}
func (n *srcNamespace) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildSourceResponse(ctx, n.ThisID, nil)
}
func (n *srcNameNode) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildSourceResponse(ctx, n.ThisID, nil)
}

func (p *srcNameNode) setSrcMapLinks(ctx context.Context, id string, c *demoClient) error {
	p.SrcMapLinks = append(p.SrcMapLinks, id)
	return setkv(ctx, srcNameCol, p, c)
}
func (p *srcNameNode) setScorecardLinks(ctx context.Context, id string, c *demoClient) error {
	p.ScorecardLinks = append(p.ScorecardLinks, id)
	return setkv(ctx, srcNameCol, p, c)
}
func (p *srcNameNode) setOccurrenceLinks(ctx context.Context, id string, c *demoClient) error {
	p.Occurrences = append(p.Occurrences, id)
	return setkv(ctx, srcNameCol, p, c)
}
func (p *srcNameNode) setCertifyBadLinks(ctx context.Context, id string, c *demoClient) error {
	p.BadLinks = append(p.BadLinks, id)
	return setkv(ctx, srcNameCol, p, c)
}
func (p *srcNameNode) setCertifyGoodLinks(ctx context.Context, id string, c *demoClient) error {
	p.GoodLinks = append(p.GoodLinks, id)
	return setkv(ctx, srcNameCol, p, c)
}
func (p *srcNameNode) setCertifyLegals(ctx context.Context, id string, c *demoClient) error {
	p.CertifyLegals = append(p.CertifyLegals, id)
	return setkv(ctx, srcNameCol, p, c)
}
func (p *srcNameNode) setHasMetadataLinks(ctx context.Context, id string, c *demoClient) error {
	p.HasMetadataLinks = append(p.HasMetadataLinks, id)
	return setkv(ctx, srcNameCol, p, c)
}
func (p *srcNameNode) setPointOfContactLinks(ctx context.Context, id string, c *demoClient) error {
	p.PointOfContactLinks = append(p.PointOfContactLinks, id)
	return setkv(ctx, srcNameCol, p, c)
}

func (n *srcType) addNamespace(ctx context.Context, ns string, c *demoClient) error {
	n.Namespaces = append(n.Namespaces, ns)
	return setkv(ctx, srcTypeCol, n, c)
}

func (n *srcNamespace) addName(ctx context.Context, name string, c *demoClient) error {
	n.Names = append(n.Names, name)
	return setkv(ctx, srcNSCol, n, c)
}

// Ingest Source

func (c *demoClient) IngestSources(ctx context.Context, sources []*model.IDorSourceInput) ([]*model.SourceIDs, error) {
	var modelSources []*model.SourceIDs
	for _, src := range sources {
		modelSrc, err := c.IngestSource(ctx, *src)
		if err != nil {
			return nil, gqlerror.Errorf("IngestSources failed with err: %v", err)
		}
		modelSources = append(modelSources, modelSrc)
	}
	return modelSources, nil
}

func (c *demoClient) IngestSource(ctx context.Context, input model.IDorSourceInput) (*model.SourceIDs, error) {
	inType := &srcType{
		Type: input.Type,
	}
	c.m.RLock()
	outType, err := byKeykv[*srcType](ctx, srcTypeCol, inType.Key(), c)
	c.m.RUnlock()
	if err != nil {
		if !errors.Is(err, kv.NotFoundError) {
			return nil, err
		}
		c.m.Lock()
		outType, err = byKeykv[*srcType](ctx, srcTypeCol, inType.Key(), c)
		if err != nil {
			if !errors.Is(err, kv.NotFoundError) {
				c.m.Unlock()
				return nil, err
			}
			inType.ThisID = c.getNextID()
			if err := c.addToIndex(ctx, srcTypeCol, inType); err != nil {
				c.m.Unlock()
				return nil, err
			}
			if err := setkv(ctx, srcTypeCol, inType, c); err != nil {
				c.m.Unlock()
				return nil, err
			}
			outType = inType
		}
		c.m.Unlock()
	}

	inNamespace := &srcNamespace{
		Parent:    outType.ThisID,
		Namespace: input.Namespace,
	}
	c.m.RLock()
	outNamespace, err := byKeykv[*srcNamespace](ctx, srcNSCol, inNamespace.Key(), c)
	c.m.RUnlock()
	if err != nil {
		if !errors.Is(err, kv.NotFoundError) {
			return nil, err
		}
		c.m.Lock()
		outNamespace, err = byKeykv[*srcNamespace](ctx, srcNSCol, inNamespace.Key(), c)
		if err != nil {
			if !errors.Is(err, kv.NotFoundError) {
				c.m.Unlock()
				return nil, err
			}
			inNamespace.ThisID = c.getNextID()
			if err := c.addToIndex(ctx, srcNSCol, inNamespace); err != nil {
				c.m.Unlock()
				return nil, err
			}
			if err := setkv(ctx, srcNSCol, inNamespace, c); err != nil {
				c.m.Unlock()
				return nil, err
			}
			if err := outType.addNamespace(ctx, inNamespace.ThisID, c); err != nil {
				c.m.Unlock()
				return nil, err
			}
			outNamespace = inNamespace
		}
		c.m.Unlock()
	}

	inName := &srcNameNode{
		Parent: outNamespace.ThisID,
		Name:   input.Name,
		Tag:    nilToEmpty(input.Tag),
		Commit: nilToEmpty(input.Commit),
	}
	c.m.RLock()
	outName, err := byKeykv[*srcNameNode](ctx, srcNameCol, inName.Key(), c)
	c.m.RUnlock()
	if err != nil {
		if !errors.Is(err, kv.NotFoundError) {
			return nil, err
		}
		c.m.Lock()
		outName, err = byKeykv[*srcNameNode](ctx, srcNameCol, inName.Key(), c)
		if err != nil {
			if !errors.Is(err, kv.NotFoundError) {
				c.m.Unlock()
				return nil, err
			}
			inName.ThisID = c.getNextID()
			if err := c.addToIndex(ctx, srcNameCol, inName); err != nil {
				c.m.Unlock()
				return nil, err
			}
			if err := setkv(ctx, srcNameCol, inName, c); err != nil {
				c.m.Unlock()
				return nil, err
			}
			if err := outNamespace.addName(ctx, inName.ThisID, c); err != nil {
				c.m.Unlock()
				return nil, err
			}
			outName = inName
		}
		c.m.Unlock()
	}

	return &model.SourceIDs{
		SourceTypeID:      outType.ThisID,
		SourceNamespaceID: outNamespace.ThisID,
		SourceNameID:      outName.ThisID,
	}, nil
}

// Query Source

func (c *demoClient) Sources(ctx context.Context, filter *model.SourceSpec) ([]*model.Source, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	if filter != nil && filter.ID != nil {
		s, err := c.buildSourceResponse(ctx, *filter.ID, filter)
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
		inType := &srcType{
			Type: *filter.Type,
		}
		srcTypeNode, err := byKeykv[*srcType](ctx, srcTypeCol, inType.Key(), c)
		if err == nil {
			sNamespaces := c.buildSourceNamespace(ctx, srcTypeNode, filter)
			if len(sNamespaces) > 0 {
				out = append(out, &model.Source{
					ID:         srcTypeNode.ThisID,
					Type:       srcTypeNode.Type,
					Namespaces: sNamespaces,
				})
			}
		}
	} else {
		var done bool
		scn := c.kv.Keys(srcTypeCol)
		for !done {
			var typeKeys []string
			var err error
			typeKeys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}
			for _, tk := range typeKeys {
				srcTypeNode, err := byKeykv[*srcType](ctx, srcTypeCol, tk, c)
				if err != nil {
					return nil, err
				}
				sNamespaces := c.buildSourceNamespace(ctx, srcTypeNode, filter)
				if len(sNamespaces) > 0 {
					out = append(out, &model.Source{
						ID:         srcTypeNode.ThisID,
						Type:       srcTypeNode.Type,
						Namespaces: sNamespaces,
					})
				}
			}
		}
	}
	return out, nil
}

func (c *demoClient) buildSourceNamespace(ctx context.Context, srcTypeNode *srcType, filter *model.SourceSpec) []*model.SourceNamespace {
	sNamespaces := []*model.SourceNamespace{}
	if filter != nil && filter.Namespace != nil {
		inNS := &srcNamespace{
			Parent:    srcTypeNode.ThisID,
			Namespace: *filter.Namespace,
		}
		srcNS, err := byKeykv[*srcNamespace](ctx, srcNSCol, inNS.Key(), c)
		if err == nil {
			sns := c.buildSourceName(ctx, srcNS, filter)
			if len(sns) > 0 {
				sNamespaces = append(sNamespaces, &model.SourceNamespace{
					ID:        srcNS.ThisID,
					Namespace: srcNS.Namespace,
					Names:     sns,
				})
			}
		}
	} else {
		for _, nsID := range srcTypeNode.Namespaces {
			srcNS, err := byIDkv[*srcNamespace](ctx, nsID, c)
			if err != nil {
				continue
			}
			sns := c.buildSourceName(ctx, srcNS, filter)
			if len(sns) > 0 {
				sNamespaces = append(sNamespaces, &model.SourceNamespace{
					ID:        srcNS.ThisID,
					Namespace: srcNS.Namespace,
					Names:     sns,
				})
			}
		}
	}
	return sNamespaces
}

func (c *demoClient) buildSourceName(ctx context.Context, srcNamespace *srcNamespace, filter *model.SourceSpec) []*model.SourceName {
	if filter != nil &&
		filter.Name != nil &&
		(filter.Tag != nil || filter.Commit != nil) {
		inName := &srcNameNode{
			Parent: srcNamespace.ThisID,
			Name:   *filter.Name,
			Tag:    nilToEmpty(filter.Tag),
			Commit: nilToEmpty(filter.Commit),
		}
		srcName, err := byKeykv[*srcNameNode](ctx, srcNameCol, inName.Key(), c)
		if err != nil {
			return nil
		}
		m := &model.SourceName{
			ID:   srcName.ThisID,
			Name: srcName.Name,
		}
		if srcName.Tag != "" {
			m.Tag = &srcName.Tag
		}
		if srcName.Commit != "" {
			m.Commit = &srcName.Commit
		}
		return []*model.SourceName{m}
	}
	sns := []*model.SourceName{}
	for _, nameID := range srcNamespace.Names {
		s, err := byIDkv[*srcNameNode](ctx, nameID, c)
		if err != nil {
			return nil
		}
		if filter != nil && noMatch(filter.Name, s.Name) {
			continue
		}
		if filter != nil && noMatch(filter.Tag, s.Tag) {
			continue
		}
		if filter != nil && noMatch(filter.Commit, s.Commit) {
			continue
		}
		m := &model.SourceName{
			ID:   s.ThisID,
			Name: s.Name,
		}
		if s.Tag != "" {
			m.Tag = &s.Tag
		}
		if s.Commit != "" {
			m.Commit = &s.Commit
		}
		sns = append(sns, m)
	}
	return sns
}

// Builds a model.Source to send as GraphQL response, starting from id.
// The optional filter allows restricting output (on selection operations).
func (c *demoClient) buildSourceResponse(ctx context.Context, id string, filter *model.SourceSpec) (*model.Source, error) {
	if filter != nil && filter.ID != nil && *filter.ID != id {
		return nil, nil
	}

	currentID := id

	snl := []*model.SourceName{}
	if nameNode, err := byIDkv[*srcNameNode](ctx, currentID, c); err == nil {
		if filter != nil && noMatch(filter.Name, nameNode.Name) {
			return nil, nil
		}
		if filter != nil && noMatch(filter.Tag, nameNode.Tag) {
			return nil, nil
		}
		if filter != nil && noMatch(filter.Commit, nameNode.Commit) {
			return nil, nil
		}
		model := &model.SourceName{
			ID:   nameNode.ThisID,
			Name: nameNode.Name,
		}
		if nameNode.Tag != "" {
			model.Tag = &nameNode.Tag
		}
		if nameNode.Commit != "" {
			model.Commit = &nameNode.Commit
		}
		snl = append(snl, model)
		currentID = nameNode.Parent
	} else if !errors.Is(err, kv.NotFoundError) && !errors.Is(err, errTypeNotMatch) {
		return nil, fmt.Errorf("Error retrieving node for id: %v : %w", currentID, err)
	}

	snsl := []*model.SourceNamespace{}
	if namespaceNode, err := byIDkv[*srcNamespace](ctx, currentID, c); err == nil {
		if filter != nil && noMatch(filter.Namespace, namespaceNode.Namespace) {
			return nil, nil
		}
		snsl = append(snsl, &model.SourceNamespace{
			ID:        namespaceNode.ThisID,
			Namespace: namespaceNode.Namespace,
			Names:     snl,
		})
		currentID = namespaceNode.Parent
	} else if !errors.Is(err, kv.NotFoundError) && !errors.Is(err, errTypeNotMatch) {
		return nil, fmt.Errorf("Error retrieving node for id: %v : %w", currentID, err)
	}

	typeNode, err := byIDkv[*srcType](ctx, currentID, c)
	if err != nil {
		if errors.Is(err, kv.NotFoundError) || errors.Is(err, errTypeNotMatch) {
			return nil, fmt.Errorf("%w: ID does not match expected node type for package namespace", errNotFound)
		} else {
			return nil, fmt.Errorf("Error retrieving node for id: %v : %w", currentID, err)
		}
	}
	if filter != nil && noMatch(filter.Type, typeNode.Type) {
		return nil, nil
	}
	s := model.Source{
		ID:         typeNode.ThisID,
		Type:       typeNode.Type,
		Namespaces: snsl,
	}
	return &s, nil
}

func (c *demoClient) getSourceNameFromInput(ctx context.Context, input model.SourceInputSpec) (*srcNameNode, error) {
	inType := &srcType{
		Type: input.Type,
	}
	srcT, err := byKeykv[*srcType](ctx, srcTypeCol, inType.Key(), c)
	if err != nil {
		return nil, gqlerror.Errorf("Package type \"%s\" not found", input.Type)
	}

	inNS := &srcNamespace{
		Parent:    srcT.ThisID,
		Namespace: input.Namespace,
	}
	srcNS, err := byKeykv[*srcNamespace](ctx, srcNSCol, inNS.Key(), c)
	if err != nil {
		return nil, gqlerror.Errorf("Package namespace \"%s\" not found", input.Namespace)
	}

	inName := &srcNameNode{
		Parent: srcNS.ThisID,
		Name:   input.Name,
		Tag:    nilToEmpty(input.Tag),
		Commit: nilToEmpty(input.Commit),
	}
	srcN, err := byKeykv[*srcNameNode](ctx, srcNameCol, inName.Key(), c)
	if err != nil {
		return nil, gqlerror.Errorf("Package name \"%s\" not found", input.Name)
	}

	return srcN, nil
}

func (c *demoClient) exactSource(ctx context.Context, filter *model.SourceSpec) (*srcNameNode, error) {
	if filter == nil {
		return nil, nil
	}
	if filter.ID != nil {
		if srcN, err := byIDkv[*srcNameNode](ctx, *filter.ID, c); err == nil {
			return srcN, nil
		} else {
			if !errors.Is(err, kv.NotFoundError) && !errors.Is(err, errTypeNotMatch) {
				return nil, err
			}
			return nil, nil
		}
	}
	if filter.Type != nil && filter.Namespace != nil && filter.Name != nil && (filter.Tag != nil || filter.Commit != nil) {
		inType := &srcType{
			Type: *filter.Type,
		}
		srcT, err := byKeykv[*srcType](ctx, srcTypeCol, inType.Key(), c)
		if err != nil {
			if !errors.Is(err, kv.NotFoundError) && !errors.Is(err, errTypeNotMatch) {
				return nil, err
			}
			return nil, nil
		}

		inNS := &srcNamespace{
			Parent:    srcT.ThisID,
			Namespace: *filter.Namespace,
		}
		srcNS, err := byKeykv[*srcNamespace](ctx, srcNSCol, inNS.Key(), c)
		if err != nil {
			if !errors.Is(err, kv.NotFoundError) && !errors.Is(err, errTypeNotMatch) {
				return nil, err
			}
			return nil, nil
		}

		inName := &srcNameNode{
			Parent: srcNS.ThisID,
			Name:   *filter.Name,
			Tag:    nilToEmpty(filter.Tag),
			Commit: nilToEmpty(filter.Commit),
		}
		srcN, err := byKeykv[*srcNameNode](ctx, srcNameCol, inName.Key(), c)
		if err != nil {
			if !errors.Is(err, kv.NotFoundError) && !errors.Is(err, errTypeNotMatch) {
				return nil, err
			}
			return nil, nil
		}
		return srcN, nil
	}
	return nil, nil
}
