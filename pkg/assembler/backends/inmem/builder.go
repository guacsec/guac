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
	"strconv"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type builderMap map[string]*builderStruct
type builderStruct struct {
	id       uint32
	uri      string
	hasSLSAs []uint32
}

func (b *builderStruct) ID() uint32 { return b.id }

func (b *builderStruct) Neighbors(allowedEdges edgeMap) []uint32 {
	if allowedEdges[model.EdgeBuilderHasSlsa] {
		return b.hasSLSAs
	}
	return []uint32{}
}

func (b *builderStruct) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.convBuilder(b), nil
}

func (n *builderStruct) setHasSLSAs(id uint32) { n.hasSLSAs = append(n.hasSLSAs, id) }

// TODO make these into test cases
// func registerAllBuilders(client *demoClient) {
// 	client.registerBuilder("https://github.com/Attestations/GitHubHostedActions@v1")
// 	client.registerBuilder("https://tekton.dev/chains/v2")
// }

func (c *demoClient) builderByKey(uri string) (*builderStruct, error) {
	if b, ok := c.builders[uri]; ok {
		return b, nil
	}
	return nil, errors.New("builder not found")
}

// Ingest Builder
func (c *demoClient) IngestBuilder(ctx context.Context, builder *model.BuilderInputSpec) (*model.Builder, error) {
	return c.ingestBuilder(ctx, builder, true)
}

func (c *demoClient) ingestBuilder(ctx context.Context, builder *model.BuilderInputSpec, readOnly bool) (*model.Builder, error) {
	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	b, err := c.builderByKey(builder.URI)
	if err != nil {
		if readOnly {
			c.m.RUnlock()
			b, err := c.ingestBuilder(ctx, builder, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return b, err
		}
		b = &builderStruct{
			id:  c.getNextID(),
			uri: builder.URI,
		}
		c.index[b.id] = b
		c.builders[builder.URI] = b
	}
	return c.convBuilder(b), nil
}

// Query Builder
func (c *demoClient) Builders(ctx context.Context, builderSpec *model.BuilderSpec) ([]*model.Builder, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	if builderSpec.ID != nil {
		id64, err := strconv.ParseUint(*builderSpec.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("Builders :: couldn't parse id %v", err)
		}
		id := uint32(id64)
		b, err := byID[*builderStruct](id, c)
		if err != nil {
			return nil, nil
		}
		return []*model.Builder{c.convBuilder(b)}, nil
	}
	if builderSpec.URI != nil {
		b, err := c.builderByKey(*builderSpec.URI)
		if err != nil {
			return nil, nil
		}
		return []*model.Builder{c.convBuilder(b)}, nil
	}
	var builders []*model.Builder
	for _, b := range c.builders {
		builders = append(builders, c.convBuilder(b))
	}
	return builders, nil
}

func (c *demoClient) convBuilder(b *builderStruct) *model.Builder {
	return &model.Builder{
		ID:  nodeID(b.id),
		URI: b.uri,
	}
}

func (c *demoClient) exactBuilder(filter *model.BuilderSpec) (*builderStruct, error) {
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
			if b, ok := node.(*builderStruct); ok {
				return b, nil
			}
		}
	}
	if filter.URI != nil {
		if b, ok := c.builders[*filter.URI]; ok {
			return b, nil
		}
	}
	return nil, nil
}
