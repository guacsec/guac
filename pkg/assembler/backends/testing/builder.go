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
	"strconv"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

type builderMap map[string]*builderStruct
type builderStruct struct {
	id       uint32
	uri      string
	hasSLSAs []uint32
}

func (b *builderStruct) getID() uint32 { return b.id }

func (b *builderStruct) neighbors() []uint32 { return b.hasSLSAs }

func (b *builderStruct) buildModelNode(c *demoClient) (model.Node, error) {
	return c.convBuilder(b), nil
}

func (n *builderStruct) getHasSLSAs() []uint32 { return n.hasSLSAs }
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
	b, err := c.builderByKey(builder.URI)
	if err != nil {
		b = &builderStruct{
			id:  c.getNextID(),
			uri: builder.URI,
		}
		c.index[b.id] = b
		c.builders[builder.URI] = b
	}
	return c.convBuilder(b), nil
}

// 	for _, b := range c.builders {
// 		if b.URI == uri {
// 			return b
// 		}
// 	}
// 	newBuilder := &model.Builder{URI: uri}
// 	c.builders = append(c.builders, newBuilder)
// 	return newBuilder
// }

func (c *demoClient) builderByID(id uint32) (*builderStruct, error) {
	o, ok := c.index[id]
	if !ok {
		return nil, errors.New("could not find builder")
	}
	b, ok := o.(*builderStruct)
	if !ok {
		return nil, errors.New("not a builder")
	}
	return b, nil
}

// Query Builder
func (c *demoClient) Builders(ctx context.Context, builderSpec *model.BuilderSpec) ([]*model.Builder, error) {
	if builderSpec.ID != nil {
		id64, err := strconv.ParseUint(*builderSpec.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("Builders :: couldn't parse id %v", err)
		}
		id := uint32(id64)
		b, err := c.builderByID(id)
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
