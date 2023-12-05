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

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
)

type builderStruct struct {
	ThisID   string
	URI      string
	HasSLSAs []string
}

func (n *builderStruct) Key() string {
	return n.URI
}

func (b *builderStruct) ID() string { return b.ThisID }

func (b *builderStruct) Neighbors(allowedEdges edgeMap) []string {
	if allowedEdges[model.EdgeBuilderHasSlsa] {
		return b.HasSLSAs
	}
	return []string{}
}

func (b *builderStruct) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.convBuilder(b), nil
}

func (n *builderStruct) setHasSLSAs(ctx context.Context, id string, c *demoClient) error {
	n.HasSLSAs = append(n.HasSLSAs, id)
	return setkv(ctx, builderCol, n, c)
}

func (c *demoClient) builderByInput(ctx context.Context, b *model.BuilderInputSpec) (*builderStruct, error) {
	in := &builderStruct{
		URI: b.URI,
	}
	return byKeykv[*builderStruct](ctx, builderCol, in.Key(), c)
}

// Ingest Builders

func (c *demoClient) IngestBuilders(ctx context.Context, builders []*model.BuilderInputSpec) ([]string, error) {
	var modelBuilders []string
	for _, build := range builders {
		modelBuild, err := c.IngestBuilder(ctx, build)
		if err != nil {
			return nil, gqlerror.Errorf("IngestBuilder failed with err: %v", err)
		}
		modelBuilders = append(modelBuilders, modelBuild)
	}
	return modelBuilders, nil
}

// Ingest Builder

func (c *demoClient) IngestBuilder(ctx context.Context, builder *model.BuilderInputSpec) (string, error) {
	return c.ingestBuilder(ctx, builder, true)
}

func (c *demoClient) ingestBuilder(ctx context.Context, builder *model.BuilderInputSpec, readOnly bool) (string, error) {
	in := &builderStruct{
		URI: builder.URI,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	out, err := byKeykv[*builderStruct](ctx, builderCol, in.Key(), c)
	if err == nil {
		return out.ThisID, nil
	}
	if !errors.Is(err, kv.NotFoundError) {
		return "", err
	}
	if readOnly {
		c.m.RUnlock()
		b, err := c.ingestBuilder(ctx, builder, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return b, err
	}
	in.ThisID = c.getNextID()
	if err := c.addToIndex(ctx, builderCol, in); err != nil {
		return "", err
	}
	if err := setkv(ctx, builderCol, in, c); err != nil {
		return "", err
	}

	return in.ThisID, nil
}

// Query Builder
func (c *demoClient) Builders(ctx context.Context, builderSpec *model.BuilderSpec) ([]*model.Builder, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	b, err := c.exactBuilder(ctx, builderSpec)
	if err != nil {
		return nil, err
	}
	if b != nil {
		return []*model.Builder{c.convBuilder(b)}, nil
	}
	var builders []*model.Builder
	var done bool
	scn := c.kv.Keys(builderCol)
	for !done {
		var bKeys []string
		bKeys, done, err = scn.Scan(ctx)
		if err != nil {
			return nil, err
		}
		for _, bk := range bKeys {
			b, err := byKeykv[*builderStruct](ctx, builderCol, bk, c)
			if err != nil {
				return nil, err
			}
			builders = append(builders, c.convBuilder(b))
		}
	}
	return builders, nil
}

func (c *demoClient) convBuilder(b *builderStruct) *model.Builder {
	return &model.Builder{
		ID:  b.ThisID,
		URI: b.URI,
	}
}

func (c *demoClient) exactBuilder(ctx context.Context, filter *model.BuilderSpec) (*builderStruct, error) {
	if filter == nil {
		return nil, nil
	}
	if filter.ID != nil {
		b, err := byIDkv[*builderStruct](ctx, *filter.ID, c)
		if err == nil {
			return b, nil
		}
		if !errors.Is(err, kv.NotFoundError) && !errors.Is(err, errTypeNotMatch) {
			return nil, err
		}
		// id not found
		return nil, nil
	}
	if filter.URI != nil {
		in := &builderStruct{
			URI: *filter.URI,
		}
		out, err := byKeykv[*builderStruct](ctx, builderCol, in.Key(), c)
		if err == nil {
			return out, nil
		}
		if !errors.Is(err, kv.NotFoundError) {
			return nil, err
		}
	}
	return nil, nil
}
