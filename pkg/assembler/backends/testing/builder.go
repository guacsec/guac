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

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func registerAllBuilders(client *demoClient) {
	client.registerBuilder("https://github.com/Attestations/GitHubHostedActions@v1")
	client.registerBuilder("https://tekton.dev/chains/v2")
}

// Ingest Builder

func (c *demoClient) registerBuilder(uri string) *model.Builder {
	for _, b := range c.builders {
		if b.URI == uri {
			return b
		}
	}
	newBuilder := &model.Builder{URI: uri}
	c.builders = append(c.builders, newBuilder)
	return newBuilder
}

// Query Builder

func (c *demoClient) Builders(ctx context.Context, builderSpec *model.BuilderSpec) ([]*model.Builder, error) {
	var builders []*model.Builder
	for _, b := range c.builders {
		if builderSpec.URI == nil || b.URI == *builderSpec.URI {
			builders = append(builders, b)
		}
	}
	return builders, nil
}

func (c *demoClient) IngestBuilder(ctx context.Context, builder *model.BuilderInputSpec) (*model.Builder, error) {
	return c.registerBuilder(builder.URI), nil
}
