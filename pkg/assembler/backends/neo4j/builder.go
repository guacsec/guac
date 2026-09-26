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

package neo4j

import (
	"context"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func (c *neo4jClient) BuildersList(ctx context.Context, builderSpec model.BuilderSpec, after *string, first *int) (*model.BuilderConnection, error) {
	return nil, fmt.Errorf("not implemented: BuildersList")
}

func (c *neo4jClient) Builders(ctx context.Context, builderSpec *model.BuilderSpec) ([]*model.Builder, error) {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer closeSession(ctx, session)

	var query string
	values := map[string]any{}
	if builderSpec.URI != nil {
		query = "MATCH (b:Builder) WHERE b.uri = $uri RETURN b.uri"
		values["uri"] = *builderSpec.URI
	} else {
		query = "MATCH (b:Builder) RETURN b.uri"
	}

	result, err := session.ExecuteRead(ctx,
		func(tx neo4j.ManagedTransaction) (interface{}, error) {
			result, err := tx.Run(ctx, query, values)
			if err != nil {
				return nil, err
			}

			builders := []*model.Builder{}
			for result.Next(ctx) {
				uri := result.Record().Values[0].(string)
				builder := generateModelBuilder(uri)
				builders = append(builders, builder)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			return builders, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Builder), nil
}

func (c *neo4jClient) IngestBuilders(ctx context.Context, builders []*model.IDorBuilderInput) ([]string, error) {
	return []string{}, fmt.Errorf("not implemented: IngestBuilders")
}

func (c *neo4jClient) IngestBuilder(ctx context.Context, builder *model.IDorBuilderInput) (string, error) {
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer closeSession(ctx, session)

	values := map[string]any{}
	values["uri"] = builder.BuilderInput.URI

	result, err := session.ExecuteWrite(ctx,
		func(tx neo4j.ManagedTransaction) (interface{}, error) {
			query := "MERGE (b:Builder{uri:$uri}) RETURN b.uri"
			result, err := tx.Run(ctx, query, values)
			if err != nil {
				return nil, err
			}

			// query returns a single record
			record, err := result.Single(ctx)
			if err != nil {
				return nil, err
			}
			uri := record.Values[0].(string)
			builder := generateModelBuilder(uri)

			return builder, nil
		})
	if err != nil {
		return "", err
	}

	return result.(*model.Builder).ID, nil
}

func generateModelBuilder(uri string) *model.Builder {
	builder := model.Builder{
		URI: uri,
	}
	return &builder
}
