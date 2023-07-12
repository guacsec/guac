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
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

// builderNode represents the builder
type builderNode struct {
	uri string
}

func (bn builderNode) Type() string {
	return "Builder"
}

func (bn builderNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["uri"] = bn.uri
	return properties
}

func (bn builderNode) PropertyNames() []string {
	fields := []string{"uri"}
	return fields
}

func (bn builderNode) IdentifiablePropertyNames() []string {
	return []string{"uri"}
}

func (c *neo4jClient) Builders(ctx context.Context, builderSpec *model.BuilderSpec) ([]*model.Builder, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	var query string
	values := map[string]any{}
	if builderSpec.URI != nil {
		query = "MATCH (b:Builder) WHERE b.uri = $uri RETURN b.uri"
		values["uri"] = *builderSpec.URI
	} else {
		query = "MATCH (b:Builder) RETURN b.uri"
	}

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			result, err := tx.Run(query, values)
			if err != nil {
				return nil, err
			}

			builders := []*model.Builder{}
			for result.Next() {
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

func (c *neo4jClient) IngestBuilders(ctx context.Context, builders []*model.BuilderInputSpec) ([]*model.Builder, error) {
	return []*model.Builder{}, fmt.Errorf("not implemented: IngestBuilders")
}

func (c *neo4jClient) IngestBuilder(ctx context.Context, builder *model.BuilderInputSpec) (*model.Builder, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close()

	values := map[string]any{}
	values["uri"] = builder.URI

	result, err := session.WriteTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			query := "MERGE (b:Builder{uri:$uri}) RETURN b.uri"
			result, err := tx.Run(query, values)
			if err != nil {
				return nil, err
			}

			// query returns a single record
			record, err := result.Single()
			if err != nil {
				return nil, err
			}
			uri := record.Values[0].(string)
			builder := generateModelBuilder(uri)

			return builder, nil
		})
	if err != nil {
		return nil, err
	}

	return result.(*model.Builder), nil
}

func generateModelBuilder(uri string) *model.Builder {
	builder := model.Builder{
		URI: uri,
	}
	return &builder
}
