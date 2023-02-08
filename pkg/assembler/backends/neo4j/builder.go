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

package neo4jBackend

import (
	"context"
	"fmt"
	"strings"

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

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {

			var sb strings.Builder
			queryValues := map[string]any{}

			sb.WriteString("MATCH (n:Builder)")

			if builderSpec.URI != nil {
				err := matchWhere(&sb, "n", "uri", "$builderUri")
				if err != nil {
					return nil, fmt.Errorf("string builder failed with err: %w", err)
				}
				queryValues["builderUri"] = builderSpec.URI
			}

			sb.WriteString(" RETURN n.uri")
			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			builders := []*model.Builder{}
			for result.Next() {
				builder := &model.Builder{
					URI: result.Record().Values[0].(string),
				}
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
