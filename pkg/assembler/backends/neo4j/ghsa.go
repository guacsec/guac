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
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

func (c *neo4jClient) Ghsa(ctx context.Context, ghsaSpec *model.GHSASpec) ([]*model.Ghsa, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	var sb strings.Builder
	var firstMatch bool = true
	queryValues := map[string]any{}

	sb.WriteString("MATCH (root:Ghsa)-[:GhsaHasID]->(ghsaID:GhsaID)")

	setGhsaMatchValues(&sb, ghsaSpec, &firstMatch, queryValues)

	sb.WriteString(" RETURN ghsaID.id")

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			// FIXME update to GHSA without root node.
			// result, err := tx.Run(sb.String(), queryValues)
			// if err != nil {
			// 	return nil, err
			// }

			// ghsaIds := []*model.GHSAId{}
			// for result.Next() {
			// 	ghsaId := &model.GHSAId{
			// 		GhsaID: result.Record().Values[0].(string),
			// 	}
			// 	ghsaIds = append(ghsaIds, ghsaId)
			// }
			// if err = result.Err(); err != nil {
			// 	return nil, err
			// }

			ghsa := &model.Ghsa{
				// GhsaIds: ghsaIds,
			}

			return []*model.Ghsa{ghsa}, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Ghsa), nil
}

func setGhsaMatchValues(sb *strings.Builder, ghsa *model.GHSASpec, firstMatch *bool, queryValues map[string]any) {
	if ghsa != nil {
		if ghsa.GhsaID != nil {
			matchProperties(sb, *firstMatch, "ghsaID", "id", "$ghsaID")
			queryValues["ghsaID"] = strings.ToLower(*ghsa.GhsaID)
			*firstMatch = false
		}
	}
}

func (c *neo4jClient) IngestGhsa(ctx context.Context, ghsa *model.GHSAInputSpec) (*model.Ghsa, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close()

	values := map[string]any{}
	values["id"] = strings.ToLower(ghsa.GhsaID)

	result, err := session.WriteTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			query := `MERGE (root:Ghsa)
MERGE (root) -[:GhsaHasID]-> (ghsaID:GhsaID{id:$id})
RETURN ghsaID.id`
			result, err := tx.Run(query, values)
			if err != nil {
				return nil, err
			}

			// query returns a single record
			record, err := result.Single()
			if err != nil {
				return nil, err
			}

			ghsaID := record.Values[0].(string)
			ghsa := generateModelGhsa(ghsaID)

			return ghsa, nil
		})
	if err != nil {
		return nil, err
	}

	return result.(*model.Ghsa), nil
}

// TODO: update to pass in the ID from neo4j
func generateModelGhsa(id string) *model.Ghsa {
	// FIXME update to GHSA without root node.
	// ghsaID := &model.GHSAId{GhsaID: id}
	ghsa := model.Ghsa{
		// GhsaIds: []*model.GHSAId{ghsaID},
	}
	return &ghsa
}
