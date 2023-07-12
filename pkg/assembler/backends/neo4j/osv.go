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
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

func (c *neo4jClient) Osv(ctx context.Context, osvSpec *model.OSVSpec) ([]*model.Osv, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	var sb strings.Builder
	var firstMatch bool = true
	queryValues := map[string]any{}

	sb.WriteString("MATCH (root:Osv)-[:OsvHasID]->(osvID:OsvID)")

	setOSVMatchValues(&sb, osvSpec, &firstMatch, queryValues)

	sb.WriteString(" RETURN osvID.id")

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			// FIXME update to OSV without root node.
			// result, err := tx.Run(sb.String(), queryValues)
			// if err != nil {
			// 	return nil, err
			// }

			// osvIds := []*model.OSVId{}
			// for result.Next() {
			// 	osvId := &model.OSVId{
			// 		OsvID: result.Record().Values[0].(string),
			// 	}
			// 	osvIds = append(osvIds, osvId)
			// }
			// if err = result.Err(); err != nil {
			// 	return nil, err
			// }

			osv := &model.Osv{
				// OsvIds: osvIds,
			}

			return []*model.Osv{osv}, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Osv), nil
}

func setOSVMatchValues(sb *strings.Builder, osv *model.OSVSpec, firstMatch *bool, queryValues map[string]any) {
	if osv != nil {
		if osv.OsvID != nil {
			matchProperties(sb, *firstMatch, "osvID", "id", "$osvID")
			queryValues["osvID"] = strings.ToLower(*osv.OsvID)
			*firstMatch = false
		}
	}
}

func (c *neo4jClient) IngestOSVs(ctx context.Context, osvs []*model.OSVInputSpec) ([]*model.Osv, error) {
	return []*model.Osv{}, fmt.Errorf("not implemented: IngestOSVs")
}

func (c *neo4jClient) IngestOsv(ctx context.Context, osv *model.OSVInputSpec) (*model.Osv, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close()

	values := map[string]any{}
	values["id"] = strings.ToLower(osv.OsvID)

	result, err := session.WriteTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			query := `MERGE (root:Osv)
MERGE (root) -[:OsvHasID]-> (osvID:OsvID{id:$id})
RETURN osvID.id`
			result, err := tx.Run(query, values)
			if err != nil {
				return nil, err
			}

			// query returns a single record
			record, err := result.Single()
			if err != nil {
				return nil, err
			}

			osvID := record.Values[0].(string)
			osv := generateModelOsv(osvID)

			return osv, nil
		})
	if err != nil {
		return nil, err
	}

	return result.(*model.Osv), nil
}

// TODO: update to pass in the ID from neo4j
func generateModelOsv(id string) *model.Osv {
	// FIXME update to GHSA without root node.
	// osvID := &model.OSVId{OsvID: id}
	osv := model.Osv{
		// OsvIds: []*model.OSVId{osvID},
	}
	return &osv
}
