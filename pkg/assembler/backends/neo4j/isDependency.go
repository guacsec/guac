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
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

func (c *neo4jClient) IsDependency(ctx context.Context, isDependencySpec *model.IsDependencySpec) ([]*model.IsDependency, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {

			var sb strings.Builder
			queryValues := map[string]any{}

			sb.WriteString("MATCH (n:Osv)-[:OsvHasID]->(osvID:OsvID)")

			if osvSpec.OsvID != nil {
				matchProperties(&sb, true, "osvID", "id", "$osvID")
				queryValues["osvID"] = osvSpec.OsvID
			}

			sb.WriteString(" RETURN osvID.id")
			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			osvIds := []*model.OSVId{}
			for result.Next() {
				osvId := &model.OSVId{
					ID: result.Record().Values[0].(string),
				}
				osvIds = append(osvIds, osvId)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			osv := &model.Osv{
				OsvID: osvIds,
			}

			return []*model.Osv{osv}, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Osv), nil
}
