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

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

// ghsaNode represents the top level GHSA->GHSAID
type ghsaNode struct {
}

func (gn *ghsaNode) Type() string {
	return "Ghsa"
}

func (gn *ghsaNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["ghsa"] = "ghsa"
	return properties
}

func (gn *ghsaNode) PropertyNames() []string {
	fields := []string{"ghsa"}
	return fields
}

func (gn *ghsaNode) IdentifiablePropertyNames() []string {
	return []string{"ghsa"}
}

type ghsaID struct {
	id string
}

func (gi *ghsaID) Type() string {
	return "GhsaID"
}

func (gi *ghsaID) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["id"] = gi.id
	return properties
}

func (gi *ghsaID) PropertyNames() []string {
	fields := []string{"id"}
	return fields
}

func (gi *ghsaID) IdentifiablePropertyNames() []string {
	return []string{"id"}
}

type ghsaToID struct {
	ghsa *ghsaNode
	id   *ghsaID
}

func (e *ghsaToID) Type() string {
	return "GhsaHasID"
}

func (e *ghsaToID) Nodes() (v, u assembler.GuacNode) {
	return e.ghsa, e.id
}

func (e *ghsaToID) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e *ghsaToID) PropertyNames() []string {
	return []string{}
}

func (e *ghsaToID) IdentifiablePropertyNames() []string {
	return []string{}
}

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
			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			ghsaIds := []*model.GHSAId{}
			for result.Next() {
				ghsaId := &model.GHSAId{
					ID: result.Record().Values[0].(string),
				}
				ghsaIds = append(ghsaIds, ghsaId)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			ghsa := &model.Ghsa{
				GhsaID: ghsaIds,
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

			id := record.Values[0].(string)
			ghsa := generateModelGhsa(id)

			return ghsa, nil
		})
	if err != nil {
		return nil, err
	}

	return result.(*model.Ghsa), nil
}

func generateModelGhsa(id string) *model.Ghsa {
	ghsaID := &model.GHSAId{ID: id}
	ghsa := model.Ghsa{
		GhsaID: []*model.GHSAId{ghsaID},
	}
	return &ghsa
}

// TODO: maybe use generics for GHSAInputSpec and GHSASpec?
func convertGhsaInputSpecToGhsaSpec(ghsaInput *model.GHSAInputSpec) *model.GHSASpec {
	ghsaID := strings.ToLower(ghsaInput.GhsaID)
	ghsaSpec := model.GHSASpec{
		GhsaID: &ghsaID,
	}
	return &ghsaSpec
}
