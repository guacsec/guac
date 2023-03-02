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

// osvNode presentes the top level OSV->OSVID
type osvNode struct {
}

func (ov *osvNode) Type() string {
	return "Osv"
}

func (ov *osvNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["osv"] = "osv"
	return properties
}

func (ov *osvNode) PropertyNames() []string {
	fields := []string{"osv"}
	return fields
}

func (ov *osvNode) IdentifiablePropertyNames() []string {
	return []string{"osv"}
}

type osvID struct {
	id string
}

func (oi *osvID) Type() string {
	return "OsvID"
}

func (oi *osvID) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["id"] = oi.id
	return properties
}

func (oi *osvID) PropertyNames() []string {
	fields := []string{"id"}
	return fields
}

func (oi *osvID) IdentifiablePropertyNames() []string {
	return []string{"id"}
}

type osvToID struct {
	osv *osvNode
	id  *osvID
}

func (e *osvToID) Type() string {
	return "OsvHasID"
}

func (e *osvToID) Nodes() (v, u assembler.GuacNode) {
	return e.osv, e.id
}

func (e *osvToID) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e *osvToID) PropertyNames() []string {
	return []string{}
}

func (e *osvToID) IdentifiablePropertyNames() []string {
	return []string{}
}

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

func setOSVMatchValues(sb *strings.Builder, osv *model.OSVSpec, firstMatch *bool, queryValues map[string]any) {
	if osv != nil {
		if osv.OsvID != nil {
			matchProperties(sb, *firstMatch, "osvID", "id", "$osvID")
			queryValues["osvID"] = strings.ToLower(*osv.OsvID)
			*firstMatch = false
		}
	}
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

			id := record.Values[0].(string)
			osv := generateModelOsv(id)

			return &osv, nil
		})
	if err != nil {
		return nil, err
	}

	return result.(*model.Osv), nil
}

func generateModelOsv(id string) model.Osv {
	osvID := &model.OSVId{ID: id}
	osv := model.Osv{
		OsvID: []*model.OSVId{osvID},
	}
	return osv
}
