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
	"github.com/neo4j/neo4j-go-driver/v4/neo4j/dbtype"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (c *neo4jClient) HashEqual(ctx context.Context, hashEqualSpec *model.HashEqualSpec) ([]*model.HashEqual, error) {

	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	var sb strings.Builder
	var firstMatch bool = true

	var selectedArt *model.ArtifactSpec = nil
	var dependentArt *model.ArtifactSpec = nil
	if hashEqualSpec.Artifacts != nil && len(hashEqualSpec.Artifacts) != 0 {
		if len(hashEqualSpec.Artifacts) == 1 {
			selectedArt = hashEqualSpec.Artifacts[0]
		} else {
			selectedArt = hashEqualSpec.Artifacts[0]
			dependentArt = hashEqualSpec.Artifacts[1]
		}
	}
	queryValues := map[string]any{}

	returnValue := " RETURN a.algorithm, a.digest, hashEqual, objArt.algorithm, objArt.digest"

	// query with selectedArt being subject
	query := "MATCH (a:Artifact)-[:subject]-(hashEqual:HashEqual)-[:is_equal]-(objArt:Artifact)"
	sb.WriteString(query)

	setArtifactMatchValues(&sb, selectedArt, false, &firstMatch, queryValues)
	setArtifactMatchValues(&sb, dependentArt, true, &firstMatch, queryValues)
	setHashEqualValues(&sb, hashEqualSpec, &firstMatch, queryValues)

	sb.WriteString(returnValue)

	if len(hashEqualSpec.Artifacts) > 0 {
		sb.WriteString("\nUNION")

		// query with dependentArt being subject
		query = "\nMATCH (a:Artifact)-[:subject]-(hashEqual:HashEqual)-[:is_equal]-(objArt:Artifact)"
		sb.WriteString(query)

		firstMatch = true
		setArtifactMatchValues(&sb, dependentArt, false, &firstMatch, queryValues)
		setArtifactMatchValues(&sb, selectedArt, true, &firstMatch, queryValues)
		setHashEqualValues(&sb, hashEqualSpec, &firstMatch, queryValues)

		sb.WriteString(returnValue)
	}

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			collectedHashEqual := []*model.HashEqual{}

			for result.Next() {

				algorithm := result.Record().Values[0].(string)
				digest := result.Record().Values[1].(string)
				artifact := generateModelArtifact(algorithm, digest)

				algorithm = result.Record().Values[3].(string)
				digest = result.Record().Values[4].(string)
				depArtifact := generateModelArtifact(algorithm, digest)

				hashEqualNode := dbtype.Node{}
				if result.Record().Values[2] != nil {
					hashEqualNode = result.Record().Values[6].(dbtype.Node)
				} else {
					return nil, gqlerror.Errorf("hashEqual Node not found in neo4j")
				}

				hashEqual := &model.HashEqual{
					Artifacts:     []*model.Artifact{artifact, depArtifact},
					Justification: hashEqualNode.Props[justification].(string),
					Origin:        hashEqualNode.Props[origin].(string),
					Collector:     hashEqualNode.Props[collector].(string),
				}
				collectedHashEqual = append(collectedHashEqual, hashEqual)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			return collectedHashEqual, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.HashEqual), nil
}

func setHashEqualValues(sb *strings.Builder, hashEqualSpec *model.HashEqualSpec, firstMatch *bool, queryValues map[string]any) {
	if hashEqualSpec.Justification != nil {
		matchProperties(sb, *firstMatch, "hashEqual", "justification", "$justification")
		*firstMatch = false
		queryValues["justification"] = hashEqualSpec.Justification
	}
	if hashEqualSpec.Origin != nil {
		matchProperties(sb, *firstMatch, "hashEqual", "origin", "$origin")
		*firstMatch = false
		queryValues["origin"] = hashEqualSpec.Origin
	}
	if hashEqualSpec.Collector != nil {
		matchProperties(sb, *firstMatch, "hashEqual", "collector", "$collector")
		*firstMatch = false
		queryValues["collector"] = hashEqualSpec.Collector
	}
}

func (c *neo4jClient) IngestHashEqual(ctx context.Context, artifact model.ArtifactInputSpec, equalArtifact model.ArtifactInputSpec, hashEqual model.HashEqualInputSpec) (string, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))
}

func (c *neo4jClient) IngestHashEquals(ctx context.Context, artifacts []*model.ArtifactInputSpec, otherArtifacts []*model.ArtifactInputSpec, hashEquals []*model.HashEqualInputSpec) ([]string, error) {
	return []string{}, fmt.Errorf("not implemented: IngestHashEquals")
}
