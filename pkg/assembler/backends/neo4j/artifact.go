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

// ArtifactNode is a node that represents an artifact
type artifactNode struct {
	algorithm string
	digest    string
}

func (an *artifactNode) Type() string {
	return "Artifact"
}

func (an *artifactNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["algorithm"] = an.algorithm
	properties["digest"] = strings.ToLower(an.digest)
	return properties
}

func (an *artifactNode) PropertyNames() []string {
	fields := []string{"algorithm", "digest"}
	return fields
}

func (an *artifactNode) IdentifiablePropertyNames() []string {
	// An artifact can be uniquely identified by algorithm and digest
	return []string{"algorithm", "digest"}
}

func (c *neo4jClient) Artifacts(ctx context.Context, artifactSpec *model.ArtifactSpec) ([]*model.Artifact, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {

			var sb strings.Builder
			var firstMatch bool = true
			queryValues := map[string]any{}

			sb.WriteString("MATCH (n:Artifact)")
			if artifactSpec.Algorithm != nil {

				err := matchWhere(&sb, "n", "algorithm", "$artifactAlgo")
				if err != nil {
					return nil, fmt.Errorf("string builder failed with err: %w", err)
				}
				firstMatch = false

				queryValues["artifactAlgo"] = artifactSpec.Algorithm
			}
			if artifactSpec.Digest != nil {

				if firstMatch {
					err := matchWhere(&sb, "n", "digest", "$artifactDigest")
					if err != nil {
						return nil, fmt.Errorf("string builder failed with err: %w", err)
					}
				} else {
					err := matchAnd(&sb, "n", "digest", "$artifactDigest")
					if err != nil {
						return nil, fmt.Errorf("string builder failed with err: %w", err)
					}
				}
				queryValues["artifactDigest"] = artifactSpec.Digest
			}

			sb.WriteString(" RETURN n.algorithm, n.digest")
			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			artifacts := []*model.Artifact{}
			for result.Next() {
				artifact := &model.Artifact{
					Algorithm: result.Record().Values[0].(string),
					Digest:    result.Record().Values[1].(string),
				}
				artifacts = append(artifacts, artifact)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			return artifacts, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Artifact), nil
}
