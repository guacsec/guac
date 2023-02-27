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

	var sb strings.Builder
	var firstMatch bool = true
	queryValues := map[string]any{}

	sb.WriteString("MATCH (a:Artifact)")

	setArtifactMatchValues(&sb, artifactSpec, false, &firstMatch, queryValues)

	sb.WriteString(" RETURN a.algorithm, a.digest")

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
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

func (c *neo4jClient) IngestArtifact(ctx context.Context, artifact *model.ArtifactInputSpec) (*model.Artifact, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close()

	values := map[string]any{}
	values["algorithm"] = strings.ToLower(artifact.Algorithm)
	values["digest"] = strings.ToLower(artifact.Digest)

	result, err := session.WriteTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			query := `
MERGE (a:Artifact{algorithm:$algorithm,digest:$digest})
RETURN a.algorithm, a.digest`
			result, err := tx.Run(query, values)
			if err != nil {
				return nil, err
			}

			// query returns a single record
			record, err := result.Single()
			if err != nil {
				return nil, err
			}

			digest := record.Values[1].(string)
			algorithm := record.Values[0].(string)
			artifact := model.Artifact{
				Algorithm: algorithm,
				Digest:    digest,
			}

			return &artifact, nil
		})
	if err != nil {
		return nil, err
	}

	return result.(*model.Artifact), nil
}

func setArtifactMatchValues(sb *strings.Builder, art *model.ArtifactSpec, objectArt bool, firstMatch *bool, queryValues map[string]any) {
	if art != nil {
		if art.Algorithm != nil {
			if !objectArt {
				matchProperties(sb, *firstMatch, "a", "algorithm", "$algorithm")
				queryValues["algorithm"] = strings.ToLower(*art.Algorithm)
			} else {
				matchProperties(sb, *firstMatch, "objArt", "algorithm", "$objAlgorithm")
				queryValues["objAlgorithm"] = strings.ToLower(*art.Algorithm)
			}
			*firstMatch = false
		}

		if art.Digest != nil {
			if !objectArt {
				matchProperties(sb, *firstMatch, "a", "digest", "$digest")
				queryValues["digest"] = strings.ToLower(*art.Digest)
			} else {
				matchProperties(sb, *firstMatch, "objArt", "digest", "$objDigest")
				queryValues["objDigest"] = strings.ToLower(*art.Digest)
			}
			*firstMatch = false
		}
	}
}
