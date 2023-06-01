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

package arangodb

import (
	"context"
	"fmt"
	"strings"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func registerAllArtifacts(ctx context.Context, client *arangoClient) {
	// strings.ToLower(string(checksum.Algorithm)) + ":" + checksum.Value
	client.IngestArtifact(ctx, &model.ArtifactInputSpec{Algorithm: "sha256", Digest: "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"})
	client.IngestArtifact(ctx, &model.ArtifactInputSpec{Algorithm: "sha1", Digest: "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9"})
	client.IngestArtifact(ctx, &model.ArtifactInputSpec{Algorithm: "sha512", Digest: "374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7"})
}

func (c *arangoClient) Artifacts(ctx context.Context, artifactSpec *model.ArtifactSpec) ([]*model.Artifact, error) {
	panic(fmt.Errorf("not implemented: IngestHashEqual - IngestHashEqual"))

	// 	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	// 	defer session.Close()

	// 	var sb strings.Builder
	// 	var firstMatch bool = true
	// 	queryValues := map[string]any{}

	// 	sb.WriteString("MATCH (a:Artifact)")

	// 	setArtifactMatchValues(&sb, artifactSpec, false, &firstMatch, queryValues)

	// 	sb.WriteString(" RETURN a.algorithm, a.digest")

	// 	result, err := session.ReadTransaction(
	// 		func(tx neo4j.Transaction) (interface{}, error) {
	// 			result, err := tx.Run(sb.String(), queryValues)
	// 			if err != nil {
	// 				return nil, err
	// 			}

	// 			artifacts := []*model.Artifact{}
	// 			for result.Next() {
	// 				algorithm := result.Record().Values[0].(string)
	// 				digest := result.Record().Values[1].(string)
	// 				artifact := generateModelArtifact(algorithm, digest)
	// 				artifacts = append(artifacts, artifact)
	// 			}
	// 			if err = result.Err(); err != nil {
	// 				return nil, err
	// 			}

	// 			return artifacts, nil
	// 		})
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// return result.([]*model.Artifact), nil
}

func (c *arangoClient) IngestArtifact(ctx context.Context, artifact *model.ArtifactInputSpec) (*model.Artifact, error) {
	artifactCollection, err := c.graph.VertexCollection(ctx, "artifacts")
	if err != nil {
		return nil, fmt.Errorf("failed to get vertex collection: %w", err)
	}

	values := map[string]any{}
	values["algorithm"] = strings.ToLower(artifact.Algorithm)
	values["digest"] = strings.ToLower(artifact.Digest)

	query := `
UPSERT { algorithm:@algorithm, digest:@digest } 
INSERT { algorithm:@algorithm, digest:@digest } 
UPDATE {} IN artifacts`

	cursor, err := artifactCollection.Database().Query(ctx, query, values)
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w", err)
	}
	defer cursor.Close()

	for {
		var doc *model.Artifact
		_, err := cursor.ReadDocument(ctx, &doc)
		if driver.IsNoMoreDocuments(err) {
			return doc, nil
		} else if err != nil {
			return nil, fmt.Errorf("failed to ingest artifact: %w", err)
		}
	}
}

// func setArtifactMatchValues(sb *strings.Builder, art *model.ArtifactSpec, objectArt bool, firstMatch *bool, queryValues map[string]any) {
// 	if art != nil {
// 		if art.Algorithm != nil {
// 			if !objectArt {
// 				matchProperties(sb, *firstMatch, "a", "algorithm", "$algorithm")
// 				queryValues["algorithm"] = strings.ToLower(*art.Algorithm)
// 			} else {
// 				matchProperties(sb, *firstMatch, "objArt", "algorithm", "$objAlgorithm")
// 				queryValues["objAlgorithm"] = strings.ToLower(*art.Algorithm)
// 			}
// 			*firstMatch = false
// 		}

// 		if art.Digest != nil {
// 			if !objectArt {
// 				matchProperties(sb, *firstMatch, "a", "digest", "$digest")
// 				queryValues["digest"] = strings.ToLower(*art.Digest)
// 			} else {
// 				matchProperties(sb, *firstMatch, "objArt", "digest", "$objDigest")
// 				queryValues["objDigest"] = strings.ToLower(*art.Digest)
// 			}
// 			*firstMatch = false
// 		}
// 	}
// }

// func generateModelArtifact(algorithm, digest string) *model.Artifact {
// 	artifact := model.Artifact{
// 		Algorithm: algorithm,
// 		Digest:    digest,
// 	}
// 	return &artifact
// }
