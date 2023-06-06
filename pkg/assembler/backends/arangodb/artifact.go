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

	values := map[string]any{}
	arangoQueryBuilder := newForQuery("artifacts", "art")
	if artifactSpec.Algorithm != nil {
		arangoQueryBuilder.filter("algorithm", "==", "@algorithm")
		values["algorithm"] = strings.ToLower(*artifactSpec.Algorithm)
	}
	if artifactSpec.Digest != nil {
		arangoQueryBuilder.filter("digest", "==", "@digest")
		values["digest"] = strings.ToLower(*artifactSpec.Digest)
	}
	arangoQueryBuilder.returnStatement()

	fmt.Println(arangoQueryBuilder.string())
	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values)
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w", err)
	}
	defer cursor.Close()

	var collectedArtifacts []*model.Artifact
	for {
		var doc *model.Artifact
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to ingest artifact: %w", err)
			}
		} else {
			collectedArtifacts = append(collectedArtifacts, doc)
		}
	}

	return collectedArtifacts, nil
}

func (c *arangoClient) IngestArtifact(ctx context.Context, artifact *model.ArtifactInputSpec) (*model.Artifact, error) {
	values := map[string]any{}
	values["algorithm"] = strings.ToLower(artifact.Algorithm)
	values["digest"] = strings.ToLower(artifact.Digest)

	query := `
UPSERT { algorithm:@algorithm, digest:@digest } 
INSERT { algorithm:@algorithm, digest:@digest } 
UPDATE {} IN artifacts
RETURN NEW`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, values)
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w", err)
	}
	defer cursor.Close()

	var createdArtifacts []*model.Artifact
	for {
		var doc *model.Artifact
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to ingest artifact: %w", err)
			}
		} else {
			createdArtifacts = append(createdArtifacts, doc)
		}
	}
	if len(createdArtifacts) == 1 {
		return createdArtifacts[0], nil
	} else {
		return nil, fmt.Errorf("number of artifacts ingested is too great")
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

func generateModelArtifact(algorithm, digest string) *model.Artifact {
	artifact := model.Artifact{
		Algorithm: algorithm,
		Digest:    digest,
	}
	return &artifact
}
