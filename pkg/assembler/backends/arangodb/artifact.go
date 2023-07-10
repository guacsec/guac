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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (c *arangoClient) Artifacts(ctx context.Context, artifactSpec *model.ArtifactSpec) ([]*model.Artifact, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery("artifacts", "art")
	if artifactSpec.Algorithm != nil {
		arangoQueryBuilder.filter("algorithm", "art", "==", "@algorithm")
		values["algorithm"] = strings.ToLower(*artifactSpec.Algorithm)
	}
	if artifactSpec.Digest != nil {
		arangoQueryBuilder.filter("digest", "art", "==", "@digest")
		values["digest"] = strings.ToLower(*artifactSpec.Digest)
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"id": art._id,
		"algorithm": art.algorithm,
		"digest": art.digest
	  }`)

	fmt.Println(arangoQueryBuilder.string())
	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "Artifacts")
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
				return nil, fmt.Errorf("failed to query artifact: %w", err)
			}
		} else {
			collectedArtifacts = append(collectedArtifacts, doc)
		}
	}

	return collectedArtifacts, nil
}

func (c *arangoClient) IngestArtifacts(ctx context.Context, artifacts []*model.ArtifactInputSpec) ([]*model.Artifact, error) {

	listOfValues := []map[string]any{}

	for i := range artifacts {
		values := map[string]any{}

		values["algorithm"] = strings.ToLower(artifacts[i].Algorithm)
		values["digest"] = strings.ToLower(artifacts[i].Digest)

		listOfValues = append(listOfValues, values)
	}

	var documents []string
	for _, val := range listOfValues {
		bs, _ := json.Marshal(val)
		documents = append(documents, string(bs))
	}

	queryValues := map[string]any{}
	queryValues["documents"] = fmt.Sprint(strings.Join(documents, ","))

	var sb strings.Builder

	sb.WriteString("for doc in [")
	for i, val := range listOfValues {
		bs, _ := json.Marshal(val)
		if i == len(listOfValues)-1 {
			sb.WriteString(string(bs))
		} else {
			sb.WriteString(string(bs) + ",")
		}
	}
	sb.WriteString("]")

	query := `
UPSERT { algorithm:doc.algorithm, digest:doc.digest } 
INSERT { algorithm:doc.algorithm, digest:doc.digest } 
UPDATE {} IN artifacts OPTIONS { indexHint: "byArtAndDigest" }
RETURN NEW`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestArtifacts")
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
	return createdArtifacts, nil

}

func (c *arangoClient) IngestArtifact(ctx context.Context, artifact *model.ArtifactInputSpec) (*model.Artifact, error) {
	values := map[string]any{}
	values["algorithm"] = strings.ToLower(artifact.Algorithm)
	values["digest"] = strings.ToLower(artifact.Digest)

	query := `
UPSERT { algorithm:@algorithm, digest:@digest } 
INSERT { algorithm:@algorithm, digest:@digest } 
UPDATE {} IN artifacts OPTIONS { indexHint: "byArtAndDigest" }
RETURN NEW`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, values, "IngestArtifact")
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
		return nil, fmt.Errorf("number of artifacts ingested is greater than one")
	}
}

func generateModelArtifact(algorithm, digest string) *model.Artifact {
	artifact := model.Artifact{
		Algorithm: algorithm,
		Digest:    digest,
	}
	return &artifact
}
