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

	arangoQueryBuilder := setArtifactMatchValues(nil, artifactSpec, values)
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"id": art._id,
		"algorithm": art.algorithm,
		"digest": art.digest
	  }`)

	fmt.Println(arangoQueryBuilder.string())
	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "Artifacts")
	if err != nil {
		return nil, fmt.Errorf("failed to query for artifacts: %w", err)
	}
	defer cursor.Close()

	return getArtifacts(ctx, cursor)
}

func setArtifactMatchValues(arangoQueryBuilder *arangoQueryBuilder, artifactSpec *model.ArtifactSpec, queryValues map[string]any) *arangoQueryBuilder {
	if arangoQueryBuilder == nil {
		arangoQueryBuilder = newForQuery(artifactsStr, "art")
	}
	if artifactSpec != nil {
		if artifactSpec.ID != nil {
			arangoQueryBuilder.filter("art", "_id", "==", "@id")
			queryValues["id"] = *artifactSpec.ID
		}
		if artifactSpec.Algorithm != nil {
			arangoQueryBuilder.filter("art", "algorithm", "==", "@algorithm")
			queryValues["algorithm"] = strings.ToLower(*artifactSpec.Algorithm)
		}
		if artifactSpec.Digest != nil {
			arangoQueryBuilder.filter("art", "digest", "==", "@digest")
			queryValues["digest"] = strings.ToLower(*artifactSpec.Digest)
		}
	}
	return arangoQueryBuilder
}

// getMaterialsByID return an slice of artifacts as based on only their IDs
func (c *arangoClient) getMaterialsByID(ctx context.Context, artifactIDs []string) ([]*model.Artifact, error) {
	var listOfValues []map[string]any
	for _, id := range artifactIDs {
		values := map[string]any{}
		values["id"] = id
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
	sb.WriteString("\n")

	arangoQueryBuilder := newForQuery(artifactsStr, "art")
	arangoQueryBuilder.filter("art", "_id", "==", "doc.id")
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"id": art._id,
		"algorithm": art.algorithm,
		"digest": art.digest
	  }`)

	sb.WriteString(arangoQueryBuilder.string())

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "getMaterialsByID")
	if err != nil {
		return nil, fmt.Errorf("failed to query for Materials: %w", err)
	}
	defer cursor.Close()

	return getArtifacts(ctx, cursor)
}

// getMaterials return an slice of artifacts as they are already ingested to be used for hasSLSA
func (c *arangoClient) getMaterials(ctx context.Context, artifactSpec []*model.ArtifactInputSpec) ([]*model.Artifact, error) {
	var listOfValues []map[string]any
	for i := range artifactSpec {
		listOfValues = append(listOfValues, getArtifactQueryValues(artifactSpec[i]))
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
	sb.WriteString("\n")

	arangoQueryBuilder := newForQuery(artifactsStr, "art")
	arangoQueryBuilder.filter("art", "algorithm", "==", "doc.algorithm")
	arangoQueryBuilder.filter("art", "digest", "==", "doc.digest")
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"id": art._id,
		"algorithm": art.algorithm,
		"digest": art.digest
	  }`)

	sb.WriteString(arangoQueryBuilder.string())

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "getMaterials")
	if err != nil {
		return nil, fmt.Errorf("failed to query for Materials: %w", err)
	}
	defer cursor.Close()

	return getArtifacts(ctx, cursor)
}

func getArtifactQueryValues(artifact *model.ArtifactInputSpec) map[string]any {
	values := map[string]any{}
	values["algorithm"] = strings.ToLower(artifact.Algorithm)
	values["digest"] = strings.ToLower(artifact.Digest)
	return values
}

func (c *arangoClient) IngestArtifacts(ctx context.Context, artifacts []*model.ArtifactInputSpec) ([]*model.Artifact, error) {
	var listOfValues []map[string]any
	for i := range artifacts {
		listOfValues = append(listOfValues, getArtifactQueryValues(artifacts[i]))
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
RETURN {
	"id": NEW._id,
	"algorithm": NEW.algorithm,
	"digest": NEW.digest
  }`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestArtifacts")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest artifact: %w", err)
	}
	defer cursor.Close()

	return getArtifacts(ctx, cursor)
}

func (c *arangoClient) IngestArtifact(ctx context.Context, artifact *model.ArtifactInputSpec) (*model.Artifact, error) {
	query := `
UPSERT { algorithm:@algorithm, digest:@digest } 
INSERT { algorithm:@algorithm, digest:@digest } 
UPDATE {} IN artifacts OPTIONS { indexHint: "byArtAndDigest" }
RETURN {
	"id": NEW._id,
	"algorithm": NEW.algorithm,
	"digest": NEW.digest
  }`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getArtifactQueryValues(artifact), "IngestArtifact")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest artifact: %w", err)
	}
	defer cursor.Close()

	createdArtifacts, err := getArtifacts(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get artifacts from arango cursor: %w", err)
	}
	if len(createdArtifacts) == 1 {
		return createdArtifacts[0], nil
	} else {
		return nil, fmt.Errorf("number of artifacts ingested is greater than one")
	}
}

func getArtifacts(ctx context.Context, cursor driver.Cursor) ([]*model.Artifact, error) {
	var createdArtifacts []*model.Artifact
	for {
		var doc *model.Artifact
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to get artifact from cursor: %w", err)
			}
		} else {
			createdArtifacts = append(createdArtifacts, doc)
		}
	}
	return createdArtifacts, nil
}
