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
	"sort"
	"strings"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (c *arangoClient) HashEqual(ctx context.Context, hashEqualSpec *model.HashEqualSpec) ([]*model.HashEqual, error) {
	values := map[string]any{}
	if hashEqualSpec.Artifacts != nil {
		if len(hashEqualSpec.Artifacts) == 1 {
			return matchHashEqualByInput(ctx, c, hashEqualSpec, hashEqualSpec.Artifacts[0], nil, values)
		} else {
			return matchHashEqualByInput(ctx, c, hashEqualSpec, hashEqualSpec.Artifacts[0], hashEqualSpec.Artifacts[1], values)
		}
	} else {
		arangoQueryBuilder := newForQuery(hashEqualsStr, "hashEqual")
		setHashEqualMatchValues(arangoQueryBuilder, hashEqualSpec, values)
		arangoQueryBuilder.forInBound(hashEqualSubjectArtEdgesStr, "art", "hashEqual")
		arangoQueryBuilder.forOutBound(hashEqualArtEdgesStr, "equalArt", "hashEqual")

		return getHashEqualForQuery(ctx, c, arangoQueryBuilder, values)
	}
}

func matchHashEqualByInput(ctx context.Context, c *arangoClient, hashEqualSpec *model.HashEqualSpec, firstArtifact *model.ArtifactSpec,
	secondArtifact *model.ArtifactSpec, values map[string]any) ([]*model.HashEqual, error) {

	var combinedHashEqual []*model.HashEqual

	arangoQueryBuilder := setArtifactMatchValues(firstArtifact, values)
	arangoQueryBuilder.forOutBound(hashEqualSubjectArtEdgesStr, "hashEqual", "art")
	setHashEqualMatchValues(arangoQueryBuilder, hashEqualSpec, values)
	arangoQueryBuilder.forOutBound(hashEqualArtEdgesStr, "equalArt", "hashEqual")
	if secondArtifact != nil {
		if secondArtifact.ID != nil {
			arangoQueryBuilder.filter("equalArt", "_id", "==", "@equal_id")
			values["equal_id"] = *secondArtifact.ID
		}
		if secondArtifact.Algorithm != nil {
			arangoQueryBuilder.filter("equalArt", "algorithm", "==", "@equal_algorithm")
			values["equal_algorithm"] = strings.ToLower(*secondArtifact.Algorithm)
		}
		if secondArtifact.Digest != nil {
			arangoQueryBuilder.filter("equalArt", "digest", "==", "@equal_digest")
			values["equal_digest"] = strings.ToLower(*secondArtifact.Digest)
		}
	}

	artSubjectHashEqual, err := getHashEqualForQuery(ctx, c, arangoQueryBuilder, values)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve artifact hashEqual with error: %w", err)
	}
	combinedHashEqual = append(combinedHashEqual, artSubjectHashEqual...)

	arangoQueryBuilder = setArtifactMatchValues(firstArtifact, values)
	arangoQueryBuilder.forInBound(hashEqualArtEdgesStr, "hashEqual", "art")
	setHashEqualMatchValues(arangoQueryBuilder, hashEqualSpec, values)
	arangoQueryBuilder.forInBound(hashEqualSubjectArtEdgesStr, "equalArt", "hashEqual")
	if secondArtifact != nil {
		if secondArtifact.ID != nil {
			arangoQueryBuilder.filter("equalArt", "_id", "==", "@equal_id")
			values["equal_id"] = *secondArtifact.ID
		}
		if secondArtifact.Algorithm != nil {
			arangoQueryBuilder.filter("equalArt", "algorithm", "==", "@equal_algorithm")
			values["equal_algorithm"] = strings.ToLower(*secondArtifact.Algorithm)
		}
		if secondArtifact.Digest != nil {
			arangoQueryBuilder.filter("equalArt", "digest", "==", "@equal_digest")
			values["equal_digest"] = strings.ToLower(*secondArtifact.Digest)
		}
	}

	artEqualHashEqual, err := getHashEqualForQuery(ctx, c, arangoQueryBuilder, values)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve artifact hashEqual with error: %w", err)
	}
	combinedHashEqual = append(combinedHashEqual, artEqualHashEqual...)

	return combinedHashEqual, nil
}

func getHashEqualForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.HashEqual, error) {
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
				'artifact': {
					'id': art._id,
					'algorithm': art.algorithm,
					'digest': art.digest
				},
				'equalArtifact': {
					'id': equalArt._id,
					'algorithm': equalArt.algorithm,
					'digest': equalArt.digest
				},
				'hashEqual_id': hashEqual._id,
				'justification': hashEqual.justification,
				'collector': hashEqual.collector,
				'origin': hashEqual.origin
			}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "HashEqual")
	if err != nil {
		return nil, fmt.Errorf("failed to query for HashEqual: %w", err)
	}
	defer cursor.Close()

	return getHashEqualFromCursor(ctx, cursor)
}

func setHashEqualMatchValues(arangoQueryBuilder *arangoQueryBuilder, hashEqualSpec *model.HashEqualSpec, queryValues map[string]any) {
	if hashEqualSpec.ID != nil {
		arangoQueryBuilder.filter("hashEqual", "_id", "==", "@id")
		queryValues["id"] = *hashEqualSpec.ID
	}
	if hashEqualSpec.Justification != nil {
		arangoQueryBuilder.filter("hashEqual", justification, "==", "@"+justification)
		queryValues[justification] = *hashEqualSpec.Justification
	}
	if hashEqualSpec.Origin != nil {
		arangoQueryBuilder.filter("hashEqual", origin, "==", "@"+origin)
		queryValues[origin] = *hashEqualSpec.Origin
	}
	if hashEqualSpec.Collector != nil {
		arangoQueryBuilder.filter("hashEqual", collector, "==", "@"+collector)
		queryValues[collector] = *hashEqualSpec.Collector
	}
}

func getHashEqualQueryValues(artifact *model.ArtifactInputSpec, equalArtifact *model.ArtifactInputSpec, hashEqual *model.HashEqualInputSpec) map[string]any {

	artifacts := []model.ArtifactInputSpec{*artifact, *equalArtifact}
	sort.SliceStable(artifacts, func(i, j int) bool {
		return artifacts[i].Digest < artifacts[j].Digest
	})

	values := map[string]any{}
	values["art_algorithm"] = strings.ToLower(artifacts[0].Algorithm)
	values["art_digest"] = strings.ToLower(artifacts[0].Digest)
	values["equal_algorithm"] = strings.ToLower(artifacts[1].Algorithm)
	values["equal_digest"] = strings.ToLower(artifacts[1].Digest)
	values["justification"] = strings.ToLower(hashEqual.Justification)
	values["collector"] = strings.ToLower(hashEqual.Collector)
	values["origin"] = strings.ToLower(hashEqual.Origin)

	return values
}

func (c *arangoClient) IngestHashEquals(ctx context.Context, artifacts []*model.ArtifactInputSpec, otherArtifacts []*model.ArtifactInputSpec, hashEquals []*model.HashEqualInputSpec) ([]*model.HashEqual, error) {
	var listOfValues []map[string]any

	for i := range artifacts {
		listOfValues = append(listOfValues, getHashEqualQueryValues(artifacts[i], otherArtifacts[i], hashEquals[i]))
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
	LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == doc.art_algorithm FILTER art.digest == doc.art_digest RETURN art)
	LET equalArtifact = FIRST(FOR art IN artifacts FILTER art.algorithm == doc.equal_algorithm FILTER art.digest == doc.equal_digest RETURN art)
	LET hashEqual = FIRST(
		UPSERT { artifactID:artifact._id, equalArtifactID:equalArtifact._id, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
			INSERT { artifactID:artifact._id, equalArtifactID:equalArtifact._id, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
			UPDATE {} IN hashEquals
			RETURN NEW
	)
	
	INSERT { _key: CONCAT("hashEqualSubjectArtEdges", artifact._key, hashEqual._key), _from: artifact._id, _to: hashEqual._id} INTO hashEqualSubjectArtEdges OPTIONS { overwriteMode: "ignore" }
	INSERT { _key: CONCAT("hashEqualArtEdges", hashEqual._key, equalArtifact._key), _from: hashEqual._id, _to: equalArtifact._id} INTO hashEqualArtEdges OPTIONS { overwriteMode: "ignore" }
	
	RETURN {
		'artifact': {
			'id': artifact._id,
			'algorithm': artifact.algorithm,
			'digest': artifact.digest
		},
		'equalArtifact': {
			'id': equalArtifact._id,
			'algorithm': equalArtifact.algorithm,
			'digest': equalArtifact.digest
		},
		'hashEqual_id': hashEqual._id,
		'justification': hashEqual.justification,
		'collector': hashEqual.collector,
		'origin': hashEqual.origin
	}`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestHashEquals")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest hashEquals: %w", err)
	}
	defer cursor.Close()

	return getHashEqualFromCursor(ctx, cursor)
}

func (c *arangoClient) IngestHashEqual(ctx context.Context, artifact model.ArtifactInputSpec, equalArtifact model.ArtifactInputSpec, hashEqual model.HashEqualInputSpec) (*model.HashEqual, error) {
	query := `
LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == @art_algorithm FILTER art.digest == @art_digest RETURN art)
LET equalArtifact = FIRST(FOR art IN artifacts FILTER art.algorithm == @equal_algorithm FILTER art.digest == @equal_digest RETURN art)
LET hashEqual = FIRST(
	UPSERT { artifactID:artifact._id, equalArtifactID:equalArtifact._id, justification:@justification, collector:@collector, origin:@origin } 
		INSERT { artifactID:artifact._id, equalArtifactID:equalArtifact._id, justification:@justification, collector:@collector, origin:@origin } 
		UPDATE {} IN hashEquals
		RETURN NEW
)

INSERT { _key: CONCAT("hashEqualSubjectArtEdges", artifact._key, hashEqual._key), _from: artifact._id, _to: hashEqual._id} INTO hashEqualSubjectArtEdges OPTIONS { overwriteMode: "ignore" }
INSERT { _key: CONCAT("hashEqualArtEdges", hashEqual._key, equalArtifact._key), _from: hashEqual._id, _to: equalArtifact._id} INTO hashEqualArtEdges OPTIONS { overwriteMode: "ignore" }

RETURN {
	'artifact': {
		'id': artifact._id,
		'algorithm': artifact.algorithm,
		'digest': artifact.digest
	},
	'equalArtifact': {
		'id': equalArtifact._id,
		'algorithm': equalArtifact.algorithm,
		'digest': equalArtifact.digest
	},
	'hashEqual_id': hashEqual._id,
	'justification': hashEqual.justification,
    'collector': hashEqual.collector,
    'origin': hashEqual.origin
}`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getHashEqualQueryValues(&artifact, &equalArtifact, &hashEqual), "IngestHashEqual")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest hashEqual: %w", err)
	}
	defer cursor.Close()

	hashEqualList, err := getHashEqualFromCursor(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get hashEqual from arango cursor: %w", err)
	}

	if len(hashEqualList) == 1 {
		return hashEqualList[0], nil
	} else {
		return nil, fmt.Errorf("number of hashEqual ingested is greater than one")
	}
}

func getHashEqualFromCursor(ctx context.Context, cursor driver.Cursor) ([]*model.HashEqual, error) {
	type collectedData struct {
		Artifact      *model.Artifact `json:"artifact"`
		EqualArtifact *model.Artifact `json:"equalArtifact"`
		HashEqualId   string          `json:"hashEqual_id"`
		Justification string          `json:"justification"`
		Collector     string          `json:"collector"`
		Origin        string          `json:"origin"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to hashEqual from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var hashEqualList []*model.HashEqual
	for _, createdValue := range createdValues {
		hashEqual := &model.HashEqual{
			ID:            createdValue.HashEqualId,
			Artifacts:     []*model.Artifact{createdValue.Artifact, createdValue.EqualArtifact},
			Justification: createdValue.Justification,
			Origin:        createdValue.Collector,
			Collector:     createdValue.Origin,
		}
		hashEqualList = append(hashEqualList, hashEqual)
	}
	return hashEqualList, nil
}
