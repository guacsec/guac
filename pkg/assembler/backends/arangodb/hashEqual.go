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

func (c *arangoClient) HashEqual(ctx context.Context, hashEqualSpec *model.HashEqualSpec) ([]*model.HashEqual, error) {
	if hashEqualSpec.Artifacts != nil && len(hashEqualSpec.Artifacts) > 2 {
		return nil, fmt.Errorf("cannot specify more than 2 artifacts in HashEquals")
	}

	// 	query := `
	// LET a = (
	// 	FOR art IN artifacts
	// 	  FILTER art.algorithm == "sha256" && art.digest == "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"
	// 	  FOR hashEqual IN OUTBOUND art hashEqualsEdges
	// 		FOR objArt IN OUTBOUND hashEqual hashEqualsEdges
	// 		FILTER objArt.algorithm == "sha512" && objArt.digest == "374ab8f711235830769aa5f0b31ce9b72c5670074b34cb302cdafe3b606233ee92ee01e298e5701f15cc7087714cd9abd7ddb838a6e1206b3642de16d9fc9dd7"
	// 		RETURN {
	// 			"algorithmA" : art.algorithm,
	// 			"digestA" : art.digest,
	// 			"hashEqual" : hashEqual,
	// 			"algorithmB" : objArt.algorithm,
	// 			"digestB" : objArt.digest
	// 		  }
	//   )

	//   LET b = (
	// 	FOR objArt IN artifacts
	// 	  FILTER objArt.algorithm == "sha256" && objArt.digest == "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"
	// 	  FOR hashEqual IN INBOUND objArt hashEqualsEdges
	// 		FOR art IN INBOUND hashEqual hashEqualsEdges
	// 		FILTER art.algorithm == "sha512" && art.digest == "374ab8f711235830769aa5f0b31ce9b72c5670074b34cb302cdafe3b606233ee92ee01e298e5701f15cc7087714cd9abd7ddb838a6e1206b3642de16d9fc9dd7"
	// 		  RETURN {
	// 			"algorithmA" : objArt.algorithm,
	// 			"digestA" : objArt.digest,
	// 			"hashEqual" : hashEqual,
	// 			"algorithmB" : art.algorithm,
	// 			"digestB" : art.digest
	// 		  }
	//   )

	//   RETURN APPEND(a, b)`

	return []*model.HashEqual{}, fmt.Errorf("not implemented: HashEqual")
}

func getHashEqualQueryValues(artifact model.ArtifactInputSpec, equalArtifact model.ArtifactInputSpec, hashEqual model.HashEqualInputSpec) map[string]any {
	values := map[string]any{}
	values["art_algorithm"] = strings.ToLower(artifact.Algorithm)
	values["art_digest"] = strings.ToLower(artifact.Digest)
	values["equal_algorithm"] = strings.ToLower(equalArtifact.Algorithm)
	values["equal_digest"] = strings.ToLower(equalArtifact.Digest)
	values["justification"] = strings.ToLower(hashEqual.Justification)
	values["collector"] = strings.ToLower(hashEqual.Collector)
	values["origin"] = strings.ToLower(hashEqual.Origin)

	return values
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
LET edgeCollection = (FOR edgeData IN [
    {fromKey: hashEqual._key, toKey: equalArtifact._key, from: hashEqual._id, to: equalArtifact._id, label: "is_equal"}, 
    {fromKey: artifact._key, toKey: hashEqual._key, from: artifact._id, to: hashEqual._id, label: "subject"}]

    INSERT { _key: CONCAT("hashEqualsEdges", edgeData.fromKey, edgeData.toKey), _from: edgeData.from, _to: edgeData.to, label : edgeData.label } INTO hashEqualsEdges OPTIONS { overwriteMode: "ignore" }
)
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

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getHashEqualQueryValues(artifact, equalArtifact, hashEqual), "IngestHashEqual")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest hashEqual: %w", err)
	}
	defer cursor.Close()

	hashEqualList, err := getHashEqual(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get hashEqual from arango cursor: %w", err)
	}

	if len(hashEqualList) == 1 {
		return hashEqualList[0], nil
	} else {
		return nil, fmt.Errorf("number of hashEqual ingested is greater than one")
	}
}

func getHashEqual(ctx context.Context, cursor driver.Cursor) ([]*model.HashEqual, error) {
	type collectedData struct {
		Artifact      model.Artifact `json:"artifact"`
		EqualArtifact model.Artifact `json:"equalArtifact"`
		HashEqualId   string         `json:"hashEqual"`
		Justification string         `json:"justification"`
		Collector     string         `json:"collector"`
		Origin        string         `json:"origin"`
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
			Artifacts:     []*model.Artifact{&createdValue.Artifact, &createdValue.EqualArtifact},
			Justification: createdValue.Justification,
			Origin:        createdValue.Collector,
			Collector:     createdValue.Origin,
		}
		hashEqualList = append(hashEqualList, hashEqual)
	}
	return hashEqualList, nil
}
