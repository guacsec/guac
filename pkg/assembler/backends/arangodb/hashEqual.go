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

	query := `
LET a = (
	FOR art IN artifacts
	  FILTER art.algorithm == "sha256" && art.digest == "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"
	  FOR hashEqual IN OUTBOUND art hashEqualsEdges
		FOR objArt IN OUTBOUND hashEqual hashEqualsEdges
		FILTER objArt.algorithm == "sha512" && objArt.digest == "374ab8f711235830769aa5f0b31ce9b72c5670074b34cb302cdafe3b606233ee92ee01e298e5701f15cc7087714cd9abd7ddb838a6e1206b3642de16d9fc9dd7"
		RETURN {
			"algorithmA" : art.algorithm,
			"digestA" : art.digest,
			"hashEqual" : hashEqual,
			"algorithmB" : objArt.algorithm,
			"digestB" : objArt.digest
		  }
  )
  
  LET b = (
	FOR objArt IN artifacts
	  FILTER objArt.algorithm == "sha256" && objArt.digest == "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"
	  FOR hashEqual IN INBOUND objArt hashEqualsEdges
		FOR art IN INBOUND hashEqual hashEqualsEdges
		FILTER art.algorithm == "sha512" && art.digest == "374ab8f711235830769aa5f0b31ce9b72c5670074b34cb302cdafe3b606233ee92ee01e298e5701f15cc7087714cd9abd7ddb838a6e1206b3642de16d9fc9dd7"
		  RETURN {
			"algorithmA" : objArt.algorithm,
			"digestA" : objArt.digest,
			"hashEqual" : hashEqual,
			"algorithmB" : art.algorithm,
			"digestB" : art.digest
		  }
  )
  
  RETURN APPEND(a, b)`

	// var sb strings.Builder
	// var firstMatch bool = true

	// var selectedArt *model.ArtifactSpec = nil
	// var dependentArt *model.ArtifactSpec = nil
	// if hashEqualSpec.Artifacts != nil && len(hashEqualSpec.Artifacts) != 0 {
	// 	if len(hashEqualSpec.Artifacts) == 1 {
	// 		selectedArt = hashEqualSpec.Artifacts[0]
	// 	} else {
	// 		selectedArt = hashEqualSpec.Artifacts[0]
	// 		dependentArt = hashEqualSpec.Artifacts[1]
	// 	}
	// }
	// queryValues := map[string]any{}

	// returnValue := " RETURN a.algorithm, a.digest, hashEqual, objArt.algorithm, objArt.digest"

	// // query with selectedArt being subject
	// query := "MATCH (a:Artifact)-[:subject]-(hashEqual:HashEqual)-[:is_equal]-(objArt:Artifact)"
	// sb.WriteString(query)

	// setArtifactMatchValues(&sb, selectedArt, false, &firstMatch, queryValues)
	// setArtifactMatchValues(&sb, dependentArt, true, &firstMatch, queryValues)
	// setHashEqualValues(&sb, hashEqualSpec, &firstMatch, queryValues)

	// sb.WriteString(returnValue)

	// if len(hashEqualSpec.Artifacts) > 0 {
	// 	sb.WriteString("\nUNION")

	// 	// query with dependentArt being subject
	// 	query = "\nMATCH (a:Artifact)-[:subject]-(hashEqual:HashEqual)-[:is_equal]-(objArt:Artifact)"
	// 	sb.WriteString(query)

	// 	firstMatch = true
	// 	setArtifactMatchValues(&sb, dependentArt, false, &firstMatch, queryValues)
	// 	setArtifactMatchValues(&sb, selectedArt, true, &firstMatch, queryValues)
	// 	setHashEqualValues(&sb, hashEqualSpec, &firstMatch, queryValues)

	// 	sb.WriteString(returnValue)
	// }

	fmt.Println(query)

	// result, err := session.ReadTransaction(
	// 	func(tx neo4j.Transaction) (interface{}, error) {
	// 		result, err := tx.Run(sb.String(), queryValues)
	// 		if err != nil {
	// 			return nil, err
	// 		}

	// 		collectedHashEqual := []*model.HashEqual{}

	// 		for result.Next() {

	// 			algorithm := result.Record().Values[0].(string)
	// 			digest := result.Record().Values[1].(string)
	// 			artifact := generateModelArtifact(algorithm, digest)

	// 			algorithm = result.Record().Values[3].(string)
	// 			digest = result.Record().Values[4].(string)
	// 			depArtifact := generateModelArtifact(algorithm, digest)

	// 			hashEqualNode := dbtype.Node{}
	// 			if result.Record().Values[2] != nil {
	// 				hashEqualNode = result.Record().Values[6].(dbtype.Node)
	// 			} else {
	// 				return nil, gqlerror.Errorf("hashEqual Node not found in neo4j")
	// 			}

	// 			hashEqual := &model.HashEqual{
	// 				Artifacts:     []*model.Artifact{artifact, depArtifact},
	// 				Justification: hashEqualNode.Props[justification].(string),
	// 				Origin:        hashEqualNode.Props[origin].(string),
	// 				Collector:     hashEqualNode.Props[collector].(string),
	// 			}
	// 			collectedHashEqual = append(collectedHashEqual, hashEqual)
	// 		}
	// 		if err = result.Err(); err != nil {
	// 			return nil, err
	// 		}

	// 		return collectedHashEqual, nil
	// 	})
	// if err != nil {
	// 	return nil, err
	// }

	// return result.([]*model.HashEqual), nil
	return nil, nil
}

// func setHashEqualValues(sb *strings.Builder, hashEqualSpec *model.HashEqualSpec, firstMatch *bool, queryValues map[string]any) {
// 	if hashEqualSpec.Justification != nil {
// 		matchProperties(sb, *firstMatch, "hashEqual", "justification", "$justification")
// 		*firstMatch = false
// 		queryValues["justification"] = hashEqualSpec.Justification
// 	}
// 	if hashEqualSpec.Origin != nil {
// 		matchProperties(sb, *firstMatch, "hashEqual", "origin", "$origin")
// 		*firstMatch = false
// 		queryValues["origin"] = hashEqualSpec.Origin
// 	}
// 	if hashEqualSpec.Collector != nil {
// 		matchProperties(sb, *firstMatch, "hashEqual", "collector", "$collector")
// 		*firstMatch = false
// 		queryValues["collector"] = hashEqualSpec.Collector
// 	}
// }

// func matchProperties(sb *strings.Builder, firstMatch bool, label, property string, resolver string) {
// 	if firstMatch {
// 		sb.WriteString(" WHERE ")
// 	} else {
// 		sb.WriteString(" AND ")
// 	}
// 	sb.WriteString(label)
// 	sb.WriteString(".")
// 	sb.WriteString(property)
// 	sb.WriteString(" = ")
// 	sb.WriteString(resolver)
// }

func (c *arangoClient) IngestHashEqual(ctx context.Context, artifact model.ArtifactInputSpec, equalArtifact model.ArtifactInputSpec, hashEqual model.HashEqualInputSpec) (*model.HashEqual, error) {
	values := map[string]any{}
	values["art_algorithm"] = strings.ToLower(artifact.Algorithm)
	values["art_digest"] = strings.ToLower(artifact.Digest)
	values["equal_algorithm"] = strings.ToLower(equalArtifact.Algorithm)
	values["equal_digest"] = strings.ToLower(equalArtifact.Digest)
	values["justification"] = strings.ToLower(hashEqual.Justification)
	values["collector"] = strings.ToLower(hashEqual.Collector)
	values["origin"] = strings.ToLower(hashEqual.Origin)

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
    {from: hashEqual._id, to: equalArtifact._id, label: "is_equal"}, 
    {from: artifact._id, to: hashEqual._id, label: "subject"}]

  UPSERT { _from: edgeData.from, _to: edgeData.to, label : edgeData.label }
    INSERT { _from: edgeData.from, _to: edgeData.to, label : edgeData.label }
    UPDATE {} IN hashEqualsEdges
)
RETURN {
	"artAlgo": artifact.algorithm,
	"artDigest": artifact.digest,
	"equalArtAlgo": equalArtifact.algorithm,
	"equalArtDigest": equalArtifact.digest,
	"hashEqualJustification": hashEqual.justification,
	"hashEqualOrigin": hashEqual.origin,
	"hashEqualCollector": hashEqual.collector
}`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, values, "IngestHashEqual")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w", err)
	}
	defer cursor.Close()

	type collectedData struct {
		ArtAlgo                string `json:"artAlgo"`
		ArtDigest              string `json:"artDigest"`
		EqualArtAlgo           string `json:"equalArtAlgo"`
		EqualArtDigest         string `json:"equalArtDigest"`
		HashEqualJustification string `json:"hashEqualJustification"`
		HashEqualOrigin        string `json:"hashEqualOrigin"`
		HashEqualCollector     string `json:"hashEqualCollector"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to ingest artifact: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}
	if len(createdValues) == 1 {

		algorithm := createdValues[0].ArtAlgo
		digest := createdValues[0].ArtDigest
		artifact := generateModelArtifact(algorithm, digest)

		algorithm = createdValues[0].EqualArtAlgo
		digest = createdValues[0].EqualArtDigest
		depArtifact := generateModelArtifact(algorithm, digest)

		hashEqual := &model.HashEqual{
			Artifacts:     []*model.Artifact{artifact, depArtifact},
			Justification: createdValues[0].HashEqualJustification,
			Origin:        createdValues[0].HashEqualOrigin,
			Collector:     createdValues[0].HashEqualCollector,
		}
		return hashEqual, nil
	} else {
		return nil, fmt.Errorf("number of hashEqual ingested is too great")
	}
}
