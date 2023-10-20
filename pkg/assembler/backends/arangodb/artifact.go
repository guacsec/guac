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
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (c *arangoClient) Artifacts(ctx context.Context, artifactSpec *model.ArtifactSpec) ([]*model.Artifact, error) {
	values := map[string]any{}

	arangoQueryBuilder := setArtifactMatchValues(artifactSpec, values)
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"id": art._id,
		"algorithm": art.algorithm,
		"digest": art.digest
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "Artifacts")
	if err != nil {
		return nil, fmt.Errorf("failed to query for artifacts: %w", err)
	}
	defer cursor.Close()

	return getArtifacts(ctx, cursor)
}

func setArtifactMatchValues(artifactSpec *model.ArtifactSpec, queryValues map[string]any) *arangoQueryBuilder {
	arangoQueryBuilder := newForQuery(artifactsStr, "art")
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

func (c *arangoClient) buildArtifactResponseByID(ctx context.Context, id string, filter *model.ArtifactSpec) (*model.Artifact, error) {
	if filter != nil && filter.ID != nil {
		if *filter.ID != id {
			return nil, fmt.Errorf("ID does not match filter")
		}
	}
	idSplit := strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	if idSplit[0] == artifactsStr {
		if filter != nil {
			filter.ID = ptrfrom.String(id)
		} else {
			filter = &model.ArtifactSpec{
				ID: ptrfrom.String(id),
			}
		}
		foundArtifacts, err := c.Artifacts(ctx, filter)
		if err != nil {
			return nil, fmt.Errorf("failed to get artifact node by ID with error: %w", err)
		}
		if len(foundArtifacts) != 1 {
			return nil, fmt.Errorf("number of artifact nodes found for ID: %s is greater than one", id)
		}
		return foundArtifacts[0], nil
	} else {
		return nil, fmt.Errorf("id type does not match for artifact query: %s", id)
	}
}

func (c *arangoClient) artifactNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := []string{}
	if allowedEdges[model.EdgeArtifactHashEqual] {
		// hashEqualSubjectArtEdgesStr collection query
		values := map[string]any{}
		arangoQueryBuilder := setArtifactMatchValues(&model.ArtifactSpec{ID: &nodeID}, values)
		arangoQueryBuilder.forOutBound(hashEqualSubjectArtEdgesStr, "hashEqual", "art")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: hashEqual._id }")

		foundSubjectIDsOutBound, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "artifactNeighbors - hashEqualSubjectArtEdges outbound")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundSubjectIDsOutBound...)

		values = map[string]any{}
		arangoQueryBuilder = setArtifactMatchValues(&model.ArtifactSpec{ID: &nodeID}, values)
		arangoQueryBuilder.forInBound(hashEqualSubjectArtEdgesStr, "hashEqual", "art")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  hashEqual._id }")

		foundSubjectIDsInBound, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "artifactNeighbors - hashEqualSubjectArtEdges inbound")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundSubjectIDsInBound...)

		//hashEqualArtEdgesStr collection query

		values = map[string]any{}
		arangoQueryBuilder = setArtifactMatchValues(&model.ArtifactSpec{ID: &nodeID}, values)
		arangoQueryBuilder.forOutBound(hashEqualArtEdgesStr, "hashEqual", "art")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  hashEqual._id }")

		foundEqualIDsOutBound, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "artifactNeighbors - hashEqualArtEdges outbound")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundEqualIDsOutBound...)

		values = map[string]any{}
		arangoQueryBuilder = setArtifactMatchValues(&model.ArtifactSpec{ID: &nodeID}, values)
		arangoQueryBuilder.forInBound(hashEqualArtEdgesStr, "hashEqual", "art")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  hashEqual._id }")

		foundEqualIDsInBound, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "artifactNeighbors - hashEqualArtEdges inbound")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundEqualIDsInBound...)
	}
	if allowedEdges[model.EdgeArtifactIsOccurrence] {
		values := map[string]any{}
		arangoQueryBuilder := setArtifactMatchValues(&model.ArtifactSpec{ID: &nodeID}, values)
		arangoQueryBuilder.forInBound(isOccurrenceArtEdgesStr, "isOccurrence", "art")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: isOccurrence._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "artifactNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeArtifactHasSbom] {
		values := map[string]any{}
		arangoQueryBuilder := setArtifactMatchValues(&model.ArtifactSpec{ID: &nodeID}, values)
		arangoQueryBuilder.forOutBound(hasSBOMArtEdgesStr, "hasSBOM", "art")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: hasSBOM._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "artifactNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeArtifactHasSlsa] {
		values := map[string]any{}
		arangoQueryBuilder := setArtifactMatchValues(&model.ArtifactSpec{ID: &nodeID}, values)
		arangoQueryBuilder.forOutBound(hasSLSASubjectArtEdgesStr, "hasSLSA", "art")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  hasSLSA._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "artifactNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeArtifactCertifyVexStatement] {
		values := map[string]any{}
		arangoQueryBuilder := setArtifactMatchValues(&model.ArtifactSpec{ID: &nodeID}, values)
		arangoQueryBuilder.forOutBound(certifyVexArtEdgesStr, "certifyVex", "art")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: certifyVex._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "artifactNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeArtifactCertifyBad] {
		values := map[string]any{}
		arangoQueryBuilder := setArtifactMatchValues(&model.ArtifactSpec{ID: &nodeID}, values)
		arangoQueryBuilder.forOutBound(certifyBadArtEdgesStr, "certifyBad", "art")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  certifyBad._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "artifactNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeArtifactCertifyGood] {
		values := map[string]any{}
		arangoQueryBuilder := setArtifactMatchValues(&model.ArtifactSpec{ID: &nodeID}, values)
		arangoQueryBuilder.forOutBound(certifyGoodArtEdgesStr, "certifyGood", "art")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: certifyGood._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "artifactNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeArtifactHasMetadata] {
		values := map[string]any{}
		arangoQueryBuilder := setArtifactMatchValues(&model.ArtifactSpec{ID: &nodeID}, values)
		arangoQueryBuilder.forOutBound(hasMetadataArtEdgesStr, "hasMetadata", "art")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: hasMetadata._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "artifactNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeArtifactPointOfContact] {
		values := map[string]any{}
		arangoQueryBuilder := setArtifactMatchValues(&model.ArtifactSpec{ID: &nodeID}, values)
		arangoQueryBuilder.forOutBound(pointOfContactArtEdgesStr, "pointOfContact", "art")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: pointOfContact._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "artifactNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}

	return out, nil
}

func (c *arangoClient) getNeighborIDFromCursor(ctx context.Context, arangoQueryBuilder *arangoQueryBuilder, values map[string]any, callingFuncName string) ([]string, error) {
	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "getNeighborIDFromCursor - "+callingFuncName)
	if err != nil {
		return nil, fmt.Errorf("failed to query for Neighbors for %s with error: %w", callingFuncName, err)
	}
	defer cursor.Close()

	type dbNeighbor struct {
		NeighborID *string `json:"neighbor"`
		ParentID   *string `json:"parent"`
	}

	var foundNeighbors []dbNeighbor
	for {
		var doc dbNeighbor
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to get neighbor id from cursor for %s with error: %w", callingFuncName, err)
			}
		} else {
			foundNeighbors = append(foundNeighbors, doc)
		}
	}

	var foundIDs []string
	for _, foundNeighbor := range foundNeighbors {
		if foundNeighbor.NeighborID != nil {
			foundIDs = append(foundIDs, *foundNeighbor.NeighborID)
		}
		if foundNeighbor.ParentID != nil {
			foundIDs = append(foundIDs, *foundNeighbor.ParentID)
		}
	}
	return foundIDs, nil
}
