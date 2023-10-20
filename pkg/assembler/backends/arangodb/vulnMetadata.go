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
	"time"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

const (
	scoreTypeStr  string = "scoreType"
	scoreValueStr string = "scoreValue"
	timeStampStr  string = "timestamp"
)

func (c *arangoClient) VulnerabilityMetadata(ctx context.Context, vulnerabilityMetadataSpec *model.VulnerabilityMetadataSpec) ([]*model.VulnerabilityMetadata, error) {

	if vulnerabilityMetadataSpec != nil && vulnerabilityMetadataSpec.ID != nil {
		cv, err := c.buildVulnerabilityMetadataByID(ctx, *vulnerabilityMetadataSpec.ID, vulnerabilityMetadataSpec)
		if err != nil {
			return nil, fmt.Errorf("buildVulnerabilityMetadataByID failed with an error: %w", err)
		}
		return []*model.VulnerabilityMetadata{cv}, nil
	}

	var arangoQueryBuilder *arangoQueryBuilder
	if vulnerabilityMetadataSpec.Vulnerability != nil {
		values := map[string]any{}
		arangoQueryBuilder = setVulnMatchValues(vulnerabilityMetadataSpec.Vulnerability, values)
		arangoQueryBuilder.forOutBound(vulnMetadataEdgesStr, "vulnMetadata", "vVulnID")
		err := setVulnMetadataMatchValues(arangoQueryBuilder, vulnerabilityMetadataSpec, values)
		if err != nil {
			return nil, fmt.Errorf("setting match values for vuln metadata resulted in error: %w", err)
		}
		return getVulnMetadataForQuery(ctx, c, arangoQueryBuilder, values)

	} else {
		values := map[string]any{}
		arangoQueryBuilder = newForQuery(vulnMetadataStr, "vulnMetadata")
		err := setVulnMetadataMatchValues(arangoQueryBuilder, vulnerabilityMetadataSpec, values)
		if err != nil {
			return nil, fmt.Errorf("setting match values for vuln metadata resulted in error: %w", err)
		}
		arangoQueryBuilder.forInBound(vulnMetadataEdgesStr, "vVulnID", "vulnMetadata")
		arangoQueryBuilder.forInBound(vulnHasVulnerabilityIDStr, "vType", "vVulnID")

		return getVulnMetadataForQuery(ctx, c, arangoQueryBuilder, values)
	}
}

func getVulnMetadataForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.VulnerabilityMetadata, error) {
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'vulnerability': {
			"type_id": vType._id,
		    "type": vType.type,
		    "vuln_id": vVulnID._id,
		    "vuln": vVulnID.vulnerabilityID
		},
		'vulnMetadata_id': vulnMetadata._id,
		'scoreType': vulnMetadata.scoreType,
		'scoreValue': vulnMetadata.scoreValue,
		'timestamp': vulnMetadata.timestamp,
		'collector': vulnMetadata.collector,
		'origin': vulnMetadata.origin
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "VulnerabilityMetadata")
	if err != nil {
		return nil, fmt.Errorf("failed to query for VulnerabilityMetadata: %w", err)
	}
	defer cursor.Close()

	return geVulnMetadataFromCursor(ctx, cursor)
}

func setVulnMetadataMatchValues(arangoQueryBuilder *arangoQueryBuilder, vulnMetadata *model.VulnerabilityMetadataSpec, queryValues map[string]any) error {
	if vulnMetadata.ID != nil {
		arangoQueryBuilder.filter("vulnMetadata", "_id", "==", "@id")
		queryValues["id"] = *vulnMetadata.ID
	}
	if vulnMetadata.ScoreType != nil {
		arangoQueryBuilder.filter("vulnMetadata", scoreTypeStr, "==", "@"+scoreTypeStr)
		queryValues[scoreTypeStr] = *vulnMetadata.ScoreType
	}

	if vulnMetadata.Comparator != nil {
		if vulnMetadata.ScoreValue == nil {
			return fmt.Errorf("comparator set without a vulnerability score being specified")
		}
		switch *vulnMetadata.Comparator {
		case model.ComparatorEqual:
			arangoQueryBuilder.filter("vulnMetadata", scoreValueStr, "==", "@"+scoreValueStr)
			queryValues[scoreValueStr] = *vulnMetadata.ScoreValue
		case model.ComparatorGreaterEqual:
			arangoQueryBuilder.filter("vulnMetadata", scoreValueStr, ">=", "@"+scoreValueStr)
			queryValues[scoreValueStr] = *vulnMetadata.ScoreValue
		case model.ComparatorGreater:
			arangoQueryBuilder.filter("vulnMetadata", scoreValueStr, ">", "@"+scoreValueStr)
			queryValues[scoreValueStr] = *vulnMetadata.ScoreValue
		case model.ComparatorLessEqual:
			arangoQueryBuilder.filter("vulnMetadata", scoreValueStr, "<=", "@"+scoreValueStr)
			queryValues[scoreValueStr] = *vulnMetadata.ScoreValue
		case model.ComparatorLess:
			arangoQueryBuilder.filter("vulnMetadata", scoreValueStr, "<", "@"+scoreValueStr)
			queryValues[scoreValueStr] = *vulnMetadata.ScoreValue
		}
	} else {
		if vulnMetadata.ScoreValue != nil {
			arangoQueryBuilder.filter("vulnMetadata", scoreValueStr, "==", "@"+scoreValueStr)
			queryValues[scoreValueStr] = *vulnMetadata.ScoreValue
		}
	}
	if vulnMetadata.Timestamp != nil {
		arangoQueryBuilder.filter("vulnMetadata", timeStampStr, "==", "@"+timeStampStr)
		queryValues[timeStampStr] = vulnMetadata.Timestamp.UTC()
	}
	if vulnMetadata.Origin != nil {
		arangoQueryBuilder.filter("vulnMetadata", origin, "==", "@"+origin)
		queryValues[origin] = *vulnMetadata.Origin
	}
	if vulnMetadata.Collector != nil {
		arangoQueryBuilder.filter("vulnMetadata", collector, "==", "@"+collector)
		queryValues[collector] = *vulnMetadata.Collector
	}
	return nil
}

func getVulnMetadataQueryValues(vulnerability *model.VulnerabilityInputSpec, vulnerabilityMetadata model.VulnerabilityMetadataInputSpec) map[string]any {
	values := map[string]any{}
	// add guac keys
	if vulnerability != nil {
		vuln := guacVulnId(*vulnerability)
		values["guacVulnKey"] = vuln.VulnerabilityID
	}

	values[scoreTypeStr] = vulnerabilityMetadata.ScoreType
	values[scoreValueStr] = vulnerabilityMetadata.ScoreValue
	values[timeStampStr] = vulnerabilityMetadata.Timestamp.UTC()
	values[origin] = vulnerabilityMetadata.Origin
	values[collector] = vulnerabilityMetadata.Collector

	return values
}

func (c *arangoClient) IngestVulnerabilityMetadata(ctx context.Context, vulnerability model.VulnerabilityInputSpec, vulnerabilityMetadata model.VulnerabilityMetadataInputSpec) (string, error) {
	query := `
	LET firstVuln = FIRST(
		FOR vVulnID in vulnerabilities
		  FILTER vVulnID.guacKey == @guacVulnKey
		FOR vType in vulnTypes
		  FILTER vType._id == vVulnID._parent

		RETURN {
		  "typeID": vType._id,
		  "type": vType.type,
		  "vuln_id": vVulnID._id,
		  "vuln": vVulnID.vulnerabilityID,
		  "vulnDoc": vVulnID
		}
	)
	  
	  LET vulnMetadata = FIRST(
		  UPSERT { vulnerabilityID:firstVuln.vulnDoc._id, scoreType:@scoreType, scoreValue:@scoreValue, timestamp:@timestamp, collector:@collector, origin:@origin } 
			  INSERT { vulnerabilityID:firstVuln.vulnDoc._id, scoreType:@scoreType, scoreValue:@scoreValue, timestamp:@timestamp, collector:@collector, origin:@origin } 
			  UPDATE {} IN vulnMetadataCollection
			  RETURN NEW
	  )
				  
	  INSERT { _key: CONCAT("vulnMetadataEdges", firstVuln.vulnDoc._key, vulnMetadata._key), _from: firstVuln.vulnDoc._id, _to: vulnMetadata._id } INTO vulnMetadataEdges OPTIONS { overwriteMode: "ignore" }
	  
	  RETURN {
		'vulnerability': {
			'type_id': firstVuln.typeID,
			'type': firstVuln.type,
			'vuln_id': firstVuln.vuln_id,
			'vuln': firstVuln.vuln
		},
		'vulnMetadata_id': vulnMetadata._id,
		'scoreType': vulnMetadata.scoreType,
		'scoreValue': vulnMetadata.scoreValue,
		'timestamp': vulnMetadata.timestamp,
		'collector': vulnMetadata.collector,
		'origin': vulnMetadata.origin
	  }`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getVulnMetadataQueryValues(&vulnerability, vulnerabilityMetadata), "IngestVulnerabilityMetadata")
	if err != nil {
		return "", fmt.Errorf("failed to ingest VulnerabilityMetadata: %w", err)
	}
	defer cursor.Close()

	vulnMetadataList, err := geVulnMetadataFromCursor(ctx, cursor)
	if err != nil {
		return "", fmt.Errorf("failed to get VulnerabilityMetadata from arango cursor: %w", err)
	}

	if len(vulnMetadataList) == 1 {
		return vulnMetadataList[0].ID, nil
	} else {
		return "", fmt.Errorf("number of VulnerabilityMetadata ingested is greater than one")
	}
}

func (c *arangoClient) IngestBulkVulnerabilityMetadata(ctx context.Context, vulnerabilities []*model.VulnerabilityInputSpec, vulnerabilityMetadataList []*model.VulnerabilityMetadataInputSpec) ([]string, error) {
	var listOfValues []map[string]any

	for i := range vulnerabilityMetadataList {
		listOfValues = append(listOfValues, getVulnMetadataQueryValues(vulnerabilities[i], *vulnerabilityMetadataList[i]))
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
	  LET firstVuln = FIRST(
		FOR vVulnID in vulnerabilities
		  FILTER vVulnID.guacKey == doc.guacVulnKey
		FOR vType in vulnTypes
		  FILTER vType._id == vVulnID._parent

		RETURN {
		  "typeID": vType._id,
		  "type": vType.type,
		  "vuln_id": vVulnID._id,
		  "vuln": vVulnID.vulnerabilityID,
		  "vulnDoc": vVulnID
		}
	  )
	  
	  LET vulnMetadata = FIRST(
		  UPSERT { vulnerabilityID:firstVuln.vulnDoc._id, scoreType:doc.scoreType, scoreValue:doc.scoreValue, timestamp:doc.timestamp, collector:doc.collector, origin:doc.origin } 
			  INSERT { vulnerabilityID:firstVuln.vulnDoc._id, scoreType:doc.scoreType, scoreValue:doc.scoreValue, timestamp:doc.timestamp, collector:doc.collector, origin:doc.origin } 
			  UPDATE {} IN vulnMetadataCollection
			  RETURN NEW
	  )
				  
	  INSERT { _key: CONCAT("vulnMetadataEdges", firstVuln.vulnDoc._key, vulnMetadata._key), _from: firstVuln.vulnDoc._id, _to: vulnMetadata._id } INTO vulnMetadataEdges OPTIONS { overwriteMode: "ignore" }
	  
	  RETURN {
		'vulnerability': {
			'type_id': firstVuln.typeID,
			'type': firstVuln.type,
			'vuln_id': firstVuln.vuln_id,
			'vuln': firstVuln.vuln
		},
		'vulnMetadata_id': vulnMetadata._id,
		'scoreType': vulnMetadata.scoreType,
		'scoreValue': vulnMetadata.scoreValue,
		'timestamp': vulnMetadata.timestamp,
		'collector': vulnMetadata.collector,
		'origin': vulnMetadata.origin
	  }`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestVulnerabilityMetadatas")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest VulnerabilityMetadatas %w", err)
	}
	defer cursor.Close()

	vulnMetadataList, err := geVulnMetadataFromCursor(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get VulnerabilityMetadatas from arango cursor: %w", err)
	}

	var vulnMetadataIDList []string
	for _, ingestedVulnMeta := range vulnMetadataList {
		vulnMetadataIDList = append(vulnMetadataIDList, ingestedVulnMeta.ID)
	}
	return vulnMetadataIDList, nil
}

func geVulnMetadataFromCursor(ctx context.Context, cursor driver.Cursor) ([]*model.VulnerabilityMetadata, error) {
	type collectedData struct {
		Vulnerability  *dbVulnID                    `json:"vulnerability"`
		VulnMetadataID string                       `json:"vulnMetadata_id"`
		ScoreType      model.VulnerabilityScoreType `json:"scoreType"`
		ScoreValue     float64                      `json:"scoreValue"`
		Timestamp      time.Time                    `json:"timestamp"`
		Collector      string                       `json:"collector"`
		Origin         string                       `json:"origin"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to package occurrence from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var vulnMetadataList []*model.VulnerabilityMetadata
	for _, createdValue := range createdValues {
		vuln := &model.Vulnerability{
			ID:   createdValue.Vulnerability.VulnID,
			Type: createdValue.Vulnerability.VulnType,
			VulnerabilityIDs: []*model.VulnerabilityID{
				{
					ID:              createdValue.Vulnerability.VulnID,
					VulnerabilityID: createdValue.Vulnerability.Vuln,
				},
			},
		}

		vulnMetadata := &model.VulnerabilityMetadata{
			ID:            createdValue.VulnMetadataID,
			Vulnerability: vuln,
			ScoreType:     createdValue.ScoreType,
			ScoreValue:    createdValue.ScoreValue,
			Timestamp:     createdValue.Timestamp,
			Origin:        createdValue.Origin,
			Collector:     createdValue.Collector,
		}
		vulnMetadataList = append(vulnMetadataList, vulnMetadata)
	}
	return vulnMetadataList, nil
}

func (c *arangoClient) buildVulnerabilityMetadataByID(ctx context.Context, id string, filter *model.VulnerabilityMetadataSpec) (*model.VulnerabilityMetadata, error) {
	if filter != nil && filter.ID != nil {
		if *filter.ID != id {
			return nil, fmt.Errorf("ID does not match filter")
		}
	}

	idSplit := strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	if idSplit[0] == vulnMetadataStr {
		if filter != nil {
			filter.ID = ptrfrom.String(id)
		} else {
			filter = &model.VulnerabilityMetadataSpec{
				ID: ptrfrom.String(id),
			}
		}
		return c.queryVulnerabilityMetadataNodeByID(ctx, filter)
	} else {
		return nil, fmt.Errorf("id type does not match for Vulnerability Metadata query: %s", id)
	}
}

func (c *arangoClient) queryVulnerabilityMetadataNodeByID(ctx context.Context, filter *model.VulnerabilityMetadataSpec) (*model.VulnerabilityMetadata, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(vulnMetadataStr, "vulnMetadata")
	err := setVulnMetadataMatchValues(arangoQueryBuilder, filter, values)
	if err != nil {
		return nil, fmt.Errorf("setting match values for vuln metadata resulted in error: %w", err)
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN vulnMetadata`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "queryVulnerabilityMetadataNodeByID")
	if err != nil {
		return nil, fmt.Errorf("failed to query for vulnMetadata: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type dbVulnMetadata struct {
		VulnMetadataID  string                       `json:"_id"`
		VulnerabilityID string                       `json:"vulnerabilityID"`
		ScoreType       model.VulnerabilityScoreType `json:"scoreType"`
		ScoreValue      float64                      `json:"scoreValue"`
		Timestamp       time.Time                    `json:"timestamp"`
		Collector       string                       `json:"collector"`
		Origin          string                       `json:"origin"`
	}

	var collectedValues []dbVulnMetadata
	for {
		var doc dbVulnMetadata
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to vulnMetadata from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, fmt.Errorf("number of vulnMetadata nodes found for ID: %s is greater than one", *filter.ID)
	}

	builtVuln, err := c.buildVulnResponseByID(ctx, collectedValues[0].VulnerabilityID, filter.Vulnerability)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability from ID: %s, with error: %w", collectedValues[0].VulnerabilityID, err)
	}

	return &model.VulnerabilityMetadata{
		ID:            collectedValues[0].VulnMetadataID,
		Vulnerability: builtVuln,
		ScoreType:     collectedValues[0].ScoreType,
		ScoreValue:    collectedValues[0].ScoreValue,
		Timestamp:     collectedValues[0].Timestamp,
		Origin:        collectedValues[0].Origin,
		Collector:     collectedValues[0].Collector,
	}, nil
}

func (c *arangoClient) vulnMetadataNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := make([]string, 0, 1)
	if allowedEdges[model.EdgeVulnMetadataVulnerability] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(vulnMetadataStr, "vulnMetadata")
		arangoQueryBuilder.filter("vulnMetadata", "_id", "==", "@id")
		values["id"] = nodeID
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  vulnMetadata.vulnerabilityID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "vulnMetadataNeighbors - vulnerability")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}

	return out, nil
}
