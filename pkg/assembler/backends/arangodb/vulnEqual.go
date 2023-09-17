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
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Query VulnEqual
func (c *arangoClient) VulnEqual(ctx context.Context, vulnEqualSpec *model.VulnEqualSpec) ([]*model.VulnEqual, error) {
	values := map[string]any{}
	if vulnEqualSpec.Vulnerabilities != nil {
		if len(vulnEqualSpec.Vulnerabilities) == 1 {
			return matchVulnEqualByInput(ctx, c, vulnEqualSpec, vulnEqualSpec.Vulnerabilities[0], nil, values)
		} else {
			return matchVulnEqualByInput(ctx, c, vulnEqualSpec, vulnEqualSpec.Vulnerabilities[0], vulnEqualSpec.Vulnerabilities[1], values)
		}
	} else {
		arangoQueryBuilder := newForQuery(vulnEqualsStr, "vulnEqual")
		setVulnEqualMatchValues(arangoQueryBuilder, vulnEqualSpec, values)
		arangoQueryBuilder.forInBound(vulnEqualSubjectVulnEdgesStr, "vVulnID", "vulnEqual")
		arangoQueryBuilder.forInBound(vulnHasVulnerabilityIDStr, "vType", "vVulnID")
		arangoQueryBuilder.forOutBound(vulnEqualVulnEdgesStr, "evVulnID", "vulnEqual")
		arangoQueryBuilder.forInBound(vulnHasVulnerabilityIDStr, "evType", "evVulnID")

		return getVulnEqualForQuery(ctx, c, arangoQueryBuilder, values)
	}
}

func matchVulnEqualByInput(ctx context.Context, c *arangoClient, vulnEqualSpec *model.VulnEqualSpec, firstVulnerability *model.VulnerabilitySpec,
	secondVulnerability *model.VulnerabilitySpec, values map[string]any) ([]*model.VulnEqual, error) {

	var combinedVulnEqual []*model.VulnEqual

	arangoQueryBuilder := setVulnMatchValues(firstVulnerability, values)
	arangoQueryBuilder.forOutBound(vulnEqualSubjectVulnEdgesStr, "vulnEqual", "vVulnID")
	setVulnEqualMatchValues(arangoQueryBuilder, vulnEqualSpec, values)
	if secondVulnerability != nil {

		if secondVulnerability.NoVuln != nil && *secondVulnerability.NoVuln {
			secondVulnerability.Type = ptrfrom.String(noVulnType)
			secondVulnerability.VulnerabilityID = ptrfrom.String("")
		}

		arangoQueryBuilder.forOutBound(vulnEqualVulnEdgesStr, "evVulnID", "vulnEqual")
		if secondVulnerability.ID != nil {
			arangoQueryBuilder.filter("evVulnID", "_id", "==", "@equal_id")
			values["equal_id"] = *secondVulnerability.ID
		}
		if secondVulnerability.VulnerabilityID != nil {
			arangoQueryBuilder.filter("evVulnID", "vulnerabilityID", "==", "@equal_vulnerabilityID")
			values["equal_vulnerabilityID"] = strings.ToLower(*secondVulnerability.VulnerabilityID)
		}
		arangoQueryBuilder.forInBound(vulnHasVulnerabilityIDStr, "evType", "evVulnID")
		if secondVulnerability.Type != nil {
			arangoQueryBuilder.filter("evType", "type", "==", "@equal_vulnType")
			values["equal_vulnType"] = strings.ToLower(*secondVulnerability.Type)
		}
	} else {
		arangoQueryBuilder.forOutBound(vulnEqualVulnEdgesStr, "evVulnID", "vulnEqual")
		arangoQueryBuilder.forInBound(vulnHasVulnerabilityIDStr, "evType", "evVulnID")
	}

	vulnSubjectVulnEqual, err := getVulnEqualForQuery(ctx, c, arangoQueryBuilder, values)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve vulnEqual with error: %w", err)
	}
	combinedVulnEqual = append(combinedVulnEqual, vulnSubjectVulnEqual...)

	arangoQueryBuilder = setVulnMatchValues(firstVulnerability, values)
	arangoQueryBuilder.forInBound(vulnEqualVulnEdgesStr, "vulnEqual", "vVulnID")
	setVulnEqualMatchValues(arangoQueryBuilder, vulnEqualSpec, values)
	if secondVulnerability != nil {

		if secondVulnerability.NoVuln != nil && *secondVulnerability.NoVuln {
			secondVulnerability.Type = ptrfrom.String(noVulnType)
			secondVulnerability.VulnerabilityID = ptrfrom.String("")
		}

		arangoQueryBuilder.forInBound(vulnEqualSubjectVulnEdgesStr, "evVulnID", "vulnEqual")
		if secondVulnerability.ID != nil {
			arangoQueryBuilder.filter("evVulnID", "_id", "==", "@equal_id")
			values["equal_id"] = *secondVulnerability.ID
		}
		if secondVulnerability.VulnerabilityID != nil {
			arangoQueryBuilder.filter("evVulnID", "vulnerabilityID", "==", "@equal_vulnerabilityID")
			values["equal_vulnerabilityID"] = strings.ToLower(*secondVulnerability.VulnerabilityID)
		}
		arangoQueryBuilder.forInBound(vulnHasVulnerabilityIDStr, "evType", "evVulnID")
		if secondVulnerability.Type != nil {
			arangoQueryBuilder.filter("evType", "type", "==", "@equal_vulnType")
			values["equal_vulnType"] = strings.ToLower(*secondVulnerability.Type)
		}
	} else {
		arangoQueryBuilder.forInBound(vulnEqualSubjectVulnEdgesStr, "evVulnID", "vulnEqual")
		arangoQueryBuilder.forInBound(vulnHasVulnerabilityIDStr, "evType", "evVulnID")
	}

	vulnEqualVulnEqual, err := getVulnEqualForQuery(ctx, c, arangoQueryBuilder, values)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve vulnEqual with error: %w", err)
	}
	combinedVulnEqual = append(combinedVulnEqual, vulnEqualVulnEqual...)

	return combinedVulnEqual, nil
}

func getVulnEqualForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.VulnEqual, error) {
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'vulnerability': {
			"type_id": vType._id,
		    "type": vType.type,
		    "vuln_id": vVulnID._id,
		    "vuln": vVulnID.vulnerabilityID
		},
		'equalVulnerability': {
			"type_id": evType._id,
		    "type": evType.type,
		    "vuln_id": evVulnID._id,
		    "vuln": evVulnID.vulnerabilityID
		},
		'vulnEqual_id': vulnEqual._id,
		'justification': vulnEqual.justification,
		'collector': vulnEqual.collector,
		'origin': vulnEqual.origin
	}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "vulnEqual")
	if err != nil {
		return nil, fmt.Errorf("failed to query for vulnEqual: %w", err)
	}
	defer cursor.Close()

	return getVulnEqualFromCursor(ctx, cursor)
}

func setVulnEqualMatchValues(arangoQueryBuilder *arangoQueryBuilder, vulnEqualSpec *model.VulnEqualSpec, queryValues map[string]any) {
	if vulnEqualSpec.ID != nil {
		arangoQueryBuilder.filter("vulnEqual", "_id", "==", "@id")
		queryValues["id"] = *vulnEqualSpec.ID
	}
	if vulnEqualSpec.Justification != nil {
		arangoQueryBuilder.filter("vulnEqual", justification, "==", "@"+justification)
		queryValues[justification] = *vulnEqualSpec.Justification
	}
	if vulnEqualSpec.Origin != nil {
		arangoQueryBuilder.filter("vulnEqual", origin, "==", "@"+origin)
		queryValues[origin] = *vulnEqualSpec.Origin
	}
	if vulnEqualSpec.Collector != nil {
		arangoQueryBuilder.filter("vulnEqual", collector, "==", "@"+collector)
		queryValues[collector] = *vulnEqualSpec.Collector
	}
}

func getVulnEqualQueryValues(vulnerability *model.VulnerabilityInputSpec, otherVulnerability *model.VulnerabilityInputSpec, vulnEqual *model.VulnEqualInputSpec) map[string]any {
	vulns := []model.VulnerabilityInputSpec{*vulnerability, *otherVulnerability}
	sort.SliceStable(vulns, func(i, j int) bool {
		return vulns[i].VulnerabilityID < vulns[j].VulnerabilityID
	})

	values := map[string]any{}
	// add guac keys
	vuln := guacVulnId(vulns[0])
	values["guacVulnKey"] = vuln.VulnerabilityID

	equalVuln := guacVulnId(vulns[1])
	values["equalGuacVulnKey"] = equalVuln.VulnerabilityID

	values[justification] = vulnEqual.Justification
	values[origin] = vulnEqual.Origin
	values[collector] = vulnEqual.Collector

	return values
}

// Ingest IngestVulnEqual
func (c *arangoClient) IngestVulnEquals(ctx context.Context, vulnerabilities []*model.VulnerabilityInputSpec, otherVulnerabilities []*model.VulnerabilityInputSpec, vulnEquals []*model.VulnEqualInputSpec) ([]string, error) {
	var listOfValues []map[string]any

	for i := range vulnEquals {
		listOfValues = append(listOfValues, getVulnEqualQueryValues(vulnerabilities[i], otherVulnerabilities[i], vulnEquals[i]))
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

	LET equalVuln = FIRST(
		FOR vVulnID in vulnerabilities
		  FILTER vVulnID.guacKey == doc.equalGuacVulnKey
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
	
	LET vulnEqual = FIRST(
		UPSERT { vulnerabilityID:firstVuln.vulnDoc._id, equalVulnerabilityID:equalVuln.vulnDoc._id, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
			INSERT { vulnerabilityID:firstVuln.vulnDoc._id, equalVulnerabilityID:equalVuln.vulnDoc._id, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
			UPDATE {} IN vulnEquals
			RETURN NEW
	)
	
	INSERT { _key: CONCAT("vulnEqualSubjectVulnEdges", firstVuln.vulnDoc._key, vulnEqual._key), _from: firstVuln.vulnDoc._id, _to: vulnEqual._id} INTO vulnEqualSubjectVulnEdges OPTIONS { overwriteMode: "ignore" }
	INSERT { _key: CONCAT("vulnEqualVulnEdges", vulnEqual._key, equalVuln.vulnDoc._key), _from: vulnEqual._id, _to: equalVuln.vulnDoc._id} INTO vulnEqualVulnEdges OPTIONS { overwriteMode: "ignore" }
	
	RETURN {
		'vulnerability': {
			'type_id': firstVuln.typeID,
			'type': firstVuln.type,
			'vuln_id': firstVuln.vuln_id,
			'vuln': firstVuln.vuln
		},
		'equalVulnerability': {
			'type_id': equalVuln.typeID,
			'type': equalVuln.type,
			'vuln_id': equalVuln.vuln_id,
			'vuln': equalVuln.vuln
		},
		'vulnEqual_id': vulnEqual._id,
		'justification': vulnEqual.justification,
		'collector': vulnEqual.collector,
		'origin': vulnEqual.origin
	}`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestVulnEquals")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest vulnEqual: %w", err)
	}
	defer cursor.Close()

	vulnEqualList, err := getVulnEqualFromCursor(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnEqual from arango cursor: %w", err)
	}

	var vulnEqualIDList []string
	for _, ingestedVulnEqual := range vulnEqualList {
		vulnEqualIDList = append(vulnEqualIDList, ingestedVulnEqual.ID)
	}

	return vulnEqualIDList, nil
}

func (c *arangoClient) IngestVulnEqual(ctx context.Context, vulnerability model.VulnerabilityInputSpec, otherVulnerability model.VulnerabilityInputSpec, vulnEqual model.VulnEqualInputSpec) (*model.VulnEqual, error) {
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

	LET equalVuln = FIRST(
		FOR vVulnID in vulnerabilities
		  FILTER vVulnID.guacKey == @equalGuacVulnKey
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
	
	LET vulnEqual = FIRST(
		UPSERT { vulnerabilityID:firstVuln.vulnDoc._id, equalVulnerabilityID:equalVuln.vulnDoc._id, justification:@justification, collector:@collector, origin:@origin } 
			INSERT { vulnerabilityID:firstVuln.vulnDoc._id, equalVulnerabilityID:equalVuln.vulnDoc._id, justification:@justification, collector:@collector, origin:@origin } 
			UPDATE {} IN vulnEquals
			RETURN NEW
	)
	
	INSERT { _key: CONCAT("vulnEqualSubjectVulnEdges", firstVuln.vulnDoc._key, vulnEqual._key), _from: firstVuln.vulnDoc._id, _to: vulnEqual._id} INTO vulnEqualSubjectVulnEdges OPTIONS { overwriteMode: "ignore" }
	INSERT { _key: CONCAT("vulnEqualVulnEdges", vulnEqual._key, equalVuln.vulnDoc._key), _from: vulnEqual._id, _to: equalVuln.vulnDoc._id} INTO vulnEqualVulnEdges OPTIONS { overwriteMode: "ignore" }
	
	RETURN {
		'vulnerability': {
			'type_id': firstVuln.typeID,
			'type': firstVuln.type,
			'vuln_id': firstVuln.vuln_id,
			'vuln': firstVuln.vuln
		},
		'equalVulnerability': {
			'type_id': equalVuln.typeID,
			'type': equalVuln.type,
			'vuln_id': equalVuln.vuln_id,
			'vuln': equalVuln.vuln
		},
		'vulnEqual_id': vulnEqual._id,
		'justification': vulnEqual.justification,
		'collector': vulnEqual.collector,
		'origin': vulnEqual.origin
	}`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getVulnEqualQueryValues(&vulnerability, &otherVulnerability, &vulnEqual), "IngestVulnEqual")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest vulnEqual: %w", err)
	}
	defer cursor.Close()

	vulnEqualList, err := getVulnEqualFromCursor(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnEqual from arango cursor: %w", err)
	}

	if len(vulnEqualList) == 1 {
		return vulnEqualList[0], nil
	} else {
		return nil, fmt.Errorf("number of vulnEqual ingested is greater than one")
	}
}

func getVulnEqualFromCursor(ctx context.Context, cursor driver.Cursor) ([]*model.VulnEqual, error) {
	type collectedData struct {
		Vulnerability      *dbVulnID `json:"vulnerability"`
		EqualVulnerability *dbVulnID `json:"equalVulnerability"`
		VulnEqualId        string    `json:"vulnEqual_id"`
		Justification      string    `json:"justification"`
		Collector          string    `json:"collector"`
		Origin             string    `json:"origin"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to vulnEqual from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var vulnEqualList []*model.VulnEqual
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

		equalVuln := &model.Vulnerability{
			ID:   createdValue.EqualVulnerability.VulnID,
			Type: createdValue.EqualVulnerability.VulnType,
			VulnerabilityIDs: []*model.VulnerabilityID{
				{
					ID:              createdValue.EqualVulnerability.VulnID,
					VulnerabilityID: createdValue.EqualVulnerability.Vuln,
				},
			},
		}

		vulnEqual := &model.VulnEqual{
			ID:              createdValue.VulnEqualId,
			Vulnerabilities: []*model.Vulnerability{vuln, equalVuln},
			Justification:   createdValue.Justification,
			Origin:          createdValue.Collector,
			Collector:       createdValue.Origin,
		}
		vulnEqualList = append(vulnEqualList, vulnEqual)
	}
	return vulnEqualList, nil
}
