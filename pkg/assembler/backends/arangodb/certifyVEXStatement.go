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
	"time"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

const (
	statusStr           string = "status"
	vexJustificationStr string = "vexJustification"
	statementStr        string = "statement"
	statusNotesStr      string = "statusNotes"
	knownSinceStr       string = "knownSince"
)

func (c *arangoClient) CertifyVEXStatement(ctx context.Context, certifyVEXStatementSpec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {

	// TODO (pxp928): Optimize/add other queries based on input and starting node/edge for most efficient retrieval
	var arangoQueryBuilder *arangoQueryBuilder
	if certifyVEXStatementSpec.Subject != nil {
		var combinedVEX []*model.CertifyVEXStatement
		if certifyVEXStatementSpec.Subject.Package != nil {
			values := map[string]any{}
			arangoQueryBuilder = setPkgVersionMatchValues(certifyVEXStatementSpec.Subject.Package, values)
			arangoQueryBuilder.forOutBound(certifyVexPkgEdgesStr, "certifyVex", "pVersion")
			setVexMatchValues(arangoQueryBuilder, certifyVEXStatementSpec, values)

			pkgVersionVEXs, err := getPkgVexForQuery(ctx, c, arangoQueryBuilder, values)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve package version certifyVex with error: %w", err)
			}

			combinedVEX = append(combinedVEX, pkgVersionVEXs...)
		}
		if certifyVEXStatementSpec.Subject.Artifact != nil {
			values := map[string]any{}
			arangoQueryBuilder = setArtifactMatchValues(certifyVEXStatementSpec.Subject.Artifact, values)
			arangoQueryBuilder.forOutBound(certifyVexArtEdgesStr, "certifyVex", "art")
			setVexMatchValues(arangoQueryBuilder, certifyVEXStatementSpec, values)

			artVEXs, err := getArtifactVexForQuery(ctx, c, arangoQueryBuilder, values)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve artifact certifyVex with error: %w", err)
			}
			combinedVEX = append(combinedVEX, artVEXs...)
		}
		return combinedVEX, nil
	} else {
		values := map[string]any{}
		var combinedVEX []*model.CertifyVEXStatement

		// get packages
		arangoQueryBuilder = newForQuery(certifyVEXsStr, "certifyVex")
		setVexMatchValues(arangoQueryBuilder, certifyVEXStatementSpec, values)
		arangoQueryBuilder.forInBound(certifyVexPkgEdgesStr, "pVersion", "certifyVex")
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "pName", "pVersion")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")

		pkgVersionVEXs, err := getPkgVexForQuery(ctx, c, arangoQueryBuilder, values)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve package certifyVex with error: %w", err)
		}
		combinedVEX = append(combinedVEX, pkgVersionVEXs...)

		// get artifacts
		arangoQueryBuilder = newForQuery(certifyVEXsStr, "certifyVex")
		setVexMatchValues(arangoQueryBuilder, certifyVEXStatementSpec, values)
		arangoQueryBuilder.forInBound(certifyVexArtEdgesStr, "art", "certifyVex")

		artVEXs, err := getArtifactVexForQuery(ctx, c, arangoQueryBuilder, values)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve artifact certifyVex with error: %w", err)
		}
		combinedVEX = append(combinedVEX, artVEXs...)

		return combinedVEX, nil
	}
}

func getPkgVexForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.CertifyVEXStatement, error) {
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'pkgVersion': {
			"type_id": pType._id,
			"type": pType.type,
			"namespace_id": pNs._id,
			"namespace": pNs.namespace,
			"name_id": pName._id,
			"name": pName.name,
			"version_id": pVersion._id,
			"version": pVersion.version,
			"subpath": pVersion.subpath,
			"qualifier_list": pVersion.qualifier_list
		},
		'vulnerability': {
			"type_id": vType._id,
		    "type": vType.type,
		    "vuln_id": vVulnID._id,
		    "vuln": vVulnID.vulnerabilityID
		},
		'certifyVex': certifyVex._id,
		'status': certifyVex.status,
		'vexJustification': certifyVex.vexJustification,
		'statement': certifyVex.statement,
		'statusNotes': certifyVex.statusNotes,
		'knownSince': certifyVex.knownSince,
		'collector': certifyVex.collector,
		'origin': certifyVex.origin  
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "CertifyVEXStatement")
	if err != nil {
		return nil, fmt.Errorf("failed to query for CertifyVEXStatement: %w", err)
	}
	defer cursor.Close()

	return getCertifyVexFromCursor(ctx, cursor)
}

func getArtifactVexForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.CertifyVEXStatement, error) {
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'artifact': {
			'id': art._id,
			'algorithm': art.algorithm,
			'digest': art.digest
		},
		'vulnerability': {
			"type_id": vType._id,
		    "type": vType.type,
		    "vuln_id": vVulnID._id,
		    "vuln": vVulnID.vulnerabilityID
		},
		'certifyVex': certifyVex._id,
		'status': certifyVex.status,
		'vexJustification': certifyVex.vexJustification,
		'statement': certifyVex.statement,
		'statusNotes': certifyVex.statusNotes,
		'knownSince': certifyVex.knownSince,
		'collector': certifyVex.collector,
		'origin': certifyVex.origin  
	}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "CertifyVEXStatement")
	if err != nil {
		return nil, fmt.Errorf("failed to query for CertifyVEXStatement: %w", err)
	}
	defer cursor.Close()

	return getCertifyVexFromCursor(ctx, cursor)
}

func setVexMatchValues(arangoQueryBuilder *arangoQueryBuilder, certifyVexSpec *model.CertifyVEXStatementSpec, queryValues map[string]any) {
	if certifyVexSpec.ID != nil {
		arangoQueryBuilder.filter("certifyVex", "_id", "==", "@id")
		queryValues["id"] = *certifyVexSpec.ID
	}
	if certifyVexSpec.Status != nil {
		arangoQueryBuilder.filter("certifyVex", statusStr, "==", "@"+statusStr)
		queryValues[statusStr] = *certifyVexSpec.Status
	}
	if certifyVexSpec.VexJustification != nil {
		arangoQueryBuilder.filter("certifyVex", vexJustificationStr, "==", "@"+vexJustificationStr)
		queryValues[vexJustificationStr] = *certifyVexSpec.VexJustification
	}
	if certifyVexSpec.Statement != nil {
		arangoQueryBuilder.filter("certifyVex", statementStr, "==", "@"+statementStr)
		queryValues[statementStr] = *certifyVexSpec.Statement
	}
	if certifyVexSpec.StatusNotes != nil {
		arangoQueryBuilder.filter("certifyVex", statusNotesStr, "==", "@"+statusNotesStr)
		queryValues[statusNotesStr] = *certifyVexSpec.StatusNotes
	}
	if certifyVexSpec.KnownSince != nil {
		arangoQueryBuilder.filter("certifyVex", knownSinceStr, "==", "@"+knownSinceStr)
		queryValues[knownSinceStr] = *certifyVexSpec.KnownSince
	}
	if certifyVexSpec.Origin != nil {
		arangoQueryBuilder.filter("certifyVex", origin, "==", "@"+origin)
		queryValues[origin] = *certifyVexSpec.Origin
	}
	if certifyVexSpec.Collector != nil {
		arangoQueryBuilder.filter("certifyVex", collector, "==", "@"+collector)
		queryValues[collector] = *certifyVexSpec.Collector
	}
	if certifyVexSpec.Vulnerability != nil {
		arangoQueryBuilder.forOutBound(certifyVexVulnEdgesStr, "vVulnID", "certifyVex")
		if certifyVexSpec.Vulnerability.ID != nil {
			arangoQueryBuilder.filter("vVulnID", "_id", "==", "@id")
			queryValues["id"] = *certifyVexSpec.Vulnerability.ID
		}
		if certifyVexSpec.Vulnerability.VulnerabilityID != nil {
			arangoQueryBuilder.filter("vVulnID", "vulnerabilityID", "==", "@vulnerabilityID")
			queryValues["vulnerabilityID"] = strings.ToLower(*certifyVexSpec.Vulnerability.VulnerabilityID)
		}
		arangoQueryBuilder.forInBound(vulnHasVulnerabilityIDStr, "vType", "vVulnID")
		if certifyVexSpec.Vulnerability.Type != nil {
			arangoQueryBuilder.filter("vType", "type", "==", "@vulnType")
			queryValues["vulnType"] = strings.ToLower(*certifyVexSpec.Vulnerability.Type)
		}
	} else {
		arangoQueryBuilder.forOutBound(certifyVexVulnEdgesStr, "vVulnID", "certifyVex")
		arangoQueryBuilder.forInBound(vulnHasVulnerabilityIDStr, "vType", "vVulnID")
	}
}

func getVEXStatementQueryValues(pkg *model.PkgInputSpec, artifact *model.ArtifactInputSpec, vulnerability *model.VulnerabilityInputSpec, vexStatement *model.VexStatementInputSpec) map[string]any {
	values := map[string]any{}
	// add guac keys
	if pkg != nil {
		pkgId := guacPkgId(*pkg)
		values["pkgVersionGuacKey"] = pkgId.VersionId
	} else {
		values["art_algorithm"] = strings.ToLower(artifact.Algorithm)
		values["art_digest"] = strings.ToLower(artifact.Digest)
	}
	if vulnerability != nil {
		vuln := guacVulnId(*vulnerability)
		values["guacVulnKey"] = vuln.VulnerabilityID
	}
	values[statusStr] = vexStatement.Status
	values[vexJustificationStr] = vexStatement.VexJustification
	values[statementStr] = vexStatement.Statement
	values[statusNotesStr] = vexStatement.StatusNotes
	values[knownSinceStr] = vexStatement.KnownSince
	values[origin] = vexStatement.Origin
	values[collector] = vexStatement.Collector

	return values
}

func (c *arangoClient) IngestVEXStatements(ctx context.Context, subjects model.PackageOrArtifactInputs, vulnerabilities []*model.VulnerabilityInputSpec, vexStatements []*model.VexStatementInputSpec) ([]string, error) {
	if len(subjects.Artifacts) > 0 {
		var listOfValues []map[string]any

		for i := range subjects.Artifacts {
			listOfValues = append(listOfValues, getVEXStatementQueryValues(nil, subjects.Artifacts[i], vulnerabilities[i], vexStatements[i]))
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

		query := `LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == doc.art_algorithm FILTER art.digest == doc.art_digest RETURN art)

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
		  
		LET certifyVex = FIRST(
			UPSERT { artifactID:artifact._id, vulnerabilityID:firstVuln.vulnDoc._id, status:doc.status, vexJustification:doc.vexJustification, statement:doc.statement, statusNotes:doc.statusNotes, knownSince:doc.knownSince, collector:doc.collector, origin:doc.origin } 
				INSERT {artifactID:artifact._id, vulnerabilityID:firstVuln.vulnDoc._id, status:doc.status, vexJustification:doc.vexJustification, statement:doc.statement, statusNotes:doc.statusNotes, knownSince:doc.knownSince, collector:doc.collector, origin:doc.origin } 
				UPDATE {} IN certifyVEXs
				RETURN NEW
		)
		
		INSERT { _key: CONCAT("certifyVexArtEdges", artifact._key, certifyVex._key), _from: artifact._id, _to: certifyVex._id } INTO certifyVexArtEdges OPTIONS { overwriteMode: "ignore" }
		INSERT { _key: CONCAT("certifyVexVulnEdges", certifyVex._key, firstVuln.vulnDoc._key), _from: certifyVex._id, _to: firstVuln.vulnDoc._id } INTO certifyVexVulnEdges OPTIONS { overwriteMode: "ignore" }
		
		RETURN {
		  'artifact': {
			  'id': artifact._id,
			  'algorithm': artifact.algorithm,
			  'digest': artifact.digest
		  },
		  'vulnerability': {
			  'type_id': firstVuln.typeID,
			  'type': firstVuln.type,
			  'vuln_id': firstVuln.vuln_id,
			  'vuln': firstVuln.vuln
		  },
		  'certifyVex': certifyVex._id,
		  'status': certifyVex.status,
		  'vexJustification': certifyVex.vexJustification,
		  'statement': certifyVex.statement,
		  'statusNotes': certifyVex.statusNotes,
		  'knownSince': certifyVex.knownSince,
		  'collector': certifyVex.collector,
		  'origin': certifyVex.origin  
		}`

		sb.WriteString(query)

		cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestVEXStatements")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest artifact VEX: %w", err)
		}
		defer cursor.Close()
		vexList, err := getCertifyVexFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get VEX from arango cursor: %w", err)
		}

		var vexIDList []string
		for _, ingestedVex := range vexList {
			vexIDList = append(vexIDList, ingestedVex.ID)
		}

		return vexIDList, nil

	} else if len(subjects.Packages) > 0 {

		var listOfValues []map[string]any

		for i := range subjects.Packages {
			listOfValues = append(listOfValues, getVEXStatementQueryValues(subjects.Packages[i], nil, vulnerabilities[i], vexStatements[i]))
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
		LET firstPkg = FIRST(
			FOR pVersion in pkgVersions
			  FILTER pVersion.guacKey == doc.pkgVersionGuacKey
			FOR pName in pkgNames
			  FILTER pName._id == pVersion._parent
			FOR pNs in pkgNamespaces
			  FILTER pNs._id == pName._parent
			FOR pType in pkgTypes
			  FILTER pType._id == pNs._parent
	
			RETURN {
			  'typeID': pType._id,
			  'type': pType.type,
			  'namespace_id': pNs._id,
			  'namespace': pNs.namespace,
			  'name_id': pName._id,
			  'name': pName.name,
			  'version_id': pVersion._id,
			  'version': pVersion.version,
			  'subpath': pVersion.subpath,
			  'qualifier_list': pVersion.qualifier_list,
			  'versionDoc': pVersion
			}
		)

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
		  
		LET certifyVex = FIRST(
			UPSERT { packageID:firstPkg.versionDoc._id, vulnerabilityID:firstVuln.vulnDoc._id, status:doc.status, vexJustification:doc.vexJustification, statement:doc.statement, statusNotes:doc.statusNotes, knownSince:doc.knownSince, collector:doc.collector, origin:doc.origin } 
				INSERT {packageID:firstPkg.versionDoc._id, vulnerabilityID:firstVuln.vulnDoc._id, status:doc.status, vexJustification:doc.vexJustification, statement:doc.statement, statusNotes:doc.statusNotes, knownSince:doc.knownSince, collector:doc.collector, origin:doc.origin } 
				UPDATE {} IN certifyVEXs
				RETURN NEW
		)
		
		INSERT { _key: CONCAT("certifyVexPkgEdges", firstPkg.versionDoc._key, certifyVex._key), _from: firstPkg.versionDoc._id, _to: certifyVex._id } INTO certifyVexPkgEdges OPTIONS { overwriteMode: "ignore" }
		INSERT { _key: CONCAT("certifyVexVulnEdges", certifyVex._key, firstVuln.vulnDoc._key), _from: certifyVex._id, _to: firstVuln.vulnDoc._id } INTO certifyVexVulnEdges OPTIONS { overwriteMode: "ignore" }
		
		  
		  RETURN {
			'pkgVersion': {
				'type_id': firstPkg.typeID,
				'type': firstPkg.type,
				'namespace_id': firstPkg.namespace_id,
				'namespace': firstPkg.namespace,
				'name_id': firstPkg.name_id,
				'name': firstPkg.name,
				'version_id': firstPkg.version_id,
				'version': firstPkg.version,
				'subpath': firstPkg.subpath,
				'qualifier_list': firstPkg.qualifier_list
			},
			'vulnerability': {
				'type_id': firstVuln.typeID,
				'type': firstVuln.type,
				'vuln_id': firstVuln.vuln_id,
				'vuln': firstVuln.vuln
			},
			'certifyVex_id': certifyVex._id,
			'status': certifyVex.status,
			'vexJustification': certifyVex.vexJustification,
			'statement': certifyVex.statement,
			'statusNotes': certifyVex.statusNotes,
			'knownSince': certifyVex.knownSince,
			'collector': certifyVex.collector,
			'origin': certifyVex.origin  
		  }`

		sb.WriteString(query)

		cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestVEXStatements")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest package Vex: %w", err)
		}
		defer cursor.Close()

		vexList, err := getCertifyVexFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get Vex from arango cursor: %w", err)
		}

		var vexIDList []string
		for _, ingestedVex := range vexList {
			vexIDList = append(vexIDList, ingestedVex.ID)
		}

		return vexIDList, nil

	} else {
		return nil, fmt.Errorf("packages or artifacts not specified for IngestVEXStatements")
	}
}

func (c *arangoClient) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInputSpec, vexStatement model.VexStatementInputSpec) (*model.CertifyVEXStatement, error) {
	if subject.Artifact != nil {
		query := `
		  LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == @art_algorithm FILTER art.digest == @art_digest RETURN art)

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
		  
		  LET certifyVex = FIRST(
			  UPSERT { artifactID:artifact._id, vulnerabilityID:firstVuln.vulnDoc._id, status:@status, vexJustification:@vexJustification, statement:@statement, statusNotes:@statusNotes, knownSince:@knownSince, collector:@collector, origin:@origin } 
				  INSERT {artifactID:artifact._id, vulnerabilityID:firstVuln.vulnDoc._id, status:@status, vexJustification:@vexJustification, statement:@statement, statusNotes:@statusNotes, knownSince:@knownSince, collector:@collector, origin:@origin } 
				  UPDATE {} IN certifyVEXs
				  RETURN NEW
		  )
		  
		  INSERT { _key: CONCAT("certifyVexArtEdges", artifact._key, certifyVex._key), _from: artifact._id, _to: certifyVex._id } INTO certifyVexArtEdges OPTIONS { overwriteMode: "ignore" }
		  INSERT { _key: CONCAT("certifyVexVulnEdges", certifyVex._key, firstVuln.vulnDoc._key), _from: certifyVex._id, _to: firstVuln.vulnDoc._id } INTO certifyVexVulnEdges OPTIONS { overwriteMode: "ignore" }
		  
		  RETURN {
			'artifact': {
				'id': artifact._id,
				'algorithm': artifact.algorithm,
				'digest': artifact.digest
			},
			'vulnerability': {
				'type_id': firstVuln.typeID,
				'type': firstVuln.type,
				'vuln_id': firstVuln.vuln_id,
				'vuln': firstVuln.vuln
			},
			'certifyVex': certifyVex._id,
			'status': certifyVex.status,
			'vexJustification': certifyVex.vexJustification,
			'statement': certifyVex.statement,
			'statusNotes': certifyVex.statusNotes,
			'knownSince': certifyVex.knownSince,
			'collector': certifyVex.collector,
			'origin': certifyVex.origin  
		  }`

		cursor, err := executeQueryWithRetry(ctx, c.db, query, getVEXStatementQueryValues(nil, subject.Artifact, &vulnerability, &vexStatement), "IngestVEXStatement - Artifact")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest VEX: %w", err)
		}
		defer cursor.Close()
		vexList, err := getCertifyVexFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get VEX from arango cursor: %w", err)
		}

		if len(vexList) == 1 {
			return vexList[0], nil
		} else {
			return nil, fmt.Errorf("number of VEX ingested is greater than one")
		}
	} else {
		query := `
		LET firstPkg = FIRST(
			FOR pVersion in pkgVersions
			  FILTER pVersion.guacKey == @pkgVersionGuacKey
			FOR pName in pkgNames
			  FILTER pName._id == pVersion._parent
			FOR pNs in pkgNamespaces
			  FILTER pNs._id == pName._parent
			FOR pType in pkgTypes
			  FILTER pType._id == pNs._parent
	
			RETURN {
			  'typeID': pType._id,
			  'type': pType.type,
			  'namespace_id': pNs._id,
			  'namespace': pNs.namespace,
			  'name_id': pName._id,
			  'name': pName.name,
			  'version_id': pVersion._id,
			  'version': pVersion.version,
			  'subpath': pVersion.subpath,
			  'qualifier_list': pVersion.qualifier_list,
			  'versionDoc': pVersion
			}
		)

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
		  
		LET certifyVex = FIRST(
			UPSERT { packageID:firstPkg.versionDoc._id, vulnerabilityID:firstVuln.vulnDoc._id, status:@status, vexJustification:@vexJustification, statement:@statement, statusNotes:@statusNotes, knownSince:@knownSince, collector:@collector, origin:@origin } 
				INSERT {packageID:firstPkg.versionDoc._id, vulnerabilityID:firstVuln.vulnDoc._id, status:@status, vexJustification:@vexJustification, statement:@statement, statusNotes:@statusNotes, knownSince:@knownSince, collector:@collector, origin:@origin } 
				UPDATE {} IN certifyVEXs
				RETURN NEW
		)
		
		INSERT { _key: CONCAT("certifyVexPkgEdges", firstPkg.versionDoc._key, certifyVex._key), _from: firstPkg.versionDoc._id, _to: certifyVex._id } INTO certifyVexPkgEdges OPTIONS { overwriteMode: "ignore" }
		INSERT { _key: CONCAT("certifyVexVulnEdges", certifyVex._key, firstVuln.vulnDoc._key), _from: certifyVex._id, _to: firstVuln.vulnDoc._id } INTO certifyVexVulnEdges OPTIONS { overwriteMode: "ignore" }
		
		  
		  RETURN {
			'pkgVersion': {
				'type_id': firstPkg.typeID,
				'type': firstPkg.type,
				'namespace_id': firstPkg.namespace_id,
				'namespace': firstPkg.namespace,
				'name_id': firstPkg.name_id,
				'name': firstPkg.name,
				'version_id': firstPkg.version_id,
				'version': firstPkg.version,
				'subpath': firstPkg.subpath,
				'qualifier_list': firstPkg.qualifier_list
			},
			'vulnerability': {
				'type_id': firstVuln.typeID,
				'type': firstVuln.type,
				'vuln_id': firstVuln.vuln_id,
				'vuln': firstVuln.vuln
			},
			'certifyVex_id': certifyVex._id,
			'status': certifyVex.status,
			'vexJustification': certifyVex.vexJustification,
			'statement': certifyVex.statement,
			'statusNotes': certifyVex.statusNotes,
			'knownSince': certifyVex.knownSince,
			'collector': certifyVex.collector,
			'origin': certifyVex.origin  
		  }`

		cursor, err := executeQueryWithRetry(ctx, c.db, query, getVEXStatementQueryValues(subject.Package, nil, &vulnerability, &vexStatement), "IngestVEXStatement - Package")
		if err != nil {
			return nil, fmt.Errorf("failed to create ingest VEX: %w", err)
		}
		defer cursor.Close()

		vexList, err := getCertifyVexFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get VEX from arango cursor: %w", err)
		}

		if len(vexList) == 1 {
			return vexList[0], nil
		} else {
			return nil, fmt.Errorf("number of VEX ingested is greater than one")
		}
	}
}

func getCertifyVexFromCursor(ctx context.Context, cursor driver.Cursor) ([]*model.CertifyVEXStatement, error) {
	type collectedData struct {
		PkgVersion       *dbPkgVersion   `json:"pkgVersion"`
		Artifact         *model.Artifact `json:"artifact"`
		Vulnerability    *dbVulnID       `json:"vulnerability"`
		CertifyVexId     string          `json:"certifyVex_id"`
		Status           string          `json:"status"`
		VexJustification string          `json:"vexJustification"`
		Statement        string          `json:"statement"`
		StatusNotes      string          `json:"statusNotes"`
		KnownSince       time.Time       `json:"knownSince"`
		Collector        string          `json:"collector"`
		Origin           string          `json:"origin"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to package Vex from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var certifyVexList []*model.CertifyVEXStatement
	for _, createdValue := range createdValues {
		var pkg *model.Package = nil
		if createdValue.PkgVersion != nil {
			pkg = generateModelPackage(createdValue.PkgVersion.TypeID, createdValue.PkgVersion.PkgType, createdValue.PkgVersion.NamespaceID, createdValue.PkgVersion.Namespace, createdValue.PkgVersion.NameID,
				createdValue.PkgVersion.Name, createdValue.PkgVersion.VersionID, createdValue.PkgVersion.Version, createdValue.PkgVersion.Subpath, createdValue.PkgVersion.QualifierList)
		}

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
		certifyVex := &model.CertifyVEXStatement{
			ID:               createdValue.CertifyVexId,
			Vulnerability:    vuln,
			Status:           model.VexStatus(createdValue.Status),
			VexJustification: model.VexJustification(createdValue.VexJustification),
			Statement:        createdValue.Statement,
			StatusNotes:      createdValue.StatusNotes,
			KnownSince:       createdValue.KnownSince,
			Origin:           createdValue.Collector,
			Collector:        createdValue.Origin,
		}
		if pkg != nil {
			certifyVex.Subject = pkg
		} else if createdValue.Artifact != nil {
			certifyVex.Subject = createdValue.Artifact
		} else {
			return nil, fmt.Errorf("failed to get subject from cursor for certifyVex")
		}

		certifyVexList = append(certifyVexList, certifyVex)
	}
	return certifyVexList, nil
}
