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
	panic(fmt.Errorf("not implemented: CertifyVEXStatement - CertifyVEXStatement"))
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
	return []string{}, fmt.Errorf("not implemented - IngestVEXStatements")
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
		vexList, err := getCertifyVex(ctx, cursor)
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

		vexList, err := getCertifyVex(ctx, cursor)
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

func getCertifyVex(ctx context.Context, cursor driver.Cursor) ([]*model.CertifyVEXStatement, error) {
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
		} else {
			certifyVex.Subject = createdValue.Artifact
		}

		certifyVexList = append(certifyVexList, certifyVex)
	}
	return certifyVexList, nil
}
