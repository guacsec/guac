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

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

const (
	dbUriStr          string = "dbUri"
	dbVersionStr      string = "dbVersion"
	scannerUriStr     string = "scannerUri"
	scannerVersionStr string = "scannerVersion"
)

func (c *arangoClient) CertifyVuln(ctx context.Context, certifyVulnSpec *model.CertifyVulnSpec) ([]*model.CertifyVuln, error) {
	panic(fmt.Errorf("not implemented: CertifyVuln - CertifyVuln"))
}

func getCertifyVulnQueryValues(pkg *model.PkgInputSpec, vulnerability *model.VulnerabilityInputSpec, certifyVuln *model.ScanMetadataInput) map[string]any {
	values := map[string]any{}
	// add guac keys
	if pkg != nil {
		pkgId := guacPkgId(*pkg)
		values["pkgVersionGuacKey"] = pkgId.VersionId
	}
	if vulnerability != nil {
		vuln := guacVulnId(*vulnerability)
		values["guacVulnKey"] = vuln.VulnerabilityID
	}

	values[timeScannedStr] = certifyVuln.TimeScanned
	values[dbUriStr] = certifyVuln.TimeScanned
	values[dbVersionStr] = certifyVuln.TimeScanned
	values[scannerUriStr] = certifyVuln.TimeScanned
	values[scannerVersionStr] = certifyVuln.TimeScanned
	values[origin] = certifyVuln.Origin
	values[collector] = certifyVuln.Collector

	return values
}

func (c *arangoClient) IngestCertifyVulns(ctx context.Context, pkgs []*model.PkgInputSpec, vulnerabilities []*model.VulnerabilityInputSpec, certifyVulns []*model.ScanMetadataInput) ([]*model.CertifyVuln, error) {
	// TODO (pxp928): move checks to resolver so all backends don't have to implement
	if len(pkgs) != len(vulnerabilities) {
		return nil, fmt.Errorf("uneven packages and vulnerabilities for ingestion")
	}
	if len(pkgs) != len(certifyVulns) {
		return nil, fmt.Errorf("uneven packages and certifyVuln for ingestion")
	}

	var listOfValues []map[string]any

	for i := range certifyVulns {
		listOfValues = append(listOfValues, getCertifyVulnQueryValues(pkgs[i], vulnerabilities[i], certifyVulns[i]))
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
			FOR pVersion in pkgVersions
			  FILTER pVersion.guacKey == doc.pkgVersionGuacKey
			FOR pName in pkgNames
			  FILTER pName._id == pVersion._parent
			FOR pNs in pkgNamespaces
			  FILTER pNs._id == pName._parent
			FOR pType in pkgTypes
			  FILTER pType._id == pNs._parent
	
			RETURN {
			  "type_id": vType._id,
			  "type": vType.type,
			  "vuln_id": vVulnID._id,
			  "vuln": vVulnID.vulnerabilityID
			}
		)
		  
		  LET isOccurrence = FIRST(
			  UPSERT { packageID:firstPkg.versionDoc._id, artifactID:artifact._id, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
				  INSERT { packageID:firstPkg.versionDoc._id, artifactID:artifact._id, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
				  UPDATE {} IN isOccurrences
				  RETURN NEW
		  )
		  			
		  INSERT { _key: CONCAT("isOccurrenceSubjectPkgEdges", firstPkg.versionDoc._key, isOccurrence._key), _from: firstPkg.versionDoc._id, _to: isOccurrence._id } INTO isOccurrenceSubjectPkgEdges OPTIONS { overwriteMode: "ignore" }
		  INSERT { _key: CONCAT("isOccurrenceArtEdges", isOccurrence._key, artifact._key), _from: isOccurrence._id, _to: artifact._id } INTO isOccurrenceArtEdges OPTIONS { overwriteMode: "ignore" }
		  
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
			'artifact': {
				'id': artifact._id,
				'algorithm': artifact.algorithm,
				'digest': artifact.digest
			},
			'isOccurrence_id': isOccurrence._id,
     		'justification': isOccurrence.justification,
			'collector': isOccurrence.collector,
			'origin': isOccurrence.origin
		  }`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestOccurrence")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest package occurrence: %w", err)
	}
	defer cursor.Close()

	isOccurrenceList, err := getPkgIsOccurrence(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get occurrences from arango cursor: %w", err)
	}

	return isOccurrenceList, nil
}

func (c *arangoClient) IngestCertifyVuln(ctx context.Context, pkg model.PkgInputSpec, vulnerability model.VulnerabilityInputSpec, certifyVuln model.ScanMetadataInput) (*model.CertifyVuln, error) {
	return nil, fmt.Errorf("not implemented - IngestCertifyVuln")
}
