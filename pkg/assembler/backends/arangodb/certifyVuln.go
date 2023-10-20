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
	dbUriStr          string = "dbUri"
	dbVersionStr      string = "dbVersion"
	scannerUriStr     string = "scannerUri"
	scannerVersionStr string = "scannerVersion"
)

func (c *arangoClient) CertifyVuln(ctx context.Context, certifyVulnSpec *model.CertifyVulnSpec) ([]*model.CertifyVuln, error) {

	if certifyVulnSpec != nil && certifyVulnSpec.ID != nil {
		cv, err := c.buildCertifyVulnByID(ctx, *certifyVulnSpec.ID, certifyVulnSpec)
		if err != nil {
			return nil, fmt.Errorf("buildCertifyVulnByID failed with an error: %w", err)
		}
		return []*model.CertifyVuln{cv}, nil
	}

	// TODO (pxp928): Optimization of the query can be done by starting from the vulnerability node (if specified)
	var arangoQueryBuilder *arangoQueryBuilder
	if certifyVulnSpec.Package != nil {
		values := map[string]any{}
		arangoQueryBuilder = setPkgVersionMatchValues(certifyVulnSpec.Package, values)
		arangoQueryBuilder.forOutBound(certifyVulnPkgEdgesStr, "certifyVuln", "pVersion")
		setCertifyVulnMatchValues(arangoQueryBuilder, certifyVulnSpec, values)

		return getPkgCertifyVulnForQuery(ctx, c, arangoQueryBuilder, values)

	} else {
		values := map[string]any{}
		arangoQueryBuilder = newForQuery(certifyVulnsStr, "certifyVuln")
		setCertifyVulnMatchValues(arangoQueryBuilder, certifyVulnSpec, values)
		arangoQueryBuilder.forInBound(certifyVulnPkgEdgesStr, "pVersion", "certifyVuln")
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "pName", "pVersion")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")

		return getPkgCertifyVulnForQuery(ctx, c, arangoQueryBuilder, values)
	}
}

func getPkgCertifyVulnForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.CertifyVuln, error) {
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'pkgVersion': {
			'type_id': pType._id,
			'type': pType.type,
			'namespace_id': pNs._id,
			'namespace': pNs.namespace,
			'name_id': pName._id,
			'name': pName.name,
			'version_id': pVersion._id,
			'version': pVersion.version,
			'subpath': pVersion.subpath,
			'qualifier_list': pVersion.qualifier_list
		},
		'vulnerability': {
			"type_id": vType._id,
		    "type": vType.type,
		    "vuln_id": vVulnID._id,
		    "vuln": vVulnID.vulnerabilityID
		},
		'certifyVuln_id': certifyVuln._id,
		'timeScanned': certifyVuln.timeScanned,
		'dbUri': certifyVuln.dbUri,
		'dbVersion': certifyVuln.dbVersion,
		'scannerUri': certifyVuln.scannerUri,
		'scannerVersion': certifyVuln.scannerVersion,
		'collector': certifyVuln.collector,
		'origin': certifyVuln.origin
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "CertifyVuln")
	if err != nil {
		return nil, fmt.Errorf("failed to query for CertifyVuln: %w", err)
	}
	defer cursor.Close()

	return geCertifyVulnFromCursor(ctx, cursor)
}

func setCertifyVulnMatchValues(arangoQueryBuilder *arangoQueryBuilder, certifyVulnSpec *model.CertifyVulnSpec, queryValues map[string]any) {
	if certifyVulnSpec.ID != nil {
		arangoQueryBuilder.filter("certifyVuln", "_id", "==", "@id")
		queryValues["id"] = *certifyVulnSpec.ID
	}
	if certifyVulnSpec.TimeScanned != nil {
		arangoQueryBuilder.filter("certifyVuln", timeScannedStr, "==", "@"+timeScannedStr)
		queryValues[timeScannedStr] = certifyVulnSpec.TimeScanned.UTC()
	}
	if certifyVulnSpec.DbURI != nil {
		arangoQueryBuilder.filter("certifyVuln", dbUriStr, "==", "@"+dbUriStr)
		queryValues[dbUriStr] = *certifyVulnSpec.DbURI
	}
	if certifyVulnSpec.DbVersion != nil {
		arangoQueryBuilder.filter("certifyVuln", dbVersionStr, "==", "@"+dbVersionStr)
		queryValues[dbVersionStr] = *certifyVulnSpec.DbVersion
	}
	if certifyVulnSpec.ScannerURI != nil {
		arangoQueryBuilder.filter("certifyVuln", scannerUriStr, "==", "@"+scannerUriStr)
		queryValues[scannerUriStr] = *certifyVulnSpec.ScannerURI
	}
	if certifyVulnSpec.ScannerVersion != nil {
		arangoQueryBuilder.filter("certifyVuln", scannerVersionStr, "==", "@"+scannerVersionStr)
		queryValues[scannerVersionStr] = *certifyVulnSpec.ScannerVersion
	}
	if certifyVulnSpec.Origin != nil {
		arangoQueryBuilder.filter("certifyVuln", origin, "==", "@"+origin)
		queryValues[origin] = *certifyVulnSpec.Origin
	}
	if certifyVulnSpec.Collector != nil {
		arangoQueryBuilder.filter("certifyVuln", collector, "==", "@"+collector)
		queryValues[collector] = *certifyVulnSpec.Collector
	}
	if certifyVulnSpec.Vulnerability != nil {

		if certifyVulnSpec.Vulnerability.NoVuln != nil && *certifyVulnSpec.Vulnerability.NoVuln {
			certifyVulnSpec.Vulnerability.Type = ptrfrom.String(noVulnType)
			certifyVulnSpec.Vulnerability.VulnerabilityID = ptrfrom.String("")
		}

		arangoQueryBuilder.forOutBound(certifyVulnEdgesStr, "vVulnID", "certifyVuln")
		if certifyVulnSpec.Vulnerability.ID != nil {
			arangoQueryBuilder.filter("vVulnID", "_id", "==", "@id")
			queryValues["id"] = *certifyVulnSpec.Vulnerability.ID
		}
		if certifyVulnSpec.Vulnerability.VulnerabilityID != nil {
			arangoQueryBuilder.filter("vVulnID", "vulnerabilityID", "==", "@vulnerabilityID")
			queryValues["vulnerabilityID"] = strings.ToLower(*certifyVulnSpec.Vulnerability.VulnerabilityID)
		}
		arangoQueryBuilder.forInBound(vulnHasVulnerabilityIDStr, "vType", "vVulnID")
		if certifyVulnSpec.Vulnerability.Type != nil {
			arangoQueryBuilder.filter("vType", "type", "==", "@vulnType")
			queryValues["vulnType"] = strings.ToLower(*certifyVulnSpec.Vulnerability.Type)
		}
	} else {
		arangoQueryBuilder.forOutBound(certifyVulnEdgesStr, "vVulnID", "certifyVuln")
		arangoQueryBuilder.forInBound(vulnHasVulnerabilityIDStr, "vType", "vVulnID")
	}
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

	values[timeScannedStr] = certifyVuln.TimeScanned.UTC()
	values[dbUriStr] = certifyVuln.DbURI
	values[dbVersionStr] = certifyVuln.DbVersion
	values[scannerUriStr] = certifyVuln.ScannerURI
	values[scannerVersionStr] = certifyVuln.ScannerVersion
	values[origin] = certifyVuln.Origin
	values[collector] = certifyVuln.Collector

	return values
}

func (c *arangoClient) IngestCertifyVulns(ctx context.Context, pkgs []*model.PkgInputSpec, vulnerabilities []*model.VulnerabilityInputSpec, certifyVulns []*model.ScanMetadataInput) ([]*model.CertifyVuln, error) {
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
		  
		  LET certifyVuln = FIRST(
			  UPSERT { packageID:firstPkg.versionDoc._id, vulnerabilityID:firstVuln.vulnDoc._id, timeScanned:doc.timeScanned, dbUri:doc.dbUri, dbVersion:doc.dbVersion, scannerUri:doc.scannerUri, scannerVersion:doc.scannerVersion, collector:doc.collector, origin:doc.origin } 
				  INSERT { packageID:firstPkg.versionDoc._id, vulnerabilityID:firstVuln.vulnDoc._id, timeScanned:doc.timeScanned, dbUri:doc.dbUri, dbVersion:doc.dbVersion, scannerUri:doc.scannerUri, scannerVersion:doc.scannerVersion, collector:doc.collector, origin:doc.origin } 
				  UPDATE {} IN certifyVulns
				  RETURN NEW
		  )
		  			
		  INSERT { _key: CONCAT("certifyVulnPkgEdges", firstPkg.versionDoc._key, certifyVuln._key), _from: firstPkg.versionDoc._id, _to: certifyVuln._id } INTO certifyVulnPkgEdges OPTIONS { overwriteMode: "ignore" }
		  INSERT { _key: CONCAT("certifyVulnEdges", certifyVuln._key, firstVuln.vulnDoc._key), _from: certifyVuln._id, _to: firstVuln.vulnDoc._id } INTO certifyVulnEdges OPTIONS { overwriteMode: "ignore" }
		  
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
			'certifyVuln_id': certifyVuln._id,
     		'timeScanned': certifyVuln.timeScanned,
			'dbUri': certifyVuln.dbUri,
			'dbVersion': certifyVuln.dbVersion,
			'scannerUri': certifyVuln.scannerUri,
			'scannerVersion': certifyVuln.scannerVersion,
			'collector': certifyVuln.collector,
			'origin': certifyVuln.origin
		  }`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestCertifyVulns")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest certifyVulns %w", err)
	}
	defer cursor.Close()

	certifyVulnList, err := geCertifyVulnFromCursor(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get certifyVulns from arango cursor: %w", err)
	}

	return certifyVulnList, nil
}

func (c *arangoClient) IngestCertifyVuln(ctx context.Context, pkg model.PkgInputSpec, vulnerability model.VulnerabilityInputSpec, certifyVuln model.ScanMetadataInput) (*model.CertifyVuln, error) {
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
		  
		  LET certifyVuln = FIRST(
			  UPSERT { packageID:firstPkg.versionDoc._id, vulnerabilityID:firstVuln.vulnDoc._id, timeScanned:@timeScanned, dbUri:@dbUri, dbVersion:@dbVersion, scannerUri:@scannerUri, scannerVersion:@scannerVersion, collector:@collector, origin:@origin } 
				  INSERT { packageID:firstPkg.versionDoc._id, vulnerabilityID:firstVuln.vulnDoc._id, timeScanned:@timeScanned, dbUri:@dbUri, dbVersion:@dbVersion, scannerUri:@scannerUri, scannerVersion:@scannerVersion, collector:@collector, origin:@origin } 
				  UPDATE {} IN certifyVulns
				  RETURN NEW
		  )
		  			
		  INSERT { _key: CONCAT("certifyVulnPkgEdges", firstPkg.versionDoc._key, certifyVuln._key), _from: firstPkg.versionDoc._id, _to: certifyVuln._id } INTO certifyVulnPkgEdges OPTIONS { overwriteMode: "ignore" }
		  INSERT { _key: CONCAT("certifyVulnEdges", certifyVuln._key, firstVuln.vulnDoc._key), _from: certifyVuln._id, _to: firstVuln.vulnDoc._id } INTO certifyVulnEdges OPTIONS { overwriteMode: "ignore" }
		  
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
			'certifyVuln_id': certifyVuln._id,
     		'timeScanned': certifyVuln.timeScanned,
			'dbUri': certifyVuln.dbUri,
			'dbVersion': certifyVuln.dbVersion,
			'scannerUri': certifyVuln.scannerUri,
			'scannerVersion': certifyVuln.scannerVersion,
			'collector': certifyVuln.collector,
			'origin': certifyVuln.origin
		  }`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getCertifyVulnQueryValues(&pkg, &vulnerability, &certifyVuln), "IngestCertifyVuln")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest certifyVuln: %w", err)
	}
	defer cursor.Close()

	certifyVulnList, err := geCertifyVulnFromCursor(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get certifyVulns from arango cursor: %w", err)
	}

	if len(certifyVulnList) == 1 {
		return certifyVulnList[0], nil
	} else {
		return nil, fmt.Errorf("number of certifyVulns ingested is greater than one")
	}
}

func geCertifyVulnFromCursor(ctx context.Context, cursor driver.Cursor) ([]*model.CertifyVuln, error) {
	type collectedData struct {
		PkgVersion     *dbPkgVersion `json:"pkgVersion"`
		Vulnerability  *dbVulnID     `json:"vulnerability"`
		CertifyVulnID  string        `json:"certifyVuln_id"`
		TimeScanned    time.Time     `json:"timeScanned"`
		DbUri          string        `json:"dbUri"`
		DbVersion      string        `json:"dbVersion"`
		ScannerUri     string        `json:"scannerUri"`
		ScannerVersion string        `json:"scannerVersion"`
		Collector      string        `json:"collector"`
		Origin         string        `json:"origin"`
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

	var certifyVulnList []*model.CertifyVuln
	for _, createdValue := range createdValues {
		pkg := generateModelPackage(createdValue.PkgVersion.TypeID, createdValue.PkgVersion.PkgType, createdValue.PkgVersion.NamespaceID, createdValue.PkgVersion.Namespace, createdValue.PkgVersion.NameID,
			createdValue.PkgVersion.Name, createdValue.PkgVersion.VersionID, createdValue.PkgVersion.Version, createdValue.PkgVersion.Subpath, createdValue.PkgVersion.QualifierList)

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

		certifyVuln := &model.CertifyVuln{
			ID:            createdValue.CertifyVulnID,
			Package:       pkg,
			Vulnerability: vuln,
			Metadata: &model.ScanMetadata{
				TimeScanned:    createdValue.TimeScanned,
				DbURI:          createdValue.DbUri,
				DbVersion:      createdValue.DbVersion,
				ScannerURI:     createdValue.ScannerUri,
				ScannerVersion: createdValue.ScannerVersion,
				Origin:         createdValue.Origin,
				Collector:      createdValue.Collector,
			},
		}
		certifyVulnList = append(certifyVulnList, certifyVuln)
	}
	return certifyVulnList, nil
}

func (c *arangoClient) buildCertifyVulnByID(ctx context.Context, id string, filter *model.CertifyVulnSpec) (*model.CertifyVuln, error) {
	if filter != nil && filter.ID != nil {
		if *filter.ID != id {
			return nil, fmt.Errorf("ID does not match filter")
		}
	}

	idSplit := strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	if idSplit[0] == certifyVulnsStr {
		if filter != nil {
			filter.ID = ptrfrom.String(id)
		} else {
			filter = &model.CertifyVulnSpec{
				ID: ptrfrom.String(id),
			}
		}
		return c.queryCertifyVulnNodeByID(ctx, filter)
	} else {
		return nil, fmt.Errorf("id type does not match for certifyVuln query: %s", id)
	}
}

func (c *arangoClient) queryCertifyVulnNodeByID(ctx context.Context, filter *model.CertifyVulnSpec) (*model.CertifyVuln, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(certifyVulnsStr, "certifyVuln")
	setCertifyVulnMatchValues(arangoQueryBuilder, filter, values)
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN certifyVuln`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "queryCertifyVulnNodeByID")
	if err != nil {
		return nil, fmt.Errorf("failed to query for certifyVuln: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type dbVuln struct {
		CertifyVulnID   string    `json:"_id"`
		PackageID       *string   `json:"packageID"`
		VulnerabilityID string    `json:"vulnerabilityID"`
		TimeScanned     time.Time `json:"timeScanned"`
		DbUri           string    `json:"dbUri"`
		DbVersion       string    `json:"dbVersion"`
		ScannerUri      string    `json:"scannerUri"`
		ScannerVersion  string    `json:"scannerVersion"`
		Collector       string    `json:"collector"`
		Origin          string    `json:"origin"`
	}

	var collectedValues []dbVuln
	for {
		var doc dbVuln
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to certifyVuln from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, fmt.Errorf("number of certifyVuln nodes found for ID: %s is greater than one", *filter.ID)
	}

	certifyVuln := &model.CertifyVuln{
		ID: collectedValues[0].CertifyVulnID,
		Metadata: &model.ScanMetadata{
			TimeScanned:    collectedValues[0].TimeScanned,
			DbURI:          collectedValues[0].DbUri,
			DbVersion:      collectedValues[0].DbVersion,
			ScannerURI:     collectedValues[0].ScannerUri,
			ScannerVersion: collectedValues[0].ScannerVersion,
			Origin:         collectedValues[0].Origin,
			Collector:      collectedValues[0].Collector,
		},
	}

	builtVuln, err := c.buildVulnResponseByID(ctx, collectedValues[0].VulnerabilityID, filter.Vulnerability)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability from ID: %s, with error: %w", collectedValues[0].VulnerabilityID, err)
	}
	certifyVuln.Vulnerability = builtVuln

	builtPackage, err := c.buildPackageResponseFromID(ctx, *collectedValues[0].PackageID, filter.Package)
	if err != nil {
		return nil, fmt.Errorf("failed to get package from ID: %s, with error: %w", *collectedValues[0].PackageID, err)
	}

	certifyVuln.Package = builtPackage

	return certifyVuln, nil
}

func (c *arangoClient) certifyVulnNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := make([]string, 0, 2)
	if allowedEdges[model.EdgeCertifyVulnPackage] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(certifyVulnsStr, "certifyVuln")
		setCertifyVulnMatchValues(arangoQueryBuilder, &model.CertifyVulnSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  certifyVuln.packageID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "certifyVulnNeighbors - package")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeCertifyVulnVulnerability] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(certifyVulnsStr, "certifyVuln")
		setCertifyVulnMatchValues(arangoQueryBuilder, &model.CertifyVulnSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  certifyVuln.vulnerabilityID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "certifyVulnNeighbors - vulnerability")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}

	return out, nil
}
