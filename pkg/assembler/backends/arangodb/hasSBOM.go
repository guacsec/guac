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

func (c *arangoClient) HasSBOM(ctx context.Context, hasSBOMSpec *model.HasSBOMSpec) ([]*model.HasSbom, error) {
	values := map[string]any{}
	var arangoQueryBuilder *arangoQueryBuilder
	if hasSBOMSpec.Subject != nil {
		if hasSBOMSpec.Subject.Package != nil {
			arangoQueryBuilder = setPkgMatchValues(hasSBOMSpec.Subject.Package, values)
			arangoQueryBuilder.ForOutBound(hasSBOMEdgesStr, "hasSBOM", "pVersion")
		} else {
			arangoQueryBuilder = setArtifactMatchValues(hasSBOMSpec.Subject.Artifact, values)
			arangoQueryBuilder.ForOutBound(hasSBOMEdgesStr, "hasSBOM", "art")
		}
	} else {
		arangoQueryBuilder = newForQuery(hasSBOMsStr, "hasSBOM")
	}

	setHasSBOMMatchValues(arangoQueryBuilder, hasSBOMSpec, values)

	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'artifact': {
			'id': art._id,
			'algorithm': art.algorithm,
			'digest': art.digest
		},
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
		'hasSBOM_id': hasSBOM._id,
		'uri': hasSBOM.uri,
		'algorithm': hasSBOM.algorithm,
		'digest': hasSBOM.digest,
		'downloadLocation': hasSBOM.downloadLocation,
		'collector': hasSBOM.collector,
		'origin': hasSBOM.origin  
	  }`)

	fmt.Println(arangoQueryBuilder.string())

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "HasSBOM")
	if err != nil {
		return nil, fmt.Errorf("failed to query for HasSBOM: %w", err)
	}
	defer cursor.Close()

	return geHasSBOMs(ctx, cursor)
}

func setHasSBOMMatchValues(arangoQueryBuilder *arangoQueryBuilder, hasSBOMSpec *model.HasSBOMSpec, queryValues map[string]any) {
	if hasSBOMSpec.URI != nil {
		arangoQueryBuilder.filter("hasSBOM", "uri", "==", "@uri")
		queryValues["uri"] = hasSBOMSpec.URI
	}
	if hasSBOMSpec.Algorithm != nil {
		arangoQueryBuilder.filter("hasSBOM", "algorithm", "==", "@algorithm")
		queryValues["algorithm"] = hasSBOMSpec.Algorithm
	}
	if hasSBOMSpec.Digest != nil {
		arangoQueryBuilder.filter("hasSBOM", "digest", "==", "@digest")
		queryValues["digest"] = hasSBOMSpec.Digest
	}
	if hasSBOMSpec.DownloadLocation != nil {
		arangoQueryBuilder.filter("hasSBOM", "downloadLocation", "==", "@downloadLocation")
		queryValues["downloadLocation"] = hasSBOMSpec.DownloadLocation
	}
	if hasSBOMSpec.Origin != nil {
		arangoQueryBuilder.filter("hasSBOM", buildTypeStr, "==", "@"+buildTypeStr)
		queryValues[origin] = hasSBOMSpec.Origin
	}
	if hasSBOMSpec.Collector != nil {
		arangoQueryBuilder.filter("hasSBOM", buildTypeStr, "==", "@"+buildTypeStr)
		queryValues[collector] = hasSBOMSpec.Collector
	}
	if hasSBOMSpec.Subject == nil {
		// get packages
		arangoQueryBuilder.ForInBound(hasSBOMEdgesStr, "pVersion", "hasSBOM")
		arangoQueryBuilder.ForInBound(pkgHasVersionStr, "pName", "pVersion")
		arangoQueryBuilder.ForInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.ForInBound(pkgHasNamespaceStr, "pType", "pNs")

		// get artifacts
		arangoQueryBuilder.ForInBound(hasSBOMEdgesStr, "art", "hasSBOM")
	}
}

func getHasSBOMQueryValues(pkg *model.PkgInputSpec, artifact *model.ArtifactInputSpec, hasSbom *model.HasSBOMInputSpec) map[string]any {
	values := map[string]any{}
	// add guac keys
	if pkg != nil {
		pkgId := guacPkgId(*pkg)
		values["pkgVersionGuacKey"] = pkgId.VersionId
	} else {
		values["art_algorithm"] = strings.ToLower(artifact.Algorithm)
		values["art_digest"] = strings.ToLower(artifact.Digest)
	}

	values["uri"] = hasSbom.URI
	values["algorithm"] = hasSbom.Algorithm
	values["digest"] = hasSbom.Digest
	values["downloadLocation"] = hasSbom.DownloadLocation
	values["origin"] = hasSbom.Origin
	values["collector"] = hasSbom.Collector

	return values
}

func (c *arangoClient) IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, hasSbom model.HasSBOMInputSpec) (*model.HasSbom, error) {
	if subject.Artifact != nil {
		query := `LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == @art_algorithm FILTER art.digest == @art_digest RETURN art)
		  
		  LET hasSBOM = FIRST(
			  UPSERT { artifactID:artifact._id, uri:@uri, algorithm:@algorithm, digest:@digest, downloadLocation:@downloadLocation, collector:@collector, origin:@origin } 
				  INSERT { uri:@uri, algorithm:@algorithm, digest:@digest, downloadLocation:@downloadLocation, collector:@collector, origin:@origin } 
				  UPDATE {} IN hasSBOMs
				  RETURN NEW
		  )
		  
		  LET edgeCollection = (
			INSERT {  _key: CONCAT("hasSBOMEdges", artifact._key, hasSBOM._key), _from: artifact._id, _to: hasSBOM._id } INTO hasSBOMEdges OPTIONS { overwriteMode: "ignore" }
		  )
		  
		  RETURN {
			'artifact': {
				'id': artifact._id,
				'algorithm': artifact.algorithm,
				'digest': artifact.digest
			},
			'hasSBOM_id': hasSBOM._id,
			'uri': hasSBOM.uri,
			'algorithm': hasSBOM.algorithm,
			'digest': hasSBOM.digest,
			'downloadLocation': hasSBOM.downloadLocation,
			'collector': hasSBOM.collector,
			'origin': hasSBOM.origin  
		  }`

		cursor, err := executeQueryWithRetry(ctx, c.db, query, getHasSBOMQueryValues(nil, subject.Artifact, &hasSbom), "IngestHasSbom - Artifact")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest hasSBOM: %w", err)
		}
		defer cursor.Close()
		hasSBOMList, err := geHasSBOMs(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get hasSBOM from arango cursor: %w", err)
		}

		if len(hasSBOMList) == 1 {
			return hasSBOMList[0], nil
		} else {
			return nil, fmt.Errorf("number of hasSBOM ingested is greater than one")
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
		  
		  LET hasSBOM = FIRST(
			  UPSERT {  packageID:firstPkg.version_id, uri:@uri, algorithm:@algorithm, digest:@digest, downloadLocation:@downloadLocation, collector:@collector, origin:@origin } 
				  INSERT {  packageID:firstPkg.version_id, uri:@uri, algorithm:@algorithm, digest:@digest, downloadLocation:@downloadLocation, collector:@collector, origin:@origin } 
				  UPDATE {} IN hasSBOMs
				  RETURN NEW
		  )
		  
		  LET edgeCollection = (
			INSERT {  _key: CONCAT("hasSBOMEdges", firstPkg.versionDoc._key, hasSBOM._key), _from: firstPkg.version_id, _to: hasSBOM._id } INTO hasSBOMEdges OPTIONS { overwriteMode: "ignore" }
		  )
		  
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
			'hasSBOM_id': hasSBOM._id,
			'uri': hasSBOM.uri,
			'algorithm': hasSBOM.algorithm,
			'digest': hasSBOM.digest,
			'downloadLocation': hasSBOM.downloadLocation,
			'collector': hasSBOM.collector,
			'origin': hasSBOM.origin  
		  }`

		cursor, err := executeQueryWithRetry(ctx, c.db, query, getHasSBOMQueryValues(subject.Package, nil, &hasSbom), "IngestHasSbom - Package")
		if err != nil {
			return nil, fmt.Errorf("failed to create ingest hasSBOM: %w", err)
		}
		defer cursor.Close()

		hasSBOMList, err := geHasSBOMs(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get hasSBOM from arango cursor: %w", err)
		}

		if len(hasSBOMList) == 1 {
			return hasSBOMList[0], nil
		} else {
			return nil, fmt.Errorf("number of hasSBOM ingested is greater than one")
		}
	}
}

func geHasSBOMs(ctx context.Context, cursor driver.Cursor) ([]*model.HasSbom, error) {
	type collectedData struct {
		PkgVersion       *dbPkgVersion   `json:"pkgVersion"`
		Artifact         *model.Artifact `json:"artifact"`
		HasSBOMId        string          `json:"hasSBOM_id"`
		Uri              string          `json:"uri"`
		Algorithm        string          `json:"algorithm"`
		Digest           string          `json:"digest"`
		DownloadLocation string          `json:"downloadLocation"`
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
				return nil, fmt.Errorf("failed to package hasSBOM from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var hasSBOMList []*model.HasSbom
	for _, createdValue := range createdValues {
		hasSBOM := &model.HasSbom{
			ID:               createdValue.HasSBOMId,
			URI:              createdValue.Uri,
			Algorithm:        createdValue.Algorithm,
			Digest:           createdValue.Digest,
			DownloadLocation: createdValue.DownloadLocation,
			Origin:           createdValue.Collector,
			Collector:        createdValue.Origin,
		}
		if createdValue.PkgVersion != nil {
			pkg := generateModelPackage(createdValue.PkgVersion.TypeID, createdValue.PkgVersion.PkgType, createdValue.PkgVersion.NamespaceID, createdValue.PkgVersion.Namespace, createdValue.PkgVersion.NameID,
				createdValue.PkgVersion.Name, &createdValue.PkgVersion.VersionID, &createdValue.PkgVersion.Version, &createdValue.PkgVersion.Subpath, createdValue.PkgVersion.QualifierList)
			hasSBOM.Subject = pkg
		} else {
			hasSBOM.Subject = createdValue.Artifact
		}
		hasSBOMList = append(hasSBOMList, hasSBOM)
	}
	return hasSBOMList, nil
}
