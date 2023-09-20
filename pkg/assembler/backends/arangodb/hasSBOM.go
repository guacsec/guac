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

func (c *arangoClient) HasSBOM(ctx context.Context, hasSBOMSpec *model.HasSBOMSpec) ([]*model.HasSbom, error) {

	if hasSBOMSpec != nil && hasSBOMSpec.ID != nil {
		sbom, err := c.buildHasSbomByID(ctx, *hasSBOMSpec.ID, hasSBOMSpec)
		if err != nil {
			return nil, fmt.Errorf("buildHasSbomByID failed with an error: %w", err)
		}
		return []*model.HasSbom{sbom}, nil
	}

	// TODO (pxp928): Optimize/add other queries based on input and starting node/edge for most efficient retrieval
	var arangoQueryBuilder *arangoQueryBuilder
	if hasSBOMSpec.Subject != nil {
		var combinedHasSBOM []*model.HasSbom
		if hasSBOMSpec.Subject.Package != nil {
			values := map[string]any{}
			arangoQueryBuilder = setPkgVersionMatchValues(hasSBOMSpec.Subject.Package, values)
			arangoQueryBuilder.forOutBound(hasSBOMPkgEdgesStr, "hasSBOM", "pVersion")
			setHasSBOMMatchValues(arangoQueryBuilder, hasSBOMSpec, values)

			pkgVersionHasSboms, err := getPkgHasSBOMForQuery(ctx, c, arangoQueryBuilder, values)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve package version hasSBOM with error: %w", err)
			}

			combinedHasSBOM = append(combinedHasSBOM, pkgVersionHasSboms...)
		}
		if hasSBOMSpec.Subject.Artifact != nil {
			values := map[string]any{}
			arangoQueryBuilder = setArtifactMatchValues(hasSBOMSpec.Subject.Artifact, values)
			arangoQueryBuilder.forOutBound(hasSBOMArtEdgesStr, "hasSBOM", "art")
			setHasSBOMMatchValues(arangoQueryBuilder, hasSBOMSpec, values)

			artHasSboms, err := getArtifactHasSBOMForQuery(ctx, c, arangoQueryBuilder, values)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve artifact hasSBOM with error: %w", err)
			}
			combinedHasSBOM = append(combinedHasSBOM, artHasSboms...)
		}
		return combinedHasSBOM, nil
	} else {
		values := map[string]any{}
		var combinedHasSBOM []*model.HasSbom

		// get packages
		arangoQueryBuilder = newForQuery(hasSBOMsStr, "hasSBOM")
		setHasSBOMMatchValues(arangoQueryBuilder, hasSBOMSpec, values)
		arangoQueryBuilder.forInBound(hasSBOMPkgEdgesStr, "pVersion", "hasSBOM")
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "pName", "pVersion")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")

		pkgHasSBOMs, err := getPkgHasSBOMForQuery(ctx, c, arangoQueryBuilder, values)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve package SBOMs with error: %w", err)
		}
		combinedHasSBOM = append(combinedHasSBOM, pkgHasSBOMs...)

		// get artifacts
		arangoQueryBuilder = newForQuery(hasSBOMsStr, "hasSBOM")
		setHasSBOMMatchValues(arangoQueryBuilder, hasSBOMSpec, values)
		arangoQueryBuilder.forInBound(hasSBOMArtEdgesStr, "art", "hasSBOM")

		artifactHasSBOMs, err := getArtifactHasSBOMForQuery(ctx, c, arangoQueryBuilder, values)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve artifact SBOMs with error: %w", err)
		}
		combinedHasSBOM = append(combinedHasSBOM, artifactHasSBOMs...)

		return combinedHasSBOM, nil
	}
}

func getPkgHasSBOMForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.HasSbom, error) {
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
		'hasSBOM_id': hasSBOM._id,
		'uri': hasSBOM.uri,
		'algorithm': hasSBOM.algorithm,
		'digest': hasSBOM.digest,
		'downloadLocation': hasSBOM.downloadLocation,
		'collector': hasSBOM.collector,
		'knownSince': hasSBOM.knownSince,
		'origin': hasSBOM.origin  
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "HasSBOM")
	if err != nil {
		return nil, fmt.Errorf("failed to query for HasSBOM: %w", err)
	}
	defer cursor.Close()

	return getHasSBOMFromCursor(ctx, cursor)
}

func getArtifactHasSBOMForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.HasSbom, error) {
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'artifact': {
			'id': art._id,
			'algorithm': art.algorithm,
			'digest': art.digest
		},
		'hasSBOM_id': hasSBOM._id,
		'uri': hasSBOM.uri,
		'algorithm': hasSBOM.algorithm,
		'digest': hasSBOM.digest,
		'downloadLocation': hasSBOM.downloadLocation,
		'collector': hasSBOM.collector,
		'knownSince': hasSBOM.knownSince,
		'origin': hasSBOM.origin  
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "HasSBOM")
	if err != nil {
		return nil, fmt.Errorf("failed to query for HasSBOM: %w", err)
	}
	defer cursor.Close()

	return getHasSBOMFromCursor(ctx, cursor)
}

func setHasSBOMMatchValues(arangoQueryBuilder *arangoQueryBuilder, hasSBOMSpec *model.HasSBOMSpec, queryValues map[string]any) {
	if hasSBOMSpec.ID != nil {
		arangoQueryBuilder.filter("hasSBOM", "_id", "==", "@id")
		queryValues["id"] = *hasSBOMSpec.ID
	}
	if hasSBOMSpec.URI != nil {
		arangoQueryBuilder.filter("hasSBOM", "uri", "==", "@uri")
		queryValues["uri"] = *hasSBOMSpec.URI
	}
	if hasSBOMSpec.Algorithm != nil {
		arangoQueryBuilder.filter("hasSBOM", "algorithm", "==", "@algorithm")
		queryValues["algorithm"] = strings.ToLower(*hasSBOMSpec.Algorithm)
	}
	if hasSBOMSpec.Digest != nil {
		arangoQueryBuilder.filter("hasSBOM", "digest", "==", "@digest")
		queryValues["digest"] = strings.ToLower(*hasSBOMSpec.Digest)
	}
	if hasSBOMSpec.DownloadLocation != nil {
		arangoQueryBuilder.filter("hasSBOM", "downloadLocation", "==", "@downloadLocation")
		queryValues["downloadLocation"] = *hasSBOMSpec.DownloadLocation
	}
	if hasSBOMSpec.Origin != nil {
		arangoQueryBuilder.filter("hasSBOM", origin, "==", "@"+origin)
		queryValues[origin] = *hasSBOMSpec.Origin
	}
	if hasSBOMSpec.Collector != nil {
		arangoQueryBuilder.filter("hasSBOM", collector, "==", "@"+collector)
		queryValues[collector] = *hasSBOMSpec.Collector
	}
	if hasSBOMSpec.KnownSince != nil {
		hasSBOMKnownSince := *hasSBOMSpec.KnownSince
		arangoQueryBuilder.filter("hasSBOM", "knownSince", ">=", "@"+knownSince)
		queryValues[knownSince] = hasSBOMKnownSince.UTC()
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
	values["algorithm"] = strings.ToLower(hasSbom.Algorithm)
	values["digest"] = strings.ToLower(hasSbom.Digest)
	values["downloadLocation"] = hasSbom.DownloadLocation
	values["origin"] = hasSbom.Origin
	values["collector"] = hasSbom.Collector
	values[knownSince] = hasSbom.KnownSince.UTC()

	return values
}

func (c *arangoClient) IngestHasSBOMs(ctx context.Context, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec, includes []*model.HasSBOMIncludesInputSpec) ([]*model.HasSbom, error) {
	// TODO(knrc) - handle includes
	if len(subjects.Packages) > 0 {
		var listOfValues []map[string]any

		for i := range subjects.Packages {
			listOfValues = append(listOfValues, getHasSBOMQueryValues(subjects.Packages[i], nil, hasSBOMs[i]))
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
		  
		  LET hasSBOM = FIRST(
			  UPSERT {  packageID:firstPkg.version_id, uri:doc.uri, algorithm:doc.algorithm, digest:doc.digest, downloadLocation:doc.downloadLocation, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				  INSERT {  packageID:firstPkg.version_id, uri:doc.uri, algorithm:doc.algorithm, digest:doc.digest, downloadLocation:doc.downloadLocation, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				  UPDATE {} IN hasSBOMs
				  RETURN NEW
		  )
		  
		  LET edgeCollection = (
			INSERT {  _key: CONCAT("hasSBOMPkgEdges", firstPkg.versionDoc._key, hasSBOM._key), _from: firstPkg.version_id, _to: hasSBOM._id } INTO hasSBOMPkgEdges OPTIONS { overwriteMode: "ignore" }
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
			'knownSince': hasSBOM.knownSince,
			'origin': hasSBOM.origin  
		  }`

		sb.WriteString(query)

		cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestHasSBOMs")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest package hasSBOMs: %w", err)
		}
		defer cursor.Close()

		hasSBOMList, err := getHasSBOMFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get hasSBOMs from arango cursor: %w", err)
		}

		return hasSBOMList, nil

	} else if len(subjects.Artifacts) > 0 {

		var listOfValues []map[string]any

		for i := range subjects.Artifacts {
			listOfValues = append(listOfValues, getHasSBOMQueryValues(nil, subjects.Artifacts[i], hasSBOMs[i]))
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
		  
		LET hasSBOM = FIRST(
			UPSERT { artifactID:artifact._id, uri:doc.uri, algorithm:doc.algorithm, digest:doc.digest, downloadLocation:doc.downloadLocation, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				INSERT { artifactID:artifact._id, uri:doc.uri, algorithm:doc.algorithm, digest:doc.digest, downloadLocation:doc.downloadLocation, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				UPDATE {} IN hasSBOMs
				RETURN NEW
		)
		
		LET edgeCollection = (
		  INSERT {  _key: CONCAT("hasSBOMArtEdges", artifact._key, hasSBOM._key), _from: artifact._id, _to: hasSBOM._id } INTO hasSBOMArtEdges OPTIONS { overwriteMode: "ignore" }
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
		  'knownSince': hasSBOM.knownSince,
		  'origin': hasSBOM.origin  
		}`

		sb.WriteString(query)

		cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestHasSBOMs")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest artifact hasSBOM: %w", err)
		}
		defer cursor.Close()
		hasSBOMList, err := getHasSBOMFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get hasSBOM from arango cursor: %w", err)
		}

		return hasSBOMList, nil

	} else {
		return nil, fmt.Errorf("packages or artifacts not specified for IngestHasSBOMs")
	}
}

func (c *arangoClient) IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, hasSbom model.HasSBOMInputSpec, includes model.HasSBOMIncludesInputSpec) (*model.HasSbom, error) {
	// TODO(knrc) - handle includes
	if subject.Artifact != nil {
		query := `LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == @art_algorithm FILTER art.digest == @art_digest RETURN art)
		  
		  LET hasSBOM = FIRST(
			  UPSERT { artifactID:artifact._id, uri:@uri, algorithm:@algorithm, digest:@digest, downloadLocation:@downloadLocation, collector:@collector, origin:@origin, knownSince:@knownSince } 
				  INSERT { artifactID:artifact._id, uri:@uri, algorithm:@algorithm, digest:@digest, downloadLocation:@downloadLocation, collector:@collector, origin:@origin, knownSince:@knownSince } 
				  UPDATE {} IN hasSBOMs
				  RETURN NEW
		  )
		  
		  LET edgeCollection = (
			INSERT {  _key: CONCAT("hasSBOMArtEdges", artifact._key, hasSBOM._key), _from: artifact._id, _to: hasSBOM._id } INTO hasSBOMArtEdges OPTIONS { overwriteMode: "ignore" }
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
			'knownSince': hasSBOM.knownSince,
			'origin': hasSBOM.origin  
		  }`

		cursor, err := executeQueryWithRetry(ctx, c.db, query, getHasSBOMQueryValues(nil, subject.Artifact, &hasSbom), "IngestHasSbom - Artifact")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest hasSBOM: %w", err)
		}
		defer cursor.Close()
		hasSBOMList, err := getHasSBOMFromCursor(ctx, cursor)
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
			  UPSERT {  packageID:firstPkg.version_id, uri:@uri, algorithm:@algorithm, digest:@digest, downloadLocation:@downloadLocation, collector:@collector, origin:@origin, knownSince:@knownSince } 
				  INSERT {  packageID:firstPkg.version_id, uri:@uri, algorithm:@algorithm, digest:@digest, downloadLocation:@downloadLocation, collector:@collector, origin:@origin, knownSince:@knownSince } 
				  UPDATE {} IN hasSBOMs
				  RETURN NEW
		  )
		  
		  LET edgeCollection = (
			INSERT {  _key: CONCAT("hasSBOMPkgEdges", firstPkg.versionDoc._key, hasSBOM._key), _from: firstPkg.version_id, _to: hasSBOM._id } INTO hasSBOMPkgEdges OPTIONS { overwriteMode: "ignore" }
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
			'knownSince': hasSBOM.knownSince,
			'origin': hasSBOM.origin  
		  }`

		cursor, err := executeQueryWithRetry(ctx, c.db, query, getHasSBOMQueryValues(subject.Package, nil, &hasSbom), "IngestHasSbom - Package")
		if err != nil {
			return nil, fmt.Errorf("failed to create ingest hasSBOM: %w", err)
		}
		defer cursor.Close()

		hasSBOMList, err := getHasSBOMFromCursor(ctx, cursor)
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

func getHasSBOMFromCursor(ctx context.Context, cursor driver.Cursor) ([]*model.HasSbom, error) {
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
		KnownSince       time.Time       `json:"knownSince"`
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
		var pkg *model.Package = nil
		if createdValue.PkgVersion != nil {
			pkg = generateModelPackage(createdValue.PkgVersion.TypeID, createdValue.PkgVersion.PkgType, createdValue.PkgVersion.NamespaceID, createdValue.PkgVersion.Namespace, createdValue.PkgVersion.NameID,
				createdValue.PkgVersion.Name, createdValue.PkgVersion.VersionID, createdValue.PkgVersion.Version, createdValue.PkgVersion.Subpath, createdValue.PkgVersion.QualifierList)
		}

		hasSBOM := &model.HasSbom{
			ID:               createdValue.HasSBOMId,
			URI:              createdValue.Uri,
			Algorithm:        createdValue.Algorithm,
			Digest:           createdValue.Digest,
			DownloadLocation: createdValue.DownloadLocation,
			Origin:           createdValue.Collector,
			Collector:        createdValue.Origin,
			KnownSince:       createdValue.KnownSince,
		}
		if pkg != nil {
			hasSBOM.Subject = pkg
		} else if createdValue.Artifact != nil {
			hasSBOM.Subject = createdValue.Artifact
		} else {
			return nil, fmt.Errorf("failed to get subject from cursor for hasSBOM")
		}
		hasSBOMList = append(hasSBOMList, hasSBOM)
	}
	return hasSBOMList, nil
}

func (c *arangoClient) buildHasSbomByID(ctx context.Context, id string, filter *model.HasSBOMSpec) (*model.HasSbom, error) {
	if filter != nil && filter.ID != nil {
		if *filter.ID != id {
			return nil, fmt.Errorf("ID does not match filter")
		}
	}

	idSplit := strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	if idSplit[0] == hasSBOMsStr {
		if filter != nil {
			filter.ID = ptrfrom.String(id)
		} else {
			filter = &model.HasSBOMSpec{
				ID: ptrfrom.String(id),
			}
		}
		return c.queryHasSbomNodeByID(ctx, filter)
	} else {
		return nil, fmt.Errorf("id type does not match for hasSBOM query: %s", id)
	}
}

func (c *arangoClient) queryHasSbomNodeByID(ctx context.Context, filter *model.HasSBOMSpec) (*model.HasSbom, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(hasSBOMsStr, "hasSBOM")
	setHasSBOMMatchValues(arangoQueryBuilder, filter, values)
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN hasSBOM`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "queryHasSbomNodeByID")
	if err != nil {
		return nil, fmt.Errorf("failed to query for hasSBOM: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type dbHasSbom struct {
		HasSbomID        string  `json:"_id"`
		PackageID        *string `json:"packageID"`
		ArtifactID       *string `json:"artifactID"`
		Uri              string  `json:"uri"`
		Algorithm        string  `json:"algorithm"`
		Digest           string  `json:"digest"`
		DownloadLocation string  `json:"downloadLocation"`
		Collector        string  `json:"collector"`
		Origin           string  `json:"origin"`
	}

	var collectedValues []dbHasSbom
	for {
		var doc dbHasSbom
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to hasSBOM from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, fmt.Errorf("number of hasSBOM nodes found for ID: %s is greater than one", *filter.ID)
	}

	hasSBOM := &model.HasSbom{
		ID:               collectedValues[0].HasSbomID,
		URI:              collectedValues[0].Uri,
		Algorithm:        collectedValues[0].Algorithm,
		Digest:           collectedValues[0].Digest,
		DownloadLocation: collectedValues[0].DownloadLocation,
		Origin:           collectedValues[0].Origin,
		Collector:        collectedValues[0].Collector,
	}

	if collectedValues[0].PackageID != nil {
		var builtPackage *model.Package
		if filter.Subject != nil && filter.Subject.Package != nil {
			builtPackage, err = c.buildPackageResponseFromID(ctx, *collectedValues[0].PackageID, filter.Subject.Package)
			if err != nil {
				return nil, fmt.Errorf("failed to get package from ID: %s, with error: %w", *collectedValues[0].PackageID, err)
			}
		} else {
			builtPackage, err = c.buildPackageResponseFromID(ctx, *collectedValues[0].PackageID, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to get package from ID: %s, with error: %w", *collectedValues[0].PackageID, err)
			}
		}
		hasSBOM.Subject = builtPackage
	} else if collectedValues[0].ArtifactID != nil {
		var builtArtifact *model.Artifact
		if filter.Subject != nil && filter.Subject.Artifact != nil {
			builtArtifact, err = c.buildArtifactResponseByID(ctx, *collectedValues[0].ArtifactID, filter.Subject.Artifact)
			if err != nil {
				return nil, fmt.Errorf("failed to get artifact from ID: %s, with error: %w", *collectedValues[0].ArtifactID, err)
			}
		} else {
			builtArtifact, err = c.buildArtifactResponseByID(ctx, *collectedValues[0].ArtifactID, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to get artifact from ID: %s, with error: %w", *collectedValues[0].ArtifactID, err)
			}
		}
		hasSBOM.Subject = builtArtifact
	} else {
		return nil, fmt.Errorf("failed to get subject from hasSBOM")
	}
	return hasSBOM, nil
}

func (c *arangoClient) hasSbomNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := make([]string, 0, 1)

	if allowedEdges[model.EdgeHasSbomPackage] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(hasSBOMsStr, "hasSBOM")
		setHasSBOMMatchValues(arangoQueryBuilder, &model.HasSBOMSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  hasSBOM.packageID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "hasSbomNeighbors - package")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeHasSbomArtifact] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(hasSBOMsStr, "hasSBOM")
		setHasSBOMMatchValues(arangoQueryBuilder, &model.HasSBOMSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  hasSBOM.artifactID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "hasSbomNeighbors - artifact")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}

	return out, nil
}
