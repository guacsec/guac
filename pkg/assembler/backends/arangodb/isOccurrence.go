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

// Query IsOccurrence
func (c *arangoClient) IsOccurrence(ctx context.Context, isOccurrenceSpec *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {

	// TODO (pxp928): Optimization of the query can be done by starting from the occurrence artifact node (if specified)
	var arangoQueryBuilder *arangoQueryBuilder
	if isOccurrenceSpec.Subject != nil {
		var combinedOccurrence []*model.IsOccurrence
		if isOccurrenceSpec.Subject.Package != nil {
			values := map[string]any{}

			arangoQueryBuilder = setPkgVersionMatchValues(isOccurrenceSpec.Subject.Package, values)
			arangoQueryBuilder.forOutBound(isOccurrenceSubjectPkgEdgesStr, "isOccurrence", "pVersion")
			setIsOccurrenceMatchValues(arangoQueryBuilder, isOccurrenceSpec, values)

			pkgVersionOccurrences, err := getPkgOccurrencesForQuery(ctx, c, arangoQueryBuilder, values)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve package version occurrences with error: %w", err)
			}

			combinedOccurrence = append(combinedOccurrence, pkgVersionOccurrences...)
		}
		if isOccurrenceSpec.Subject.Source != nil {
			values := map[string]any{}

			arangoQueryBuilder = setSrcMatchValues(isOccurrenceSpec.Subject.Source, values)
			arangoQueryBuilder.forOutBound(isOccurrenceSubjectSrcEdgesStr, "isOccurrence", "sName")
			setIsOccurrenceMatchValues(arangoQueryBuilder, isOccurrenceSpec, values)

			srcOccurrences, err := getSrcOccurrencesForQuery(ctx, c, arangoQueryBuilder, values)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve source occurrences with error: %w", err)
			}

			combinedOccurrence = append(combinedOccurrence, srcOccurrences...)
		}
		return combinedOccurrence, nil
	} else {
		var combinedOccurrence []*model.IsOccurrence
		values := map[string]any{}
		// get packages
		arangoQueryBuilder = newForQuery(isOccurrencesStr, "isOccurrence")
		setIsOccurrenceMatchValues(arangoQueryBuilder, isOccurrenceSpec, values)
		arangoQueryBuilder.forInBound(isOccurrenceSubjectPkgEdgesStr, "pVersion", "isOccurrence")
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "pName", "pVersion")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")

		pkgIsOccurrences, err := getPkgOccurrencesForQuery(ctx, c, arangoQueryBuilder, values)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve package occurrences with error: %w", err)
		}
		combinedOccurrence = append(combinedOccurrence, pkgIsOccurrences...)

		// get sources
		values = map[string]any{}
		arangoQueryBuilder = newForQuery(isOccurrencesStr, "isOccurrence")
		setIsOccurrenceMatchValues(arangoQueryBuilder, isOccurrenceSpec, values)
		arangoQueryBuilder.forInBound(isOccurrenceSubjectSrcEdgesStr, "sName", "isOccurrence")
		arangoQueryBuilder.forInBound(srcHasNameStr, "sNs", "sName")
		arangoQueryBuilder.forInBound(srcHasNamespaceStr, "sType", "sNs")

		srcIsOccurrences, err := getSrcOccurrencesForQuery(ctx, c, arangoQueryBuilder, values)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve source occurrences with error: %w", err)
		}
		combinedOccurrence = append(combinedOccurrence, srcIsOccurrences...)

		return combinedOccurrence, nil
	}
}

func getSrcOccurrencesForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.IsOccurrence, error) {
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'srcName': {
			'type_id': sType._id,
			'type': sType.type,
			'namespace_id': sNs._id,
			'namespace': sNs.namespace,
			'name_id': sName._id,
			'name': sName.name,
			'commit': sName.commit,
			'tag': sName.tag
		},
		'artifact': {
			'id': art._id,
			'algorithm': art.algorithm,
			'digest': art.digest
		},
		'isOccurrence_id': isOccurrence._id,
		'justification': isOccurrence.justification,
		'collector': isOccurrence.collector,
		'origin': isOccurrence.origin
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "IsOccurrence")
	if err != nil {
		return nil, fmt.Errorf("failed to query for IsOccurrence: %w", err)
	}
	defer cursor.Close()

	return getIsOccurrenceFromCursor(ctx, cursor)
}

func getPkgOccurrencesForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.IsOccurrence, error) {
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
		'artifact': {
			'id': art._id,
			'algorithm': art.algorithm,
			'digest': art.digest
		},
		'isOccurrence_id': isOccurrence._id,
		'justification': isOccurrence.justification,
		'collector': isOccurrence.collector,
		'origin': isOccurrence.origin
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "IsOccurrence")
	if err != nil {
		return nil, fmt.Errorf("failed to query for IsOccurrence: %w", err)
	}
	defer cursor.Close()

	return getIsOccurrenceFromCursor(ctx, cursor)
}

func setIsOccurrenceMatchValues(arangoQueryBuilder *arangoQueryBuilder, isOccurrenceSpec *model.IsOccurrenceSpec, queryValues map[string]any) {
	if isOccurrenceSpec.ID != nil {
		arangoQueryBuilder.filter("isOccurrence", "_id", "==", "@id")
		queryValues["id"] = *isOccurrenceSpec.ID
	}
	if isOccurrenceSpec.Justification != nil {
		arangoQueryBuilder.filter("isOccurrence", justification, "==", "@"+justification)
		queryValues[justification] = *isOccurrenceSpec.Justification
	}
	if isOccurrenceSpec.Origin != nil {
		arangoQueryBuilder.filter("isOccurrence", origin, "==", "@"+origin)
		queryValues[origin] = *isOccurrenceSpec.Origin
	}
	if isOccurrenceSpec.Collector != nil {
		arangoQueryBuilder.filter("isOccurrence", collector, "==", "@"+collector)
		queryValues[collector] = *isOccurrenceSpec.Collector
	}
	arangoQueryBuilder.forOutBound(isOccurrenceArtEdgesStr, "art", "isOccurrence")
	if isOccurrenceSpec.Artifact != nil {
		if isOccurrenceSpec.Artifact.ID != nil {
			arangoQueryBuilder.filter("art", "_id", "==", "@id")
			queryValues["id"] = *isOccurrenceSpec.Artifact.ID
		}
		if isOccurrenceSpec.Artifact.Algorithm != nil {
			arangoQueryBuilder.filter("art", "algorithm", "==", "@algorithm")
			queryValues["algorithm"] = strings.ToLower(*isOccurrenceSpec.Artifact.Algorithm)
		}
		if isOccurrenceSpec.Artifact.Digest != nil {
			arangoQueryBuilder.filter("art", "digest", "==", "@digest")
			queryValues["digest"] = strings.ToLower(*isOccurrenceSpec.Artifact.Digest)
		}
	}

}

// Ingest IngestOccurrence

func getOccurrenceQueryValues(pkg *model.PkgInputSpec, src *model.SourceInputSpec, artifact *model.ArtifactInputSpec, occurrence *model.IsOccurrenceInputSpec) map[string]any {
	values := map[string]any{}
	// add guac keys
	if pkg != nil {
		pkgId := guacPkgId(*pkg)
		values["pkgVersionGuacKey"] = pkgId.VersionId
	} else {
		source := guacSrcId(*src)
		values["srcNameGuacKey"] = source.NameId
	}
	values["art_algorithm"] = strings.ToLower(artifact.Algorithm)
	values["art_digest"] = strings.ToLower(artifact.Digest)
	values[justification] = occurrence.Justification
	values[origin] = occurrence.Origin
	values[collector] = occurrence.Collector

	return values
}

func (c *arangoClient) IngestOccurrences(ctx context.Context, subjects model.PackageOrSourceInputs, artifacts []*model.ArtifactInputSpec, occurrences []*model.IsOccurrenceInputSpec) ([]*model.IsOccurrence, error) {
	if len(subjects.Packages) > 0 {
		var listOfValues []map[string]any

		for i := range subjects.Packages {
			listOfValues = append(listOfValues, getOccurrenceQueryValues(subjects.Packages[i], nil, artifacts[i], occurrences[i]))
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
		  
		  LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == doc.art_algorithm FILTER art.digest == doc.art_digest RETURN art)
		  
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

		isOccurrenceList, err := getIsOccurrenceFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get occurrences from arango cursor: %w", err)
		}

		return isOccurrenceList, nil

	} else if len(subjects.Sources) > 0 {
		var listOfValues []map[string]any

		for i := range subjects.Sources {
			listOfValues = append(listOfValues, getOccurrenceQueryValues(nil, subjects.Sources[i], artifacts[i], occurrences[i]))
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
		LET firstSrc = FIRST(
			FOR sName in srcNames
			  FILTER sName.guacKey == doc.srcNameGuacKey
			FOR sNs in srcNamespaces
			  FILTER sNs._id == sName._parent
			FOR sType in srcTypes
			  FILTER sType._id == sNs._parent
	
			RETURN {
			  'typeID': sType._id,
			  'type': sType.type,
			  'namespace_id': sNs._id,
			  'namespace': sNs.namespace,
			  'name_id': sName._id,
			  'name': sName.name,
			  'commit': sName.commit,
			  'tag': sName.tag,
			  'nameDoc': sName
			}
		)
		  
		  LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == doc.art_algorithm FILTER art.digest == doc.art_digest RETURN art)
		  
		  LET isOccurrence = FIRST(
			  UPSERT { sourceID:firstSrc.name_id, artifactID:artifact._id, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
				  INSERT { sourceID:firstSrc.name_id, artifactID:artifact._id, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
				  UPDATE {} IN isOccurrences
				  RETURN NEW
		  )
	
		  INSERT { _key: CONCAT("isOccurrenceSubjectSrcEdges", firstSrc.nameDoc._key, isOccurrence._key), _from: firstSrc.name_id, _to: isOccurrence._id } INTO isOccurrenceSubjectSrcEdges OPTIONS { overwriteMode: "ignore" }
		  INSERT { _key: CONCAT("isOccurrenceArtEdges", isOccurrence._key, artifact._key), _from: isOccurrence._id, _to: artifact._id } INTO isOccurrenceArtEdges OPTIONS { overwriteMode: "ignore" }
		  
		  RETURN {
			'srcName': {
				'type_id': firstSrc.typeID,
				'type': firstSrc.type,
				'namespace_id': firstSrc.namespace_id,
				'namespace': firstSrc.namespace,
				'name_id': firstSrc.name_id,
				'name': firstSrc.name,
				'commit': firstSrc.commit,
				'tag': firstSrc.tag
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
			return nil, fmt.Errorf("failed to ingest source occurrence: %w", err)
		}
		defer cursor.Close()
		isOccurrenceList, err := getIsOccurrenceFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get occurrences from arango cursor: %w", err)
		}

		return isOccurrenceList, nil

	} else {
		return nil, fmt.Errorf("package or source not specified for IngestOccurrence")
	}
}

func (c *arangoClient) IngestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, artifact model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec) (*model.IsOccurrence, error) {
	if subject.Package != nil {
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
	  
	LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == @art_algorithm FILTER art.digest == @art_digest RETURN art)
	  
	LET isOccurrence = FIRST(
		  UPSERT { packageID:firstPkg.versionDoc._id, artifactID:artifact._id, justification:@justification, collector:@collector, origin:@origin } 
			  INSERT { packageID:firstPkg.versionDoc._id, artifactID:artifact._id, justification:@justification, collector:@collector, origin:@origin } 
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

		cursor, err := executeQueryWithRetry(ctx, c.db, query, getOccurrenceQueryValues(subject.Package, nil, &artifact, &occurrence), "IngestOccurrence")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest package occurrence: %w", err)
		}
		defer cursor.Close()

		isOccurrenceList, err := getIsOccurrenceFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get occurrences from arango cursor: %w", err)
		}

		if len(isOccurrenceList) == 1 {
			return isOccurrenceList[0], nil
		} else {
			return nil, fmt.Errorf("number of occurrences ingested is greater than one")
		}

	} else if subject.Source != nil {
		query := `
		LET firstSrc = FIRST(
			FOR sName in srcNames
			  FILTER sName.guacKey == @srcNameGuacKey
			FOR sNs in srcNamespaces
			  FILTER sNs._id == sName._parent
			FOR sType in srcTypes
			  FILTER sType._id == sNs._parent
	
			RETURN {
			  'typeID': sType._id,
			  'type': sType.type,
			  'namespace_id': sNs._id,
			  'namespace': sNs.namespace,
			  'name_id': sName._id,
			  'name': sName.name,
			  'commit': sName.commit,
			  'tag': sName.tag,
			  'nameDoc': sName
			}
		)
		  
		  LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == @art_algorithm FILTER art.digest == @art_digest RETURN art)
		  
		  LET isOccurrence = FIRST(
			  UPSERT { sourceID:firstSrc.name_id, artifactID:artifact._id, justification:@justification, collector:@collector, origin:@origin } 
				  INSERT { sourceID:firstSrc.name_id, artifactID:artifact._id, justification:@justification, collector:@collector, origin:@origin } 
				  UPDATE {} IN isOccurrences
				  RETURN NEW
		  )

		  INSERT { _key: CONCAT("isOccurrenceSubjectSrcEdges", firstSrc.nameDoc._key, isOccurrence._key), _from: firstSrc.name_id, _to: isOccurrence._id } INTO isOccurrenceSubjectSrcEdges OPTIONS { overwriteMode: "ignore" }
		  INSERT { _key: CONCAT("isOccurrenceArtEdges", isOccurrence._key, artifact._key), _from: isOccurrence._id, _to: artifact._id } INTO isOccurrenceArtEdges OPTIONS { overwriteMode: "ignore" }
		  
		  RETURN {
			'srcName': {
				'type_id': firstSrc.typeID,
				'type': firstSrc.type,
				'namespace_id': firstSrc.namespace_id,
				'namespace': firstSrc.namespace,
				'name_id': firstSrc.name_id,
				'name': firstSrc.name,
				'commit': firstSrc.commit,
				'tag': firstSrc.tag
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

		cursor, err := executeQueryWithRetry(ctx, c.db, query, getOccurrenceQueryValues(nil, subject.Source, &artifact, &occurrence), "IngestOccurrence")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest source occurrence: %w", err)
		}
		defer cursor.Close()

		isOccurrenceList, err := getIsOccurrenceFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get occurrences from arango cursor: %w", err)
		}

		if len(isOccurrenceList) == 1 {
			return isOccurrenceList[0], nil
		} else {
			return nil, fmt.Errorf("number of occurrences ingested is greater than one")
		}

	} else {
		return nil, fmt.Errorf("package or source not specified for IngestOccurrence")
	}
}

func getIsOccurrenceFromCursor(ctx context.Context, cursor driver.Cursor) ([]*model.IsOccurrence, error) {
	type collectedData struct {
		PkgVersion     *dbPkgVersion   `json:"pkgVersion"`
		SrcName        *dbSrcName      `json:"srcName"`
		Artifact       *model.Artifact `json:"artifact"`
		IsOccurrenceID string          `json:"isOccurrence_id"`
		Justification  string          `json:"justification"`
		Collector      string          `json:"collector"`
		Origin         string          `json:"origin"`
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

	var isOccurrenceList []*model.IsOccurrence
	for _, createdValue := range createdValues {
		if createdValue.Artifact == nil {
			return nil, fmt.Errorf("failed to get artifact from cursor for isOccurrence")
		}
		var pkg *model.Package = nil
		var src *model.Source = nil
		if createdValue.PkgVersion != nil {
			pkg = generateModelPackage(createdValue.PkgVersion.TypeID, createdValue.PkgVersion.PkgType, createdValue.PkgVersion.NamespaceID, createdValue.PkgVersion.Namespace, createdValue.PkgVersion.NameID,
				createdValue.PkgVersion.Name, createdValue.PkgVersion.VersionID, createdValue.PkgVersion.Version, createdValue.PkgVersion.Subpath, createdValue.PkgVersion.QualifierList)
		} else {
			src = generateModelSource(createdValue.SrcName.TypeID, createdValue.SrcName.SrcType, createdValue.SrcName.NamespaceID, createdValue.SrcName.Namespace,
				createdValue.SrcName.NameID, createdValue.SrcName.Name, createdValue.SrcName.Commit, createdValue.SrcName.Tag)
		}

		isOccurrence := &model.IsOccurrence{
			ID:            createdValue.IsOccurrenceID,
			Artifact:      createdValue.Artifact,
			Justification: createdValue.Justification,
			Origin:        createdValue.Origin,
			Collector:     createdValue.Collector,
		}
		if pkg != nil {
			isOccurrence.Subject = pkg
		} else if src != nil {
			isOccurrence.Subject = src
		} else {
			return nil, fmt.Errorf("failed to get subject from cursor for isOccurrence")
		}
		isOccurrenceList = append(isOccurrenceList, isOccurrence)
	}
	return isOccurrenceList, nil
}
