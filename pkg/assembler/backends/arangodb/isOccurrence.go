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

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Query IsOccurrence
func (c *arangoClient) IsOccurrence(ctx context.Context, isOccurrenceSpec *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {
	return []*model.IsOccurrence{}, fmt.Errorf("not implemented: IsOccurrence")
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
		if len(subjects.Packages) != len(artifacts) {
			return nil, fmt.Errorf("uneven packages and artifacts for ingestion")
		} else if len(subjects.Packages) != len(occurrences) {
			return nil, fmt.Errorf("uneven packages and occurrence for ingestion")
		}

		listOfValues := []map[string]any{}

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
		  
		  LET edgeCollection = (FOR edgeData IN [
			{fromKey: isOccurrence._key, toKey: artifact._key, from: isOccurrence._id, to: artifact._id, label: "has_occurrence"}, 
			{fromKey: firstPkg.versionDoc._key, toKey: isOccurrence._key, from: firstPkg.versionDoc._id, to: isOccurrence._id, label: "subject"}]
		
		  INSERT { _key: CONCAT("isOccurrencesEdges", edgeData.fromKey, edgeData.toKey), _from: edgeData.from, _to: edgeData.to, label : edgeData.label } INTO isOccurrencesEdges OPTIONS { overwriteMode: "ignore" }
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

	} else if len(subjects.Sources) > 0 {
		if len(subjects.Sources) != len(artifacts) {
			return nil, fmt.Errorf("uneven sources and artifacts for ingestion")
		} else if len(subjects.Sources) != len(occurrences) {
			return nil, fmt.Errorf("uneven sources and occurrence for ingestion")
		}

		listOfValues := []map[string]any{}

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
		  
		  LET edgeCollection = (FOR edgeData IN [
			{fromKey: isOccurrence._key, toKey: artifact._key, from: isOccurrence._id, to: artifact._id, label: "has_occurrence"}, 
			{fromKey: firstSrc.nameDoc._key, toKey: isOccurrence._key, from: firstSrc.name_id, to: isOccurrence._id, label: "subject"}]
		
		  INSERT { _key: CONCAT("isOccurrencesEdges", edgeData.fromKey, edgeData.toKey), _from: edgeData.from, _to: edgeData.to, label : edgeData.label } INTO isOccurrencesEdges OPTIONS { overwriteMode: "ignore" }
		  )
		  
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
		isOccurrenceList, err := getSrcIsOccurrence(ctx, cursor)
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
	  
	LET edgeCollection = (FOR edgeData IN [
		{fromKey: isOccurrence._key, toKey: artifact._key, from: isOccurrence._id, to: artifact._id, label: "has_occurrence"}, 
		{fromKey: firstPkg.versionDoc._key, toKey: isOccurrence._key, from: firstPkg.versionDoc._id, to: isOccurrence._id, label: "subject"}]
	
	  INSERT { _key: CONCAT("isOccurrencesEdges", edgeData.fromKey, edgeData.toKey), _from: edgeData.from, _to: edgeData.to, label : edgeData.label } INTO isOccurrencesEdges OPTIONS { overwriteMode: "ignore" }
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

		isOccurrenceList, err := getPkgIsOccurrence(ctx, cursor)
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
		  
		  LET edgeCollection = (FOR edgeData IN [
			{fromKey: isOccurrence._key, toKey: artifact._key, from: isOccurrence._id, to: artifact._id, label: "has_occurrence"}, 
			{fromKey: firstSrc.nameDoc._key, toKey: isOccurrence._key, from: firstSrc.name_id, to: isOccurrence._id, label: "subject"}]
		
		  INSERT { _key: CONCAT("isOccurrencesEdges", edgeData.fromKey, edgeData.toKey), _from: edgeData.from, _to: edgeData.to, label : edgeData.label } INTO isOccurrencesEdges OPTIONS { overwriteMode: "ignore" }
		  )
		  
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

		isOccurrenceList, err := getSrcIsOccurrence(ctx, cursor)
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

func getPkgIsOccurrence(ctx context.Context, cursor driver.Cursor) ([]*model.IsOccurrence, error) {
	type collectedData struct {
		PkgVersion struct {
			TypeID        string   `json:"type_id"`
			PkgType       string   `json:"type"`
			NamespaceID   string   `json:"namespace_id"`
			Namespace     string   `json:"namespace"`
			NameID        string   `json:"name_id"`
			Name          string   `json:"name"`
			VersionID     string   `json:"version_id"`
			Version       string   `json:"version"`
			Subpath       string   `json:"subpath"`
			QualifierList []string `json:"qualifier_list"`
		} `json:"pkgVersion"`
		Artifact       model.Artifact `json:"artifact"`
		IsOccurrenceID string         `json:"isOccurrence_id"`
		Justification  string         `json:"justification"`
		Collector      string         `json:"collector"`
		Origin         string         `json:"origin"`
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
		pkg := generateModelPackage(createdValue.PkgVersion.TypeID, createdValue.PkgVersion.PkgType, createdValue.PkgVersion.NamespaceID, createdValue.PkgVersion.Namespace, createdValue.PkgVersion.NameID,
			createdValue.PkgVersion.Name, &createdValue.PkgVersion.VersionID, &createdValue.PkgVersion.Version, &createdValue.PkgVersion.Subpath, createdValue.PkgVersion.QualifierList)

		isOccurrence := &model.IsOccurrence{
			ID:        createdValue.IsOccurrenceID,
			Subject:   pkg,
			Artifact:  &createdValue.Artifact,
			Origin:    createdValue.Collector,
			Collector: createdValue.Origin,
		}
		isOccurrenceList = append(isOccurrenceList, isOccurrence)
	}
	return isOccurrenceList, nil
}

func getSrcIsOccurrence(ctx context.Context, cursor driver.Cursor) ([]*model.IsOccurrence, error) {
	type collectedData struct {
		SrcName struct {
			TypeID      string `json:"type_id"`
			SrcType     string `json:"type"`
			NamespaceID string `json:"namespace_id"`
			Namespace   string `json:"namespace"`
			NameID      string `json:"name_id"`
			Name        string `json:"name"`
			Commit      string `json:"commit"`
			Tag         string `json:"tag"`
		} `json:"srcName"`
		Artifact       model.Artifact `json:"artifact"`
		IsOccurrenceID string         `json:"isOccurrence_id"`
		Justification  string         `json:"justification"`
		Collector      string         `json:"collector"`
		Origin         string         `json:"origin"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to get source occurrence from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var isOccurrenceList []*model.IsOccurrence
	for _, createdValue := range createdValues {
		src := generateModelSource(createdValue.SrcName.TypeID, createdValue.SrcName.SrcType, createdValue.SrcName.NamespaceID, createdValue.SrcName.Namespace,
			createdValue.SrcName.NameID, createdValue.SrcName.Name, createdValue.SrcName.Commit, createdValue.SrcName.Tag)

		isOccurrence := &model.IsOccurrence{
			ID:        createdValue.IsOccurrenceID,
			Subject:   src,
			Artifact:  &createdValue.Artifact,
			Origin:    createdValue.Collector,
			Collector: createdValue.Origin,
		}
		isOccurrenceList = append(isOccurrenceList, isOccurrence)
	}
	return isOccurrenceList, nil
}
