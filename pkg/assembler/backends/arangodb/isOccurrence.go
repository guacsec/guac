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
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Query IsOccurrence
func (c *arangoClient) IsOccurrence(ctx context.Context, isOccurrenceSpec *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {
	panic(fmt.Errorf("not implemented: IsOccurrence - IsOccurrence"))
}

func generateModelIsOccurrence(subject model.PackageOrSource, artifact *model.Artifact, justification, origin, collector string) *model.IsOccurrence {
	isOccurrence := model.IsOccurrence{
		Subject:       subject,
		Artifact:      artifact,
		Justification: justification,
		Origin:        origin,
		Collector:     collector,
	}
	return &isOccurrence
}

// Ingest IngestOccurrence

func (c *arangoClient) IngestOccurrences(ctx context.Context, subject model.PackageOrSourceInputs, artifact []*model.ArtifactInputSpec, occurrence []*model.IsOccurrenceInputSpec) ([]*model.IsOccurrence, error) {

	// TODO(pxp928): currently only supporting package for testing. Will add in source once testing is completed
	if len(subject.Packages) == 0 {
		return nil, fmt.Errorf("source as a subject is currently unimplemented for the IngestOccurrence")
	}

	if len(subject.Packages) != len(artifact) {
		return nil, fmt.Errorf("uneven packages and artifacts for ingestion")
	} else if len(subject.Packages) != len(occurrence) {
		return nil, fmt.Errorf("uneven packages and occurrence for ingestion")
	}

	listOfValues := []map[string]any{}

	for i, _ := range subject.Packages {
		values := map[string]any{}

		// add guac keys
		pkgId := guacPkgId(*subject.Packages[i])
		values["pkgVersionGuacKey"] = pkgId.VersionId

		values["pkgType"] = subject.Packages[i].Type
		values["name"] = subject.Packages[i].Name
		if subject.Packages[i].Namespace != nil {
			values["namespace"] = *subject.Packages[i].Namespace
		} else {
			values["namespace"] = ""
		}
		if subject.Packages[i].Version != nil {
			values["version"] = *subject.Packages[i].Version
		} else {
			values["version"] = ""
		}
		if subject.Packages[i].Subpath != nil {
			values["subpath"] = *subject.Packages[i].Subpath
		} else {
			values["subpath"] = ""
		}

		// To ensure consistency, always sort the qualifiers by key
		qualifiersMap := map[string]string{}
		keys := []string{}
		for _, kv := range subject.Packages[i].Qualifiers {
			qualifiersMap[kv.Key] = kv.Value
			keys = append(keys, kv.Key)
		}
		sort.Strings(keys)
		qualifiers := []string{}
		for _, k := range keys {
			qualifiers = append(qualifiers, k, qualifiersMap[k])
		}
		values["qualifier"] = qualifiers

		// dependent package
		values["art_algorithm"] = strings.ToLower(artifact[i].Algorithm)
		values["art_digest"] = strings.ToLower(artifact[i].Digest)

		// isDependency

		values[justification] = occurrence[i].Justification
		values[origin] = occurrence[i].Origin
		values[collector] = occurrence[i].Collector
		listOfValues = append(listOfValues, values)
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
		FOR pVersion in PkgVersion
		  FILTER pVersion.guacKey == doc.pkgVersionGuacKey
		  FOR pName in PkgName
		  FILTER pName._id == pVersion._parent
		  FOR pNs in PkgNamespace
		  FILTER pNs._id == pName._parent
		  FOR pType in PkgType
		  FILTER pType._id == pNs._parent

			  RETURN {
			  'type': pType.type,
			  'namespace': pNs.namespace,
			  'name': pName.name,
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
		  "firstPkgType": firstPkg.type,
		  "firstPkgNamespace": firstPkg.namespace,
		  "firstPkgName": firstPkg.name,
		  "firstPkgVersion": firstPkg.version,
		  "firstPkgSubpath": firstPkg.subpath,
		  "firstPkgQualifier_list": firstPkg.qualifier_list,
		  "artAlgo": artifact.algorithm,
		  "artDigest": artifact.digest,
		  "justification": isOccurrence.justification,
		  "collector": isOccurrence.collector,
		  "origin": isOccurrence.origin
	  }`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestOccurrence")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w", err)
	}
	defer cursor.Close()

	type collectedData struct {
		FirstPkgType          string      `json:"firstPkgType"`
		FirstPkgNamespace     string      `json:"firstPkgNamespace"`
		FirstPkgName          string      `json:"firstPkgName"`
		FirstPkgVersion       string      `json:"firstPkgVersion"`
		FirstPkgSubpath       string      `json:"firstPkgSubpath"`
		FirstPkgQualifierList interface{} `json:"firstPkgQualifier_list"`
		ArtAlgo               string      `json:"artAlgo"`
		ArtDigest             string      `json:"artDigest"`
		Justification         string      `json:"justification"`
		Collector             string      `json:"collector"`
		Origin                string      `json:"origin"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to ingest occurrence: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var isOccurrenceList []*model.IsOccurrence
	for _, createdValue := range createdValues {
		pkg := generateModelPackage(createdValue.FirstPkgType, createdValue.FirstPkgNamespace,
			createdValue.FirstPkgName, createdValue.FirstPkgVersion, createdValue.FirstPkgSubpath, createdValue.FirstPkgQualifierList)

		algorithm := createdValue.ArtAlgo
		digest := createdValue.ArtDigest
		artifact := generateModelArtifact(algorithm, digest)

		isOccurrence := &model.IsOccurrence{
			Subject:   pkg,
			Artifact:  artifact,
			Origin:    createdValue.Collector,
			Collector: createdValue.Origin,
		}
		isOccurrenceList = append(isOccurrenceList, isOccurrence)

	}

	return isOccurrenceList, nil
}

func (c *arangoClient) IngestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, artifact model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec) (*model.IsOccurrence, error) {
	values := map[string]any{}

	// TODO(pxp928): currently only supporting package for testing. Will add in source once testing is completed
	if subject.Package == nil {
		return nil, fmt.Errorf("source as a subject is currently unimplemented for the IngestOccurrence")
	}

	values["pkgType"] = subject.Package.Type
	values["name"] = subject.Package.Name
	if subject.Package.Namespace != nil {
		values["namespace"] = *subject.Package.Namespace
	} else {
		values["namespace"] = ""
	}
	if subject.Package.Version != nil {
		values["version"] = *subject.Package.Version
	} else {
		values["version"] = ""
	}
	if subject.Package.Subpath != nil {
		values["subpath"] = *subject.Package.Subpath
	} else {
		values["subpath"] = ""
	}

	// To ensure consistency, always sort the qualifiers by key
	qualifiersMap := map[string]string{}
	keys := []string{}
	for _, kv := range subject.Package.Qualifiers {
		qualifiersMap[kv.Key] = kv.Value
		keys = append(keys, kv.Key)
	}
	sort.Strings(keys)
	qualifiers := []string{}
	for _, k := range keys {
		qualifiers = append(qualifiers, k, qualifiersMap[k])
	}
	values["qualifier"] = qualifiers

	values["art_algorithm"] = strings.ToLower(artifact.Algorithm)
	values["art_digest"] = strings.ToLower(artifact.Digest)
	values[justification] = occurrence.Justification
	values[origin] = occurrence.Origin
	values[collector] = occurrence.Collector
	// values["typeID"] = c.pkgTypeMap[subject.Package.Type].Id
	// values["typeValue"] = c.pkgTypeMap[subject.Package.Type].PkgType

	query := `LET firstPkg = FIRST(
		FOR pkg IN Pkg
		  FILTER pkg.root == "pkg"
		  FOR pkgHasType IN OUTBOUND pkg PkgHasType
			  FILTER pkgHasType.type == @pkgType && pkgHasType._parent == pkg._id
		    FOR pkgHasNamespace IN OUTBOUND pkgHasType PkgHasNamespace
				  FILTER pkgHasNamespace.namespace == @namespace && pkgHasNamespace._parent == pkgHasType._id
			  FOR pkgHasName IN OUTBOUND pkgHasNamespace PkgHasName
					  FILTER pkgHasName.name == @name && pkgHasName._parent == pkgHasNamespace._id
				FOR pkgHasVersion IN OUTBOUND pkgHasName PkgHasVersion
						  FILTER pkgHasVersion.version == @version && pkgHasVersion.subpath == @subpath && pkgHasVersion.qualifier_list == @qualifier && pkgHasVersion._parent == pkgHasName._id
				  RETURN {
					"type": pkgHasType.type,
					"namespace": pkgHasNamespace.namespace,
					"name": pkgHasName.name,
					"version": pkgHasVersion.version,
					"subpath": pkgHasVersion.subpath,
					"qualifier_list": pkgHasVersion.qualifier_list,
					"versionDoc": pkgHasVersion
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
		  "firstPkgType": firstPkg.type,
		  "firstPkgNamespace": firstPkg.namespace,
		  "firstPkgName": firstPkg.name,
		  "firstPkgVersion": firstPkg.version,
		  "firstPkgSubpath": firstPkg.subpath,
		  "firstPkgQualifier_list": firstPkg.qualifier_list,
		  "artAlgo": artifact.algorithm,
		  "artDigest": artifact.digest,
		  "justification": isOccurrence.justification,
		  "collector": isOccurrence.collector,
		  "origin": isOccurrence.origin
	  }`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, values, "IngestOccurrence")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w", err)
	}
	defer cursor.Close()

	type collectedData struct {
		FirstPkgType          string      `json:"firstPkgType"`
		FirstPkgNamespace     string      `json:"firstPkgNamespace"`
		FirstPkgName          string      `json:"firstPkgName"`
		FirstPkgVersion       string      `json:"firstPkgVersion"`
		FirstPkgSubpath       string      `json:"firstPkgSubpath"`
		FirstPkgQualifierList interface{} `json:"firstPkgQualifier_list"`
		ArtAlgo               string      `json:"artAlgo"`
		ArtDigest             string      `json:"artDigest"`
		Justification         string      `json:"justification"`
		Collector             string      `json:"collector"`
		Origin                string      `json:"origin"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to ingest occurrence: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}
	if len(createdValues) == 1 {

		pkg := generateModelPackage(createdValues[0].FirstPkgType, createdValues[0].FirstPkgNamespace,
			createdValues[0].FirstPkgName, createdValues[0].FirstPkgVersion, createdValues[0].FirstPkgSubpath, createdValues[0].FirstPkgQualifierList)

		algorithm := createdValues[0].ArtAlgo
		digest := createdValues[0].ArtDigest
		artifact := generateModelArtifact(algorithm, digest)

		isOccurrence := &model.IsOccurrence{
			Subject:   pkg,
			Artifact:  artifact,
			Origin:    createdValues[0].Collector,
			Collector: createdValues[0].Origin,
		}

		return isOccurrence, nil
	} else {
		return nil, fmt.Errorf("number of hashEqual ingested is too great")
	}
}
