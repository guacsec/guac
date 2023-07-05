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

const (
	versionRange   string = "versionRange"
	dependencyType string = "dependencyType"
)

// Ingest IsDependency

func (c *arangoClient) IngestDependencies(ctx context.Context, pkg []*model.PkgInputSpec, depPkg []*model.PkgInputSpec, dependency []*model.IsDependencyInputSpec) ([]*model.IsDependency, error) {
	if len(pkg) != len(depPkg) {
		return nil, fmt.Errorf("uneven packages and dependent packages for ingestion")
	} else if len(pkg) != len(dependency) {
		return nil, fmt.Errorf("uneven packages and isDependency for ingestion")
	}

	listOfValues := []map[string]any{}

	for i := range pkg {
		values := map[string]any{}

		// add guac keys
		pkgId := guacPkgId(*pkg[i])
		depPkgId := guacPkgId(*depPkg[i])
		values["pkgVersionGuacKey"] = pkgId.VersionId
		values["secondPkgNameGuacKey"] = depPkgId.NameId

		values["pkgType"] = pkg[i].Type
		values["name"] = pkg[i].Name
		if pkg[i].Namespace != nil {
			values["namespace"] = *pkg[i].Namespace
		} else {
			values["namespace"] = ""
		}
		if pkg[i].Version != nil {
			values["version"] = *pkg[i].Version
		} else {
			values["version"] = ""
		}
		if pkg[i].Subpath != nil {
			values["subpath"] = *pkg[i].Subpath
		} else {
			values["subpath"] = ""
		}

		// To ensure consistency, always sort the qualifiers by key
		qualifiersMap := map[string]string{}
		keys := []string{}
		for _, kv := range pkg[i].Qualifiers {
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
		values["secondPkgType"] = depPkg[i].Type
		if depPkg[i].Namespace != nil {
			values["secondNamespace"] = *depPkg[i].Namespace
		} else {
			values["secondNamespace"] = ""
		}
		values["secondName"] = depPkg[i].Name

		// isDependency

		values[versionRange] = dependency[i].VersionRange
		values[dependencyType] = dependency[i].DependencyType.String()
		values[justification] = dependency[i].Justification
		values[origin] = dependency[i].Origin
		values[collector] = dependency[i].Collector
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

    LET secondPkg = FIRST(
        FOR pName in PkgName
          FILTER pName.guacKey == doc.secondPkgNameGuacKey
        FOR pNs in PkgNamespace
          FILTER pNs._id == pName._parent
        FOR pType in PkgType
          FILTER pType._id == pNs._parent

        RETURN {
          'type': pType.type,
          'namespace': pNs.namespace,
          'name': pName.name,
          'nameDoc': pName
        }
    )
		
	LET isDependency = FIRST(
		  UPSERT { packageID:firstPkg.versionDoc._id, depPackageID:secondPkg.nameDoc._id, versionRange:doc.versionRange, dependencyType:doc.dependencyType, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
			INSERT { packageID:firstPkg.versionDoc._id, depPackageID:secondPkg.nameDoc._id, versionRange:doc.versionRange, dependencyType:doc.dependencyType, justification:doc.justification, collector:doc.collector, origin:doc.origin }
			UPDATE {} IN isDependencies
			RETURN NEW
		)
		
	LET edgeCollection = (FOR edgeData IN [
		{fromKey: isDependency._key, toKey: secondPkg.nameDoc._key, from: isDependency._id, to: secondPkg.nameDoc._id, label: 'dependency'}, 
		{fromKey: firstPkg.versionDoc._key, toKey: isDependency._key, from: firstPkg.versionDoc._id, to: isDependency._id, label: 'subject'}]
	  
		INSERT { _key: CONCAT('isDependencyEdges', edgeData.fromKey, edgeData.toKey), _from: edgeData.from, _to: edgeData.to, label : edgeData.label } INTO isDependencyEdges OPTIONS { overwriteMode: 'ignore' }
		)
		
	RETURN {
		  'firstPkgType': firstPkg.type,
		  'firstPkgNamespace': firstPkg.namespace,
		  'firstPkgName': firstPkg.name,
		  'firstPkgVersion': firstPkg.version,
		  'firstPkgSubpath': firstPkg.subpath,
		  'firstPkgQualifier_list': firstPkg.qualifier_list,
		  'secondPkgType': secondPkg.type,
		  'secondPkgNamespace': secondPkg.namespace,
		  'secondPkgName': secondPkg.name,
		  'versionRange': isDependency.versionRange,
		  'dependencyType': isDependency.dependencyType,
		  'justification': isDependency.justification,
		  'collector': isDependency.collector,
		  'origin': isDependency.origin
	}`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestDependency")
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
		SecondPkgType         string      `json:"secondPkgType"`
		SecondPkgNamespace    string      `json:"secondPkgNamespace"`
		SecondPkgName         string      `json:"secondPkgName"`
		VersionRange          string      `json:"versionRange"`
		DependencyType        string      `json:"dependencyType"`
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
				return nil, fmt.Errorf("failed to ingest dependency: %w, values: %v", err, queryValues)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var isDependencyList []*model.IsDependency
	for _, createdValue := range createdValues {
		pkg, err := generateModelPackage(createdValue.FirstPkgType, createdValue.FirstPkgNamespace,
			createdValue.FirstPkgName, createdValue.FirstPkgVersion, createdValue.FirstPkgSubpath, createdValue.FirstPkgQualifierList)
		if err != nil {
			return nil, fmt.Errorf("failed to get model.package with err: %w", err)
		}
		depPkg, err := generateModelPackage(createdValue.SecondPkgType, createdValue.SecondPkgNamespace,
			createdValue.SecondPkgName, nil, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get dependent model.package with err: %w", err)
		}
		dependencyTypeEnum, err := convertDependencyTypeToEnum(createdValue.DependencyType)
		if err != nil {
			return nil, fmt.Errorf("convertDependencyTypeToEnum failed with error: %w", err)
		}

		isDependency := &model.IsDependency{
			Package:          pkg,
			DependentPackage: depPkg,
			VersionRange:     createdValue.VersionRange,
			DependencyType:   dependencyTypeEnum,
			Origin:           createdValue.Collector,
			Collector:        createdValue.Origin,
		}
		isDependencyList = append(isDependencyList, isDependency)
	}

	return isDependencyList, nil

}

func (c *arangoClient) IngestDependency(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, dependency model.IsDependencyInputSpec) (*model.IsDependency, error) {
	values := map[string]any{}

	// add guac keys
	pkgId := guacPkgId(pkg)
	depPkgId := guacPkgId(depPkg)
	values["pkgVersionGuacKey"] = pkgId.VersionId
	values["secondPkgNameGuacKey"] = depPkgId.NameId

	values[versionRange] = dependency.VersionRange
	values[dependencyType] = dependency.DependencyType.String()
	values[justification] = dependency.Justification
	values[origin] = dependency.Origin
	values[collector] = dependency.Collector

	query := `
	LET firstPkg = FIRST(
		FOR pVersion in PkgVersion
		  FILTER pVersion.guacKey == @pkgVersionGuacKey
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

    LET secondPkg = FIRST(
        FOR pName in PkgName
          FILTER pName.guacKey == @secondPkgNameGuacKey
        FOR pNs in PkgNamespace
          FILTER pNs._id == pName._parent
        FOR pType in PkgType
          FILTER pType._id == pNs._parent

        RETURN {
          'type': pType.type,
          'namespace': pNs.namespace,
          'name': pName.name,
          'nameDoc': pName
        }
    )
	  
	  LET isDependency = FIRST(
		  UPSERT { packageID:firstPkg.versionDoc._id, depPackageID:secondPkg.nameDoc._id, versionRange:@versionRange, dependencyType:@dependencyType, justification:@justification, collector:@collector, origin:@origin } 
			  INSERT { packageID:firstPkg.versionDoc._id, depPackageID:secondPkg.nameDoc._id, versionRange:@versionRange, dependencyType:@dependencyType, justification:@justification, collector:@collector, origin:@origin } 
			  UPDATE {} IN isDependencies
			  RETURN NEW
	  )
	  
	  LET edgeCollection = (FOR edgeData IN [
		{fromKey: isDependency._key, toKey: secondPkg.nameDoc._key, from: isDependency._id, to: secondPkg.nameDoc._id, label: "dependency"}, 
		{fromKey: firstPkg.versionDoc._key, toKey: isDependency._key, from: firstPkg.versionDoc._id, to: isDependency._id, label: "subject"}]
	
		INSERT { _key: CONCAT("isDependencyEdges", edgeData.fromKey, edgeData.toKey), _from: edgeData.from, _to: edgeData.to, label : edgeData.label } INTO isDependencyEdges OPTIONS { overwriteMode: "ignore" }
	  )
	  
	  RETURN {
		  "firstPkgType": firstPkg.type,
		  "firstPkgNamespace": firstPkg.namespace,
		  "firstPkgName": firstPkg.name,
		  "firstPkgVersion": firstPkg.version,
		  "firstPkgSubpath": firstPkg.subpath,
		  "firstPkgQualifier_list": firstPkg.qualifier_list,
		  "secondPkgType": secondPkg.type,
		  "secondPkgNamespace": secondPkg.namespace,
		  "secondPkgName": secondPkg.name,
		  "versionRange": isDependency.versionRange,
		  "dependencyType": isDependency.dependencyType,
		  "justification": isDependency.justification,
		  "collector": isDependency.collector,
		  "origin": isDependency.origin
	  }`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, values, "IngestDependency")
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
		SecondPkgType         string      `json:"secondPkgType"`
		SecondPkgNamespace    string      `json:"secondPkgNamespace"`
		SecondPkgName         string      `json:"secondPkgName"`
		VersionRange          string      `json:"versionRange"`
		DependencyType        string      `json:"dependencyType"`
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
				return nil, fmt.Errorf("failed to ingest dependency: %w, values: %v", err, values)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}
	if len(createdValues) == 1 {

		pkg, err := generateModelPackage(createdValues[0].FirstPkgType, createdValues[0].FirstPkgNamespace,
			createdValues[0].FirstPkgName, createdValues[0].FirstPkgVersion, createdValues[0].FirstPkgSubpath, createdValues[0].FirstPkgQualifierList)
		if err != nil {
			return nil, fmt.Errorf("failed to get model.package with err: %w", err)
		}
		depPkg, err := generateModelPackage(createdValues[0].SecondPkgType, createdValues[0].SecondPkgNamespace,
			createdValues[0].SecondPkgName, nil, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get dependent model.package with err: %w", err)
		}
		dependencyTypeEnum, err := convertDependencyTypeToEnum(createdValues[0].DependencyType)
		if err != nil {
			return nil, fmt.Errorf("convertDependencyTypeToEnum failed with error: %w", err)
		}

		isDependency := &model.IsDependency{
			Package:          pkg,
			DependentPackage: depPkg,
			VersionRange:     createdValues[0].VersionRange,
			DependencyType:   dependencyTypeEnum,
			Origin:           createdValues[0].Collector,
			Collector:        createdValues[0].Origin,
		}

		return isDependency, nil
	} else {
		return nil, fmt.Errorf("number of hashEqual ingested is too great")
	}
}

func convertDependencyTypeToEnum(status string) (model.DependencyType, error) {
	if status == model.DependencyTypeDirect.String() {
		return model.DependencyTypeDirect, nil
	}
	if status == model.DependencyTypeIndirect.String() {
		return model.DependencyTypeIndirect, nil
	}
	if status == model.DependencyTypeUnknown.String() {
		return model.DependencyTypeUnknown, nil
	}
	return model.DependencyTypeUnknown, fmt.Errorf("failed to convert DependencyType to enum")
}
