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
	"sort"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

const (
	versionRange   string = "versionRange"
	dependencyType string = "dependencyType"
)

// Ingest IsDependency

func (c *arangoClient) IngestDependency(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, dependency model.IsDependencyInputSpec) (*model.IsDependency, error) {
	values := map[string]any{}

	values["pkgType"] = pkg.Type
	values["name"] = pkg.Name
	if pkg.Namespace != nil {
		values["namespace"] = *pkg.Namespace
	} else {
		values["namespace"] = ""
	}
	if pkg.Version != nil {
		values["version"] = *pkg.Version
	} else {
		values["version"] = ""
	}
	if pkg.Subpath != nil {
		values["subpath"] = *pkg.Subpath
	} else {
		values["subpath"] = ""
	}

	// To ensure consistency, always sort the qualifiers by key
	qualifiersMap := map[string]string{}
	keys := []string{}
	for _, kv := range pkg.Qualifiers {
		qualifiersMap[kv.Key] = kv.Value
		keys = append(keys, kv.Key)
	}
	sort.Strings(keys)
	qualifiers := []string{}
	for _, k := range keys {
		qualifiers = append(qualifiers, k, qualifiersMap[k])
	}
	values["qualifier"] = qualifiers

	values["secondPkgType"] = pkg.Type
	values["secondNamespace"] = pkg.Namespace
	values["secondName"] = pkg.Name
	values[versionRange] = dependency.VersionRange
	values[dependencyType] = dependency.DependencyType.String()
	values[justification] = dependency.Justification
	values[origin] = dependency.Origin
	values[collector] = dependency.Collector

	query := `LET firstPkg = FIRST(
		FOR pkg IN Pkg
		  FILTER pkg.root == "pkg"
		  FOR pkgHasType IN OUTBOUND pkg PkgHasType
			  FILTER pkgHasType.type == @pkgType
			FOR pkgHasNamespace IN OUTBOUND pkgHasType PkgHasNamespace
				  FILTER pkgHasNamespace.namespace == @namespace
			  FOR pkgHasName IN OUTBOUND pkgHasNamespace PkgHasName
					  FILTER pkgHasName.name == @name
				FOR pkgHasVersion IN OUTBOUND pkgHasName PkgHasVersion
						  FILTER pkgHasVersion.version == @version && pkgHasVersion.subpath == @subpath && pkgHasVersion.qualifier_list == @qualifier
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
	  
	  LET secondPkg = FIRST(
		FOR pkg IN Pkg
		  FILTER pkg.root == "pkg"
		  FOR pkgHasType IN OUTBOUND pkg PkgHasType
			  FILTER pkgHasType.type == @secondPkgType
			FOR pkgHasNamespace IN OUTBOUND pkgHasType PkgHasNamespace
				  FILTER pkgHasNamespace.namespace == @secondNamespace
			  FOR pkgHasName IN OUTBOUND pkgHasNamespace PkgHasName
					  FILTER pkgHasName.name == @secondName
				  RETURN {
					"type": pkgHasType.type,
					"namespace": pkgHasNamespace.namespace,
					"name": pkgHasName.name,
					"nameDoc": pkgHasName
				  }
	  )
	  
	  LET isDependency = FIRST(
		  UPSERT { versionRange:@versionRange, dependencyType:@dependencyType, justification:@justification, collector:@collector, origin:@origin } 
			  INSERT { versionRange:@versionRange, dependencyType:@dependencyType, justification:@justification, collector:@collector, origin:@origin } 
			  UPDATE {} IN isDependencies
			  RETURN NEW
	  )
	  
	  LET edgeCollection = (FOR edgeData IN [
		  {from: isDependency._id, to: secondPkg.nameDoc._id, label: "dependency"}, 
		  {from: firstPkg.versionDoc._id, to: isDependency._id, label: "subject"}]
	  
		UPSERT { _from: edgeData.from, _to: edgeData.to, label : edgeData.label }
		  INSERT { _from: edgeData.from, _to: edgeData.to, label : edgeData.label }
		  UPDATE {} IN isDependencyEdges
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

	cursor, err := c.db.Query(ctx, query, values)
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
				return nil, fmt.Errorf("failed to ingest artifact: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}
	if len(createdValues) == 1 {

		pkg := generateModelPackage(createdValues[0].FirstPkgType, createdValues[0].FirstPkgNamespace,
			createdValues[0].FirstPkgName, createdValues[0].FirstPkgVersion, createdValues[0].FirstPkgSubpath, createdValues[0].FirstPkgQualifierList)

		depPkg := generateModelPackage(createdValues[0].SecondPkgType, createdValues[0].SecondPkgNamespace,
			createdValues[0].SecondPkgName, nil, nil, nil)

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
