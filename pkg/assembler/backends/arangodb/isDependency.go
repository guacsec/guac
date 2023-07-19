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

const (
	versionRange   string = "versionRange"
	dependencyType string = "dependencyType"
)

// Query IsDependency

func (c *arangoClient) IsDependency(ctx context.Context, isDependencySpec *model.IsDependencySpec) ([]*model.IsDependency, error) {
	return []*model.IsDependency{}, fmt.Errorf("not implemented: IsDependency")
}

// Ingest IsDependency

func getDependencyQueryValues(pkg *model.PkgInputSpec, depPkg *model.PkgInputSpec, dependency *model.IsDependencyInputSpec) map[string]any {
	values := map[string]any{}

	// add guac keys
	pkgId := guacPkgId(*pkg)
	depPkgId := guacPkgId(*depPkg)
	values["pkgVersionGuacKey"] = pkgId.VersionId
	values["secondPkgNameGuacKey"] = depPkgId.NameId

	// isDependency

	values[versionRange] = dependency.VersionRange
	values[dependencyType] = dependency.DependencyType.String()
	values[justification] = dependency.Justification
	values[origin] = dependency.Origin
	values[collector] = dependency.Collector

	return values
}

func (c *arangoClient) IngestDependencies(ctx context.Context, pkgs []*model.PkgInputSpec, depPkgs []*model.PkgInputSpec, dependencies []*model.IsDependencyInputSpec) ([]*model.IsDependency, error) {
	if len(pkgs) != len(depPkgs) {
		return nil, fmt.Errorf("uneven packages and dependent packages for ingestion")
	} else if len(pkgs) != len(dependencies) {
		return nil, fmt.Errorf("uneven packages and isDependency for ingestion")
	}

	listOfValues := []map[string]any{}

	for i := range pkgs {
		listOfValues = append(listOfValues, getDependencyQueryValues(pkgs[i], depPkgs[i], dependencies[i]))
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

    LET secondPkg = FIRST(
        FOR pName in pkgNames
          FILTER pName.guacKey == doc.secondPkgNameGuacKey
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
		  'nameDoc': pName
        }
    )
		
	LET isDependency = FIRST(
		  UPSERT { packageID:firstPkg.version_id, depPackageID:secondPkg.name_id, versionRange:doc.versionRange, dependencyType:doc.dependencyType, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
			INSERT { packageID:firstPkg.version_id, depPackageID:secondPkg.name_id, versionRange:doc.versionRange, dependencyType:doc.dependencyType, justification:doc.justification, collector:doc.collector, origin:doc.origin }
			UPDATE {} IN isDependencies
			RETURN NEW
		)
		
	LET edgeCollection = (FOR edgeData IN [
		{fromKey: isDependency._key, toKey: secondPkg.nameDoc._key, from: isDependency._id, to: secondPkg.name_id, label: 'dependency'}, 
		{fromKey: firstPkg.versionDoc._key, toKey: isDependency._key, from: firstPkg.version_id, to: isDependency._id, label: 'subject'}]
	  
		INSERT { _key: CONCAT('isDependencyEdges', edgeData.fromKey, edgeData.toKey), _from: edgeData.from, _to: edgeData.to, label : edgeData.label } INTO isDependencyEdges OPTIONS { overwriteMode: 'ignore' }
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
		'depPkg': {
			'type_id': secondPkg.typeID,
			'type': secondPkg.type,
			'namespace_id': secondPkg.namespace_id,
			'namespace': secondPkg.namespace,
			'name_id': secondPkg.name_id,
			'name': secondPkg.name
		},
		'isDependency_id': isDependency._id,
		'versionRange': isDependency.versionRange,
		'dependencyType': isDependency.dependencyType,
		'justification': isDependency.justification,
		'collector': isDependency.collector,
		'origin': isDependency.origin
	}`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestDependency")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest isDependency: %w", err)
	}
	defer cursor.Close()

	return getIsDependency(ctx, cursor)
}

func (c *arangoClient) IngestDependency(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, dependency model.IsDependencyInputSpec) (*model.IsDependency, error) {
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

    LET secondPkg = FIRST(
        FOR pName in pkgNames
          FILTER pName.guacKey == @secondPkgNameGuacKey
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
		  'nameDoc': pName
        }
    )
	  
	  LET isDependency = FIRST(
		  UPSERT { packageID:firstPkg.version_id, depPackageID:secondPkg.name_id, versionRange:@versionRange, dependencyType:@dependencyType, justification:@justification, collector:@collector, origin:@origin } 
			  INSERT { packageID:firstPkg.version_id, depPackageID:secondPkg.name_id, versionRange:@versionRange, dependencyType:@dependencyType, justification:@justification, collector:@collector, origin:@origin } 
			  UPDATE {} IN isDependencies
			  RETURN NEW
	  )
	  
	  LET edgeCollection = (FOR edgeData IN [
		{fromKey: isDependency._key, toKey: secondPkg.nameDoc._key, from: isDependency._id, to: secondPkg.name_id, label: "dependency"}, 
		{fromKey: firstPkg.versionDoc._key, toKey: isDependency._key, from: firstPkg.version_id, to: isDependency._id, label: "subject"}]
	
		INSERT { _key: CONCAT("isDependencyEdges", edgeData.fromKey, edgeData.toKey), _from: edgeData.from, _to: edgeData.to, label : edgeData.label } INTO isDependencyEdges OPTIONS { overwriteMode: "ignore" }
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
		'depPkg': {
			'type_id': secondPkg.typeID,
			'type': secondPkg.type,
			'namespace_id': secondPkg.namespace_id,
			'namespace': secondPkg.namespace,
			'name_id': secondPkg.name_id,
			'name': secondPkg.name
		},
		'isDependency_id': isDependency._id,
		'versionRange': isDependency.versionRange,
		'dependencyType': isDependency.dependencyType,
		'justification': isDependency.justification,
		'collector': isDependency.collector,
		'origin': isDependency.origin
	  }`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getDependencyQueryValues(&pkg, &depPkg, &dependency), "IngestDependency")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest isDependency: %w", err)
	}
	defer cursor.Close()

	isDependencyList, err := getIsDependency(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get dependency from arango cursor: %w", err)
	}

	if len(isDependencyList) == 1 {
		return isDependencyList[0], nil
	} else {
		return nil, fmt.Errorf("number of dependency ingested is greater than one")
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

func getIsDependency(ctx context.Context, cursor driver.Cursor) ([]*model.IsDependency, error) {
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
		DepPkg struct {
			TypeID      string `json:"type_id"`
			PkgType     string `json:"type"`
			NamespaceID string `json:"namespace_id"`
			Namespace   string `json:"namespace"`
			NameID      string `json:"name_id"`
			Name        string `json:"name"`
		} `json:"depPkg"`
		IsDependencyID string `json:"isDependency_id"`
		VersionRange   string `json:"versionRange"`
		DependencyType string `json:"dependencyType"`
		Justification  string `json:"justification"`
		Collector      string `json:"collector"`
		Origin         string `json:"origin"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to package dependency from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var isDependencyList []*model.IsDependency
	for _, createdValue := range createdValues {
		pkg := generateModelPackage(createdValue.PkgVersion.TypeID, createdValue.PkgVersion.PkgType, createdValue.PkgVersion.NamespaceID, createdValue.PkgVersion.Namespace, createdValue.PkgVersion.NameID,
			createdValue.PkgVersion.Name, &createdValue.PkgVersion.VersionID, &createdValue.PkgVersion.Version, &createdValue.PkgVersion.Subpath, createdValue.PkgVersion.QualifierList)

		depPkg := generateModelPackage(createdValue.DepPkg.TypeID, createdValue.DepPkg.PkgType, createdValue.DepPkg.NamespaceID, createdValue.DepPkg.Namespace, createdValue.DepPkg.NameID,
			createdValue.DepPkg.Name, nil, nil, nil, nil)

		dependencyTypeEnum, err := convertDependencyTypeToEnum(createdValue.DependencyType)
		if err != nil {
			return nil, fmt.Errorf("convertDependencyTypeToEnum failed with error: %w", err)
		}

		isDependency := &model.IsDependency{
			ID:               createdValue.IsDependencyID,
			Package:          pkg,
			DependentPackage: depPkg,
			VersionRange:     createdValue.VersionRange,
			DependencyType:   dependencyTypeEnum,
			Justification:    createdValue.Justification,
			Origin:           createdValue.Collector,
			Collector:        createdValue.Origin,
		}
		isDependencyList = append(isDependencyList, isDependency)
	}

	return isDependencyList, nil
}
