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
	versionRangeStr   string = "versionRange"
	dependencyTypeStr string = "dependencyType"
)

func checkPkgNameDependency(isDependencySpec *model.IsDependencySpec) bool {
	if isDependencySpec.DependentPackage != nil {
		if isDependencySpec.DependentPackage.ID != nil ||
			isDependencySpec.DependentPackage.Version != nil ||
			isDependencySpec.DependentPackage.Subpath != nil ||
			isDependencySpec.DependentPackage.Qualifiers != nil ||
			isDependencySpec.DependentPackage.MatchOnlyEmptyQualifiers != nil {
			return false
		}
	}
	return true
}

// Query IsDependency

func (c *arangoClient) IsDependency(ctx context.Context, isDependencySpec *model.IsDependencySpec) ([]*model.IsDependency, error) {

	// TODO (pxp928): Optimization of the query can be done by starting from the dependent package node (if specified)
	var arangoQueryBuilder *arangoQueryBuilder

	if isDependencySpec.Package != nil {
		var combinedIsDependency []*model.IsDependency
		values := map[string]any{}

		// dep pkgVersion isDependency
		arangoQueryBuilder = setPkgVersionMatchValues(isDependencySpec.Package, values)
		arangoQueryBuilder.forOutBound(isDependencySubjectPkgEdgesStr, "isDependency", "pVersion")
		setIsDependencyMatchValues(arangoQueryBuilder, isDependencySpec, values, true)

		depPkgVersionIsDependency, err := getDependencyForQuery(ctx, c, arangoQueryBuilder, values, true)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve dependent package version isDependency with error: %w", err)
		}

		combinedIsDependency = append(combinedIsDependency, depPkgVersionIsDependency...)

		if checkPkgNameDependency(isDependencySpec) {
			// dep pkgName isDependency
			values = map[string]any{}
			arangoQueryBuilder = setPkgVersionMatchValues(isDependencySpec.Package, values)
			arangoQueryBuilder.forOutBound(isDependencySubjectPkgEdgesStr, "isDependency", "pVersion")
			setIsDependencyMatchValues(arangoQueryBuilder, isDependencySpec, values, false)

			depPkgNameIsDependency, err := getDependencyForQuery(ctx, c, arangoQueryBuilder, values, false)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve dependent package name isDependency with error: %w", err)
			}

			combinedIsDependency = append(combinedIsDependency, depPkgNameIsDependency...)

		}
		return combinedIsDependency, nil
	} else {
		var combinedIsDependency []*model.IsDependency
		values := map[string]any{}
		// get pkgVersion isDependency
		arangoQueryBuilder = newForQuery(isDependenciesStr, "isDependency")
		arangoQueryBuilder.forInBound(isDependencySubjectPkgEdgesStr, "pVersion", "isDependency")
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "pName", "pVersion")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")
		setIsDependencyMatchValues(arangoQueryBuilder, isDependencySpec, values, true)

		depPkgVersionIsDependency, err := getDependencyForQuery(ctx, c, arangoQueryBuilder, values, true)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve dependent package version isDependency with error: %w", err)
		}

		combinedIsDependency = append(combinedIsDependency, depPkgVersionIsDependency...)

		if checkPkgNameDependency(isDependencySpec) {
			// dep pkgName isDependency
			values = map[string]any{}
			arangoQueryBuilder = newForQuery(isDependenciesStr, "isDependency")
			arangoQueryBuilder.forInBound(isDependencySubjectPkgEdgesStr, "pVersion", "isDependency")
			arangoQueryBuilder.forInBound(pkgHasVersionStr, "pName", "pVersion")
			arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
			arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")
			setIsDependencyMatchValues(arangoQueryBuilder, isDependencySpec, values, false)

			depPkgNameIsDependency, err := getDependencyForQuery(ctx, c, arangoQueryBuilder, values, false)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve dependent package name isDependency with error: %w", err)
			}

			combinedIsDependency = append(combinedIsDependency, depPkgNameIsDependency...)
		}
		return combinedIsDependency, nil
	}
}

func getDependencyForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any, includeDepPkgVersion bool) ([]*model.IsDependency, error) {
	if includeDepPkgVersion {
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
			'depPkg': {
				'type_id': depType._id,
				'type': depType.type,
				'namespace_id': depNamespace._id,
				'namespace': depNamespace.namespace,
				'name_id': depName._id,
				'name': depName.name,
				'version_id': depVersion._id,
				'version': depVersion.version,
				'subpath': depVersion.subpath,
				'qualifier_list': depVersion.qualifier_list
			},
			'isDependency_id': isDependency._id,
			'versionRange': isDependency.versionRange,
			'dependencyType': isDependency.dependencyType,
			'justification': isDependency.justification,
			'collector': isDependency.collector,
			'origin': isDependency.origin
		}`)
	} else {
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
			'depPkg': {
				'type_id': depType._id,
				'type': depType.type,
				'namespace_id': depNamespace._id,
				'namespace': depNamespace.namespace,
				'name_id': depName._id,
				'name': depName.name
			},
			'isDependency_id': isDependency._id,
			'versionRange': isDependency.versionRange,
			'dependencyType': isDependency.dependencyType,
			'justification': isDependency.justification,
			'collector': isDependency.collector,
			'origin': isDependency.origin
		}`)
	}

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "IsDependency")
	if err != nil {
		return nil, fmt.Errorf("failed to query for IsDependency: %w", err)
	}
	defer cursor.Close()

	return getIsDependencyFromCursor(ctx, cursor)
}

func setIsDependencyMatchValues(arangoQueryBuilder *arangoQueryBuilder, isDependencySpec *model.IsDependencySpec, queryValues map[string]any, queryDepPkgVersion bool) {
	if isDependencySpec.ID != nil {
		arangoQueryBuilder.filter("isDependency", "_id", "==", "@id")
		queryValues["id"] = *isDependencySpec.ID
	}
	if isDependencySpec.VersionRange != nil {
		arangoQueryBuilder.filter("isDependency", versionRangeStr, "==", "@"+versionRangeStr)
		queryValues[versionRangeStr] = *isDependencySpec.VersionRange
	}
	if isDependencySpec.DependencyType != nil {
		arangoQueryBuilder.filter("isDependency", dependencyTypeStr, "==", "@"+dependencyTypeStr)
		queryValues[dependencyTypeStr] = *isDependencySpec.DependencyType
	}
	if isDependencySpec.Justification != nil {
		arangoQueryBuilder.filter("isDependency", justification, "==", "@"+justification)
		queryValues[justification] = *isDependencySpec.Justification
	}
	if isDependencySpec.Origin != nil {
		arangoQueryBuilder.filter("isDependency", origin, "==", "@"+origin)
		queryValues[origin] = *isDependencySpec.Origin
	}
	if isDependencySpec.Collector != nil {
		arangoQueryBuilder.filter("isDependency", collector, "==", "@"+collector)
		queryValues[collector] = *isDependencySpec.Collector
	}
	if isDependencySpec.DependentPackage != nil {
		if !queryDepPkgVersion {
			arangoQueryBuilder.forOutBound(isDependencyDepPkgNameEdgesStr, "depName", "isDependency")
			if isDependencySpec.DependentPackage.Name != nil {
				arangoQueryBuilder.filter("depName", "name", "==", "@depName")
				queryValues["depName"] = *isDependencySpec.DependentPackage.Name
			}
			arangoQueryBuilder.forInBound(pkgHasNameStr, "depNamespace", "depName")
			if isDependencySpec.DependentPackage.Namespace != nil {
				arangoQueryBuilder.filter("depNamespace", "namespace", "==", "@depNamespace")
				queryValues["depNamespace"] = *isDependencySpec.DependentPackage.Namespace
			}
			arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "depType", "depNamespace")
			if isDependencySpec.DependentPackage.Type != nil {
				arangoQueryBuilder.filter("depType", "type", "==", "@depType")
				queryValues["depType"] = *isDependencySpec.DependentPackage.Type
			}
		} else {
			arangoQueryBuilder.forOutBound(isDependencyDepPkgVersionEdgesStr, "depVersion", "isDependency")
			if isDependencySpec.DependentPackage.ID != nil {
				arangoQueryBuilder.filter("depVersion", "_id", "==", "@depVersionID")
				queryValues["depVersionID"] = *isDependencySpec.DependentPackage.ID
			}
			if isDependencySpec.DependentPackage.Version != nil {
				arangoQueryBuilder.filter("depVersion", "version", "==", "@depVersionValue")
				queryValues["depVersionValue"] = *isDependencySpec.DependentPackage.Version
			}
			if isDependencySpec.DependentPackage.Subpath != nil {
				arangoQueryBuilder.filter("depVersion", "subpath", "==", "@depSubpath")
				queryValues["depSubpath"] = *isDependencySpec.DependentPackage.Subpath
			}
			if isDependencySpec.DependentPackage.MatchOnlyEmptyQualifiers != nil {
				if !*isDependencySpec.DependentPackage.MatchOnlyEmptyQualifiers {
					if len(isDependencySpec.DependentPackage.Qualifiers) > 0 {
						arangoQueryBuilder.filter("depVersion", "qualifier_list", "==", "@depQualifier")
						queryValues["depQualifier"] = getQualifiers(isDependencySpec.DependentPackage.Qualifiers)
					}
				} else {
					arangoQueryBuilder.filterLength("depVersion", "qualifier_list", "==", 0)
				}
			} else {
				if len(isDependencySpec.DependentPackage.Qualifiers) > 0 {
					arangoQueryBuilder.filter("depVersion", "qualifier_list", "==", "@depQualifier")
					queryValues["depQualifier"] = getQualifiers(isDependencySpec.DependentPackage.Qualifiers)
				}
			}
			arangoQueryBuilder.forInBound(pkgHasVersionStr, "depName", "depVersion")
			if isDependencySpec.DependentPackage.Name != nil {
				arangoQueryBuilder.filter("depName", "name", "==", "@depName")
				queryValues["depName"] = *isDependencySpec.DependentPackage.Name
			}
			arangoQueryBuilder.forInBound(pkgHasNameStr, "depNamespace", "depName")
			if isDependencySpec.DependentPackage.Namespace != nil {
				arangoQueryBuilder.filter("depNamespace", "namespace", "==", "@depNamespace")
				queryValues["depNamespace"] = *isDependencySpec.DependentPackage.Namespace
			}
			arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "depType", "depNamespace")
			if isDependencySpec.DependentPackage.Type != nil {
				arangoQueryBuilder.filter("depType", "type", "==", "@depType")
				queryValues["depType"] = *isDependencySpec.DependentPackage.Type
			}
		}
	} else {
		if !queryDepPkgVersion {
			arangoQueryBuilder.forOutBound(isDependencyDepPkgNameEdgesStr, "depName", "isDependency")
			arangoQueryBuilder.forInBound(pkgHasNameStr, "depNamespace", "depName")
			arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "depType", "depNamespace")
		} else {
			arangoQueryBuilder.forOutBound(isDependencyDepPkgVersionEdgesStr, "depVersion", "isDependency")
			arangoQueryBuilder.forInBound(pkgHasVersionStr, "depName", "depVersion")
			arangoQueryBuilder.forInBound(pkgHasNameStr, "depNamespace", "depName")
			arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "depType", "depNamespace")
		}

	}
}

// Ingest IsDependency

func getDependencyQueryValues(pkg *model.PkgInputSpec, depPkg *model.PkgInputSpec, depPkgMatchType model.MatchFlags, dependency *model.IsDependencyInputSpec) map[string]any {
	values := map[string]any{}

	// add guac keys
	pkgId := guacPkgId(*pkg)
	depPkgId := guacPkgId(*depPkg)
	values["pkgVersionGuacKey"] = pkgId.VersionId
	if depPkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
		values["secondPkgGuacKey"] = depPkgId.NameId
	} else {
		values["secondPkgGuacKey"] = depPkgId.VersionId
	}

	// isDependency

	values[versionRangeStr] = dependency.VersionRange
	values[dependencyTypeStr] = dependency.DependencyType.String()
	values[justification] = dependency.Justification
	values[origin] = dependency.Origin
	values[collector] = dependency.Collector

	return values
}

func (c *arangoClient) IngestDependencies(ctx context.Context, pkgs []*model.PkgInputSpec, depPkgs []*model.PkgInputSpec, depPkgMatchType model.MatchFlags, dependencies []*model.IsDependencyInputSpec) ([]*model.IsDependency, error) {
	// TODO(LUMJJB): handle pkgmatchtype

	var listOfValues []map[string]any

	for i := range pkgs {
		listOfValues = append(listOfValues, getDependencyQueryValues(pkgs[i], depPkgs[i], depPkgMatchType, dependencies[i]))
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

	if depPkgMatchType.Pkg == model.PkgMatchTypeAllVersions {

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
          FILTER pName.guacKey == doc.secondPkgGuacKey
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
	
	INSERT { _key: CONCAT("isDependencySubjectPkgEdges", firstPkg.versionDoc._key, isDependency._key), _from: firstPkg.version_id, _to: isDependency._id} INTO isDependencySubjectPkgEdges OPTIONS { overwriteMode: "ignore" }
	INSERT { _key: CONCAT("isDependencyDepPkgNameEdges", isDependency._key, secondPkg.nameDoc._key), _from: isDependency._id, _to: secondPkg.name_id} INTO isDependencyDepPkgNameEdges OPTIONS { overwriteMode: "ignore" }

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
	} else {
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
		FOR pVersion in pkgVersions
		  FILTER pVersion.guacKey == doc.secondPkgGuacKey
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
		
	LET isDependency = FIRST(
		  UPSERT { packageID:firstPkg.version_id, depPackageID:secondPkg.version_id, versionRange:doc.versionRange, dependencyType:doc.dependencyType, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
			INSERT { packageID:firstPkg.version_id, depPackageID:secondPkg.version_id, versionRange:doc.versionRange, dependencyType:doc.dependencyType, justification:doc.justification, collector:doc.collector, origin:doc.origin }
			UPDATE {} IN isDependencies
			RETURN NEW
		)
	
	INSERT { _key: CONCAT("isDependencySubjectPkgEdges", firstPkg.versionDoc._key, isDependency._key), _from: firstPkg.version_id, _to: isDependency._id} INTO isDependencySubjectPkgEdges OPTIONS { overwriteMode: "ignore" }
	INSERT { _key: CONCAT("isDependencyDepPkgVersionEdges", isDependency._key, secondPkg.versionDoc._key), _from: isDependency._id, _to: secondPkg.version_id} INTO isDependencyDepPkgVersionEdges OPTIONS { overwriteMode: "ignore" }

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
			'name': secondPkg.name,
			'version_id': secondPkg.version_id,
			'version': secondPkg.version,
			'subpath': secondPkg.subpath,
			'qualifier_list': secondPkg.qualifier_list
		},
		'isDependency_id': isDependency._id,
		'versionRange': isDependency.versionRange,
		'dependencyType': isDependency.dependencyType,
		'justification': isDependency.justification,
		'collector': isDependency.collector,
		'origin': isDependency.origin
	}`
		sb.WriteString(query)
		// TODO: add version into return
	}

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestDependency")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest isDependency: %w", err)
	}
	defer cursor.Close()

	return getIsDependencyFromCursor(ctx, cursor)
}

func (c *arangoClient) IngestDependency(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, depPkgMatchType model.MatchFlags, dependency model.IsDependencyInputSpec) (*model.IsDependency, error) {

	var query string
	if depPkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
		query = `
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
          FILTER pName.guacKey == @secondPkgGuacKey
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
	  
	  INSERT { _key: CONCAT("isDependencySubjectPkgEdges", firstPkg.versionDoc._key, isDependency._key), _from: firstPkg.version_id, _to: isDependency._id} INTO isDependencySubjectPkgEdges OPTIONS { overwriteMode: "ignore" }
	  INSERT { _key: CONCAT("isDependencyDepPkgNameEdges", isDependency._key, secondPkg.nameDoc._key), _from: isDependency._id, _to: secondPkg.name_id} INTO isDependencyDepPkgNameEdges OPTIONS { overwriteMode: "ignore" }
	  
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
	} else {

		// Specific version
		query = `
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
        FOR pVersion in pkgVersions
          FILTER pVersion.guacKey == @secondPkgGuacKey
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

	  
	  LET isDependency = FIRST(
		  UPSERT { packageID:firstPkg.version_id, depPackageID:secondPkg.version_id, versionRange:@versionRange, dependencyType:@dependencyType, justification:@justification, collector:@collector, origin:@origin } 
			  INSERT { packageID:firstPkg.version_id, depPackageID:secondPkg.version_id, versionRange:@versionRange, dependencyType:@dependencyType, justification:@justification, collector:@collector, origin:@origin } 
			  UPDATE {} IN isDependencies
			  RETURN NEW
	  )
	  
	  INSERT { _key: CONCAT("isDependencySubjectPkgEdges", firstPkg.versionDoc._key, isDependency._key), _from: firstPkg.version_id, _to: isDependency._id} INTO isDependencySubjectPkgEdges OPTIONS { overwriteMode: "ignore" }
	  INSERT { _key: CONCAT("isDependencyDepPkgVersionEdges", isDependency._key, secondPkg.versionDoc._key), _from: isDependency._id, _to: secondPkg.version_id} INTO isDependencyDepPkgVersionEdges OPTIONS { overwriteMode: "ignore" }
	  
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
			'name': secondPkg.name,
			'version_id': secondPkg.version_id,
			'version': secondPkg.version,
			'subpath': secondPkg.subpath,
			'qualifier_list': secondPkg.qualifier_list
		},
		'isDependency_id': isDependency._id,
		'versionRange': isDependency.versionRange,
		'dependencyType': isDependency.dependencyType,
		'justification': isDependency.justification,
		'collector': isDependency.collector,
		'origin': isDependency.origin
	  }`
	}

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getDependencyQueryValues(&pkg, &depPkg, depPkgMatchType, &dependency), "IngestDependency")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest isDependency: %w", err)
	}
	defer cursor.Close()

	isDependencyList, err := getIsDependencyFromCursor(ctx, cursor)
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
	if status == "" {
		return "", nil
	}
	return model.DependencyTypeUnknown, fmt.Errorf("failed to convert DependencyType to enum")
}

func getIsDependencyFromCursor(ctx context.Context, cursor driver.Cursor) ([]*model.IsDependency, error) {
	type collectedData struct {
		PkgVersion     *dbPkgVersion `json:"pkgVersion"`
		DepPkg         *dbPkgVersion `json:"depPkg"`
		IsDependencyID string        `json:"isDependency_id"`
		VersionRange   string        `json:"versionRange"`
		DependencyType string        `json:"dependencyType"`
		Justification  string        `json:"justification"`
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
				return nil, fmt.Errorf("failed to package dependency from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var isDependencyList []*model.IsDependency
	for _, createdValue := range createdValues {
		pkg := generateModelPackage(createdValue.PkgVersion.TypeID, createdValue.PkgVersion.PkgType, createdValue.PkgVersion.NamespaceID, createdValue.PkgVersion.Namespace, createdValue.PkgVersion.NameID,
			createdValue.PkgVersion.Name, createdValue.PkgVersion.VersionID, createdValue.PkgVersion.Version, createdValue.PkgVersion.Subpath, createdValue.PkgVersion.QualifierList)

		depPkg := generateModelPackage(createdValue.DepPkg.TypeID, createdValue.DepPkg.PkgType, createdValue.DepPkg.NamespaceID, createdValue.DepPkg.Namespace, createdValue.DepPkg.NameID,
			createdValue.DepPkg.Name, createdValue.DepPkg.VersionID, createdValue.DepPkg.Version, createdValue.DepPkg.Subpath, createdValue.DepPkg.QualifierList)

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
