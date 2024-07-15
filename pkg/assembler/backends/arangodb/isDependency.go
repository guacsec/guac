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
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
)

const (
	dependencyTypeStr string = "dependencyType"
)

var dependencyTypeToEnum = map[string]model.DependencyType{
	model.DependencyTypeDirect.String():   model.DependencyTypeDirect,
	model.DependencyTypeIndirect.String(): model.DependencyTypeIndirect,
	model.DependencyTypeUnknown.String():  model.DependencyTypeUnknown,
	"":                                    "",
}

// Query IsDependency

func (c *arangoClient) IsDependencyList(ctx context.Context, isDependencySpec model.IsDependencySpec, after *string, first *int) (*model.IsDependencyConnection, error) {
	return nil, fmt.Errorf("not implemented: IsDependencyList")
}

func (c *arangoClient) IsDependency(ctx context.Context, isDependencySpec *model.IsDependencySpec) ([]*model.IsDependency, error) {

	if isDependencySpec != nil && isDependencySpec.ID != nil {
		d, err := c.buildIsDependencyByID(ctx, *isDependencySpec.ID, isDependencySpec)
		if err != nil {
			return nil, fmt.Errorf("buildIsDependencyByID failed with an error: %w", err)
		}
		return []*model.IsDependency{d}, nil
	}

	// TODO (pxp928): Optimization of the query can be done by starting from the dependent package node (if specified)
	var arangoQueryBuilder *arangoQueryBuilder

	if isDependencySpec.Package != nil {
		var combinedIsDependency []*model.IsDependency
		values := map[string]any{}

		// dep pkgVersion isDependency
		arangoQueryBuilder = setPkgVersionMatchValues(isDependencySpec.Package, values)
		arangoQueryBuilder.forOutBound(isDependencySubjectPkgEdgesStr, "isDependency", "pVersion")
		setIsDependencyMatchValues(arangoQueryBuilder, isDependencySpec, values)

		depPkgVersionIsDependency, err := getDependencyForQuery(ctx, c, arangoQueryBuilder, values)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve dependent package version isDependency with error: %w", err)
		}

		combinedIsDependency = append(combinedIsDependency, depPkgVersionIsDependency...)

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
		setIsDependencyMatchValues(arangoQueryBuilder, isDependencySpec, values)

		depPkgVersionIsDependency, err := getDependencyForQuery(ctx, c, arangoQueryBuilder, values)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve dependent package version isDependency with error: %w", err)
		}

		combinedIsDependency = append(combinedIsDependency, depPkgVersionIsDependency...)

		return combinedIsDependency, nil
	}
}

func getDependencyForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.IsDependency, error) {
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
			'dependencyType': isDependency.dependencyType,
			'justification': isDependency.justification,
			'collector': isDependency.collector,
			'origin': isDependency.origin,
			'documentRef': isDependency.documentRef
		}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "IsDependency")
	if err != nil {
		return nil, fmt.Errorf("failed to query for IsDependency: %w", err)
	}
	defer cursor.Close()

	return getIsDependencyFromCursor(ctx, cursor, false)
}

func queryIsDependencyBasedOnFilter(arangoQueryBuilder *arangoQueryBuilder, isDependencySpec *model.IsDependencySpec, queryValues map[string]any) {
	if isDependencySpec.ID != nil {
		arangoQueryBuilder.filter("isDependency", "_id", "==", "@id")
		queryValues["id"] = *isDependencySpec.ID
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
	if isDependencySpec.DocumentRef != nil {
		arangoQueryBuilder.filter("isDependency", docRef, "==", "@"+docRef)
		queryValues[docRef] = *isDependencySpec.DocumentRef
	}
}

func setIsDependencyMatchValues(arangoQueryBuilder *arangoQueryBuilder, isDependencySpec *model.IsDependencySpec, queryValues map[string]any) {
	queryIsDependencyBasedOnFilter(arangoQueryBuilder, isDependencySpec, queryValues)
	if isDependencySpec.DependencyPackage != nil {
		arangoQueryBuilder.forOutBound(isDependencyDepPkgVersionEdgesStr, "depVersion", "isDependency")
		if isDependencySpec.DependencyPackage.ID != nil {
			arangoQueryBuilder.filter("depVersion", "_id", "==", "@depVersionID")
			queryValues["depVersionID"] = *isDependencySpec.DependencyPackage.ID
		}
		if isDependencySpec.DependencyPackage.Version != nil {
			arangoQueryBuilder.filter("depVersion", "version", "==", "@depVersionValue")
			queryValues["depVersionValue"] = *isDependencySpec.DependencyPackage.Version
		}
		if isDependencySpec.DependencyPackage.Subpath != nil {
			arangoQueryBuilder.filter("depVersion", "subpath", "==", "@depSubpath")
			queryValues["depSubpath"] = *isDependencySpec.DependencyPackage.Subpath
		}
		if isDependencySpec.DependencyPackage.MatchOnlyEmptyQualifiers != nil {
			if !*isDependencySpec.DependencyPackage.MatchOnlyEmptyQualifiers {
				if len(isDependencySpec.DependencyPackage.Qualifiers) > 0 {
					arangoQueryBuilder.filter("depVersion", "qualifier_list", "==", "@depQualifier")
					queryValues["depQualifier"] = getFilterQualifiers(isDependencySpec.DependencyPackage.Qualifiers)
				}
			} else {
				arangoQueryBuilder.filterLength("depVersion", "qualifier_list", "==", 0)
			}
		} else {
			if len(isDependencySpec.DependencyPackage.Qualifiers) > 0 {
				arangoQueryBuilder.filter("depVersion", "qualifier_list", "==", "@depQualifier")
				queryValues["depQualifier"] = getFilterQualifiers(isDependencySpec.DependencyPackage.Qualifiers)
			}
		}
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "depName", "depVersion")
		if isDependencySpec.DependencyPackage.Name != nil {
			arangoQueryBuilder.filter("depName", "name", "==", "@depName")
			queryValues["depName"] = *isDependencySpec.DependencyPackage.Name
		}
		arangoQueryBuilder.forInBound(pkgHasNameStr, "depNamespace", "depName")
		if isDependencySpec.DependencyPackage.Namespace != nil {
			arangoQueryBuilder.filter("depNamespace", "namespace", "==", "@depNamespace")
			queryValues["depNamespace"] = *isDependencySpec.DependencyPackage.Namespace
		}
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "depType", "depNamespace")
		if isDependencySpec.DependencyPackage.Type != nil {
			arangoQueryBuilder.filter("depType", "type", "==", "@depType")
			queryValues["depType"] = *isDependencySpec.DependencyPackage.Type
		}
	} else {
		arangoQueryBuilder.forOutBound(isDependencyDepPkgVersionEdgesStr, "depVersion", "isDependency")
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "depName", "depVersion")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "depNamespace", "depName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "depType", "depNamespace")
	}
}

// Ingest IsDependency

func getDependencyQueryValues(pkg *model.PkgInputSpec, depPkg *model.PkgInputSpec, dependency *model.IsDependencyInputSpec) map[string]any {
	values := map[string]any{}

	// add guac keys
	pkgId := helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](pkg, helpers.PkgServerKey)
	depPkgId := helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](depPkg, helpers.PkgServerKey)
	values["pkgVersionGuacKey"] = pkgId.VersionId
	values["secondPkgGuacKey"] = depPkgId.VersionId

	// isDependency

	values[dependencyTypeStr] = dependency.DependencyType.String()
	values[justification] = dependency.Justification
	values[origin] = dependency.Origin
	values[collector] = dependency.Collector
	values[docRef] = dependency.DocumentRef

	return values
}

func (c *arangoClient) IngestDependencies(ctx context.Context, pkgs []*model.IDorPkgInput, depPkgs []*model.IDorPkgInput, dependencies []*model.IsDependencyInputSpec) ([]string, error) {
	// TODO(LUMJJB): handle pkgmatchtype

	var listOfValues []map[string]any

	for i := range pkgs {
		listOfValues = append(listOfValues, getDependencyQueryValues(pkgs[i].PackageInput, depPkgs[i].PackageInput, dependencies[i]))
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
		RETURN {
		   'version_id': pVersion._id,
		   'version_key': pVersion._key
		}
	)

    LET secondPkg = FIRST(
		FOR pVersion in pkgVersions
		  FILTER pVersion.guacKey == doc.secondPkgGuacKey
		RETURN {
		   'version_id': pVersion._id,
		   'version_key': pVersion._key,
		}
    )
		
	LET isDependency = FIRST(
		  UPSERT { packageID:firstPkg.version_id, depPackageID:secondPkg.version_id, dependencyType:doc.dependencyType, justification:doc.justification, collector:doc.collector, origin:doc.origin, documentRef:doc.documentRef } 
			INSERT { packageID:firstPkg.version_id, depPackageID:secondPkg.version_id, dependencyType:doc.dependencyType, justification:doc.justification, collector:doc.collector, origin:doc.origin, documentRef:doc.documentRef }
			UPDATE {} IN isDependencies
			RETURN {
				'_id': NEW._id,
				'_key': NEW._key
			}
		)
	
	INSERT { _key: CONCAT("isDependencySubjectPkgEdges", firstPkg.version_key, isDependency._key), _from: firstPkg.version_id, _to: isDependency._id} INTO isDependencySubjectPkgEdges OPTIONS { overwriteMode: "ignore" }
	INSERT { _key: CONCAT("isDependencyDepPkgVersionEdges", isDependency._key, secondPkg.version_key), _from: isDependency._id, _to: secondPkg.version_id} INTO isDependencyDepPkgVersionEdges OPTIONS { overwriteMode: "ignore" }

	RETURN { 'isDependency_id': isDependency._id }`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestDependencies")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest isDependency: %w", err)
	}
	defer cursor.Close()

	isDepList, err := getIsDependencyFromCursor(ctx, cursor, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get isDependency from arango cursor: %w", err)
	}

	var isDepIDList []string
	for _, isDep := range isDepList {
		isDepIDList = append(isDepIDList, isDep.ID)
	}
	return isDepIDList, nil
}

func (c *arangoClient) IngestDependency(ctx context.Context, pkg model.IDorPkgInput, depPkg model.IDorPkgInput, dependency model.IsDependencyInputSpec) (string, error) {
	// Specific version
	query := `
	LET firstPkg = FIRST(
		FOR pVersion in pkgVersions
		FILTER pVersion.guacKey == @pkgVersionGuacKey
		RETURN {
			'version_id': pVersion._id,
			'version_key': pVersion._key
		}
	)

	LET secondPkg = FIRST(
        FOR pVersion in pkgVersions
		FILTER pVersion.guacKey == @secondPkgGuacKey
		RETURN {
			'version_id': pVersion._id,
			'version_key': pVersion._key
		}
    )

	  
	  LET isDependency = FIRST(
		  UPSERT { packageID:firstPkg.version_id, depPackageID:secondPkg.version_id, dependencyType:@dependencyType, justification:@justification, collector:@collector, origin:@origin, documentRef:@documentRef } 
			  INSERT { packageID:firstPkg.version_id, depPackageID:secondPkg.version_id, dependencyType:@dependencyType, justification:@justification, collector:@collector, origin:@origin, documentRef:@documentRef } 
			  UPDATE {} IN isDependencies
			  RETURN {
				'_id': NEW._id,
				'_key': NEW._key
			  }
	  )
	  
	  INSERT { _key: CONCAT("isDependencySubjectPkgEdges", firstPkg.version_key, isDependency._key), _from: firstPkg.version_id, _to: isDependency._id} INTO isDependencySubjectPkgEdges OPTIONS { overwriteMode: "ignore" }
	  INSERT { _key: CONCAT("isDependencyDepPkgVersionEdges", isDependency._key, secondPkg.version_key), _from: isDependency._id, _to: secondPkg.version_id} INTO isDependencyDepPkgVersionEdges OPTIONS { overwriteMode: "ignore" }
	  
	  RETURN { 'isDependency_id': isDependency._id }`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getDependencyQueryValues(pkg.PackageInput, depPkg.PackageInput, &dependency), "IngestDependency")
	if err != nil {
		return "", fmt.Errorf("failed to ingest isDependency: %w", err)
	}
	defer cursor.Close()

	isDependencyList, err := getIsDependencyFromCursor(ctx, cursor, true)
	if err != nil {
		return "", fmt.Errorf("failed to get dependency from arango cursor: %w", err)
	}

	if len(isDependencyList) == 1 {
		return isDependencyList[0].ID, nil
	} else {
		return "", fmt.Errorf("number of dependency ingested is greater than one")
	}
}

func getIsDependencyFromCursor(ctx context.Context, cursor driver.Cursor, ingestion bool) ([]*model.IsDependency, error) {
	type collectedData struct {
		PkgVersion     *dbPkgVersion `json:"pkgVersion"`
		DepPkg         *dbPkgVersion `json:"depPkg"`
		IsDependencyID string        `json:"isDependency_id"`
		DependencyType string        `json:"dependencyType"`
		Justification  string        `json:"justification"`
		Collector      string        `json:"collector"`
		Origin         string        `json:"origin"`
		DocumentRef    string        `json:"documentRef"`
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
		var isDependency *model.IsDependency
		if !ingestion {
			pkg := generateModelPackage(createdValue.PkgVersion.TypeID, createdValue.PkgVersion.PkgType, createdValue.PkgVersion.NamespaceID, createdValue.PkgVersion.Namespace, createdValue.PkgVersion.NameID,
				createdValue.PkgVersion.Name, createdValue.PkgVersion.VersionID, createdValue.PkgVersion.Version, createdValue.PkgVersion.Subpath, createdValue.PkgVersion.QualifierList)

			depPkg := generateModelPackage(createdValue.DepPkg.TypeID, createdValue.DepPkg.PkgType, createdValue.DepPkg.NamespaceID, createdValue.DepPkg.Namespace, createdValue.DepPkg.NameID,
				createdValue.DepPkg.Name, createdValue.DepPkg.VersionID, createdValue.DepPkg.Version, createdValue.DepPkg.Subpath, createdValue.DepPkg.QualifierList)

			isDependency = &model.IsDependency{
				ID:                createdValue.IsDependencyID,
				Package:           pkg,
				DependencyPackage: depPkg,
				Justification:     createdValue.Justification,
				Origin:            createdValue.Origin,
				Collector:         createdValue.Collector,
				DocumentRef:       createdValue.DocumentRef,
			}

			if depType, ok := dependencyTypeToEnum[createdValue.DependencyType]; ok {
				isDependency.DependencyType = depType
			} else {
				return nil, fmt.Errorf("DependencyType %s failed to match", createdValue.DependencyType)
			}
		} else {
			isDependency = &model.IsDependency{ID: createdValue.IsDependencyID}
		}
		isDependencyList = append(isDependencyList, isDependency)
	}

	return isDependencyList, nil
}

func (c *arangoClient) buildIsDependencyByID(ctx context.Context, id string, filter *model.IsDependencySpec) (*model.IsDependency, error) {
	if filter != nil && filter.ID != nil {
		if *filter.ID != id {
			return nil, fmt.Errorf("ID does not match filter")
		}
	}

	idSplit := strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	if idSplit[0] == isDependenciesStr {
		if filter != nil {
			filter.ID = ptrfrom.String(id)
		} else {
			filter = &model.IsDependencySpec{
				ID: ptrfrom.String(id),
			}
		}
		return c.queryIsDependencyNodeByID(ctx, filter)
	} else {
		return nil, fmt.Errorf("id type does not match for isDependency query: %s", id)
	}
}

func (c *arangoClient) queryIsDependencyNodeByID(ctx context.Context, filter *model.IsDependencySpec) (*model.IsDependency, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(isDependenciesStr, "isDependency")
	queryIsDependencyBasedOnFilter(arangoQueryBuilder, filter, values)
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN isDependency`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "queryIsDependencyNodeByID")
	if err != nil {
		return nil, fmt.Errorf("failed to query for isDependency: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type dbIsDependency struct {
		IsDependencyID string `json:"_id"`
		PackageID      string `json:"packageID"`
		DepPackageID   string `json:"depPackageID"`
		DependencyType string `json:"dependencyType"`
		Justification  string `json:"justification"`
		Collector      string `json:"collector"`
		Origin         string `json:"origin"`
		DocumentRef    string `json:"documentRef"`
	}

	var collectedValues []dbIsDependency
	for {
		var doc dbIsDependency
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to isDependency from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, fmt.Errorf("number of isDependency nodes found for ID: %s is greater than one", *filter.ID)
	}

	var depType model.DependencyType
	if typeEnum, ok := dependencyTypeToEnum[collectedValues[0].DependencyType]; ok {
		depType = typeEnum
	} else {
		return nil, fmt.Errorf("DependencyType %s failed to match", collectedValues[0].DependencyType)
	}

	builtPackage, err := c.buildPackageResponseFromID(ctx, collectedValues[0].PackageID, filter.Package)
	if err != nil {
		return nil, fmt.Errorf("failed to get package from ID: %s, with error: %w", collectedValues[0].PackageID, err)
	}

	builtDepPackage, err := c.buildPackageResponseFromID(ctx, collectedValues[0].DepPackageID, filter.DependencyPackage)
	if err != nil {
		return nil, fmt.Errorf("failed to get dependency package from ID: %s, with error: %w", collectedValues[0].DepPackageID, err)
	}

	return &model.IsDependency{
		ID:                collectedValues[0].IsDependencyID,
		Package:           builtPackage,
		DependencyPackage: builtDepPackage,
		DependencyType:    depType,
		Justification:     collectedValues[0].Justification,
		Origin:            collectedValues[0].Origin,
		Collector:         collectedValues[0].Collector,
		DocumentRef:       collectedValues[0].DocumentRef,
	}, nil
}

func (c *arangoClient) isDependencyNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := make([]string, 0, 2)
	if allowedEdges[model.EdgeIsDependencyPackage] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(isDependenciesStr, "isDependency")
		queryIsDependencyBasedOnFilter(arangoQueryBuilder, &model.IsDependencySpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { packageID:  isDependency.packageID, depPackageID: isDependency.depPackageID }")

		cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "getNeighborIDFromCursor - isDependencyNeighbors")
		if err != nil {
			return nil, fmt.Errorf("failed to query for Neighbors for %s with error: %w", "isDependencyNeighbors", err)
		}
		defer cursor.Close()

		type dbIsDepNeighbor struct {
			PackageID    string `json:"packageID"`
			DepPackageID string `json:"depPackageID"`
		}

		var foundNeighbors []dbIsDepNeighbor
		for {
			var doc dbIsDepNeighbor
			_, err := cursor.ReadDocument(ctx, &doc)
			if err != nil {
				if driver.IsNoMoreDocuments(err) {
					break
				} else {
					return nil, fmt.Errorf("failed to get neighbor id from cursor for %s with error: %w", "isDependencyNeighbors", err)
				}
			} else {
				foundNeighbors = append(foundNeighbors, doc)
			}
		}

		var foundIDs []string
		for _, foundNeighbor := range foundNeighbors {
			foundIDs = append(foundIDs, foundNeighbor.PackageID)
			foundIDs = append(foundIDs, foundNeighbor.DepPackageID)
		}
		out = append(out, foundIDs...)
	}

	return out, nil
}

func noMatchIsDep(filter *model.IsDependencySpec, link *model.IsDependency) bool {
	if filter != nil {
		return noMatch(filter.Justification, link.Justification) ||
			noMatch(filter.Origin, link.Origin) ||
			noMatch(filter.Collector, link.Collector) ||
			(filter.DependencyType != nil && *filter.DependencyType != link.DependencyType)
	} else {
		return false
	}
}

func matchDependencies(ctx context.Context, filters []*model.IsDependencySpec, deps []*model.IsDependency) bool {
	if len(filters) > 0 {
		var depIDs []string
		for _, dep := range deps {
			depIDs = append(depIDs, dep.ID)
		}
		for _, filter := range filters {
			if filter == nil {
				continue
			}
			if filter.ID != nil {
				// Check by ID if present
				if !helper.IsIDPresent(*filter.ID, depIDs) {
					return false
				}
			} else {
				// Otherwise match spec information
				match := false
				for _, dep := range deps {
					if !noMatchIsDep(filter, dep) &&
						(filter.Package == nil || matchPackages(ctx, []*model.PkgSpec{filter.Package}, []*model.Package{dep.Package})) &&
						(filter.DependencyPackage == nil || matchPackages(ctx, []*model.PkgSpec{filter.DependencyPackage}, []*model.Package{dep.DependencyPackage})) {
						match = true
						break
					}
				}
				if !match {
					return false
				}
			}
		}
	}
	return true
}
