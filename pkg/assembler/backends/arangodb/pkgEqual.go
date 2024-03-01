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
	"strings"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	purl "github.com/package-url/packageurl-go"
)

func (c *arangoClient) PkgEqual(ctx context.Context, pkgEqualSpec *model.PkgEqualSpec) ([]*model.PkgEqual, error) {

	if pkgEqualSpec != nil && pkgEqualSpec.ID != nil {
		pe, err := c.buildPkgEqualByID(ctx, *pkgEqualSpec.ID, pkgEqualSpec)
		if err != nil {
			return nil, fmt.Errorf("buildPkgEqualByID failed with an error: %w", err)
		}
		return []*model.PkgEqual{pe}, nil
	}

	values := map[string]any{}
	if pkgEqualSpec.Packages != nil {
		if len(pkgEqualSpec.Packages) == 1 {
			return matchPkgEqualByInput(ctx, c, pkgEqualSpec, pkgEqualSpec.Packages[0], nil, values)
		} else {
			return matchPkgEqualByInput(ctx, c, pkgEqualSpec, pkgEqualSpec.Packages[0], pkgEqualSpec.Packages[1], values)
		}
	} else {
		arangoQueryBuilder := newForQuery(pkgEqualsStr, "pkgEqual")
		setPkgEqualMatchValues(arangoQueryBuilder, pkgEqualSpec, values)
		arangoQueryBuilder.forInBound(pkgEqualSubjectPkgEdgesStr, "pVersion", "pkgEqual")
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "pName", "pVersion")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")

		arangoQueryBuilder.forOutBound(pkgEqualPkgEdgesStr, "epVersion", "pkgEqual")
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "epName", "epVersion")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "epNs", "epName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "epType", "epNs")

		return getPkgEqualForQuery(ctx, c, arangoQueryBuilder, values)
	}
}

func matchPkgEqualByInput(ctx context.Context, c *arangoClient, pkgEqualSpec *model.PkgEqualSpec, firstPkg *model.PkgSpec,
	secondPkg *model.PkgSpec, values map[string]any) ([]*model.PkgEqual, error) {

	var combinedPkgEqual []*model.PkgEqual

	arangoQueryBuilder := setPkgVersionMatchValues(firstPkg, values)
	arangoQueryBuilder.forOutBound(pkgEqualSubjectPkgEdgesStr, "pkgEqual", "pVersion")
	setPkgEqualMatchValues(arangoQueryBuilder, pkgEqualSpec, values)
	if secondPkg != nil {

		arangoQueryBuilder.forOutBound(pkgEqualPkgEdgesStr, "epVersion", "pkgEqual")
		if secondPkg.ID != nil {
			arangoQueryBuilder.filter("epVersion", "_id", "==", "@equal_id")
			values["equal_id"] = *secondPkg.ID
		}
		if secondPkg.Version != nil {
			arangoQueryBuilder.filter("epVersion", "version", "==", "@equalVersionValue")
			values["equalVersionValue"] = *secondPkg.Version
		}
		if secondPkg.Subpath != nil {
			arangoQueryBuilder.filter("epVersion", "subpath", "==", "@equalSubpath")
			values["equalSubpath"] = *secondPkg.Subpath
		}
		if secondPkg.MatchOnlyEmptyQualifiers != nil {
			if !*secondPkg.MatchOnlyEmptyQualifiers {
				if len(secondPkg.Qualifiers) > 0 {
					arangoQueryBuilder.filter("epVersion", "qualifier_list", "==", "@equalQualifier")
					values["equalQualifier"] = getFilterQualifiers(secondPkg.Qualifiers)
				}
			} else {
				arangoQueryBuilder.filterLength("epVersion", "qualifier_list", "==", 0)
			}
		} else {
			if len(secondPkg.Qualifiers) > 0 {
				arangoQueryBuilder.filter("epVersion", "qualifier_list", "==", "@equalQualifier")
				values["equalQualifier"] = getFilterQualifiers(secondPkg.Qualifiers)
			}
		}
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "epName", "epVersion")
		if secondPkg.Name != nil {
			arangoQueryBuilder.filter("epName", "name", "==", "@equalName")
			values["equalName"] = *secondPkg.Name
		}
		arangoQueryBuilder.forInBound(pkgHasNameStr, "epNs", "epName")
		if secondPkg.Namespace != nil {
			arangoQueryBuilder.filter("epNs", "namespace", "==", "@equalNamespace")
			values["equalNamespace"] = *secondPkg.Namespace
		}
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "epType", "epNs")
		if secondPkg.Type != nil {
			arangoQueryBuilder.filter("epType", "type", "==", "@equalType")
			values["equalType"] = *secondPkg.Type
		}
	} else {
		arangoQueryBuilder.forOutBound(pkgEqualPkgEdgesStr, "epVersion", "pkgEqual")
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "epName", "epVersion")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "epNs", "epName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "epType", "epNs")
	}

	pkgSubjectPkgEqual, err := getPkgEqualForQuery(ctx, c, arangoQueryBuilder, values)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve pkgEqual with error: %w", err)
	}
	combinedPkgEqual = append(combinedPkgEqual, pkgSubjectPkgEqual...)

	arangoQueryBuilder = setPkgVersionMatchValues(firstPkg, values)
	arangoQueryBuilder.forInBound(pkgEqualPkgEdgesStr, "pkgEqual", "pVersion")
	setPkgEqualMatchValues(arangoQueryBuilder, pkgEqualSpec, values)
	if secondPkg != nil {

		arangoQueryBuilder.forInBound(pkgEqualSubjectPkgEdgesStr, "epVersion", "pkgEqual")
		if secondPkg.ID != nil {
			arangoQueryBuilder.filter("epVersion", "_id", "==", "@equal_id")
			values["equal_id"] = *secondPkg.ID
		}
		if secondPkg.Version != nil {
			arangoQueryBuilder.filter("epVersion", "version", "==", "@equalVersionValue")
			values["equalVersionValue"] = *secondPkg.Version
		}
		if secondPkg.Subpath != nil {
			arangoQueryBuilder.filter("epVersion", "subpath", "==", "@equalSubpath")
			values["equalSubpath"] = *secondPkg.Subpath
		}
		if secondPkg.MatchOnlyEmptyQualifiers != nil {
			if !*secondPkg.MatchOnlyEmptyQualifiers {
				if len(secondPkg.Qualifiers) > 0 {
					arangoQueryBuilder.filter("epVersion", "qualifier_list", "==", "@equalQualifier")
					values["equalQualifier"] = getFilterQualifiers(secondPkg.Qualifiers)
				}
			} else {
				arangoQueryBuilder.filterLength("epVersion", "qualifier_list", "==", 0)
			}
		} else {
			if len(secondPkg.Qualifiers) > 0 {
				arangoQueryBuilder.filter("epVersion", "qualifier_list", "==", "@equalQualifier")
				values["equalQualifier"] = getFilterQualifiers(secondPkg.Qualifiers)
			}
		}
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "epName", "epVersion")
		if secondPkg.Name != nil {
			arangoQueryBuilder.filter("epName", "name", "==", "@equalName")
			values["equalName"] = *secondPkg.Name
		}
		arangoQueryBuilder.forInBound(pkgHasNameStr, "epNs", "epName")
		if secondPkg.Namespace != nil {
			arangoQueryBuilder.filter("epNs", "namespace", "==", "@equalNamespace")
			values["equalNamespace"] = *secondPkg.Namespace
		}
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "epType", "epNs")
		if secondPkg.Type != nil {
			arangoQueryBuilder.filter("epType", "type", "==", "@equalType")
			values["equalType"] = *secondPkg.Type
		}
	} else {
		arangoQueryBuilder.forInBound(pkgEqualSubjectPkgEdgesStr, "epVersion", "pkgEqual")
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "epName", "epVersion")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "epNs", "epName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "epType", "epNs")
	}

	pkgEqualPkgEqual, err := getPkgEqualForQuery(ctx, c, arangoQueryBuilder, values)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve pkgEqual with error: %w", err)
	}
	combinedPkgEqual = append(combinedPkgEqual, pkgEqualPkgEqual...)

	return combinedPkgEqual, nil
}

func getPkgEqualForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.PkgEqual, error) {
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
		'equalPkgVersion': {
			'type_id': epType._id,
			'type': epType.type,
			'namespace_id': epNs._id,
			'namespace': epNs.namespace,
			'name_id': epName._id,
			'name': epName.name,
			'version_id': epVersion._id,
			'version': epVersion.version,
			'subpath': epVersion.subpath,
			'qualifier_list': epVersion.qualifier_list
		},
		'pkgEqual_id': pkgEqual._id,
		'justification': pkgEqual.justification,
		'collector': pkgEqual.collector,
		'origin': pkgEqual.origin
	}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "pkgEqual")
	if err != nil {
		return nil, fmt.Errorf("failed to query for pkgEqual: %w", err)
	}
	defer cursor.Close()

	return getPkgEqualFromCursor(ctx, cursor, false)
}

func setPkgEqualMatchValues(arangoQueryBuilder *arangoQueryBuilder, pkgEqualSpec *model.PkgEqualSpec, queryValues map[string]any) {
	if pkgEqualSpec.ID != nil {
		arangoQueryBuilder.filter("pkgEqual", "_id", "==", "@id")
		queryValues["id"] = *pkgEqualSpec.ID
	}
	if pkgEqualSpec.Justification != nil {
		arangoQueryBuilder.filter("pkgEqual", justification, "==", "@"+justification)
		queryValues[justification] = *pkgEqualSpec.Justification
	}
	if pkgEqualSpec.Origin != nil {
		arangoQueryBuilder.filter("pkgEqual", origin, "==", "@"+origin)
		queryValues[origin] = *pkgEqualSpec.Origin
	}
	if pkgEqualSpec.Collector != nil {
		arangoQueryBuilder.filter("pkgEqual", collector, "==", "@"+collector)
		queryValues[collector] = *pkgEqualSpec.Collector
	}
}

func pkgInputSpecToPurl(currentPkg *model.PkgInputSpec) string {
	qualifiersMap := map[string]string{}
	keys := []string{}
	for _, kv := range currentPkg.Qualifiers {
		qualifiersMap[kv.Key] = kv.Value
		keys = append(keys, kv.Key)
	}
	sort.Strings(keys)
	qualifiers := []string{}
	for _, k := range keys {
		qualifiers = append(qualifiers, k, qualifiersMap[k])
	}

	var ns, ver, subpath string

	if currentPkg.Namespace != nil {
		ns = *currentPkg.Namespace
	}

	if currentPkg.Version != nil {
		ver = *currentPkg.Version
	}

	if currentPkg.Subpath != nil {
		subpath = *currentPkg.Subpath
	}
	return pkgToPurl(currentPkg.Type, ns, currentPkg.Name, ver, subpath, qualifiers)
}

func pkgToPurl(purlType, namespace, name, version, subpath string, qualifiersList []string) string {
	collectedQualifiers := purl.Qualifiers{}
	for i := range qualifiersList {
		if i%2 == 0 {
			qualifier := purl.Qualifier{
				Key:   qualifiersList[i],
				Value: qualifiersList[i+1],
			}
			collectedQualifiers = append(collectedQualifiers, qualifier)
		}
	}

	if purlType == purl.TypeOCI || purlType == purl.TypeDocker {
		if namespace != "" {
			collectedQualifiers = append(collectedQualifiers, purl.Qualifier{Key: "repository_url", Value: namespace})
			namespace = ""
		}
	}

	pkg := purl.NewPackageURL(purlType, namespace, name, version, collectedQualifiers, subpath)
	return pkg.ToString()
}

func getPkgEqualQueryValues(currentPkg *model.PkgInputSpec, otherPkg *model.PkgInputSpec, pkgEqual *model.PkgEqualInputSpec) map[string]any {

	pkgsMap := make(map[string]*model.PkgInputSpec, 2)
	var purls []string

	pkgPurl := pkgInputSpecToPurl(currentPkg)
	purls = append(purls, pkgPurl)
	pkgsMap[pkgPurl] = currentPkg
	otherPkgPurl := pkgInputSpecToPurl(otherPkg)
	purls = append(purls, otherPkgPurl)
	pkgsMap[otherPkgPurl] = otherPkg

	sort.Strings(purls)
	sortedPkgs := []*model.PkgInputSpec{}
	for _, k := range purls {
		sortedPkgs = append(sortedPkgs, pkgsMap[k])
	}

	values := map[string]any{}
	// add guac keys
	pkgId := helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](sortedPkgs[0], helpers.PkgServerKey)
	values["pkgVersionGuacKey"] = pkgId.VersionId

	equalPkgId := helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](sortedPkgs[1], helpers.PkgServerKey)
	values["equalPkgVersionGuacKey"] = equalPkgId.VersionId

	values[justification] = pkgEqual.Justification
	values[origin] = pkgEqual.Origin
	values[collector] = pkgEqual.Collector

	return values
}

func (c *arangoClient) IngestPkgEquals(ctx context.Context, pkgs []*model.IDorPkgInput, otherPackages []*model.IDorPkgInput, pkgEquals []*model.PkgEqualInputSpec) ([]string, error) {
	var listOfValues []map[string]any

	for i := range pkgEquals {
		listOfValues = append(listOfValues, getPkgEqualQueryValues(pkgs[i].PackageInput, otherPackages[i].PackageInput, pkgEquals[i]))
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

	LET equalPkg = FIRST(
		FOR pVersion in pkgVersions
		  FILTER pVersion.guacKey == doc.equalPkgVersionGuacKey
		RETURN {
			'version_id': pVersion._id,
			'version_key': pVersion._key
		}
	)
	
	LET pkgEqual = FIRST(
		UPSERT { packageID:firstPkg.version_id, equalPackageID:equalPkg.version_id, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
			INSERT { packageID:firstPkg.version_id, equalPackageID:equalPkg.version_id, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
			UPDATE {} IN pkgEquals
			RETURN {
				'_id': NEW._id,
				'_key': NEW._key
			}
	)
	
	INSERT { _key: CONCAT("pkgEqualSubjectPkgEdges", firstPkg.version_key, pkgEqual._key), _from: firstPkg.version_id, _to: pkgEqual._id} INTO pkgEqualSubjectPkgEdges OPTIONS { overwriteMode: "ignore" }
	INSERT { _key: CONCAT("pkgEqualPkgEdges", pkgEqual._key, equalPkg.version_key), _from: pkgEqual._id, _to: equalPkg.version_id} INTO pkgEqualPkgEdges OPTIONS { overwriteMode: "ignore" }
	
	RETURN { 'pkgEqual_id': pkgEqual._id }`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestPkgEquals")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest pkgEquals: %w", err)
	}
	defer cursor.Close()

	pkgEqualList, err := getPkgEqualFromCursor(ctx, cursor, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get pkgEqual from arango cursor: %w", err)
	}

	var pkgEqualIDList []string
	for _, ingestedPkgEqual := range pkgEqualList {
		pkgEqualIDList = append(pkgEqualIDList, ingestedPkgEqual.ID)
	}

	return pkgEqualIDList, nil
}

func (c *arangoClient) IngestPkgEqual(ctx context.Context, pkg model.IDorPkgInput, otherPackage model.IDorPkgInput, pkgEqual model.PkgEqualInputSpec) (string, error) {
	query := `
	LET firstPkg = FIRST(
		FOR pVersion in pkgVersions
		  FILTER pVersion.guacKey == @pkgVersionGuacKey
		RETURN {
			'version_id': pVersion._id,
			'version_key': pVersion._key
		}
	)

	LET equalPkg = FIRST(
		FOR pVersion in pkgVersions
		  FILTER pVersion.guacKey == @equalPkgVersionGuacKey
		RETURN {
			'version_id': pVersion._id,
			'version_key': pVersion._key
		}
	)
	
	LET pkgEqual = FIRST(
		UPSERT { packageID:firstPkg.version_id, equalPackageID:equalPkg.version_id, justification:@justification, collector:@collector, origin:@origin } 
			INSERT { packageID:firstPkg.version_id, equalPackageID:equalPkg.version_id, justification:@justification, collector:@collector, origin:@origin } 
			UPDATE {} IN pkgEquals
			RETURN {
				'_id': NEW._id,
				'_key': NEW._key
			}
	)
	
	INSERT { _key: CONCAT("pkgEqualSubjectPkgEdges", firstPkg.version_key, pkgEqual._key), _from: firstPkg.version_id, _to: pkgEqual._id} INTO pkgEqualSubjectPkgEdges OPTIONS { overwriteMode: "ignore" }
	INSERT { _key: CONCAT("pkgEqualPkgEdges", pkgEqual._key, equalPkg.version_key), _from: pkgEqual._id, _to: equalPkg.version_id} INTO pkgEqualPkgEdges OPTIONS { overwriteMode: "ignore" }
	
	RETURN { 'pkgEqual_id': pkgEqual._id }`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getPkgEqualQueryValues(pkg.PackageInput, otherPackage.PackageInput, &pkgEqual), "IngestPkgEqual")
	if err != nil {
		return "", fmt.Errorf("failed to ingest pkgEqual: %w", err)
	}
	defer cursor.Close()

	pkgEqualList, err := getPkgEqualFromCursor(ctx, cursor, true)
	if err != nil {
		return "", fmt.Errorf("failed to get pkgEqual from arango cursor: %w", err)
	}

	if len(pkgEqualList) == 1 {
		return pkgEqualList[0].ID, nil
	} else {
		return "", fmt.Errorf("number of pkgEqual ingested is greater than one")
	}
}

func getPkgEqualFromCursor(ctx context.Context, cursor driver.Cursor, ingestion bool) ([]*model.PkgEqual, error) {
	type collectedData struct {
		PkgVersion      *dbPkgVersion `json:"pkgVersion"`
		EqualPkgVersion *dbPkgVersion `json:"equalPkgVersion"`
		PkgEqualId      string        `json:"pkgEqual_id"`
		Justification   string        `json:"justification"`
		Collector       string        `json:"collector"`
		Origin          string        `json:"origin"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to pkgEqual from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var pkgEqualList []*model.PkgEqual
	for _, createdValue := range createdValues {
		var pkgEqual *model.PkgEqual
		if !ingestion {
			pkg := generateModelPackage(createdValue.PkgVersion.TypeID, createdValue.PkgVersion.PkgType, createdValue.PkgVersion.NamespaceID, createdValue.PkgVersion.Namespace, createdValue.PkgVersion.NameID,
				createdValue.PkgVersion.Name, createdValue.PkgVersion.VersionID, createdValue.PkgVersion.Version, createdValue.PkgVersion.Subpath, createdValue.PkgVersion.QualifierList)

			equalPkg := generateModelPackage(createdValue.EqualPkgVersion.TypeID, createdValue.EqualPkgVersion.PkgType, createdValue.EqualPkgVersion.NamespaceID, createdValue.EqualPkgVersion.Namespace, createdValue.EqualPkgVersion.NameID,
				createdValue.EqualPkgVersion.Name, createdValue.EqualPkgVersion.VersionID, createdValue.EqualPkgVersion.Version, createdValue.EqualPkgVersion.Subpath, createdValue.EqualPkgVersion.QualifierList)

			pkgEqual = &model.PkgEqual{
				ID:            createdValue.PkgEqualId,
				Packages:      []*model.Package{pkg, equalPkg},
				Justification: createdValue.Justification,
				Origin:        createdValue.Origin,
				Collector:     createdValue.Collector,
			}
		} else {
			pkgEqual = &model.PkgEqual{ID: createdValue.PkgEqualId}
		}

		pkgEqualList = append(pkgEqualList, pkgEqual)
	}
	return pkgEqualList, nil
}

func (c *arangoClient) buildPkgEqualByID(ctx context.Context, id string, filter *model.PkgEqualSpec) (*model.PkgEqual, error) {
	if filter != nil && filter.ID != nil {
		if *filter.ID != id {
			return nil, fmt.Errorf("ID does not match filter")
		}
	}

	idSplit := strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	if idSplit[0] == pkgEqualsStr {
		if filter != nil {
			filter.ID = ptrfrom.String(id)
		} else {
			filter = &model.PkgEqualSpec{
				ID: ptrfrom.String(id),
			}
		}
		return c.queryPkgEqualNodeByID(ctx, filter)
	} else {
		return nil, fmt.Errorf("id type does not match for pkgEqual query: %s", id)
	}
}

func (c *arangoClient) queryPkgEqualNodeByID(ctx context.Context, filter *model.PkgEqualSpec) (*model.PkgEqual, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(pkgEqualsStr, "pkgEqual")
	setPkgEqualMatchValues(arangoQueryBuilder, filter, values)
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN pkgEqual`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "queryPkgEqualNodeByID")
	if err != nil {
		return nil, fmt.Errorf("failed to query for pkgEqual: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type dbPkgEqual struct {
		PkgEqualID     string `json:"_id"`
		PackageID      string `json:"packageID"`
		EqualPackageID string `json:"equalPackageID"`
		Justification  string `json:"justification"`
		Collector      string `json:"collector"`
		Origin         string `json:"origin"`
	}

	var collectedValues []dbPkgEqual
	for {
		var doc dbPkgEqual
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to pkgEqual from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, fmt.Errorf("number of pkgEqual nodes found for ID: %s is greater than one", *filter.ID)
	}

	builtPackage, err := c.buildPackageResponseFromID(ctx, collectedValues[0].PackageID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get package from ID: %s, with error: %w", collectedValues[0].PackageID, err)
	}

	builtEqualPackage, err := c.buildPackageResponseFromID(ctx, collectedValues[0].EqualPackageID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get equal package from ID: %s, with error: %w", collectedValues[0].EqualPackageID, err)
	}

	return &model.PkgEqual{
		ID:            collectedValues[0].PkgEqualID,
		Packages:      []*model.Package{builtPackage, builtEqualPackage},
		Justification: collectedValues[0].Justification,
		Origin:        collectedValues[0].Collector,
		Collector:     collectedValues[0].Origin,
	}, nil
}

func (c *arangoClient) pkgEqualNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := make([]string, 0, 2)
	if allowedEdges[model.EdgePkgEqualPackage] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(pkgEqualsStr, "pkgEqual")
		setPkgEqualMatchValues(arangoQueryBuilder, &model.PkgEqualSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { packageID:  pkgEqual.packageID, equalPackageID: pkgEqual.equalPackageID }")

		cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "getNeighborIDFromCursor - pkgEqualNeighbors")
		if err != nil {
			return nil, fmt.Errorf("failed to query for Neighbors for %s with error: %w", "pkgEqualNeighbors", err)
		}
		defer cursor.Close()

		type dbPkgEqualNeighbor struct {
			PackageID      string `json:"packageID"`
			EqualPackageID string `json:"equalPackageID"`
		}

		var foundNeighbors []dbPkgEqualNeighbor
		for {
			var doc dbPkgEqualNeighbor
			_, err := cursor.ReadDocument(ctx, &doc)
			if err != nil {
				if driver.IsNoMoreDocuments(err) {
					break
				} else {
					return nil, fmt.Errorf("failed to get neighbor id from cursor for %s with error: %w", "pkgEqualNeighbors", err)
				}
			} else {
				foundNeighbors = append(foundNeighbors, doc)
			}
		}

		var foundIDs []string
		for _, foundNeighbor := range foundNeighbors {
			foundIDs = append(foundIDs, foundNeighbor.PackageID)
			foundIDs = append(foundIDs, foundNeighbor.EqualPackageID)
		}
		out = append(out, foundIDs...)
	}
	return out, nil
}
