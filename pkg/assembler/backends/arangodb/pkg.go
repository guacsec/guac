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

	"github.com/99designs/gqlgen/graphql"
	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type dbPkgVersion struct {
	TypeID        string   `json:"type_id"`
	PkgType       string   `json:"type"`
	NamespaceID   string   `json:"namespace_id"`
	Namespace     string   `json:"namespace"`
	NameID        string   `json:"name_id"`
	Name          string   `json:"name"`
	VersionID     *string  `json:"version_id"`
	Version       *string  `json:"version"`
	Subpath       *string  `json:"subpath"`
	QualifierList []string `json:"qualifier_list"`
}

type dbPkgName struct {
	TypeID      string `json:"type_id"`
	PkgType     string `json:"type"`
	NamespaceID string `json:"namespace_id"`
	Namespace   string `json:"namespace"`
	NameID      string `json:"name_id"`
	Name        string `json:"name"`
}

type dbPkgNamespace struct {
	TypeID      string `json:"type_id"`
	PkgType     string `json:"type"`
	NamespaceID string `json:"namespace_id"`
	Namespace   string `json:"namespace"`
}

type dbPkgType struct {
	TypeID  string `json:"type_id"`
	PkgType string `json:"type"`
}

type pkgIds struct {
	TypeId      string
	NamespaceId string
	NameId      string
	VersionId   string
}

func guacPkgId(pkg model.PkgInputSpec) pkgIds {
	ids := pkgIds{}

	ids.TypeId = pkg.Type

	var ns string
	if pkg.Namespace != nil {
		if *pkg.Namespace != "" {
			ns = *pkg.Namespace
		} else {
			ns = guacEmpty
		}
	}
	ids.NamespaceId = fmt.Sprintf("%s::%s", ids.TypeId, ns)
	ids.NameId = fmt.Sprintf("%s::%s", ids.NamespaceId, pkg.Name)

	var version string
	if pkg.Version != nil {
		if *pkg.Version != "" {
			version = *pkg.Version
		} else {
			version = guacEmpty
		}
	}

	var subpath string
	if pkg.Subpath != nil {
		if *pkg.Subpath != "" {
			subpath = *pkg.Subpath
		} else {
			subpath = guacEmpty
		}
	}

	ids.VersionId = fmt.Sprintf("%s::%s::%s?", ids.NameId, version, subpath)

	qualifiersMap := map[string]string{}
	var keys []string
	for _, kv := range pkg.Qualifiers {
		qualifiersMap[kv.Key] = kv.Value
		keys = append(keys, kv.Key)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ids.VersionId += fmt.Sprintf("%s=%s&", k, qualifiersMap[k])
	}

	return ids
}

func getPackageQueryValues(pkg *model.PkgInputSpec) map[string]any {
	values := map[string]any{}

	// add guac keys
	guacIds := guacPkgId(*pkg)
	values["guacNsKey"] = guacIds.NamespaceId
	values["guacNameKey"] = guacIds.NameId
	values["guacVersionKey"] = guacIds.VersionId

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
	var keys []string
	for _, kv := range pkg.Qualifiers {
		qualifiersMap[kv.Key] = kv.Value
		keys = append(keys, kv.Key)
	}
	sort.Strings(keys)
	var qualifiers []string
	for _, k := range keys {
		qualifiers = append(qualifiers, k, qualifiersMap[k])
	}
	values["qualifier"] = qualifiers
	return values
}

func (c *arangoClient) IngestPackages(ctx context.Context, pkgs []*model.PkgInputSpec) ([]*model.Package, error) {
	var listOfValues []map[string]any
	for i := range pkgs {
		listOfValues = append(listOfValues, getPackageQueryValues(pkgs[i]))
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
	LET type = FIRST(
		UPSERT { type: doc.pkgType}
		INSERT { type: doc.pkgType}
		UPDATE {}
		IN pkgTypes OPTIONS { indexHint: "byPkgType" }
		RETURN NEW
	)

	LET ns = FIRST(
	  UPSERT { namespace: doc.namespace, _parent: type._id , guacKey: doc.guacNsKey}
	  INSERT { namespace: doc.namespace, _parent: type._id , guacKey: doc.guacNsKey}
	  UPDATE {}
	  IN pkgNamespaces OPTIONS { indexHint: "byNsGuacKey" }
	  RETURN NEW
	)
	
	LET name = FIRST(
	  UPSERT { name: doc.name, _parent: ns._id, guacKey: doc.guacNameKey}
	  INSERT { name: doc.name, _parent: ns._id, guacKey: doc.guacNameKey}
	  UPDATE {}
	  IN pkgNames OPTIONS { indexHint: "byNameGuacKey" }
	  RETURN NEW
	)
	
	LET pkgVersionObj = FIRST(
	  UPSERT { version: doc.version, subpath: doc.subpath, qualifier_list: doc.qualifier, _parent: name._id, guacKey: doc.guacVersionKey}
	  INSERT { version: doc.version, subpath: doc.subpath, qualifier_list: doc.qualifier, _parent: name._id, guacKey: doc.guacVersionKey}
	  UPDATE {}
	  IN pkgVersions OPTIONS { indexHint: "byVersionGuacKey" }
	  RETURN NEW
	)
  
	LET pkgHasNamespaceCollection = (
	  INSERT { _key: CONCAT("pkgHasNamespace", type._key, ns._key), _from: type._id, _to: ns._id } INTO pkgHasNamespace OPTIONS { overwriteMode: "ignore" }
	)
	
	LET pkgHasNameCollection = (
 	  INSERT { _key: CONCAT("pkgHasName", ns._key, name._key), _from: ns._id, _to: name._id } INTO pkgHasName OPTIONS { overwriteMode: "ignore" }
	)
	
	LET pkgHasVersionCollection = (
	  INSERT { _key: CONCAT("pkgHasVersion", name._key, pkgVersionObj._key), _from: name._id, _to: pkgVersionObj._id } INTO pkgHasVersion OPTIONS { overwriteMode: "ignore" }
	)
	  
  RETURN {
	"type_id": type._id,
	"type": type.type,
	"namespace_id": ns._id,
	"namespace": ns.namespace,
	"name_id": name._id,
	"name": name.name,
	"version_id": pkgVersionObj._id,
	"version": pkgVersionObj.version,
	"subpath": pkgVersionObj.subpath,
	"qualifier_list": pkgVersionObj.qualifier_list
}`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestPackages")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest package: %w", err)
	}

	return getPackages(ctx, cursor)
}

func (c *arangoClient) IngestPackage(ctx context.Context, pkg model.PkgInputSpec) (*model.Package, error) {
	query := `
	  LET type = FIRST(
		UPSERT { type: @pkgType }
		INSERT { type: @pkgType }
		UPDATE {}
		IN pkgTypes OPTIONS { indexHint: "byPkgType" }
		RETURN NEW
	  )

	  LET ns = FIRST(
		UPSERT { namespace: @namespace, _parent: type._id , guacKey: @guacNsKey}
		INSERT { namespace: @namespace, _parent: type._id , guacKey: @guacNsKey}
		UPDATE {}
		IN pkgNamespaces OPTIONS { indexHint: "byNsGuacKey" }
		RETURN NEW
	  )
	  
	  LET name = FIRST(
		UPSERT { name: @name, _parent: ns._id, guacKey: @guacNameKey}
		INSERT { name: @name, _parent: ns._id, guacKey: @guacNameKey}
		UPDATE {}
		IN pkgNames OPTIONS { indexHint: "byNameGuacKey" }
		RETURN NEW
	  )
	  
	  LET pkgVersionObj = FIRST(
		UPSERT { version: @version, subpath: @subpath, qualifier_list: @qualifier, _parent: name._id, guacKey: @guacVersionKey}
		INSERT { version: @version, subpath: @subpath, qualifier_list: @qualifier, _parent: name._id, guacKey: @guacVersionKey}
		UPDATE {}
		IN pkgVersions OPTIONS { indexHint: "byVersionGuacKey" }
		RETURN NEW
	  )
	
	  LET pkgHasNamespaceCollection = (
		INSERT { _key: CONCAT("pkgHasNamespace", type._key, ns._key), _from: type._id, _to: ns._id} INTO pkgHasNamespace OPTIONS { overwriteMode: "ignore" }
	  )
	  
	  LET pkgHasNameCollection = (
		INSERT { _key: CONCAT("pkgHasName", ns._key, name._key), _from: ns._id, _to: name._id} INTO pkgHasName OPTIONS { overwriteMode: "ignore" }
	  )
	  
	  LET pkgHasVersionCollection = (
		INSERT { _key: CONCAT("pkgHasVersion", name._key, pkgVersionObj._key), _from: name._id, _to: pkgVersionObj._id } INTO pkgHasVersion OPTIONS { overwriteMode: "ignore" }
	  )
		
	RETURN {
	  "type_id": type._id,
	  "type": type.type,
	  "namespace_id": ns._id,
	  "namespace": ns.namespace,
	  "name_id": name._id,
	  "name": name.name,
	  "version_id": pkgVersionObj._id,
	  "version": pkgVersionObj.version,
	  "subpath": pkgVersionObj.subpath,
	  "qualifier_list": pkgVersionObj.qualifier_list
  }`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getPackageQueryValues(&pkg), "IngestPackage")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest package: %w", err)
	}

	createdPackages, err := getPackages(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get packages from arango cursor: %w", err)
	}
	if len(createdPackages) == 1 {
		return createdPackages[0], nil
	} else {
		return nil, fmt.Errorf("number of packages ingested is greater than one")
	}
}

func setPkgNameMatchValues(pkgSpec *model.PkgSpec, queryValues map[string]any) *arangoQueryBuilder {
	var arangoQueryBuilder *arangoQueryBuilder
	if pkgSpec != nil {
		arangoQueryBuilder = newForQuery(pkgTypesStr, "pType")
		if pkgSpec.Type != nil {
			arangoQueryBuilder.filter("pType", "type", "==", "@pkgType")
			queryValues["pkgType"] = *pkgSpec.Type
		}
		arangoQueryBuilder.forOutBound(pkgHasNamespaceStr, "pNs", "pType")
		if pkgSpec.Namespace != nil {
			arangoQueryBuilder.filter("pNs", "namespace", "==", "@namespace")
			queryValues["namespace"] = *pkgSpec.Namespace
		}
		arangoQueryBuilder.forOutBound(pkgHasNameStr, "pName", "pNs")
		if pkgSpec.Name != nil {
			arangoQueryBuilder.filter("pName", "name", "==", "@name")
			queryValues["name"] = *pkgSpec.Name
		}
	} else {
		arangoQueryBuilder = newForQuery(pkgTypesStr, "pType")
		arangoQueryBuilder.forOutBound(pkgHasNamespaceStr, "pNs", "pType")
		arangoQueryBuilder.forOutBound(pkgHasNameStr, "pName", "pNs")
	}
	return arangoQueryBuilder
}

func setPkgVersionMatchValues(pkgSpec *model.PkgSpec, queryValues map[string]any) *arangoQueryBuilder {
	var arangoQueryBuilder *arangoQueryBuilder
	if pkgSpec != nil {
		arangoQueryBuilder = newForQuery(pkgTypesStr, "pType")
		if pkgSpec.Type != nil {
			arangoQueryBuilder.filter("pType", "type", "==", "@pkgType")
			queryValues["pkgType"] = *pkgSpec.Type
		}
		arangoQueryBuilder.forOutBound(pkgHasNamespaceStr, "pNs", "pType")
		if pkgSpec.Namespace != nil {
			arangoQueryBuilder.filter("pNs", "namespace", "==", "@namespace")
			queryValues["namespace"] = *pkgSpec.Namespace
		}
		arangoQueryBuilder.forOutBound(pkgHasNameStr, "pName", "pNs")
		if pkgSpec.Name != nil {
			arangoQueryBuilder.filter("pName", "name", "==", "@name")
			queryValues["name"] = *pkgSpec.Name
		}
		arangoQueryBuilder.forOutBound(pkgHasVersionStr, "pVersion", "pName")
		if pkgSpec.ID != nil {
			arangoQueryBuilder.filter("pVersion", "_id", "==", "@id")
			queryValues["id"] = *pkgSpec.ID
		}
		if pkgSpec.Version != nil {
			arangoQueryBuilder.filter("pVersion", "version", "==", "@version")
			queryValues["version"] = *pkgSpec.Version
		}
		if pkgSpec.Subpath != nil {
			arangoQueryBuilder.filter("pVersion", "subpath", "==", "@subpath")
			queryValues["subpath"] = *pkgSpec.Subpath
		}
		if pkgSpec.MatchOnlyEmptyQualifiers != nil {
			if !*pkgSpec.MatchOnlyEmptyQualifiers {
				if len(pkgSpec.Qualifiers) > 0 {
					arangoQueryBuilder.filter("pVersion", "qualifier_list", "==", "@qualifier")
					queryValues["qualifier"] = getQualifiers(pkgSpec.Qualifiers)
				}
			} else {
				arangoQueryBuilder.filterLength("pVersion", "qualifier_list", "==", 0)
			}
		} else {
			if len(pkgSpec.Qualifiers) > 0 {
				arangoQueryBuilder.filter("pVersion", "qualifier_list", "==", "@qualifier")
				queryValues["qualifier"] = getQualifiers(pkgSpec.Qualifiers)
			}
		}
	} else {
		arangoQueryBuilder = newForQuery(pkgTypesStr, "pType")
		arangoQueryBuilder.forOutBound(pkgHasNamespaceStr, "pNs", "pType")
		arangoQueryBuilder.forOutBound(pkgHasNameStr, "pName", "pNs")
		arangoQueryBuilder.forOutBound(pkgHasVersionStr, "pVersion", "pName")
	}
	return arangoQueryBuilder
}

func (c *arangoClient) Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {

	if _, ok := ctx.Value("graphql").(graphql.OperationContext); ok {
		// fields: [type namespaces namespaces.namespace namespaces.names namespaces.names.name namespaces.names.versions
		// namespaces.names.versions.version namespaces.names.versions.qualifiers namespaces.names.versions.qualifiers.key
		// namespaces.names.versions.qualifiers.value namespaces.names.versions.subpath]
		fields := getPreloads(ctx)

		nameRequired := false
		namespaceRequired := false
		versionRequired := false
		for _, f := range fields {
			if f == namespaces {
				namespaceRequired = true
			}
			if f == names {
				nameRequired = true
			}
			if f == versions {
				versionRequired = true
			}
		}

		if !namespaceRequired && !nameRequired && !versionRequired {
			return c.packagesType(ctx, pkgSpec)
		} else if namespaceRequired && !nameRequired && !versionRequired {
			return c.packagesNamespace(ctx, pkgSpec)
		} else if nameRequired && !versionRequired {
			return c.packagesName(ctx, pkgSpec)
		}
	}

	values := map[string]any{}

	arangoQueryBuilder := setPkgVersionMatchValues(pkgSpec, values)
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
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
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "Packages")
	if err != nil {
		return nil, fmt.Errorf("failed to query for packages: %w", err)
	}
	defer cursor.Close()

	return getPackages(ctx, cursor)
}

func (c *arangoClient) packagesType(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {

	values := map[string]any{}

	arangoQueryBuilder := newForQuery(pkgTypesStr, "pType")
	if pkgSpec.Type != nil {
		arangoQueryBuilder.filter("pType", "type", "==", "@pkgType")
		values["pkgType"] = *pkgSpec.Type
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"type_id": pType._id,
		"type": pType.type
	}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "packagesType")
	if err != nil {
		return nil, fmt.Errorf("failed to query for package types: %w, values: %v", err, values)
	}
	defer cursor.Close()

	var packages []*model.Package
	for {
		var doc dbPkgType
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to query package type: %w", err)
			}
		} else {
			collectedPackage := &model.Package{
				ID:         doc.TypeID,
				Type:       doc.PkgType,
				Namespaces: []*model.PackageNamespace{},
			}
			packages = append(packages, collectedPackage)
		}
	}

	return packages, nil
}

func (c *arangoClient) packagesNamespace(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	values := map[string]any{}

	arangoQueryBuilder := newForQuery(pkgTypesStr, "pType")
	if pkgSpec.Type != nil {
		arangoQueryBuilder.filter("pType", "type", "==", "@pkgType")
		values["pkgType"] = *pkgSpec.Type
	}
	arangoQueryBuilder.forOutBound(pkgHasNamespaceStr, "pNs", "pType")
	if pkgSpec.Namespace != nil {
		arangoQueryBuilder.filter("pNs", "namespace", "==", "@namespace")
		values["namespace"] = *pkgSpec.Namespace
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"type_id": pType._id,
		"type": pType.type,
		"namespace_id": pNs._id,
		"namespace": pNs.namespace
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "packagesNamespace")
	if err != nil {
		return nil, fmt.Errorf("failed to query for package namespaces: %w, values: %v", err, values)
	}
	defer cursor.Close()

	pkgTypes := map[string][]*model.PackageNamespace{}
	for {
		var doc dbPkgNamespace
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to query package namespace: %w", err)
			}
		} else {
			namespaceString := doc.Namespace
			typeString := doc.PkgType + "," + doc.TypeID

			pkgNamespace := &model.PackageNamespace{
				ID:        doc.NamespaceID,
				Namespace: namespaceString,
				Names:     []*model.PackageName{},
			}
			pkgTypes[typeString] = append(pkgTypes[typeString], pkgNamespace)
		}
	}
	packages := []*model.Package{}
	for pkgType, namespaces := range pkgTypes {
		typeValues := strings.Split(pkgType, ",")
		collectedPackage := &model.Package{
			ID:         typeValues[1],
			Type:       typeValues[0],
			Namespaces: namespaces,
		}
		packages = append(packages, collectedPackage)
	}

	return packages, nil
}

func (c *arangoClient) packagesName(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	values := map[string]any{}

	arangoQueryBuilder := newForQuery(pkgTypesStr, "pType")
	if pkgSpec.Type != nil {
		arangoQueryBuilder.filter("pType", "type", "==", "@pkgType")
		values["pkgType"] = *pkgSpec.Type
	}
	arangoQueryBuilder.forOutBound(pkgHasNamespaceStr, "pNs", "pType")
	if pkgSpec.Namespace != nil {
		arangoQueryBuilder.filter("pNs", "namespace", "==", "@namespace")
		values["namespace"] = *pkgSpec.Namespace
	}
	arangoQueryBuilder.forOutBound(pkgHasNameStr, "pName", "pNs")
	if pkgSpec.Name != nil {
		arangoQueryBuilder.filter("pName", "name", "==", "@name")
		values["name"] = *pkgSpec.Name
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"type_id": pType._id,
		"type": pType.type,
		"namespace_id": pNs._id,
		"namespace": pNs.namespace,
		"name_id": pName._id,
		"name": pName.name
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "packagesName")
	if err != nil {
		return nil, fmt.Errorf("failed to query for package names: %w, values: %v", err, values)
	}
	defer cursor.Close()

	pkgTypes := map[string]map[string][]*model.PackageName{}
	for {
		var doc dbPkgName
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to query package names: %w", err)
			}
		} else {
			nameString := doc.Name
			namespaceString := doc.Namespace + "," + doc.NamespaceID
			typeString := doc.PkgType + "," + doc.TypeID

			pkgName := &model.PackageName{
				ID:       doc.NameID,
				Name:     nameString,
				Versions: []*model.PackageVersion{},
			}

			if pkgNamespace, ok := pkgTypes[typeString]; ok {
				pkgNamespace[namespaceString] = append(pkgNamespace[namespaceString], pkgName)
			} else {
				pkgNamespaces := map[string][]*model.PackageName{}
				pkgNamespaces[namespaceString] = append(pkgNamespaces[namespaceString], pkgName)
				pkgTypes[typeString] = pkgNamespaces
			}
		}
	}
	var packages []*model.Package
	for pkgType, pkgNamespaces := range pkgTypes {
		var collectedPkgNamespaces []*model.PackageNamespace
		for namespace, pkgNames := range pkgNamespaces {
			namespaceValues := strings.Split(namespace, ",")
			pkgNamespace := &model.PackageNamespace{
				ID:        namespaceValues[1],
				Namespace: namespaceValues[0],
				Names:     pkgNames,
			}
			collectedPkgNamespaces = append(collectedPkgNamespaces, pkgNamespace)
		}
		typeValues := strings.Split(pkgType, ",")
		collectedPackage := &model.Package{
			ID:         typeValues[1],
			Type:       typeValues[0],
			Namespaces: collectedPkgNamespaces,
		}
		packages = append(packages, collectedPackage)
	}

	return packages, nil
}

func getPackages(ctx context.Context, cursor driver.Cursor) ([]*model.Package, error) {

	pkgTypes := map[string]map[string]map[string][]*model.PackageVersion{}
	var doc dbPkgVersion
	for {
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to get packages from cursor: %w", err)
			}
		} else {
			pkgQualifiers := []*model.PackageQualifier{}
			if doc.QualifierList != nil {
				pkgQualifiers = getCollectedPackageQualifiers(doc.QualifierList)
			}

			subPathString := doc.Subpath
			versionString := doc.Version
			nameString := doc.Name + "," + doc.NameID
			namespaceString := doc.Namespace + "," + doc.NamespaceID
			typeString := doc.PkgType + "," + doc.TypeID

			pkgVersion := &model.PackageVersion{
				ID:         *doc.VersionID,
				Version:    *versionString,
				Subpath:    *subPathString,
				Qualifiers: pkgQualifiers,
			}

			if pkgNamespaces, ok := pkgTypes[typeString]; ok {
				if pkgNames, ok := pkgNamespaces[namespaceString]; ok {
					pkgNames[nameString] = append(pkgNames[nameString], pkgVersion)
				} else {
					pkgNames := map[string][]*model.PackageVersion{}
					pkgNames[nameString] = append(pkgNames[nameString], pkgVersion)
					pkgNamespaces[namespaceString] = pkgNames
					pkgTypes[typeString] = pkgNamespaces
				}
			} else {
				pkgNames := map[string][]*model.PackageVersion{}
				pkgNames[nameString] = append(pkgNames[nameString], pkgVersion)
				pkgNamespaces := map[string]map[string][]*model.PackageVersion{}
				pkgNamespaces[namespaceString] = pkgNames
				pkgTypes[typeString] = pkgNamespaces
			}
		}
	}
	var packages []*model.Package
	for pkgType, pkgNamespaces := range pkgTypes {
		collectedPkgNamespaces := []*model.PackageNamespace{}
		for namespace, pkgNames := range pkgNamespaces {
			var collectedPkgNames []*model.PackageName
			for name, versions := range pkgNames {
				nameValues := strings.Split(name, ",")
				pkgName := &model.PackageName{
					ID:       nameValues[1],
					Name:     nameValues[0],
					Versions: versions,
				}
				collectedPkgNames = append(collectedPkgNames, pkgName)
			}
			namespaceValues := strings.Split(namespace, ",")
			pkgNamespace := &model.PackageNamespace{
				ID:        namespaceValues[1],
				Namespace: namespaceValues[0],
				Names:     collectedPkgNames,
			}
			collectedPkgNamespaces = append(collectedPkgNamespaces, pkgNamespace)
		}
		typeValues := strings.Split(pkgType, ",")
		collectedPackage := &model.Package{
			ID:         typeValues[1],
			Type:       typeValues[0],
			Namespaces: collectedPkgNamespaces,
		}
		packages = append(packages, collectedPackage)
	}
	return packages, nil
}

func getCollectedPackageQualifiers(qualifierList []string) []*model.PackageQualifier {
	qualifiers := []*model.PackageQualifier{}
	for i := range qualifierList {
		if i%2 == 0 {
			key := qualifierList[i]
			value := qualifierList[i+1]
			qualifier := &model.PackageQualifier{
				Key:   key,
				Value: value,
			}
			qualifiers = append(qualifiers, qualifier)
		}
	}
	return qualifiers
}

func generateModelPackage(pkgTypeID, pkgType, namespaceID, namespaceStr, nameID, nameStr string, versionID, versionValue, subPathValue *string, qualifiersValue []string) *model.Package {
	var version *model.PackageVersion = nil
	if versionValue != nil && subPathValue != nil {
		qualifiers := getCollectedPackageQualifiers(qualifiersValue)
		version = &model.PackageVersion{
			ID:         *versionID,
			Version:    *versionValue,
			Subpath:    *subPathValue,
			Qualifiers: qualifiers,
		}
	}

	versions := []*model.PackageVersion{}
	if version != nil {
		versions = append(versions, version)
	}
	name := &model.PackageName{
		ID:       nameID,
		Name:     nameStr,
		Versions: versions,
	}
	namespace := &model.PackageNamespace{
		ID:        namespaceID,
		Namespace: namespaceStr,
		Names:     []*model.PackageName{name},
	}
	pkg := model.Package{
		ID:         pkgTypeID,
		Type:       pkgType,
		Namespaces: []*model.PackageNamespace{namespace},
	}
	return &pkg
}

func getQualifiers(qualifiersSpec []*model.PackageQualifierSpec) []string {
	qualifiersMap := map[string]string{}
	var keys []string
	for _, kv := range qualifiersSpec {
		key := removeInvalidCharFromProperty(kv.Key)
		qualifiersMap[key] = *kv.Value
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var qualifiers []string
	for _, k := range keys {
		qualifiers = append(qualifiers, k, qualifiersMap[k])
	}
	return qualifiers
}

func removeInvalidCharFromProperty(key string) string {
	// neo4j does not accept "." in its properties. If the qualifier contains a "." that must
	// be replaced by an "-"
	return strings.ReplaceAll(key, ".", "_")
}

// Builds a model.Package to send as GraphQL response, starting from id.
// The optional filter allows restricting output (on selection operations).
func (c *arangoClient) buildPackageResponseFromID(ctx context.Context, id string, filter *model.PkgSpec) (*model.Package, error) {
	if filter != nil && filter.ID != nil {
		if *filter.ID != id {
			return nil, fmt.Errorf("ID does not match filter")
		}
	}

	idSplit := strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	pvl := []*model.PackageVersion{}
	if idSplit[0] == pkgVersionsStr {
		var foundPkgVersion *model.PackageVersion
		var err error

		foundPkgVersion, id, err = c.queryPkgVersionNodeByID(ctx, id, filter)
		if err != nil {
			return nil, fmt.Errorf("failed to get pkg version node by ID with error: %w", err)
		}
		pvl = append(pvl, foundPkgVersion)
	}

	idSplit = strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	pnl := []*model.PackageName{}
	if idSplit[0] == pkgNamesStr {
		var foundPkgName *model.PackageName
		var err error

		foundPkgName, id, err = c.queryPkgNameNodeByID(ctx, id, filter, pvl)
		if err != nil {
			return nil, fmt.Errorf("failed to get pkg name node by ID with error: %w", err)
		}
		pnl = append(pnl, foundPkgName)
	}

	idSplit = strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	pnsl := []*model.PackageNamespace{}
	if idSplit[0] == pkgNamespacesStr {
		var foundPkgNamespace *model.PackageNamespace
		var err error

		foundPkgNamespace, id, err = c.queryPkgNamespaceNodeByID(ctx, id, filter, pnl)
		if err != nil {
			return nil, fmt.Errorf("failed to get pkg namespace node by ID with error: %w", err)
		}
		pnsl = append(pnsl, foundPkgNamespace)
	}

	idSplit = strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	var p *model.Package
	if idSplit[0] == pkgTypesStr {
		var err error

		p, err = c.queryPkgTypeNodeByID(ctx, id, filter, pnsl)
		if err != nil {
			return nil, fmt.Errorf("failed to get pkg type node by ID with error: %w", err)
		}
	}
	return p, nil
}

func (c *arangoClient) queryPkgVersionNodeByID(ctx context.Context, id string, filter *model.PkgSpec) (*model.PackageVersion, string, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(pkgVersionsStr, "pVersion")
	arangoQueryBuilder.filter("pVersion", "_id", "==", "@id")
	values["id"] = id
	if filter != nil {
		if filter.Version != nil {
			arangoQueryBuilder.filter("pVersion", "version", "==", "@version")
			values["version"] = *filter.Version
		}
		if filter.Subpath != nil {
			arangoQueryBuilder.filter("pVersion", "subpath", "==", "@subpath")
			values["subpath"] = *filter.Subpath
		}
		if filter.MatchOnlyEmptyQualifiers != nil {
			if !*filter.MatchOnlyEmptyQualifiers {
				if len(filter.Qualifiers) > 0 {
					arangoQueryBuilder.filter("pVersion", "qualifier_list", "==", "@qualifier")
					values["qualifier"] = getQualifiers(filter.Qualifiers)
				}
			} else {
				arangoQueryBuilder.filterLength("pVersion", "qualifier_list", "==", 0)
			}
		} else {
			if len(filter.Qualifiers) > 0 {
				arangoQueryBuilder.filter("pVersion", "qualifier_list", "==", "@qualifier")
				values["qualifier"] = getQualifiers(filter.Qualifiers)
			}
		}
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'version_id': pVersion._id,
		'version': pVersion.version,
		'subpath': pVersion.subpath,
		'qualifier_list': pVersion.qualifier_list,
		'parent': pVersion._parent
  	}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "queryPkgVersionNodeByID")
	if err != nil {
		return nil, "", fmt.Errorf("failed to query for package version: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type parsedPkgVersion struct {
		VersionID     string   `json:"version_id"`
		Version       string   `json:"version"`
		Subpath       string   `json:"subpath"`
		QualifierList []string `json:"qualifier_list"`
		Parent        string   `json:"parent"`
	}

	var collectedValues []parsedPkgVersion
	for {
		var doc parsedPkgVersion
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, "", fmt.Errorf("failed to package version from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, "", fmt.Errorf("number of package version nodes found for ID: %s is greater than one", id)
	}

	return &model.PackageVersion{
		ID:         collectedValues[0].VersionID,
		Version:    collectedValues[0].Version,
		Subpath:    collectedValues[0].Subpath,
		Qualifiers: getCollectedPackageQualifiers(collectedValues[0].QualifierList),
	}, collectedValues[0].Parent, nil
}

func (c *arangoClient) queryPkgNameNodeByID(ctx context.Context, id string, filter *model.PkgSpec, pvl []*model.PackageVersion) (*model.PackageName, string, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(pkgNamesStr, "pName")
	arangoQueryBuilder.filter("pName", "_id", "==", "@id")
	values["id"] = id

	if filter != nil && filter.Name != nil {
		arangoQueryBuilder.filter("pName", "name", "==", "@name")
		values["name"] = *filter.Name
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'name_id': pName._id,
		'name': pName.name,
		'parent': pName._parent
  	}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "queryPkgNameNodeByID")
	if err != nil {
		return nil, "", fmt.Errorf("failed to query for package name: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type parsedPkgName struct {
		NameID string `json:"name_id"`
		Name   string `json:"name"`
		Parent string `json:"parent"`
	}

	var collectedValues []parsedPkgName
	for {
		var doc parsedPkgName
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, "", fmt.Errorf("failed to package name from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, "", fmt.Errorf("number of package name nodes found for ID: %s is greater than one", id)
	}

	return &model.PackageName{
		ID:       collectedValues[0].NameID,
		Name:     collectedValues[0].Name,
		Versions: pvl,
	}, collectedValues[0].Parent, nil
}

func (c *arangoClient) queryPkgNamespaceNodeByID(ctx context.Context, id string, filter *model.PkgSpec, pnl []*model.PackageName) (*model.PackageNamespace, string, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(pkgNamespacesStr, "pNs")
	arangoQueryBuilder.filter("pNs", "_id", "==", "@id")
	values["id"] = id

	if filter != nil && filter.Namespace != nil {
		arangoQueryBuilder.filter("pNs", "namespace", "==", "@namespace")
		values["namespace"] = *filter.Namespace
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"namespace_id": pNs._id,
		"namespace": pNs.namespace,
		'parent': pNs._parent
  	}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "queryPkgNamespaceNodeByID")
	if err != nil {
		return nil, "", fmt.Errorf("failed to query for package namespace: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type parsedPkgNamespace struct {
		NamespaceID string `json:"namespace_id"`
		Namespace   string `json:"namespace"`
		Parent      string `json:"parent"`
	}

	var collectedValues []parsedPkgNamespace
	for {
		var doc parsedPkgNamespace
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, "", fmt.Errorf("failed to package namespace from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, "", fmt.Errorf("number of package namespace nodes found for ID: %s is greater than one", id)
	}

	return &model.PackageNamespace{
		ID:        collectedValues[0].NamespaceID,
		Namespace: collectedValues[0].Namespace,
		Names:     pnl,
	}, collectedValues[0].Parent, nil
}

func (c *arangoClient) queryPkgTypeNodeByID(ctx context.Context, id string, filter *model.PkgSpec, pnsl []*model.PackageNamespace) (*model.Package, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(pkgTypesStr, "pType")
	arangoQueryBuilder.filter("pType", "_id", "==", "@id")
	values["id"] = id

	if filter != nil && filter.Type != nil {
		arangoQueryBuilder.filter("pType", "type", "==", "@pkgType")
		values["pkgType"] = *filter.Type
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"type_id": pType._id,
		"type": pType.type,
  	}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "queryPkgTypeNodeByID")
	if err != nil {
		return nil, fmt.Errorf("failed to query for package type: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type parsedPkgType struct {
		TypeID  string `json:"type_id"`
		PkgType string `json:"type"`
	}

	var collectedValues []parsedPkgType
	for {
		var doc parsedPkgType
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to package type from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, fmt.Errorf("number of package type nodes found for ID: %s is greater than one", id)
	}

	return &model.Package{
		ID:         collectedValues[0].TypeID,
		Type:       collectedValues[0].PkgType,
		Namespaces: pnsl,
	}, nil
}
