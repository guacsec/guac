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

type PkgIds struct {
	TypeId      string
	NamespaceId string
	NameId      string
	VersionId   string
}

func guacPkgId(pkg model.PkgInputSpec) PkgIds {
	ids := PkgIds{}

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
	keys := []string{}
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

func (c *arangoClient) IngestPackages(ctx context.Context, pkgs []*model.PkgInputSpec) ([]*model.Package, error) {
	listOfValues := []map[string]any{}

	for i := range pkgs {
		values := map[string]any{}

		// add guac keys
		values["typeID"] = c.pkgTypeMap[pkgs[i].Type].Id
		values["typeKey"] = c.pkgTypeMap[pkgs[i].Type].Key
		values["typeValue"] = c.pkgTypeMap[pkgs[i].Type].PkgType

		guacIds := guacPkgId(*pkgs[i])
		values["guacNsKey"] = guacIds.NamespaceId
		values["guacNameKey"] = guacIds.NameId
		values["guacVersionKey"] = guacIds.VersionId

		values["name"] = pkgs[i].Name
		if pkgs[i].Namespace != nil {
			values["namespace"] = *pkgs[i].Namespace
		} else {
			values["namespace"] = ""
		}
		if pkgs[i].Version != nil {
			values["version"] = *pkgs[i].Version
		} else {
			values["version"] = ""
		}
		if pkgs[i].Subpath != nil {
			values["subpath"] = *pkgs[i].Subpath
		} else {
			values["subpath"] = ""
		}

		// To ensure consistency, always sort the qualifiers by key
		qualifiersMap := map[string]string{}
		keys := []string{}
		for _, kv := range pkgs[i].Qualifiers {
			qualifiersMap[kv.Key] = kv.Value
			keys = append(keys, kv.Key)
		}
		sort.Strings(keys)
		qualifiers := []string{}
		for _, k := range keys {
			qualifiers = append(qualifiers, k, qualifiersMap[k])
		}
		values["qualifier"] = qualifiers

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
	LET ns = FIRST(
	  UPSERT { namespace: doc.namespace, _parent: doc.typeID , guacKey: doc.guacNsKey}
	  INSERT { namespace: doc.namespace, _parent: doc.typeID , guacKey: doc.guacNsKey}
	  UPDATE {}
	  IN PkgNamespaces OPTIONS { indexHint: "byNsGuacKey" }
	  RETURN NEW
	)
	
	LET name = FIRST(
	  UPSERT { name: doc.name, _parent: ns._id, guacKey: doc.guacNameKey}
	  INSERT { name: doc.name, _parent: ns._id, guacKey: doc.guacNameKey}
	  UPDATE {}
	  IN PkgNames OPTIONS { indexHint: "byNameGuacKey" }
	  RETURN NEW
	)
	
	LET pkgVersionObj = FIRST(
	  UPSERT { version: doc.version, subpath: doc.subpath, qualifier_list: doc.qualifier, _parent: name._id, guacKey: doc.guacVersionKey}
	  INSERT { version: doc.version, subpath: doc.subpath, qualifier_list: doc.qualifier, _parent: name._id, guacKey: doc.guacVersionKey}
	  UPDATE {}
	  IN PkgVersions OPTIONS { indexHint: "byVersionGuacKey" }
	  RETURN NEW
	)
  
	LET pkgHasNamespaceCollection = (
	  INSERT { _key: CONCAT("pkgHasNamespace", doc.typeKey, ns._key), _from: doc.typeID, _to: ns._id, label : "PkgHasNamespace"} INTO PkgHasNamespace OPTIONS { overwriteMode: "ignore" }
	)
	
	LET pkgHasNameCollection = (
	  INSERT { _key: CONCAT("pkgHasName", ns._key, name._key), _from: ns._id, _to: name._id, label : "PkgHasName"} INTO PkgHasName OPTIONS { overwriteMode: "ignore" }
	)
	
	LET pkgHasVersionCollection = (
	  INSERT { _key: CONCAT("pkgHasVersion", name._key, pkgVersionObj._key), _from: name._id, _to: pkgVersionObj._id, label : "PkgHasVersion"} INTO PkgHasVersion OPTIONS { overwriteMode: "ignore" }
	)
	  
  RETURN {
  "type": doc.typeValue,
  "namespace": ns.namespace,
  "name": name.name,
  "version": pkgVersionObj.version,
  "subpath": pkgVersionObj.subpath,
  "qualifier_list": pkgVersionObj.qualifier_list
}`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestPackages")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w", err)
	}

	type collectedData struct {
		PkgType       string      `json:"type"`
		Namespace     string      `json:"namespace"`
		Name          string      `json:"name"`
		Version       string      `json:"version"`
		Subpath       string      `json:"subpath"`
		QualifierList interface{} `json:"qualifier_list"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				cursor.Close()
				break
			} else {
				return nil, fmt.Errorf("failed to ingest package: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var packageList []*model.Package
	for _, createdValue := range createdValues {
		pkg, err := generateModelPackage(createdValue.PkgType, createdValue.Namespace,
			createdValue.Name, createdValue.Version, createdValue.Subpath, createdValue.QualifierList)
		if err != nil {
			return nil, fmt.Errorf("failed to get model.package with err: %w", err)
		}
		packageList = append(packageList, pkg)
	}

	return packageList, nil
}

func (c *arangoClient) IngestPackage(ctx context.Context, pkg model.PkgInputSpec) (*model.Package, error) {

	values := map[string]any{}
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
	values["typeID"] = c.pkgTypeMap[pkg.Type].Id
	values["typeKey"] = c.pkgTypeMap[pkg.Type].Key
	values["typeValue"] = c.pkgTypeMap[pkg.Type].PkgType

	guacIds := guacPkgId(pkg)
	values["guacNsKey"] = guacIds.NamespaceId
	values["guacNameKey"] = guacIds.NameId
	values["guacVersionKey"] = guacIds.VersionId

	query := `	  
	  LET ns = FIRST(
		UPSERT { namespace: @namespace, _parent: @typeID , guacKey: @guacNsKey}
		INSERT { namespace: @namespace, _parent: @typeID , guacKey: @guacNsKey}
		UPDATE {}
		IN PkgNamespaces OPTIONS { indexHint: "byNsGuacKey" }
		RETURN NEW
	  )
	  
	  LET name = FIRST(
		UPSERT { name: @name, _parent: ns._id, guacKey: @guacNameKey}
		INSERT { name: @name, _parent: ns._id, guacKey: @guacNameKey}
		UPDATE {}
		IN PkgNames OPTIONS { indexHint: "byNameGuacKey" }
		RETURN NEW
	  )
	  
	  LET pkgVersionObj = FIRST(
		UPSERT { version: @version, subpath: @subpath, qualifier_list: @qualifier, _parent: name._id, guacKey: @guacVersionKey}
		INSERT { version: @version, subpath: @subpath, qualifier_list: @qualifier, _parent: name._id, guacKey: @guacVersionKey}
		UPDATE {}
		IN PkgVersions OPTIONS { indexHint: "byVersionGuacKey" }
		RETURN NEW
	  )
	
	  LET pkgHasNamespaceCollection = (
		INSERT { _key: CONCAT("pkgHasNamespace", @typeKey, ns._key), _from: @typeID, _to: ns._id, label : "PkgHasNamespace"} INTO PkgHasNamespace OPTIONS { overwriteMode: "ignore" }
	  )
	  
	  LET pkgHasNameCollection = (
		INSERT { _key: CONCAT("pkgHasName", ns._key, name._key), _from: ns._id, _to: name._id, label : "PkgHasName"} INTO PkgHasName OPTIONS { overwriteMode: "ignore" }
	  )
	  
	  LET pkgHasVersionCollection = (
		INSERT { _key: CONCAT("pkgHasVersion", name._key, pkgVersionObj._key), _from: name._id, _to: pkgVersionObj._id, label : "PkgHasVersion"} INTO PkgHasVersion OPTIONS { overwriteMode: "ignore" }
	  )
		
	RETURN {
    "type": @typeValue,
    "namespace": ns.namespace,
    "name": name.name,
    "version": pkgVersionObj.version,
    "subpath": pkgVersionObj.subpath,
    "qualifier_list": pkgVersionObj.qualifier_list
  }`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, values, "IngestPackage")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w, values: %v", err, values)
	}

	type collectedData struct {
		PkgType       string      `json:"type"`
		Namespace     string      `json:"namespace"`
		Name          string      `json:"name"`
		Version       string      `json:"version"`
		Subpath       string      `json:"subpath"`
		QualifierList interface{} `json:"qualifier_list"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				cursor.Close()
				break
			} else {
				return nil, fmt.Errorf("failed to ingest package: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}
	if len(createdValues) == 1 {
		return generateModelPackage(createdValues[0].PkgType, createdValues[0].Namespace,
			createdValues[0].Name, createdValues[0].Version, createdValues[0].Subpath, createdValues[0].QualifierList)
	} else {
		return nil, fmt.Errorf("number of hashEqual ingested is greater than one")
	}
}

func getCollectedPackageQualifiers(qualifierList []interface{}) ([]*model.PackageQualifier, error) {
	qualifiers := []*model.PackageQualifier{}
	for i := range qualifierList {
		if i%2 == 0 {
			key, ok := qualifierList[i].(string)
			if !ok {
				return nil, fmt.Errorf("failed to assert string value for pkg qualifier's key")
			}
			value, ok := qualifierList[i+1].(string)
			if !ok {
				return nil, fmt.Errorf("failed to assert string value for pkg qualifier's value")
			}
			qualifier := &model.PackageQualifier{
				Key:   key,
				Value: value,
			}
			qualifiers = append(qualifiers, qualifier)
		}
	}
	return qualifiers, nil
}

func generateModelPackage(pkgType, namespaceStr, nameStr string, versionValue, subPathValue, qualifiersValue interface{}) (*model.Package, error) {
	var version *model.PackageVersion = nil
	if versionValue != nil && subPathValue != nil && qualifiersValue != nil {
		qualifiersList, ok := qualifiersValue.([]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to assert slice for pkg qualifiers")
		}
		subPathString, ok := subPathValue.(string)
		if !ok {
			return nil, fmt.Errorf("failed to assert string value for pkg subpath")
		}
		versionString, ok := versionValue.(string)
		if !ok {
			return nil, fmt.Errorf("failed to assert string value for pkg version")
		}
		qualifiers, err := getCollectedPackageQualifiers(qualifiersList)
		if err != nil {
			return nil, fmt.Errorf("failed to get qualifiers with error: %w", err)
		}
		version = &model.PackageVersion{
			Version:    versionString,
			Subpath:    subPathString,
			Qualifiers: qualifiers,
		}
	}

	versions := []*model.PackageVersion{}
	if version != nil {
		versions = append(versions, version)
	}
	name := &model.PackageName{
		Name:     nameStr,
		Versions: versions,
	}
	namespace := &model.PackageNamespace{
		Namespace: namespaceStr,
		Names:     []*model.PackageName{name},
	}
	pkg := model.Package{
		Type:       pkgType,
		Namespaces: []*model.PackageNamespace{namespace},
	}
	return &pkg, nil
}

func getQualifiers(qualifiersSpec []*model.PackageQualifierSpec) []string {
	qualifiersMap := map[string]string{}
	keys := []string{}
	for _, kv := range qualifiersSpec {
		key := removeInvalidCharFromProperty(kv.Key)
		qualifiersMap[key] = *kv.Value
		keys = append(keys, key)
	}
	sort.Strings(keys)
	qualifiers := []string{}
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

func (c *arangoClient) Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
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

	values := map[string]any{}

	arangoQueryBuilder := newForQuery("PkgRoots", "pRoot")
	arangoQueryBuilder.filter("pRoot", "root", "==", "@pkg")
	values["pkg"] = "pkg"
	arangoQueryBuilder.ForOutBound("PkgHasType", "pType", "pRoot")
	if pkgSpec.Type != nil {
		arangoQueryBuilder.filter("pType", "type", "==", "@pkgType")
		values["pkgType"] = *pkgSpec.Type
	}
	arangoQueryBuilder.ForOutBound("PkgHasNamespace", "pNs", "pType")
	if pkgSpec.Namespace != nil {
		arangoQueryBuilder.filter("pNs", "namespace", "==", "@namespace")
		values["namespace"] = *pkgSpec.Namespace
	}
	arangoQueryBuilder.ForOutBound("PkgHasName", "pName", "pNs")
	if pkgSpec.Name != nil {
		arangoQueryBuilder.filter("pName", "name", "==", "@name")
		values["name"] = *pkgSpec.Name
	}
	arangoQueryBuilder.ForOutBound("PkgHasVersion", "pVersion", "pName")
	if pkgSpec.Version != nil {
		arangoQueryBuilder.filter("pVersion", "version", "==", "@version")
		values["version"] = *pkgSpec.Version
	}
	if pkgSpec.Subpath != nil {
		arangoQueryBuilder.filter("pVersion", "subpath", "==", "@subpath")
		values["subpath"] = *pkgSpec.Subpath
	}
	if len(pkgSpec.Qualifiers) > 0 {
		arangoQueryBuilder.filter("pVersion", "qualifier_list", "==", "@qualifier")
		values["qualifier"] = getQualifiers(pkgSpec.Qualifiers)
	}
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

	fmt.Println(arangoQueryBuilder.string())

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "Packages")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type collectedData struct {
		TypeID        string        `json:"type_id"`
		PkgType       string        `json:"type"`
		NamespaceID   string        `json:"namespace_id"`
		Namespace     string        `json:"namespace"`
		NameID        string        `json:"name_id"`
		Name          string        `json:"name"`
		VersionID     string        `json:"version_id"`
		Version       string        `json:"version"`
		Subpath       string        `json:"subpath"`
		QualifierList []interface{} `json:"qualifier_list"`
	}

	pkgTypes := map[string]map[string]map[string][]*model.PackageVersion{}
	var doc collectedData
	for {
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to query packages: %w", err)
			}
		} else {
			var pkgQualifiers []*model.PackageQualifier
			if doc.QualifierList != nil {
				pkgQualifiers, err = getCollectedPackageQualifiers(doc.QualifierList)
				if err != nil {
					return nil, fmt.Errorf("failed to get package qualifiers with error: %w", err)
				}
			}

			subPathString := doc.Subpath
			versionString := doc.Version
			nameString := doc.Name + "," + doc.NameID
			namespaceString := doc.Namespace + "," + doc.NamespaceID
			typeString := doc.PkgType + "," + doc.TypeID

			pkgVersion := &model.PackageVersion{
				ID:         doc.VersionID,
				Version:    versionString,
				Subpath:    subPathString,
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
			collectedPkgNames := []*model.PackageName{}
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

func (c *arangoClient) packagesType(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {

	values := map[string]any{}

	arangoQueryBuilder := newForQuery("PkgRoots", "pRoot")
	arangoQueryBuilder.filter("pRoot", "root", "==", "@pkg")
	values["pkg"] = "pkg"
	arangoQueryBuilder.ForOutBound("PkgHasType", "pType", "pRoot")
	if pkgSpec.Type != nil {
		arangoQueryBuilder.filter("pType", "type", "==", "@pkgType")
		values["pkgType"] = *pkgSpec.Type
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"type_id": pkgHasType._id,
		"type": pkgHasType.type
	}`)

	fmt.Println(arangoQueryBuilder.string())

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "packagesType")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type collectedData struct {
		TypeID  string `json:"type_id"`
		PkgType string `json:"type"`
	}

	var packages []*model.Package
	for {
		var doc collectedData
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

	arangoQueryBuilder := newForQuery("PkgRoots", "pRoot")
	arangoQueryBuilder.filter("pRoot", "root", "==", "@pkg")
	values["pkg"] = "pkg"
	arangoQueryBuilder.ForOutBound("PkgHasType", "pType", "pRoot")
	if pkgSpec.Type != nil {
		arangoQueryBuilder.filter("pType", "type", "==", "@pkgType")
		values["pkgType"] = *pkgSpec.Type
	}
	arangoQueryBuilder.ForOutBound("PkgHasNamespace", "pNs", "pType")
	if pkgSpec.Namespace != nil {
		arangoQueryBuilder.filter("pNs", "namespace", "==", "@namespace")
		values["namespace"] = *pkgSpec.Namespace
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"type_id": pkgHasType._id,
		"type": pkgHasType.type,
		"namespace_id": pkgHasNamespace._id,
		"namespace": pkgHasNamespace.namespace,
	  }`)

	fmt.Println(arangoQueryBuilder.string())

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "packagesNamespace")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type collectedData struct {
		TypeID      string `json:"type_id"`
		PkgType     string `json:"type"`
		NamespaceID string `json:"namespace_id"`
		Namespace   string `json:"namespace"`
	}

	pkgTypes := map[string][]*model.PackageNamespace{}
	for {
		var doc collectedData
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

	arangoQueryBuilder := newForQuery("PkgRoots", "pRoot")
	arangoQueryBuilder.filter("pRoot", "root", "==", "@pkg")
	values["pkg"] = "pkg"
	arangoQueryBuilder.ForOutBound("PkgHasType", "pType", "pRoot")
	if pkgSpec.Type != nil {
		arangoQueryBuilder.filter("pType", "type", "==", "@pkgType")
		values["pkgType"] = *pkgSpec.Type
	}
	arangoQueryBuilder.ForOutBound("PkgHasNamespace", "pNs", "pType")
	if pkgSpec.Namespace != nil {
		arangoQueryBuilder.filter("pNs", "namespace", "==", "@namespace")
		values["namespace"] = *pkgSpec.Namespace
	}
	arangoQueryBuilder.ForOutBound("PkgHasName", "pName", "pNs")
	if pkgSpec.Name != nil {
		arangoQueryBuilder.filter("pName", "name", "==", "@name")
		values["name"] = *pkgSpec.Name
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"type_id": pkgHasType._id,
		"type": pkgHasType.type,
		"namespace_id": pkgHasNamespace._id,
		"namespace": pkgHasNamespace.namespace,
		"name_id": pkgHasName._id,
		"name": pkgHasName.name,
	  }`)

	fmt.Println(arangoQueryBuilder.string())

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "packagesName")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type collectedData struct {
		TypeID      string `json:"type_id"`
		PkgType     string `json:"type"`
		NamespaceID string `json:"namespace_id"`
		Namespace   string `json:"namespace"`
		NameID      string `json:"name_id"`
		Name        string `json:"name"`
	}

	pkgTypes := map[string]map[string][]*model.PackageName{}
	for {
		var doc collectedData
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
	packages := []*model.Package{}
	for pkgType, pkgNamespaces := range pkgTypes {
		collectedPkgNamespaces := []*model.PackageNamespace{}
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
