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
)

func registerAllPackages(ctx context.Context, client *arangoClient) {

	var p1 = model.PkgInputSpec{
		Type: "pypi",
		Name: "tensorflow",
	}

	client.IngestPackage(ctx, p1)

	var p2 = model.PkgInputSpec{
		Type:    "pypi",
		Name:    "tensorflow",
		Version: ptrfrom.String("2.11.1"),
	}
	client.IngestPackage(ctx, p2)

	var p3 = model.PkgInputSpec{
		Type:    "pypi",
		Name:    "tensorflow",
		Version: ptrfrom.String("2.11.1"),
		Subpath: ptrfrom.String("saved_model_cli.py"),
	}

	client.IngestPackage(ctx, p3)

	var p4 = model.PkgInputSpec{
		Type:      "conan",
		Namespace: ptrfrom.String("openssl.org"),
		Name:      "openssl",
		Version:   ptrfrom.String("3.0.3"),
	}
	client.IngestPackage(ctx, p4)
}

func (c *arangoClient) IngestPackage(ctx context.Context, pkg model.PkgInputSpec) (*model.Package, error) {
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

	query := `LET root = FIRST(
		UPSERT { root: "pkg" }
		INSERT { root: "pkg" }
		UPDATE {}
		IN Pkg
		RETURN NEW
	  )
	  
	  LET type = FIRST(
		UPSERT { type: @pkgType, _parent: root._id }
		INSERT { type: @pkgType, _parent: root._id }
		UPDATE {}
		IN PkgType OPTIONS { indexHint: "byType" }
		RETURN NEW
	  )
	  
	  LET ns = FIRST(
		UPSERT { namespace: @namespace, _parent: type._id }
		INSERT { namespace: @namespace, _parent: type._id }
		UPDATE {}
		IN PkgNamespace OPTIONS { indexHint: "byNamespace" }
		RETURN NEW
	  )
	  
	  LET name = FIRST(
		UPSERT { name: @name, _parent: ns._id }
		INSERT { name: @name, _parent: ns._id }
		UPDATE {}
		IN PkgName OPTIONS { indexHint: "byName" }
		RETURN NEW
	  )
	  
	  LET pkgVersionObj = FIRST(
		UPSERT { version: @version, subpath: @subpath, qualifier_list: @qualifier, _parent: name._id }
		INSERT { version: @version, subpath: @subpath, qualifier_list: @qualifier, _parent: name._id }
		UPDATE {}
		IN PkgVersion OPTIONS { indexHint: "byAllVersion" }
		RETURN NEW
	  )
	
	  LET pkgHasTypeCollection = (
		UPSERT { _from: root._id, _to: type._id, label : "PkgHasType" }
		  INSERT { _from: root._id, _to: type._id, label : "PkgHasType" }
		  UPDATE {} IN PkgHasType
		)
	   
		LET pkgHasNamespaceCollection = (
		UPSERT { _from: type._id, _to: ns._id, label : "PkgHasNamespace" }
		  INSERT { _from: type._id, _to: ns._id, label : "PkgHasNamespace" }
		  UPDATE {} IN PkgHasNamespace
		)
	  
		LET pkgHasNameCollection = (
		UPSERT { _from: ns._id, _to: name._id, label : "PkgHasName" }
		  INSERT { _from: ns._id, _to: name._id, label : "PkgHasName" }
		  UPDATE {} IN PkgHasName
		)
	  
		LET pkgHasVersionCollection = (
		UPSERT { _from: name._id, _to: pkgVersionObj._id, label : "PkgHasVersion" }
		  INSERT { _from: name._id, _to: pkgVersionObj._id, label : "PkgHasVersion" }
		  UPDATE {} IN PkgHasVersion
		)
		
	RETURN {
    "type": type.type,
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
				return nil, fmt.Errorf("failed to ingest artifact: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}
	if len(createdValues) == 1 {
		return generateModelPackage(createdValues[0].PkgType, createdValues[0].Namespace,
			createdValues[0].Name, createdValues[0].Version, createdValues[0].Subpath, createdValues[0].QualifierList), nil
	} else {
		return nil, fmt.Errorf("number of hashEqual ingested is too great")
	}
}

func getCollectedPackageQualifiers(qualifierList []interface{}) []*model.PackageQualifier {
	qualifiers := []*model.PackageQualifier{}
	for i := range qualifierList {
		if i%2 == 0 {
			qualifier := &model.PackageQualifier{
				Key:   qualifierList[i].(string),
				Value: qualifierList[i+1].(string),
			}
			qualifiers = append(qualifiers, qualifier)
		}
	}
	return qualifiers
}

func generateModelPackage(pkgType, namespaceStr, nameStr string, versionValue, subPathValue, qualifiersValue interface{}) *model.Package {
	var version *model.PackageVersion = nil
	if versionValue != nil && subPathValue != nil && qualifiersValue != nil {
		qualifiersList := qualifiersValue.([]interface{})
		subPathString := subPathValue.(string)
		versionString := versionValue.(string)
		qualifiers := getCollectedPackageQualifiers(qualifiersList)
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
	return &pkg
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

	arangoQueryBuilder := newForQuery("Pkg", "pkg")
	arangoQueryBuilder.ForOutBound("PkgHasType", "pkgHasType", "pkg")
	if pkgSpec.Type != nil {
		arangoQueryBuilder.filter("type", "pkgHasType", "==", "@pkgType")
		values["pkgType"] = *pkgSpec.Type
	}
	arangoQueryBuilder.ForOutBound("PkgHasNamespace", "pkgHasNamespace", "pkgHasType")
	if pkgSpec.Namespace != nil {
		arangoQueryBuilder.filter("namespace", "pkgHasNamespace", "==", "@namespace")
		values["namespace"] = *pkgSpec.Namespace
	}
	arangoQueryBuilder.ForOutBound("PkgHasName", "pkgHasName", "pkgHasNamespace")
	if pkgSpec.Name != nil {
		arangoQueryBuilder.filter("name", "pkgHasName", "==", "@name")
		values["name"] = *pkgSpec.Name
	}
	arangoQueryBuilder.ForOutBound("PkgHasVersion", "pkgHasVersion", "pkgHasName")
	if pkgSpec.Version != nil {
		arangoQueryBuilder.filter("version", "pkgHasVersion", "==", "@version")
		values["version"] = *pkgSpec.Version
	}
	if pkgSpec.Subpath != nil {
		arangoQueryBuilder.filter("subpath", "pkgHasVersion", "==", "@subpath")
		values["subpath"] = *pkgSpec.Subpath
	}
	if len(pkgSpec.Qualifiers) > 0 {
		arangoQueryBuilder.filter("qualifier_list", "pkgHasVersion", "==", "@qualifier")
		values["qualifier"] = getQualifiers(pkgSpec.Qualifiers)
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"type_id": pkgHasType._id,
		"type": pkgHasType.type,
		"namespace_id": pkgHasNamespace._id,
		"namespace": pkgHasNamespace.namespace,
		"name_id": pkgHasName._id,
		"name": pkgHasName.name,
		"version_id": pkgHasVersion._id,
		"version": pkgHasVersion.version,
		"subpath": pkgHasVersion.subpath,
		"qualifier_list": pkgHasVersion.qualifier_list
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
				return nil, fmt.Errorf("failed to ingest artifact: %w", err)
			}
		} else {
			var pkgQualifiers []*model.PackageQualifier
			if doc.QualifierList != nil {
				pkgQualifiers = getCollectedPackageQualifiers(doc.QualifierList)
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

	arangoQueryBuilder := newForQuery("Pkg", "pkg")
	arangoQueryBuilder.ForOutBound("PkgHasType", "pkgHasType", "pkg")
	if pkgSpec.Type != nil {
		arangoQueryBuilder.filter("type", "pkgHasType", "==", "@pkgType")
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
				return nil, fmt.Errorf("failed to ingest artifact: %w", err)
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

	arangoQueryBuilder := newForQuery("Pkg", "pkg")
	arangoQueryBuilder.ForOutBound("PkgHasType", "pkgHasType", "pkg")
	if pkgSpec.Type != nil {
		arangoQueryBuilder.filter("type", "pkgHasType", "==", "@pkgType")
		values["pkgType"] = *pkgSpec.Type
	}
	arangoQueryBuilder.ForOutBound("PkgHasNamespace", "pkgHasNamespace", "pkgHasType")
	if pkgSpec.Namespace != nil {
		arangoQueryBuilder.filter("namespace", "pkgHasNamespace", "==", "@namespace")
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
				return nil, fmt.Errorf("failed to ingest artifact: %w", err)
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

	arangoQueryBuilder := newForQuery("Pkg", "pkg")
	arangoQueryBuilder.ForOutBound("PkgHasType", "pkgHasType", "pkg")
	if pkgSpec.Type != nil {
		arangoQueryBuilder.filter("type", "pkgHasType", "==", "@pkgType")
		values["pkgType"] = *pkgSpec.Type
	}
	arangoQueryBuilder.ForOutBound("PkgHasNamespace", "pkgHasNamespace", "pkgHasType")
	if pkgSpec.Namespace != nil {
		arangoQueryBuilder.filter("namespace", "pkgHasNamespace", "==", "@namespace")
		values["namespace"] = *pkgSpec.Namespace
	}
	arangoQueryBuilder.ForOutBound("PkgHasName", "pkgHasName", "pkgHasNamespace")
	if pkgSpec.Name != nil {
		arangoQueryBuilder.filter("name", "pkgHasName", "==", "@name")
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
				return nil, fmt.Errorf("failed to ingest artifact: %w", err)
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
