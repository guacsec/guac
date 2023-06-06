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
		UPSERT { type: @pkgType }
		INSERT { type: @pkgType }
		UPDATE {}
		IN PkgType
		RETURN NEW
	  )
	  
	  LET ns = FIRST(
		UPSERT { namespace: @namespace }
		INSERT { namespace: @namespace }
		UPDATE {}
		IN PkgNamespace
		RETURN NEW
	  )
	  
	  LET name = FIRST(
		UPSERT { name: @name }
		INSERT { name: @name }
		UPDATE {}
		IN PkgName
		RETURN NEW
	  )
	  
	  LET pkgVersionObj = FIRST(
		UPSERT { version: @version, subpath: @subpath, qualifier_list: @qualifier }
		INSERT { version: @version, subpath: @subpath, qualifier_list: @qualifier }
		UPDATE {}
		IN PkgVersion
		RETURN NEW
	  )
	  
	LET pkgHasTypeCollection = FIRST(
    UPSERT { _from: root._id, _to: type._id, label : "PkgHasType" }
      INSERT { _from: root._id, _to: type._id, label : "PkgHasType" }
      UPDATE {} IN PkgHasType
    )
   
    LET pkgHasNamespaceCollection = FIRST(
    UPSERT { _from: type._id, _to: ns._id, label : "PkgHasNamespace" }
      INSERT { _from: type._id, _to: ns._id, label : "PkgHasNamespace" }
      UPDATE {} IN PkgHasNamespace
    )
  
    LET pkgHasNameCollection = FIRST(
    UPSERT { _from: ns._id, _to: name._id, label : "PkgHasName" }
      INSERT { _from: ns._id, _to: name._id, label : "PkgHasName" }
      UPDATE {} IN PkgHasName
    )
  
    LET pkgHasVersionCollection = FIRST(
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

	cursor, err := executeQueryWithRetry(ctx, c.db, query, values)
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w, values: %v", err, values)
	}
	defer cursor.Close()

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
