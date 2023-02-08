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

package neo4jBackend

import (
	"context"
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j/dbtype"
)

// pkgNode represents the top level pkg->Type->Namespace->Name->Version
type pkgNode struct {
}

func (pn *pkgNode) Type() string {
	return "Pkg"
}

func (pn *pkgNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["pkg"] = "pkg"
	return properties
}

func (pn *pkgNode) PropertyNames() []string {
	fields := []string{"pkg"}
	return fields
}

func (pn *pkgNode) IdentifiablePropertyNames() []string {
	return []string{"pkg"}
}

type pkgType struct {
	pkgType string
}

func (pt *pkgType) Type() string {
	return "PkgType"
}

func (pt *pkgType) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["type"] = pt.pkgType
	return properties
}

func (pt *pkgType) PropertyNames() []string {
	fields := []string{"type"}
	return fields
}

func (pt *pkgType) IdentifiablePropertyNames() []string {
	return []string{"type"}
}

type pkgNamespace struct {
	namespace string
}

func (pn *pkgNamespace) Type() string {
	return "PkgNamespace"
}

func (pn *pkgNamespace) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["namespace"] = pn.namespace
	return properties
}

func (pn *pkgNamespace) PropertyNames() []string {
	fields := []string{"namespace"}
	return fields
}

func (pn *pkgNamespace) IdentifiablePropertyNames() []string {
	return []string{"namespace"}
}

type pkgName struct {
	name string
}

func (pn *pkgName) Type() string {
	return "PkgName"
}

func (pn *pkgName) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["name"] = pn.name
	return properties
}

func (pn *pkgName) PropertyNames() []string {
	fields := []string{"name"}
	return fields
}

func (pn *pkgName) IdentifiablePropertyNames() []string {
	return []string{"name"}
}

type pkgVersion struct {
	version   string
	qualifier map[string]string
	subpath   string
}

func (pv *pkgVersion) Type() string {
	return "PkgVersion"
}

func (pv *pkgVersion) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["version"] = pv.version
	properties["subpath"] = pv.subpath
	for k, v := range pv.qualifier {
		properties[k] = v
	}
	return properties
}

func (pv *pkgVersion) PropertyNames() []string {
	fields := []string{"version", "subpath"}
	for k := range pv.qualifier {
		fields = append(fields, k)
	}
	return fields
}

func (pv *pkgVersion) IdentifiablePropertyNames() []string {
	fields := []string{"version", "subpath"}
	for k := range pv.qualifier {
		fields = append(fields, k)
	}
	return fields
}

type pkgToType struct {
	pkg     *pkgNode
	pkgType *pkgType
}

func (e *pkgToType) Type() string {
	return "PkgHasType"
}

func (e *pkgToType) Nodes() (v, u assembler.GuacNode) {
	return e.pkg, e.pkgType
}

func (e *pkgToType) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e *pkgToType) PropertyNames() []string {
	return []string{}
}

func (e *pkgToType) IdentifiablePropertyNames() []string {
	return []string{}
}

type typeToNamespace struct {
	pkgType   *pkgType
	namespace *pkgNamespace
}

func (e *typeToNamespace) Type() string {
	return "PkgHasNamespace"
}

func (e *typeToNamespace) Nodes() (v, u assembler.GuacNode) {
	return e.pkgType, e.namespace
}

func (e *typeToNamespace) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e *typeToNamespace) PropertyNames() []string {
	return []string{}
}

func (e *typeToNamespace) IdentifiablePropertyNames() []string {
	return []string{}
}

type namespaceToName struct {
	namespace *pkgNamespace
	name      *pkgName
}

func (e *namespaceToName) Type() string {
	return "PkgHasName"
}

func (e *namespaceToName) Nodes() (v, u assembler.GuacNode) {
	return e.namespace, e.name
}

func (e *namespaceToName) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e *namespaceToName) PropertyNames() []string {
	return []string{}
}

func (e *namespaceToName) IdentifiablePropertyNames() []string {
	return []string{}
}

type nameToVersion struct {
	name    *pkgName
	version *pkgVersion
}

func (e *nameToVersion) Type() string {
	return "PkgHasVersion"
}

func (e *nameToVersion) Nodes() (v, u assembler.GuacNode) {
	return e.name, e.version
}

func (e *nameToVersion) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e *nameToVersion) PropertyNames() []string {
	return []string{}
}

func (e *nameToVersion) IdentifiablePropertyNames() []string {
	return []string{}
}

func (c *neo4jClient) Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			var sb strings.Builder
			var firstMatch bool = true
			queryValues := map[string]any{}

			sb.WriteString("MATCH (n:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)")

			if pkgSpec.Type != nil {

				matchProperties(&sb, firstMatch, "type", "type", "$pkgType")
				firstMatch = false
				queryValues["pkgType"] = pkgSpec.Type
			}
			if pkgSpec.Namespace != nil {

				matchProperties(&sb, firstMatch, "namespace", "namespace", "$pkgNamespace")
				firstMatch = false
				queryValues["pkgNamespace"] = pkgSpec.Namespace
			}
			if pkgSpec.Name != nil {

				matchProperties(&sb, firstMatch, "name", "name", "$pkgName")
				firstMatch = false
				queryValues["pkgName"] = pkgSpec.Name
			}
			if pkgSpec.Version != nil {

				matchProperties(&sb, firstMatch, "version", "version", "$pkgVerion")
				firstMatch = false
				queryValues["pkgVerion"] = pkgSpec.Version
			}

			if pkgSpec.Subpath != nil {

				matchProperties(&sb, firstMatch, "version", "subpath", "$pkgSubpath")
				firstMatch = false
				queryValues["pkgSubpath"] = pkgSpec.Subpath
			}

			if pkgSpec.MatchOnlyEmptyQualifiers != nil && !*pkgSpec.MatchOnlyEmptyQualifiers {

				if len(pkgSpec.Qualifiers) > 0 {

					for _, qualifier := range pkgSpec.Qualifiers {
						qualifierKey := removeInvalidCharFromProperty(qualifier.Key)
						matchProperties(&sb, firstMatch, "version", qualifierKey, "$"+qualifierKey)
						firstMatch = false
						queryValues[qualifierKey] = qualifier.Value
					}
				}
			} else {
				matchLengthProperties(&sb, firstMatch, "version", 2)
			}

			sb.WriteString(" RETURN type.type, namespace.namespace, name.name, version")
			fmt.Println(sb.String())
			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			pkgTypes := map[string]map[string]map[string][]*model.PackageVersion{}
			pkgNamespaces := map[string]map[string][]*model.PackageVersion{}
			pkgNames := map[string][]*model.PackageVersion{}
			for result.Next() {

				versionNode := result.Record().Values[3].(dbtype.Node)

				pkgQualifiers := []*model.PackageQualifier{}
				if pkgSpec.MatchOnlyEmptyQualifiers != nil && !*pkgSpec.MatchOnlyEmptyQualifiers {
					if len(pkgSpec.Qualifiers) > 0 {
						for _, qualifier := range pkgSpec.Qualifiers {

							qualifierKey := removeInvalidCharFromProperty(qualifier.Key)
							pkgQualifier := &model.PackageQualifier{
								Key:   qualifierKey,
								Value: versionNode.Props[qualifierKey].(string),
							}
							pkgQualifiers = append(pkgQualifiers, pkgQualifier)
						}
					} else {
						for key, value := range versionNode.Props {
							if key != "subpath" && key != "version" {
								pkgQualifier := &model.PackageQualifier{
									Key:   key,
									Value: value.(string),
								}
								pkgQualifiers = append(pkgQualifiers, pkgQualifier)
							}
						}
					}
				}

				pkgVersion := &model.PackageVersion{
					Version:    versionNode.Props["version"].(string),
					Subpath:    versionNode.Props["subpath"].(string),
					Qualifiers: pkgQualifiers,
				}

				pkgNames[result.Record().Values[2].(string)] = append(pkgNames[result.Record().Values[2].(string)], pkgVersion)
				pkgNamespaces[result.Record().Values[1].(string)] = pkgNames
				pkgTypes[result.Record().Values[0].(string)] = pkgNamespaces
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			packages := []*model.Package{}
			for pkgType, pkgNamespaces := range pkgTypes {
				collectedPkgNamespaces := []*model.PackageNamespace{}
				for namespace, pkgNames := range pkgNamespaces {
					collectedPkgNames := []*model.PackageName{}
					for name, versions := range pkgNames {
						pkgName := &model.PackageName{
							Name:     name,
							Versions: versions,
						}
						collectedPkgNames = append(collectedPkgNames, pkgName)
					}
					pkgNamespace := &model.PackageNamespace{
						Namespace: namespace,
						Names:     collectedPkgNames,
					}
					collectedPkgNamespaces = append(collectedPkgNamespaces, pkgNamespace)
				}
				collectedPackage := &model.Package{
					Type:       pkgType,
					Namespaces: collectedPkgNamespaces,
				}
				packages = append(packages, collectedPackage)
			}

			return packages, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Package), nil
}

func removeInvalidCharFromProperty(key string) string {
	// neo4j does not accept "." in its properties. If the qualifier contains a "." that must
	// be replaced by an "-"
	return strings.ReplaceAll(key, ".", "_")
}
