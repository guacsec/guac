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
	"sort"
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
	version string
	subpath string
	qualifier_list []string
}

func (pv *pkgVersion) Type() string {
	return "PkgVersion"
}

func (pv *pkgVersion) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["version"] = pv.version
	properties["subpath"] = pv.subpath
	properties["qualifier_list"] = pv.qualifier_list
	return properties
}

func (pv *pkgVersion) PropertyNames() []string {
	fields := []string{"version", "subpath", "qualifier_list"}
	return fields
}

func (pv *pkgVersion) IdentifiablePropertyNames() []string {
	fields := []string{"version", "subpath", "qualifier_list"}
	return fields
}

type pkgQualifier struct {
	qualifier map[string]string
}

func (pq *pkgQualifier) Type() string {
	return "PkgQualifier"
}

func (pq *pkgQualifier) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	for k, v := range pq.qualifier {
		properties[k] = v
	}
	return properties
}

func (pq *pkgQualifier) PropertyNames() []string {
	fields := []string{}
	for k := range pq.qualifier {
		fields = append(fields, k)
	}
	return fields
}

func (pq *pkgQualifier) IdentifiablePropertyNames() []string {
	fields := []string{}
	for k := range pq.qualifier {
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
						matchProperties(&sb, firstMatch, "qualifier", qualifierKey, "$"+qualifierKey)
						firstMatch = false
						queryValues[qualifierKey] = qualifier.Value
					}
				}
			} else {
				matchProperties(&sb, firstMatch, "version", "qualifier_list", "[]")
			}

			sb.WriteString(" RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, version.qualifier_list")

			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			pkgTypes := map[string]map[string]map[string][]*model.PackageVersion{}

			for result.Next() {
				pkgQualifiers := []*model.PackageQualifier{}
				if result.Record().Values[5] != nil {
					qualifierList := result.Record().Values[5].([]interface{})
					for i := range qualifierList {
						if i%2 == 0 {
							qualifier := &model.PackageQualifier{
								Key:   qualifierList[i].(string),
								Value: qualifierList[i+1].(string),
							}
							pkgQualifiers = append(pkgQualifiers, qualifier)
						}
					}
				}

				subPathString := result.Record().Values[4].(string)
				versionString := result.Record().Values[3].(string)
				nameString := result.Record().Values[2].(string)
				namespaceString := result.Record().Values[1].(string)
				typeString := result.Record().Values[0].(string)

				pkgVersion := &model.PackageVersion{
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
						pkgNamespaces := map[string]map[string][]*model.PackageVersion{}
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

func (c *neo4jClient) packagesType(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			var sb strings.Builder
			var firstMatch bool = true
			queryValues := map[string]any{}

			sb.WriteString("MATCH (n:Pkg)-[:PkgHasType]->(type:PkgType)")

			if pkgSpec.Type != nil {

				matchProperties(&sb, firstMatch, "type", "type", "$pkgType")
				queryValues["pkgType"] = pkgSpec.Type
			}

			sb.WriteString(" RETURN type.type")

			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			packages := []*model.Package{}
			for result.Next() {
				collectedPackage := &model.Package{
					Type:       result.Record().Values[0].(string),
					Namespaces: []*model.PackageNamespace{},
				}
				packages = append(packages, collectedPackage)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			return packages, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Package), nil
}

func (c *neo4jClient) packagesNamespace(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			var sb strings.Builder
			var firstMatch bool = true
			queryValues := map[string]any{}

			sb.WriteString("MATCH (n:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)")

			if pkgSpec.Type != nil {

				matchProperties(&sb, firstMatch, "type", "type", "$pkgType")
				firstMatch = false
				queryValues["pkgType"] = pkgSpec.Type
			}
			if pkgSpec.Namespace != nil {

				matchProperties(&sb, firstMatch, "namespace", "namespace", "$pkgNamespace")
				queryValues["pkgNamespace"] = pkgSpec.Namespace
			}

			sb.WriteString(" RETURN type.type, namespace.namespace")

			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			pkgTypes := map[string][]*model.PackageNamespace{}

			for result.Next() {

				namespaceString := result.Record().Values[1].(string)
				typeString := result.Record().Values[0].(string)

				pkgNamespace := &model.PackageNamespace{
					Namespace: namespaceString,
					Names:     []*model.PackageName{},
				}
				pkgTypes[typeString] = append(pkgTypes[typeString], pkgNamespace)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			packages := []*model.Package{}
			for pkgType, namespaces := range pkgTypes {
				collectedPackage := &model.Package{
					Type:       pkgType,
					Namespaces: namespaces,
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

func (c *neo4jClient) packagesName(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			var sb strings.Builder
			var firstMatch bool = true
			queryValues := map[string]any{}

			sb.WriteString("MATCH (n:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)-[:PkgHasName]->(name:PkgName)")
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
				queryValues["pkgName"] = pkgSpec.Name
			}

			sb.WriteString(" RETURN type.type, namespace.namespace, name.name")

			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			pkgTypes := map[string]map[string][]*model.PackageName{}

			for result.Next() {

				nameString := result.Record().Values[2].(string)
				namespaceString := result.Record().Values[1].(string)
				typeString := result.Record().Values[0].(string)

				pkgName := &model.PackageName{
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
			if err = result.Err(); err != nil {
				return nil, err
			}

			packages := []*model.Package{}
			for pkgType, pkgNamespaces := range pkgTypes {
				collectedPkgNamespaces := []*model.PackageNamespace{}
				for namespace, pkgNames := range pkgNamespaces {
					pkgNamespace := &model.PackageNamespace{
						Namespace: namespace,
						Names:     pkgNames,
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

func (c *neo4jClient) IngestPackage(ctx context.Context, pkg *model.PkgInputSpec) (*model.Package, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close()

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

	result, err := session.WriteTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			query := `MERGE (root:Pkg)
MERGE (root) -[:PkgHasType]-> (type:PkgType{type:$pkgType})
MERGE (type) -[:PkgHasNamespace]-> (ns:PkgNamespace{namespace:$namespace})
MERGE (ns) -[:PkgHasName]-> (name:PkgName{name:$name})
MERGE (name) -[:PkgHasVersion]-> (version:PkgVersion{version:$version,subpath:$subpath,qualifier_list:$qualifier})
RETURN type.type, ns.namespace, name.name, version.version, version.subpath, version.qualifier_list`
			result, err := tx.Run(query, values)
			if err != nil {
				return nil, err
			}

			// query returns a single record
			record, err := result.Single()
			if err != nil {
				return nil, err
			}

			// TODO(mihaimaruseac): Extract this to a utility since it is repeated
			qualifiers := []*model.PackageQualifier{}
			if record.Values[5] != nil {
				qualifierList := record.Values[5].([]interface{})
				for i := range qualifierList {
					if i%2 == 0 {
						qualifier := &model.PackageQualifier{
							Key:   qualifierList[i].(string),
							Value: qualifierList[i+1].(string),
						}
						qualifiers = append(qualifiers, qualifier)
					}
				}
			}
			subPathStr := ""
			if record.Values[4] != nil {
				subPathStr = record.Values[4].(string)
			}
			versionStr := ""
			if record.Values[3] != nil {
				versionStr = record.Values[3].(string)
			}
			version := &model.PackageVersion{
				Version:    versionStr,
				Subpath:    subPathStr,
				Qualifiers: qualifiers,
			}

			nameStr := record.Values[2].(string)
			name := &model.PackageName{
				Name:     nameStr,
				Versions: []*model.PackageVersion{version},
			}

			namespaceStr := ""
			if record.Values[1] != nil {
				namespaceStr = record.Values[1].(string)
			}
			namespace := &model.PackageNamespace{
				Namespace: namespaceStr,
				Names:     []*model.PackageName{name},
			}

			pkgType := record.Values[0].(string)
			pkg := model.Package{
				Type:       pkgType,
				Namespaces: []*model.PackageNamespace{namespace},
			}

			return &pkg, nil
		})
	if err != nil {
		return nil, err
	}

	return result.(*model.Package), nil
}
