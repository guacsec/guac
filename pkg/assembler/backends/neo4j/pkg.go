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

package neo4j

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

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

	var sb strings.Builder
	var firstMatch bool = true
	queryValues := map[string]any{}

	sb.WriteString("MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)")

	setPkgMatchValues(&sb, pkgSpec, false, &firstMatch, queryValues)

	sb.WriteString(" RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, version.qualifier_list")

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			pkgTypes := map[string]map[string]map[string][]*model.PackageVersion{}

			for result.Next() {
				pkgQualifiers := []*model.PackageQualifier{}
				if result.Record().Values[5] != nil {
					pkgQualifiers = getCollectedPackageQualifiers(result.Record().Values[5].([]interface{}))
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

	var sb strings.Builder
	var firstMatch bool = true
	queryValues := map[string]any{}

	sb.WriteString("MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)")

	if pkgSpec.Type != nil {

		matchProperties(&sb, firstMatch, "type", "type", "$pkgType")
		queryValues["pkgType"] = pkgSpec.Type
	}

	sb.WriteString(" RETURN type.type")

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
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

	var sb strings.Builder
	var firstMatch bool = true
	queryValues := map[string]any{}

	sb.WriteString("MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)")

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

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
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

	var sb strings.Builder
	var firstMatch bool = true
	queryValues := map[string]any{}

	sb.WriteString("MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)-[:PkgHasName]->(name:PkgName)")
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

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
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

func (c *neo4jClient) IngestPackages(ctx context.Context, pkgs []*model.IDorPkgInput) ([]*model.PackageIDs, error) {
	return []*model.PackageIDs{}, fmt.Errorf("not implemented: IngestPackages")
}

func (c *neo4jClient) IngestPackage(ctx context.Context, pkg model.IDorPkgInput) (*model.PackageIDs, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close()

	values := map[string]any{}
	values["pkgType"] = pkg.PackageInput.Type
	values["name"] = pkg.PackageInput.Name
	if pkg.PackageInput.Namespace != nil {
		values["namespace"] = *pkg.PackageInput.Namespace
	} else {
		values["namespace"] = ""
	}
	if pkg.PackageInput.Version != nil {
		values["version"] = *pkg.PackageInput.Version
	} else {
		values["version"] = ""
	}
	if pkg.PackageInput.Subpath != nil {
		values["subpath"] = *pkg.PackageInput.Subpath
	} else {
		values["subpath"] = ""
	}

	// To ensure consistency, always sort the qualifiers by key
	qualifiersMap := map[string]string{}
	keys := []string{}
	for _, kv := range pkg.PackageInput.Qualifiers {
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

			qualifiersList := record.Values[5]
			subPath := record.Values[4]
			version := record.Values[3]
			nameStr := record.Values[2].(string)
			namespaceStr := record.Values[1].(string)
			pkgType := record.Values[0].(string)

			pkg := generateModelPackage(pkgType, namespaceStr, nameStr, version, subPath, qualifiersList)
			return pkg, nil
		})
	if err != nil {
		return nil, err
	}

	// TODO: this need to return all IDs for type, namespace, name and version
	return &model.PackageIDs{
		PackageVersionID: result.(*model.Package).ID,
	}, nil
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

func setPkgMatchValues(sb *strings.Builder, pkg *model.PkgSpec, objectPkg bool, firstMatch *bool, queryValues map[string]any) {
	if pkg != nil {
		if pkg.Type != nil {
			if !objectPkg {
				matchProperties(sb, *firstMatch, "type", "type", "$pkgType")
				queryValues["pkgType"] = pkg.Type
			} else {
				matchProperties(sb, *firstMatch, "objPkgType", "type", "$objPkgType")
				queryValues["objPkgType"] = pkg.Type
			}
			*firstMatch = false
		}
		if pkg.Namespace != nil {
			if !objectPkg {
				matchProperties(sb, *firstMatch, "namespace", "namespace", "$pkgNamespace")
				queryValues["pkgNamespace"] = pkg.Namespace
			} else {
				matchProperties(sb, *firstMatch, "objPkgNamespace", "namespace", "$objPkgNamespace")
				queryValues["objPkgNamespace"] = pkg.Namespace
			}
			*firstMatch = false
		}
		if pkg.Name != nil {
			if !objectPkg {
				matchProperties(sb, *firstMatch, "name", "name", "$pkgName")
				queryValues["pkgName"] = pkg.Name
			} else {
				matchProperties(sb, *firstMatch, "objPkgName", "name", "$objPkgName")
				queryValues["objPkgName"] = pkg.Name
			}
			*firstMatch = false
		}
		if pkg.Version != nil {
			if !objectPkg {
				matchProperties(sb, *firstMatch, "version", "version", "$pkgVersion")
				queryValues["pkgVersion"] = pkg.Version
			} else {
				matchProperties(sb, *firstMatch, "objPkgVersion", "version", "$objPkgVersion")
				queryValues["objPkgVersion"] = pkg.Version
			}
			*firstMatch = false
		}

		if pkg.Subpath != nil {
			if !objectPkg {
				matchProperties(sb, *firstMatch, "version", "subpath", "$pkgSubpath")
				queryValues["pkgSubpath"] = pkg.Subpath
			} else {
				matchProperties(sb, *firstMatch, "objPkgVersion", "subpath", "$objPkgSubpath")
				queryValues["objPkgSubpath"] = pkg.Subpath
			}
			*firstMatch = false
		}

		if !*pkg.MatchOnlyEmptyQualifiers {
			if len(pkg.Qualifiers) > 0 {
				if !objectPkg {
					qualifiers := getQualifiers(pkg.Qualifiers)
					matchProperties(sb, *firstMatch, "version", "qualifier_list", "$pkgQualifierList")
					queryValues["pkgQualifierList"] = qualifiers
				} else {
					qualifiers := getQualifiers(pkg.Qualifiers)
					matchProperties(sb, *firstMatch, "objPkgVersion", "qualifier_list", "$objPkgQualifierList")
					queryValues["objPkgQualifierList"] = qualifiers
				}
				*firstMatch = false
			}
		} else {
			if !objectPkg {
				matchProperties(sb, *firstMatch, "version", "qualifier_list", "$pkgQualifierList")
				queryValues["pkgQualifierList"] = []string{}
			} else {
				matchProperties(sb, *firstMatch, "objPkgVersion", "qualifier_list", "$objPkgQualifierList")
				queryValues["objPkgQualifierList"] = []string{}
			}
			*firstMatch = false
		}
	}
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
