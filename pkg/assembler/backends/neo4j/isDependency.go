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
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j/dbtype"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

const (
	versionRange string = "versionRange"
)

func (c *neo4jClient) IsDependency(ctx context.Context, isDependencySpec *model.IsDependencySpec) ([]*model.IsDependency, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			var sb strings.Builder
			var firstMatch bool = true

			selectedPkg := isDependencySpec.Package
			var dependentPkg *model.PkgSpec = nil
			depMatchOnlyEmptyQualifiers := false
			if isDependencySpec.DependentPackage != nil {
				dependentPkg = &model.PkgSpec{
					Type:      isDependencySpec.DependentPackage.Type,
					Namespace: isDependencySpec.DependentPackage.Namespace,
					Name:      isDependencySpec.DependentPackage.Name,
					// remove version, subpath and set qualifiers to empty list
					Qualifiers: []*model.PackageQualifierSpec{},
					// setting to default value of false as package version is not checked for dependent packages
					MatchOnlyEmptyQualifiers: &depMatchOnlyEmptyQualifiers,
				}
			}

			returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
				"version.qualifier_list, isDependency, objPkgType.type, objPkgNamespace.namespace, objPkgName.name"

			queryValues := map[string]any{}
			// query with pkgVersion
			query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
				"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
				"-[:subject]-(isDependency:IsDependency)-[:dependency]-(objPkgName:PkgName)<-[:PkgHasName]-(objPkgNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
				"-(objPkgType:PkgType)<-[:PkgHasType]-(objPkgRoot:Pkg)"
			sb.WriteString(query)

			setPkgMatchValues(&sb, selectedPkg, false, &firstMatch, queryValues)
			setPkgMatchValues(&sb, dependentPkg, true, &firstMatch, queryValues)
			setIsDependencyValues(&sb, isDependencySpec, &firstMatch, queryValues)

			sb.WriteString(returnValue)

			if selectedPkg == nil || selectedPkg != nil && selectedPkg.Version == nil && selectedPkg.Subpath == nil &&
				len(selectedPkg.Qualifiers) == 0 && !*selectedPkg.MatchOnlyEmptyQualifiers {

				sb.WriteString("\nUNION")
				// query without pkgVersion
				query = "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
					"-[:PkgHasName]->(name:PkgName)" +
					"-[:subject]-(isDependency:IsDependency)-[:dependency]-(objPkgName:PkgName)<-[:PkgHasName]-(objPkgNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
					"-(objPkgType:PkgType)<-[:PkgHasType]-(objPkgRoot:Pkg)" +
					"\nWITH *, null AS version"
				sb.WriteString(query)

				firstMatch = true
				setPkgMatchValues(&sb, selectedPkg, false, &firstMatch, queryValues)
				setPkgMatchValues(&sb, dependentPkg, true, &firstMatch, queryValues)
				setIsDependencyValues(&sb, isDependencySpec, &firstMatch, queryValues)

				sb.WriteString(returnValue)
			}

			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			collectedIsDependency := []*model.IsDependency{}

			for result.Next() {

				pkgQualifiers := getCollectedPackageQualifiers(result.Record().Values[5].([]interface{}))
				subPathString := result.Record().Values[4].(string)
				versionString := result.Record().Values[3].(string)
				nameString := result.Record().Values[2].(string)
				namespaceString := result.Record().Values[1].(string)
				typeString := result.Record().Values[0].(string)

				version := &model.PackageVersion{
					Version:    versionString,
					Subpath:    subPathString,
					Qualifiers: pkgQualifiers,
				}

				name := &model.PackageName{
					Name:     nameString,
					Versions: []*model.PackageVersion{version},
				}

				namespace := &model.PackageNamespace{
					Namespace: namespaceString,
					Names:     []*model.PackageName{name},
				}
				pkg := model.Package{
					Type:       typeString,
					Namespaces: []*model.PackageNamespace{namespace},
				}

				nameString = result.Record().Values[9].(string)
				namespaceString = result.Record().Values[8].(string)
				typeString = result.Record().Values[7].(string)

				name = &model.PackageName{
					Name:     nameString,
					Versions: []*model.PackageVersion{version},
				}

				namespace = &model.PackageNamespace{
					Namespace: namespaceString,
					Names:     []*model.PackageName{name},
				}
				depPkg := model.Package{
					Type:       typeString,
					Namespaces: []*model.PackageNamespace{namespace},
				}

				isDependencyNode := dbtype.Node{}
				if result.Record().Values[6] != nil {
					isDependencyNode = result.Record().Values[6].(dbtype.Node)
				} else {
					return nil, gqlerror.Errorf("isDependencyEdge not found in neo4j")
				}

				isDependency := &model.IsDependency{
					Package:          &pkg,
					DependentPackage: &depPkg,
					VersionRange:     isDependencyNode.Props[versionRange].(string),
					Origin:           isDependencyNode.Props[origin].(string),
					Collector:        isDependencyNode.Props[collector].(string),
				}
				collectedIsDependency = append(collectedIsDependency, isDependency)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			return collectedIsDependency, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.IsDependency), nil
}

func setIsDependencyValues(sb *strings.Builder, isDependencySpec *model.IsDependencySpec, firstMatch *bool, queryValues map[string]any) {
	if isDependencySpec.VersionRange != nil {

		matchProperties(sb, *firstMatch, "isDependency", "versionRange", "$versionRange")
		*firstMatch = false
		queryValues["versionRange"] = isDependencySpec.VersionRange
	}
	if isDependencySpec.Origin != nil {

		matchProperties(sb, *firstMatch, "isDependency", "origin", "$origin")
		*firstMatch = false
		queryValues["origin"] = isDependencySpec.Origin
	}
	if isDependencySpec.Collector != nil {

		matchProperties(sb, *firstMatch, "isDependency", "collector", "$collector")
		*firstMatch = false
		queryValues["collector"] = isDependencySpec.Collector
	}
}
