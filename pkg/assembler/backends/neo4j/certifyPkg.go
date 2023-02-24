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

func (c *neo4jClient) CertifyPkg(ctx context.Context, certifyPkgSpec *model.CertifyPkgSpec) ([]*model.CertifyPkg, error) {

	if certifyPkgSpec.Packages != nil && len(certifyPkgSpec.Packages) > 2 {
		return nil, gqlerror.Errorf("cannot specify more than 2 packages in CertifyPkg")
	}

	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			var sb strings.Builder
			var firstMatch bool = true

			var selectedPkg *model.PkgSpec = nil
			var dependentPkg *model.PkgSpec = nil
			if certifyPkgSpec.Packages != nil && len(certifyPkgSpec.Packages) != 0 {
				if len(certifyPkgSpec.Packages) == 1 {
					selectedPkg = certifyPkgSpec.Packages[0]
				} else {
					selectedPkg = certifyPkgSpec.Packages[0]
					dependentPkg = certifyPkgSpec.Packages[1]
				}
			}

			returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
				"version.qualifier_list, certifyPkg, depType.type, depNamespace.namespace, depName.name, " +
				"depVersion.version, depVersion.subpath, depVersion.qualifier_list"

			queryValues := map[string]any{}

			// query with pkgVersion
			query := "MATCH (n:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
				"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
				"-[certifyPkg:CertifyPkg]-(depVersion:PkgVersion)<-[:PkgHasVersion]-(depName:PkgName)<-[:PkgHasName]" +
				"-(depNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
				"-(depType:PkgType)<-[:PkgHasType]-(depPkg:Pkg)"
			sb.WriteString(query)

			firstMatch = true
			setMatchValues(&sb, selectedPkg, dependentPkg, firstMatch, queryValues)
			setCertifyPkgValues(&sb, certifyPkgSpec, firstMatch, queryValues)

			sb.WriteString(returnValue)

			if dependentPkg == nil || dependentPkg != nil && dependentPkg.Version == nil && dependentPkg.Subpath == nil &&
				len(dependentPkg.Qualifiers) == 0 && !*dependentPkg.MatchOnlyEmptyQualifiers {

				sb.WriteString("\nUNION")
				// query with pkgVersion
				query = "\nMATCH (n:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
					"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
					"-[certifyPkg:CertifyPkg]-(depName:PkgName)<-[:PkgHasName]-(depNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
					"-(depType:PkgType)<-[:PkgHasType]-(depPkg:Pkg)" +
					"\nWITH *, null AS depVersion"
				sb.WriteString(query)

				setMatchValues(&sb, selectedPkg, dependentPkg, firstMatch, queryValues)
				setCertifyPkgValues(&sb, certifyPkgSpec, firstMatch, queryValues)

				sb.WriteString(returnValue)

			}

			if selectedPkg == nil || (selectedPkg != nil && selectedPkg.Version == nil && selectedPkg.Subpath == nil &&
				len(selectedPkg.Qualifiers) == 0 && !*selectedPkg.MatchOnlyEmptyQualifiers &&
				dependentPkg == nil || dependentPkg != nil && dependentPkg.Version == nil && dependentPkg.Subpath == nil &&
				len(dependentPkg.Qualifiers) == 0 && !*dependentPkg.MatchOnlyEmptyQualifiers) {

				sb.WriteString("\nUNION")
				// query without pkgVersion
				query = "\nMATCH (n:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
					"-[:PkgHasName]->(name:PkgName)" +
					"-[certifyPkg:CertifyPkg]-(depName:PkgName)<-[:PkgHasName]-(depNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
					"-(depType:PkgType)<-[:PkgHasType]-(depPkg:Pkg)" +
					"\nWITH *, null AS version, null AS depVersion"
				sb.WriteString(query)

				firstMatch = true
				setMatchValues(&sb, selectedPkg, dependentPkg, firstMatch, queryValues)
				setCertifyPkgValues(&sb, certifyPkgSpec, firstMatch, queryValues)

				sb.WriteString(returnValue)
			}

			if selectedPkg == nil || selectedPkg != nil && selectedPkg.Version == nil && selectedPkg.Subpath == nil &&
				len(selectedPkg.Qualifiers) == 0 && !*selectedPkg.MatchOnlyEmptyQualifiers {

				sb.WriteString("\nUNION")
				// query without pkgVersion
				query = "\nMATCH (n:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
					"-[:PkgHasName]->(name:PkgName)" +
					"-[certifyPkg:CertifyPkg]-(depVersion:PkgVersion)<-[:PkgHasVersion]-(depName:PkgName)<-[:PkgHasName]" +
					"-(depNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
					"-(depType:PkgType)<-[:PkgHasType]-(depPkg:Pkg)" +
					"\nWITH *, null AS version"
				sb.WriteString(query)

				firstMatch = true
				setMatchValues(&sb, selectedPkg, dependentPkg, firstMatch, queryValues)
				setCertifyPkgValues(&sb, certifyPkgSpec, firstMatch, queryValues)

				sb.WriteString(returnValue)
			}

			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			collectedCertifyPkg := []*model.CertifyPkg{}

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

				pkgQualifiers = getCollectedPackageQualifiers(result.Record().Values[12].([]interface{}))
				subPathString = result.Record().Values[11].(string)
				versionString = result.Record().Values[10].(string)
				nameString = result.Record().Values[9].(string)
				namespaceString = result.Record().Values[8].(string)
				typeString = result.Record().Values[7].(string)

				version = &model.PackageVersion{
					Version:    versionString,
					Subpath:    subPathString,
					Qualifiers: pkgQualifiers,
				}

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

				certifyPkgEdge := dbtype.Relationship{}
				if result.Record().Values[6] != nil {
					certifyPkgEdge = result.Record().Values[6].(dbtype.Relationship)
				} else {
					return nil, gqlerror.Errorf("certifyPkgEdge not found in neo4j")
				}

				certifyPkg := &model.CertifyPkg{
					Packages:      []*model.Package{&pkg, &depPkg},
					Justification: certifyPkgEdge.Props[justification].(string),
					Origin:        certifyPkgEdge.Props[origin].(string),
					Collector:     certifyPkgEdge.Props[collector].(string),
				}
				collectedCertifyPkg = append(collectedCertifyPkg, certifyPkg)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			return collectedCertifyPkg, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.CertifyPkg), nil
}

func setCertifyPkgValues(sb *strings.Builder, certifyPkgSpec *model.CertifyPkgSpec, firstMatch bool, queryValues map[string]any) {
	if certifyPkgSpec.Justification != nil {

		matchProperties(sb, firstMatch, "certifyPkg", "justification", "$justification")
		firstMatch = false
		queryValues["justification"] = certifyPkgSpec.Justification
	}
	if certifyPkgSpec.Origin != nil {

		matchProperties(sb, firstMatch, "certifyPkg", "origin", "$origin")
		firstMatch = false
		queryValues["origin"] = certifyPkgSpec.Origin
	}
	if certifyPkgSpec.Collector != nil {

		matchProperties(sb, firstMatch, "certifyPkg", "collector", "$collector")
		firstMatch = false
		queryValues["collector"] = certifyPkgSpec.Collector
	}
}
