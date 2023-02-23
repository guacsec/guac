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
				"-[certifyPkg:CertifyPkg]-(depName:PkgName)<-[:PkgHasName]-(depNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
				"-(depType:PkgType)<-[:PkgHasType]-(depPkg:Pkg)" +
				"\nWITH *, null AS depVersion"
			sb.WriteString(query)

			setMatchValues(&sb, selectedPkg, dependentPkg, firstMatch, queryValues)

			sb.WriteString(returnValue)

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

			sb.WriteString(returnValue)

			sb.WriteString("\nUNION")

			query = "\nMATCH (n:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
				"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
				"-[certifyPkg:CertifyPkg]-(depVersion:PkgVersion)<-[:PkgHasVersion]-(depName:PkgName)<-[:PkgHasName]" +
				"-(depNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
				"-(depType:PkgType)<-[:PkgHasType]-(depPkg:Pkg)"
			sb.WriteString(query)

			firstMatch = true
			setMatchValues(&sb, selectedPkg, dependentPkg, firstMatch, queryValues)

			sb.WriteString(returnValue)

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

			sb.WriteString(returnValue)

			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			collectedCertifyPkg := []*model.CertifyPkg{}

			for result.Next() {

				pkgQualifiers := []*model.PackageQualifier{}
				if result.Record().Values[5] != nil {
					pkgQualifiers = getCollectedPackageQualifiers(result.Record().Values[5].([]interface{}))
				}

				subPathString := ""
				if result.Record().Values[4] != nil {
					subPathString = result.Record().Values[4].(string)
				}
				versionString := ""
				if result.Record().Values[3] != nil {
					versionString = result.Record().Values[3].(string)
				}
				nameString := ""
				if result.Record().Values[2] != nil {
					nameString = result.Record().Values[2].(string)
				}
				namespaceString := ""
				if result.Record().Values[1] != nil {
					namespaceString = result.Record().Values[1].(string)
				}
				typeString := ""
				if result.Record().Values[0] != nil {
					typeString = result.Record().Values[0].(string)
				}

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

				pkgQualifiers = []*model.PackageQualifier{}
				if result.Record().Values[12] != nil {
					pkgQualifiers = getCollectedPackageQualifiers(result.Record().Values[12].([]interface{}))
				}

				subPathString = ""
				if result.Record().Values[11] != nil {
					subPathString = result.Record().Values[11].(string)
				}
				versionString = ""
				if result.Record().Values[10] != nil {
					versionString = result.Record().Values[10].(string)
				}
				nameString = ""
				if result.Record().Values[9] != nil {
					nameString = result.Record().Values[9].(string)
				}
				namespaceString = ""
				if result.Record().Values[8] != nil {
					namespaceString = result.Record().Values[8].(string)
				}
				typeString = ""
				if result.Record().Values[7] != nil {
					typeString = result.Record().Values[7].(string)
				}

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
