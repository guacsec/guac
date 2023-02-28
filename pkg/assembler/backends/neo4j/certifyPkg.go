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

	var sb strings.Builder
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

	queryValues := map[string]any{}

	// query with for subject and object package
	queryCertifyPkg(&sb, selectedPkg, dependentPkg, certifyPkgSpec, false, queryValues)

	if len(certifyPkgSpec.Packages) > 0 {
		// query with reverse order for subject and object package
		queryCertifyPkg(&sb, dependentPkg, selectedPkg, certifyPkgSpec, true, queryValues)
	}

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
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

				certifyPkgNode := dbtype.Node{}
				if result.Record().Values[6] != nil {
					certifyPkgNode = result.Record().Values[6].(dbtype.Node)
				} else {
					return nil, gqlerror.Errorf("certifyPkg Node not found in neo4j")
				}

				certifyPkg := &model.CertifyPkg{
					Packages:      []*model.Package{&pkg, &depPkg},
					Justification: certifyPkgNode.Props[justification].(string),
					Origin:        certifyPkgNode.Props[origin].(string),
					Collector:     certifyPkgNode.Props[collector].(string),
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

func queryCertifyPkg(sb *strings.Builder, selectedPkg *model.PkgSpec, dependentPkg *model.PkgSpec, certifyPkgSpec *model.CertifyPkgSpec, addInitialUnion bool, queryValues map[string]any) {

	returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
		"version.qualifier_list, certifyPkg, objPkgType.type, objPkgNamespace.namespace, objPkgName.name, " +
		"objPkgVersion.version, objPkgVersion.subpath, objPkgVersion.qualifier_list"

	if addInitialUnion {
		sb.WriteString("\nUNION")
		sb.WriteString("\n")
	}
	// query with selectedPkg at pkgVersion and dependentPkg at pkgVersion
	query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
		"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
		"-[:subject]-(certifyPkg:CertifyPkg)-[:pkg_certification]-(objPkgVersion:PkgVersion)<-[:PkgHasVersion]-(objPkgName:PkgName)<-[:PkgHasName]" +
		"-(objPkgNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
		"-(objPkgType:PkgType)<-[:PkgHasType]-(objPkgRoot:Pkg)"
	sb.WriteString(query)

	firstMatch := true
	setPkgMatchValues(sb, selectedPkg, false, &firstMatch, queryValues)
	setPkgMatchValues(sb, dependentPkg, true, &firstMatch, queryValues)
	setCertifyPkgValues(sb, certifyPkgSpec, &firstMatch, queryValues)

	sb.WriteString(returnValue)

	if dependentPkg == nil || dependentPkg != nil && dependentPkg.Version == nil && dependentPkg.Subpath == nil &&
		len(dependentPkg.Qualifiers) == 0 && !*dependentPkg.MatchOnlyEmptyQualifiers {

		sb.WriteString("\nUNION")
		// query with selectedPkg at pkgVersion and dependentPkg at pkgName
		query = "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
			"-[:subject]-(certifyPkg:CertifyPkg)-[:pkg_certification]-(objPkgName:PkgName)<-[:PkgHasName]-(objPkgNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
			"-(objPkgType:PkgType)<-[:PkgHasType]-(objPkgRoot:Pkg)" +
			"\nWITH *, null AS objPkgVersion"
		sb.WriteString(query)

		firstMatch = true
		setPkgMatchValues(sb, selectedPkg, false, &firstMatch, queryValues)
		setPkgMatchValues(sb, dependentPkg, true, &firstMatch, queryValues)
		setCertifyPkgValues(sb, certifyPkgSpec, &firstMatch, queryValues)

		sb.WriteString(returnValue)

	}

	if selectedPkg == nil || (selectedPkg != nil && selectedPkg.Version == nil && selectedPkg.Subpath == nil &&
		len(selectedPkg.Qualifiers) == 0 && !*selectedPkg.MatchOnlyEmptyQualifiers &&
		dependentPkg == nil || dependentPkg != nil && dependentPkg.Version == nil && dependentPkg.Subpath == nil &&
		len(dependentPkg.Qualifiers) == 0 && !*dependentPkg.MatchOnlyEmptyQualifiers) {

		sb.WriteString("\nUNION")
		// query with selectedPkg at pkgName and dependentPkg at pkgName
		query = "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)" +
			"-[:subject]-(certifyPkg:CertifyPkg)-[:pkg_certification]-(objPkgName:PkgName)<-[:PkgHasName]-(objPkgNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
			"-(objPkgType:PkgType)<-[:PkgHasType]-(objPkgRoot:Pkg)" +
			"\nWITH *, null AS version, null AS objPkgVersion"
		sb.WriteString(query)

		firstMatch = true
		setPkgMatchValues(sb, selectedPkg, false, &firstMatch, queryValues)
		setPkgMatchValues(sb, dependentPkg, true, &firstMatch, queryValues)
		setCertifyPkgValues(sb, certifyPkgSpec, &firstMatch, queryValues)

		sb.WriteString(returnValue)
	}

	if selectedPkg == nil || selectedPkg != nil && selectedPkg.Version == nil && selectedPkg.Subpath == nil &&
		len(selectedPkg.Qualifiers) == 0 && !*selectedPkg.MatchOnlyEmptyQualifiers {

		sb.WriteString("\nUNION")
		// query with selectedPkg at pkgName and dependentPkg at pkgVersion
		query = "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)" +
			"-[:subject]-(certifyPkg:CertifyPkg)-[:pkg_certification]-(objPkgVersion:PkgVersion)<-[:PkgHasVersion]-(objPkgName:PkgName)<-[:PkgHasName]" +
			"-(objPkgNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
			"-(objPkgType:PkgType)<-[:PkgHasType]-(objPkgRoot:Pkg)" +
			"\nWITH *, null AS version"
		sb.WriteString(query)

		firstMatch = true
		setPkgMatchValues(sb, selectedPkg, false, &firstMatch, queryValues)
		setPkgMatchValues(sb, dependentPkg, true, &firstMatch, queryValues)
		setCertifyPkgValues(sb, certifyPkgSpec, &firstMatch, queryValues)

		sb.WriteString(returnValue)
	}
}

func setCertifyPkgValues(sb *strings.Builder, certifyPkgSpec *model.CertifyPkgSpec, firstMatch *bool, queryValues map[string]any) {
	if certifyPkgSpec.Justification != nil {

		matchProperties(sb, *firstMatch, "certifyPkg", "justification", "$justification")
		*firstMatch = false
		queryValues["justification"] = certifyPkgSpec.Justification
	}
	if certifyPkgSpec.Origin != nil {

		matchProperties(sb, *firstMatch, "certifyPkg", "origin", "$origin")
		*firstMatch = false
		queryValues["origin"] = certifyPkgSpec.Origin
	}
	if certifyPkgSpec.Collector != nil {

		matchProperties(sb, *firstMatch, "certifyPkg", "collector", "$collector")
		*firstMatch = false
		queryValues["collector"] = certifyPkgSpec.Collector
	}
}
