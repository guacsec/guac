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

// Query IsDependency

func (c *neo4jClient) IsDependency(ctx context.Context, isDependencySpec *model.IsDependencySpec) ([]*model.IsDependency, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

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

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {

			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			collectedIsDependency := []*model.IsDependency{}

			for result.Next() {
				pkgQualifiers := result.Record().Values[5]
				subPath := result.Record().Values[4]
				version := result.Record().Values[3]
				nameString := result.Record().Values[2].(string)
				namespaceString := result.Record().Values[1].(string)
				typeString := result.Record().Values[0].(string)

				pkg := generateModelPackage(typeString, namespaceString, nameString, version, subPath, pkgQualifiers)

				nameString = result.Record().Values[9].(string)
				namespaceString = result.Record().Values[8].(string)
				typeString = result.Record().Values[7].(string)

				depPkg := generateModelPackage(typeString, namespaceString, nameString, nil, nil, nil)

				isDependencyNode := dbtype.Node{}
				if result.Record().Values[6] != nil {
					isDependencyNode = result.Record().Values[6].(dbtype.Node)
				} else {
					return nil, gqlerror.Errorf("isDependency Node not found in neo4j")
				}

				isDependency := &model.IsDependency{
					Package:          pkg,
					DependentPackage: depPkg,
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

		matchProperties(sb, *firstMatch, "isDependency", versionRange, "$"+versionRange)
		*firstMatch = false
		queryValues[versionRange] = isDependencySpec.VersionRange
	}
	if isDependencySpec.Origin != nil {

		matchProperties(sb, *firstMatch, "isDependency", origin, "$"+origin)
		*firstMatch = false
		queryValues[origin] = isDependencySpec.Origin
	}
	if isDependencySpec.Collector != nil {

		matchProperties(sb, *firstMatch, "isDependency", collector, "$"+collector)
		*firstMatch = false
		queryValues[collector] = isDependencySpec.Collector
	}
}

// Ingest IsDependency

func (c *neo4jClient) IngestDependency(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, dependency model.IsDependencyInputSpec) (*model.IsDependency, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close()

	var sb strings.Builder
	var firstMatch bool = true
	queryValues := map[string]any{}

	// TODO: use generics here between PkgInputSpec and PkgSpec?
	selectedPkgSpec := convertPkgInputSpecToPkgSpec(pkg)
	// Note: depPkgSpec only takes up to the pkgName as IsDependency does not allow for the attestation
	// to be made at the pkgVersion level. Version range for the dependent package is defined as a property
	// on IsDependency.
	matchEmpty := false
	depPkgSpec := model.PkgSpec{
		Type:                     &depPkg.Type,
		Namespace:                depPkg.Namespace,
		Name:                     &depPkg.Name,
		Version:                  nil,
		Subpath:                  nil,
		Qualifiers:               nil,
		MatchOnlyEmptyQualifiers: &matchEmpty,
	}

	queryValues[versionRange] = dependency.VersionRange
	queryValues[justification] = dependency.Justification
	queryValues[origin] = dependency.Origin
	queryValues[collector] = dependency.Collector

	returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
		"version.qualifier_list, isDependency, objPkgType.type, objPkgNamespace.namespace, objPkgName.name"

	if selectedPkgSpec.Version == nil && selectedPkgSpec.Subpath == nil &&
		len(selectedPkgSpec.Qualifiers) == 0 && !*selectedPkgSpec.MatchOnlyEmptyQualifiers {

		query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName), (objPkgRoot:Pkg)-[:PkgHasType]->(objPkgType:PkgType)-[:PkgHasNamespace]->(objPkgNamespace:PkgNamespace)" +
			"-[:PkgHasName]->(objPkgName:PkgName)" +
			"\nWITH *, null AS version"

		sb.WriteString(query)
		setPkgMatchValues(&sb, &selectedPkgSpec, false, &firstMatch, queryValues)
		setPkgMatchValues(&sb, &depPkgSpec, true, &firstMatch, queryValues)

		merge := "\nMERGE (name)<-[:subject]-(isDependency:IsDependency{versionRange:$versionRange,justification:$justification,origin:$origin,collector:$collector})" +
			"-[:dependency]->(objPkgName)" +
			"\nRETURN RETURN type.type, namespace.namespace, name.name, isDependency, objPkgType.type, objPkgNamespace.namespace, objPkgName.name"
		sb.WriteString(merge)
		sb.WriteString(returnValue)
	} else {
		query := "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion), (objPkgRoot:Pkg)-[:PkgHasType]->(objPkgType:PkgType)-[:PkgHasNamespace]->(objPkgNamespace:PkgNamespace)" +
			"-[:PkgHasName]->(objPkgName:PkgName)"

		sb.WriteString(query)
		setPkgMatchValues(&sb, &selectedPkgSpec, false, &firstMatch, queryValues)
		setPkgMatchValues(&sb, &depPkgSpec, true, &firstMatch, queryValues)

		merge := "\nMERGE (version)<-[:subject]-(isDependency:IsDependency{versionRange:$versionRange,origin:$origin,collector:$collector})" +
			"-[:dependency]->(objPkgName)"
		sb.WriteString(merge)
		sb.WriteString(returnValue)
	}

	result, err := session.WriteTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			// query returns a single record
			record, err := result.Single()
			if err != nil {
				return nil, err
			}

			pkgQualifiers := record.Values[5]
			subPath := record.Values[4]
			version := record.Values[3]
			nameString := record.Values[2].(string)
			namespaceString := record.Values[1].(string)
			typeString := record.Values[0].(string)

			pkg := generateModelPackage(typeString, namespaceString, nameString, version, subPath, pkgQualifiers)

			nameString = record.Values[9].(string)
			namespaceString = record.Values[8].(string)
			typeString = record.Values[7].(string)

			depPkg := generateModelPackage(typeString, namespaceString, nameString, nil, nil, nil)

			isDependencyNode := dbtype.Node{}
			if record.Values[6] != nil {
				isDependencyNode = record.Values[6].(dbtype.Node)
			} else {
				return nil, gqlerror.Errorf("isDependency Node not found in neo4j")
			}

			isDependency := &model.IsDependency{
				Package:          pkg,
				DependentPackage: depPkg,
				VersionRange:     isDependencyNode.Props[versionRange].(string),
				Origin:           isDependencyNode.Props[origin].(string),
				Collector:        isDependencyNode.Props[collector].(string),
			}

			return isDependency, nil
		})
	if err != nil {
		return nil, err
	}

	return result.(*model.IsDependency), nil
}
