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
	"strings"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j/dbtype"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

const (
	versionRange   string = "versionRange"
	dependencyType string = "dependencyType"
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
	if isDependencySpec.DependencyPackage != nil {
		dependentPkg = &model.PkgSpec{
			Type:      isDependencySpec.DependencyPackage.Type,
			Namespace: isDependencySpec.DependencyPackage.Namespace,
			Name:      isDependencySpec.DependencyPackage.Name,
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

				dependencyTypeEnum, err := convertDependencyTypeToEnum(isDependencyNode.Props[dependencyType].(string))
				if err != nil {
					return nil, fmt.Errorf("convertDependencyTypeToEnum failed with error: %w", err)
				}

				isDependency := &model.IsDependency{
					Package:           pkg,
					DependencyPackage: depPkg,
					VersionRange:      isDependencyNode.Props[versionRange].(string),
					DependencyType:    dependencyTypeEnum,
					Origin:            isDependencyNode.Props[origin].(string),
					Collector:         isDependencyNode.Props[collector].(string),
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
	if isDependencySpec.DependencyType != nil {
		matchProperties(sb, *firstMatch, "isDependency", dependencyType, "$"+dependencyType)
		*firstMatch = false
		queryValues[dependencyType] = isDependencySpec.DependencyType.String()
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

// Ingest IngestDependencies

func (c *neo4jClient) IngestDependencies(ctx context.Context, pkgs []*model.PkgInputSpec, depPkgs []*model.PkgInputSpec, depPkgMatchType model.MatchFlags, dependencies []*model.IsDependencyInputSpec) ([]*model.IsDependency, error) {
	return []*model.IsDependency{}, fmt.Errorf("not implemented: IngestDependencies")
}

// Ingest IsDependency

func (c *neo4jClient) IngestDependency(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, depPkgMatchType model.MatchFlags, dependency model.IsDependencyInputSpec) (*model.IsDependency, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close()
	// TODO: handle depPkgMatchType

	var sb strings.Builder
	var firstMatch bool = true
	queryValues := map[string]any{}

	// TODO: use generics here between PkgInputSpec and PkgSpec?
	selectedPkgSpec := helper.ConvertPkgInputSpecToPkgSpec(&pkg)
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
	queryValues[dependencyType] = dependency.DependencyType.String()
	queryValues[justification] = dependency.Justification
	queryValues[origin] = dependency.Origin
	queryValues[collector] = dependency.Collector

	returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
		"version.qualifier_list, isDependency, objPkgType.type, objPkgNamespace.namespace, objPkgName.name"

	query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
		"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion), (objPkgRoot:Pkg)-[:PkgHasType]->(objPkgType:PkgType)-[:PkgHasNamespace]->(objPkgNamespace:PkgNamespace)" +
		"-[:PkgHasName]->(objPkgName:PkgName)"

	sb.WriteString(query)
	setPkgMatchValues(&sb, selectedPkgSpec, false, &firstMatch, queryValues)
	setPkgMatchValues(&sb, &depPkgSpec, true, &firstMatch, queryValues)

	merge := "\nMERGE (version)<-[:subject]-(isDependency:IsDependency{versionRange:$versionRange,dependencyType:$dependencyType,justification:$justification,origin:$origin,collector:$collector})" +
		"-[:dependency]->(objPkgName)"
	sb.WriteString(merge)
	sb.WriteString(returnValue)

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

			dependencyTypeEnum, err := convertDependencyTypeToEnum(isDependencyNode.Props[dependencyType].(string))
			if err != nil {
				return nil, fmt.Errorf("convertDependencyTypeToEnum failed with error: %w", err)
			}

			isDependency := &model.IsDependency{
				Package:           pkg,
				DependencyPackage: depPkg,
				VersionRange:      isDependencyNode.Props[versionRange].(string),
				DependencyType:    dependencyTypeEnum,
				Origin:            isDependencyNode.Props[origin].(string),
				Collector:         isDependencyNode.Props[collector].(string),
			}

			return isDependency, nil
		})
	if err != nil {
		return nil, err
	}

	return result.(*model.IsDependency), nil
}

func convertDependencyTypeToEnum(status string) (model.DependencyType, error) {
	if status == model.DependencyTypeDirect.String() {
		return model.DependencyTypeDirect, nil
	}
	if status == model.DependencyTypeIndirect.String() {
		return model.DependencyTypeIndirect, nil
	}
	if status == model.DependencyTypeUnknown.String() {
		return model.DependencyTypeUnknown, nil
	}
	return model.DependencyTypeUnknown, fmt.Errorf("failed to convert DependencyType to enum")
}
