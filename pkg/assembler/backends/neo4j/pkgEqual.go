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

// Query PkgEqual

func (c *neo4jClient) PkgEqual(ctx context.Context, pkgEqualSpec *model.PkgEqualSpec) ([]*model.PkgEqual, error) {

	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	var sb strings.Builder
	var selectedPkg *model.PkgSpec = nil
	var dependentPkg *model.PkgSpec = nil
	if pkgEqualSpec.Packages != nil && len(pkgEqualSpec.Packages) != 0 {
		if len(pkgEqualSpec.Packages) == 1 {
			selectedPkg = pkgEqualSpec.Packages[0]
		} else {
			selectedPkg = pkgEqualSpec.Packages[0]
			dependentPkg = pkgEqualSpec.Packages[1]
		}
	}

	queryValues := map[string]any{}

	// query with for subject and object package
	queryPkgEqual(&sb, selectedPkg, dependentPkg, pkgEqualSpec, false, queryValues)

	if len(pkgEqualSpec.Packages) > 0 {
		// query with reverse order for subject and object package
		queryPkgEqual(&sb, dependentPkg, selectedPkg, pkgEqualSpec, true, queryValues)
	}

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			collectedPkgEqual := []*model.PkgEqual{}

			for result.Next() {

				pkgQualifiers := result.Record().Values[5]
				subPath := result.Record().Values[4]
				version := result.Record().Values[3]
				nameString := result.Record().Values[2].(string)
				namespaceString := result.Record().Values[1].(string)
				typeString := result.Record().Values[0].(string)

				pkg := generateModelPackage(typeString, namespaceString, nameString, version, subPath, pkgQualifiers)

				pkgQualifiers = result.Record().Values[12]
				subPath = result.Record().Values[11]
				version = result.Record().Values[10]
				nameString = result.Record().Values[9].(string)
				namespaceString = result.Record().Values[8].(string)
				typeString = result.Record().Values[7].(string)

				depPkg := generateModelPackage(typeString, namespaceString, nameString, version, subPath, pkgQualifiers)

				pkgEqualNode := dbtype.Node{}
				if result.Record().Values[6] != nil {
					pkgEqualNode = result.Record().Values[6].(dbtype.Node)
				} else {
					return nil, gqlerror.Errorf("pkgEqual Node not found in neo4j")
				}

				pkgEqual := &model.PkgEqual{
					Packages:      []*model.Package{pkg, depPkg},
					Justification: pkgEqualNode.Props[justification].(string),
					Origin:        pkgEqualNode.Props[origin].(string),
					Collector:     pkgEqualNode.Props[collector].(string),
				}
				collectedPkgEqual = append(collectedPkgEqual, pkgEqual)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			return collectedPkgEqual, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.PkgEqual), nil
}

func queryPkgEqual(sb *strings.Builder, selectedPkg *model.PkgSpec, dependentPkg *model.PkgSpec, pkgEqualSpec *model.PkgEqualSpec, addInitialUnion bool,
	queryValues map[string]any) {

	returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
		"version.qualifier_list, pkgEqual, objPkgType.type, objPkgNamespace.namespace, objPkgName.name, " +
		"objPkgVersion.version, objPkgVersion.subpath, objPkgVersion.qualifier_list"

	if addInitialUnion {
		sb.WriteString("\nUNION")
		sb.WriteString("\n")
	}
	// query with selectedPkg at pkgVersion and dependentPkg at pkgVersion
	query := "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
		"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
		"-[:subject]-(pkgEqual:PkgEqual)-[:pkg_certification]-(objPkgVersion:PkgVersion)" +
		"\nWITH *" +
		"\nMATCH (objPkgVersion)<-[:PkgHasVersion]-(objPkgName:PkgName)<-[:PkgHasName]" +
		"-(objPkgNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
		"-(objPkgType:PkgType)<-[:PkgHasType]-(objPkgRoot:Pkg)"
	sb.WriteString(query)

	firstMatch := true
	setPkgMatchValues(sb, selectedPkg, false, &firstMatch, queryValues)
	setPkgMatchValues(sb, dependentPkg, true, &firstMatch, queryValues)
	setPkgEqualValues(sb, pkgEqualSpec, &firstMatch, queryValues)

	sb.WriteString(returnValue)
}

func setPkgEqualValues(sb *strings.Builder, pkgEqualSpec *model.PkgEqualSpec, firstMatch *bool, queryValues map[string]any) {
	if pkgEqualSpec.Justification != nil {

		matchProperties(sb, *firstMatch, "pkgEqual", justification, "$"+justification)
		*firstMatch = false
		queryValues[justification] = pkgEqualSpec.Justification
	}
	if pkgEqualSpec.Origin != nil {

		matchProperties(sb, *firstMatch, "pkgEqual", origin, "$"+origin)
		*firstMatch = false
		queryValues[origin] = pkgEqualSpec.Origin
	}
	if pkgEqualSpec.Collector != nil {

		matchProperties(sb, *firstMatch, "pkgEqual", collector, "$"+collector)
		*firstMatch = false
		queryValues[collector] = pkgEqualSpec.Collector
	}
}

// Ingest PkgEqual

func (c *neo4jClient) IngestPkgEqual(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, pkgEqual model.PkgEqualInputSpec) (*model.PkgEqual, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close()

	var sb strings.Builder
	queryValues := map[string]any{}

	// TODO: use generics here between PkgInputSpec and PkgSpec?
	selectedPkgSpec := helper.ConvertPkgInputSpecToPkgSpec(&pkg)
	depPkgSpec := helper.ConvertPkgInputSpecToPkgSpec(&depPkg)

	queryValues[justification] = pkgEqual.Justification
	queryValues[origin] = pkgEqual.Origin
	queryValues[collector] = pkgEqual.Collector

	query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
		"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)"

	firstMatch := true
	sb.WriteString(query)
	setPkgMatchValues(&sb, selectedPkgSpec, false, &firstMatch, queryValues)

	query = "\nMATCH (objPkgRoot:Pkg)-[:PkgHasType]->(objPkgType:PkgType)-[:PkgHasNamespace]->(objPkgNamespace:PkgNamespace)" +
		"-[:PkgHasName]->(objPkgName:PkgName)-[:PkgHasVersion]->(objPkgVersion:PkgVersion)"

	firstMatch = true
	sb.WriteString(query)
	setPkgMatchValues(&sb, depPkgSpec, true, &firstMatch, queryValues)

	merge := "\nMERGE (version)<-[:subject]-(pkgEqual:PkgEqual{justification:$justification,origin:$origin,collector:$collector})" +
		"-[:pkg_certification]->(objPkgVersion)"

	sb.WriteString(merge)

	returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
		"version.qualifier_list, pkgEqual, objPkgType.type, objPkgNamespace.namespace, objPkgName.name, " +
		"objPkgVersion.version, objPkgVersion.subpath, objPkgVersion.qualifier_list"

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

			pkgQualifiers = record.Values[12]
			subPath = record.Values[11]
			version = record.Values[10]
			nameString = record.Values[9].(string)
			namespaceString = record.Values[8].(string)
			typeString = record.Values[7].(string)

			depPkg := generateModelPackage(typeString, namespaceString, nameString, version, subPath, pkgQualifiers)

			pkgEqualNode := dbtype.Node{}
			if record.Values[6] != nil {
				pkgEqualNode = record.Values[6].(dbtype.Node)
			} else {
				return nil, gqlerror.Errorf("pkgEqual Node not found in neo4j")
			}

			pkgEqual := &model.PkgEqual{
				Packages:      []*model.Package{pkg, depPkg},
				Justification: pkgEqualNode.Props[justification].(string),
				Origin:        pkgEqualNode.Props[origin].(string),
				Collector:     pkgEqualNode.Props[collector].(string),
			}

			return pkgEqual, nil
		})
	if err != nil {
		return nil, err
	}
	return result.(*model.PkgEqual), nil
}

func (c *neo4jClient) IngestPkgEquals(ctx context.Context, pkgs []*model.PkgInputSpec, otherPackages []*model.PkgInputSpec, pkgEquals []*model.PkgEqualInputSpec) ([]string, error) {
	return nil, fmt.Errorf("not implemented - IngestPkgEquals")
}
