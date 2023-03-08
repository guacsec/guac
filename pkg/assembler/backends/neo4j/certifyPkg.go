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

// Query CertifyPkg

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

				certifyPkgNode := dbtype.Node{}
				if result.Record().Values[6] != nil {
					certifyPkgNode = result.Record().Values[6].(dbtype.Node)
				} else {
					return nil, gqlerror.Errorf("certifyPkg Node not found in neo4j")
				}

				certifyPkg := &model.CertifyPkg{
					Packages:      []*model.Package{pkg, depPkg},
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

func queryCertifyPkg(sb *strings.Builder, selectedPkg *model.PkgSpec, dependentPkg *model.PkgSpec, certifyPkgSpec *model.CertifyPkgSpec, addInitialUnion bool,
	queryValues map[string]any) {

	returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
		"version.qualifier_list, certifyPkg, objPkgType.type, objPkgNamespace.namespace, objPkgName.name, " +
		"objPkgVersion.version, objPkgVersion.subpath, objPkgVersion.qualifier_list"

	if addInitialUnion {
		sb.WriteString("\nUNION")
		sb.WriteString("\n")
	}
	// query with selectedPkg at pkgVersion and dependentPkg at pkgVersion
	query := "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
		"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
		"-[:subject]-(certifyPkg:CertifyPkg)-[:pkg_certification]-(objPkgVersion:PkgVersion)" +
		"\nWITH *" +
		"\nMATCH (objPkgVersion)<-[:PkgHasVersion]-(objPkgName:PkgName)<-[:PkgHasName]" +
		"-(objPkgNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
		"-(objPkgType:PkgType)<-[:PkgHasType]-(objPkgRoot:Pkg)"
	sb.WriteString(query)

	firstMatch := true
	setPkgMatchValues(sb, selectedPkg, false, &firstMatch, queryValues)
	setPkgMatchValues(sb, dependentPkg, true, &firstMatch, queryValues)
	setCertifyPkgValues(sb, certifyPkgSpec, &firstMatch, queryValues)

	sb.WriteString(returnValue)
}

func setCertifyPkgValues(sb *strings.Builder, certifyPkgSpec *model.CertifyPkgSpec, firstMatch *bool, queryValues map[string]any) {
	if certifyPkgSpec.Justification != nil {

		matchProperties(sb, *firstMatch, "certifyPkg", justification, "$"+justification)
		*firstMatch = false
		queryValues[justification] = certifyPkgSpec.Justification
	}
	if certifyPkgSpec.Origin != nil {

		matchProperties(sb, *firstMatch, "certifyPkg", origin, "$"+origin)
		*firstMatch = false
		queryValues[origin] = certifyPkgSpec.Origin
	}
	if certifyPkgSpec.Collector != nil {

		matchProperties(sb, *firstMatch, "certifyPkg", collector, "$"+collector)
		*firstMatch = false
		queryValues[collector] = certifyPkgSpec.Collector
	}
}

// Ingest CertifyPkg

func (c *neo4jClient) IngestCertifyPkg(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, certifyPkg model.CertifyPkgInputSpec) (*model.CertifyPkg, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close()

	var sb strings.Builder
	queryValues := map[string]any{}

	// TODO: use generics here between PkgInputSpec and PkgSpec?
	selectedPkgSpec := convertPkgInputSpecToPkgSpec(&pkg)
	depPkgSpec := convertPkgInputSpecToPkgSpec(&depPkg)

	queryValues[justification] = certifyPkg.Justification
	queryValues[origin] = certifyPkg.Origin
	queryValues[collector] = certifyPkg.Collector

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

	merge := "\nMERGE (version)<-[:subject]-(certifyPkg:CertifyPkg{justification:$justification,origin:$origin,collector:$collector})" +
		"-[:pkg_certification]->(objPkgVersion)"

	sb.WriteString(merge)

	returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
		"version.qualifier_list, certifyPkg, objPkgType.type, objPkgNamespace.namespace, objPkgName.name, " +
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

			certifyPkgNode := dbtype.Node{}
			if record.Values[6] != nil {
				certifyPkgNode = record.Values[6].(dbtype.Node)
			} else {
				return nil, gqlerror.Errorf("certifyPkg Node not found in neo4j")
			}

			certifyPkg := &model.CertifyPkg{
				Packages:      []*model.Package{pkg, depPkg},
				Justification: certifyPkgNode.Props[justification].(string),
				Origin:        certifyPkgNode.Props[origin].(string),
				Collector:     certifyPkgNode.Props[collector].(string),
			}

			return certifyPkg, nil
		})
	if err != nil {
		return nil, err
	}
	return result.(*model.CertifyPkg), nil
}
