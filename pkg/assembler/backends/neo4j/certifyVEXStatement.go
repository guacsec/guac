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

func (c *neo4jClient) CertifyVEXStatement(ctx context.Context, certifyVEXStatementSpec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {
	querySubjectAll := false
	if certifyVEXStatementSpec.Package != nil && certifyVEXStatementSpec.Artifact != nil {
		return nil, gqlerror.Errorf("cannot specify package and artifact together for CertifyVEXStatement")
	} else if certifyVEXStatementSpec.Package == nil && certifyVEXStatementSpec.Artifact == nil {
		querySubjectAll = true
	}

	queryVulnAll := false
	if certifyVEXStatementSpec.Cve != nil && certifyVEXStatementSpec.Ghsa != nil {
		return nil, gqlerror.Errorf("cannot specify cve and ghsa together for CertifyVEXStatement")
	} else if certifyVEXStatementSpec.Cve == nil && certifyVEXStatementSpec.Ghsa == nil {
		queryVulnAll = true
	}

	queryAll := false
	if querySubjectAll && queryVulnAll {
		queryAll = true
	}

	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	aggregateCertifyVEXStatement := []*model.CertifyVEXStatement{}

	if queryAll || querySubjectAll && certifyVEXStatementSpec.Cve != nil || queryVulnAll && certifyVEXStatementSpec.Package != nil ||
		certifyVEXStatementSpec.Package != nil && certifyVEXStatementSpec.Cve != nil {

		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		// query CVE
		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, certifyVEXStatement, cveYear.year, cveID.id"

		// query with pkgVersion
		query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
			"-[:subject]-(certifyVEXStatement:CertifyVEXStatement)-[:about]-(cveID:CveID)<-[:CveHasID]" +
			"-(cveYear:CveYear)<-[:CveIsYear]-(rootCve:Cve)"
		sb.WriteString(query)

		setPkgMatchValues(&sb, certifyVEXStatementSpec.Package, false, &firstMatch, queryValues)
		setCveMatchValues(&sb, certifyVEXStatementSpec.Cve, &firstMatch, queryValues)
		setCertifyVEXStatementValues(&sb, certifyVEXStatementSpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

		if certifyVEXStatementSpec.Package == nil || certifyVEXStatementSpec.Package != nil && certifyVEXStatementSpec.Package.Version == nil &&
			certifyVEXStatementSpec.Package.Subpath == nil && len(certifyVEXStatementSpec.Package.Qualifiers) == 0 &&
			!*certifyVEXStatementSpec.Package.MatchOnlyEmptyQualifiers {

			sb.WriteString("\nUNION")
			// query without pkgVersion
			query = "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
				"-[:PkgHasName]->(name:PkgName)" +
				"-[:subject]-(certifyVEXStatement:CertifyVEXStatement)-[:about]-(cveID:CveID)<-[:CveHasID]" +
				"-(cveYear:CveYear)<-[:CveIsYear]-(rootCve:Cve)" +
				"\nWITH *, null AS version"
			sb.WriteString(query)

			firstMatch = true
			setPkgMatchValues(&sb, certifyVEXStatementSpec.Package, false, &firstMatch, queryValues)
			setCveMatchValues(&sb, certifyVEXStatementSpec.Cve, &firstMatch, queryValues)
			setCertifyVEXStatementValues(&sb, certifyVEXStatementSpec, &firstMatch, queryValues)
			sb.WriteString(returnValue)
		}

		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedCertifyVEXStatement := []*model.CertifyVEXStatement{}

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

					cveID := &model.CVEId{
						ID: result.Record().Values[8].(string),
					}
					cve := &model.Cve{
						Year:  result.Record().Values[7].(string),
						CveID: []*model.CVEId{cveID},
					}

					certifyVEXStatementNode := dbtype.Node{}
					if result.Record().Values[1] != nil {
						certifyVEXStatementNode = result.Record().Values[6].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyVEXStatement Node not found in neo4j")
					}

					certifyVEXStatement := &model.CertifyVEXStatement{
						Subject:       &pkg,
						Vulnerability: cve,
						Justification: certifyVEXStatementNode.Props[justification].(string),
						Origin:        certifyVEXStatementNode.Props[origin].(string),
						Collector:     certifyVEXStatementNode.Props[collector].(string),
					}
					collectedCertifyVEXStatement = append(collectedCertifyVEXStatement, certifyVEXStatement)
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				return collectedCertifyVEXStatement, nil
			})
		if err != nil {
			return nil, err
		}
		aggregateCertifyVEXStatement = append(aggregateCertifyVEXStatement, result.([]*model.CertifyVEXStatement)...)
	}

	if queryAll || querySubjectAll && certifyVEXStatementSpec.Ghsa != nil || queryVulnAll && certifyVEXStatementSpec.Package != nil ||
		certifyVEXStatementSpec.Package != nil && certifyVEXStatementSpec.Ghsa != nil {

		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		// query ghsa
		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, certifyVEXStatement, ghsaID.id"

		// query with pkgVersion
		query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
			"-[:subject]-(certifyVEXStatement:CertifyVEXStatement)-[:about]-(ghsaID:GhsaID)<-[:GhsaHasID]" +
			"-(rootGhsa:Ghsa)"
		sb.WriteString(query)

		setPkgMatchValues(&sb, certifyVEXStatementSpec.Package, false, &firstMatch, queryValues)
		setGhsaMatchValues(&sb, certifyVEXStatementSpec.Ghsa, &firstMatch, queryValues)
		setCertifyVEXStatementValues(&sb, certifyVEXStatementSpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

		if certifyVEXStatementSpec.Package == nil || certifyVEXStatementSpec.Package != nil && certifyVEXStatementSpec.Package.Version == nil &&
			certifyVEXStatementSpec.Package.Subpath == nil && len(certifyVEXStatementSpec.Package.Qualifiers) == 0 &&
			!*certifyVEXStatementSpec.Package.MatchOnlyEmptyQualifiers {

			sb.WriteString("\nUNION")
			// query without pkgVersion
			query = "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
				"-[:PkgHasName]->(name:PkgName)" +
				"-[:subject]-(certifyVEXStatement:CertifyVEXStatement)-[:about]-(ghsaID:GhsaID)<-[:GhsaHasID]" +
				"-(rootGhsa:Ghsa)" +
				"\nWITH *, null AS version"
			sb.WriteString(query)

			firstMatch = true
			setPkgMatchValues(&sb, certifyVEXStatementSpec.Package, false, &firstMatch, queryValues)
			setGhsaMatchValues(&sb, certifyVEXStatementSpec.Ghsa, &firstMatch, queryValues)
			setCertifyVEXStatementValues(&sb, certifyVEXStatementSpec, &firstMatch, queryValues)
			sb.WriteString(returnValue)
		}

		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedCertifyVEXStatement := []*model.CertifyVEXStatement{}

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

					ghsaId := &model.GHSAId{
						ID: result.Record().Values[7].(string),
					}
					ghsa := &model.Ghsa{
						GhsaID: []*model.GHSAId{ghsaId},
					}

					certifyVEXStatementNode := dbtype.Node{}
					if result.Record().Values[1] != nil {
						certifyVEXStatementNode = result.Record().Values[6].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyVEXStatement Node not found in neo4j")
					}

					certifyVEXStatement := &model.CertifyVEXStatement{
						Subject:       &pkg,
						Vulnerability: ghsa,
						Justification: certifyVEXStatementNode.Props[justification].(string),
						Origin:        certifyVEXStatementNode.Props[origin].(string),
						Collector:     certifyVEXStatementNode.Props[collector].(string),
					}
					collectedCertifyVEXStatement = append(collectedCertifyVEXStatement, certifyVEXStatement)
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				return collectedCertifyVEXStatement, nil
			})
		if err != nil {
			return nil, err
		}
		aggregateCertifyVEXStatement = append(aggregateCertifyVEXStatement, result.([]*model.CertifyVEXStatement)...)
	}
	if queryAll || querySubjectAll && certifyVEXStatementSpec.Cve != nil || queryVulnAll && certifyVEXStatementSpec.Artifact != nil ||
		certifyVEXStatementSpec.Artifact != nil && certifyVEXStatementSpec.Cve != nil {

		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		// query CVE
		returnValue := " RETURN a.algorithm, a.digest, certifyVEXStatement, cveYear.year, cveID.id"

		// query artifact
		query := "MATCH (a:Artifact)" +
			"-[:subject]-(certifyVEXStatement:CertifyVEXStatement)-[:about]-(cveID:CveID)<-[:CveHasID]" +
			"-(cveYear:CveYear)<-[:CveIsYear]-(rootCve:Cve)"
		sb.WriteString(query)

		setArtifactMatchValues(&sb, certifyVEXStatementSpec.Artifact, false, &firstMatch, queryValues)
		setCveMatchValues(&sb, certifyVEXStatementSpec.Cve, &firstMatch, queryValues)
		setCertifyVEXStatementValues(&sb, certifyVEXStatementSpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedCertifyVEXStatement := []*model.CertifyVEXStatement{}

				for result.Next() {
					artifact := model.Artifact{
						Algorithm: result.Record().Values[0].(string),
						Digest:    result.Record().Values[1].(string),
					}

					cveID := &model.CVEId{
						ID: result.Record().Values[4].(string),
					}
					cve := &model.Cve{
						Year:  result.Record().Values[3].(string),
						CveID: []*model.CVEId{cveID},
					}

					certifyVEXStatementNode := dbtype.Node{}
					if result.Record().Values[1] != nil {
						certifyVEXStatementNode = result.Record().Values[2].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyVEXStatement Node not found in neo4j")
					}

					certifyVEXStatement := &model.CertifyVEXStatement{
						Subject:       &artifact,
						Vulnerability: cve,
						Justification: certifyVEXStatementNode.Props[justification].(string),
						Origin:        certifyVEXStatementNode.Props[origin].(string),
						Collector:     certifyVEXStatementNode.Props[collector].(string),
					}
					collectedCertifyVEXStatement = append(collectedCertifyVEXStatement, certifyVEXStatement)
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				return collectedCertifyVEXStatement, nil
			})
		if err != nil {
			return nil, err
		}
		aggregateCertifyVEXStatement = append(aggregateCertifyVEXStatement, result.([]*model.CertifyVEXStatement)...)
	}

	if queryAll || querySubjectAll && certifyVEXStatementSpec.Ghsa != nil || queryVulnAll && certifyVEXStatementSpec.Artifact != nil ||
		certifyVEXStatementSpec.Artifact != nil && certifyVEXStatementSpec.Ghsa != nil {

		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		// query ghsa
		returnValue := " RETURN a.algorithm, a.digest, certifyVEXStatement, ghsaID.id"

		// query artifact
		query := "MATCH (a:Artifact)" +
			"-[:subject]-(certifyVEXStatement:CertifyVEXStatement)-[:about]-(ghsaID:GhsaID)<-[:GhsaHasID]" +
			"-(rootGhsa:Ghsa)"
		sb.WriteString(query)

		setArtifactMatchValues(&sb, certifyVEXStatementSpec.Artifact, false, &firstMatch, queryValues)
		setGhsaMatchValues(&sb, certifyVEXStatementSpec.Ghsa, &firstMatch, queryValues)
		setCertifyVEXStatementValues(&sb, certifyVEXStatementSpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedCertifyVEXStatement := []*model.CertifyVEXStatement{}

				for result.Next() {
					artifact := model.Artifact{
						Algorithm: result.Record().Values[0].(string),
						Digest:    result.Record().Values[1].(string),
					}

					ghsaId := &model.GHSAId{
						ID: result.Record().Values[3].(string),
					}
					ghsa := &model.Ghsa{
						GhsaID: []*model.GHSAId{ghsaId},
					}

					certifyVEXStatementNode := dbtype.Node{}
					if result.Record().Values[1] != nil {
						certifyVEXStatementNode = result.Record().Values[2].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyVEXStatement Node not found in neo4j")
					}

					certifyVEXStatement := &model.CertifyVEXStatement{
						Subject:       &artifact,
						Vulnerability: ghsa,
						Justification: certifyVEXStatementNode.Props[justification].(string),
						Origin:        certifyVEXStatementNode.Props[origin].(string),
						Collector:     certifyVEXStatementNode.Props[collector].(string),
					}
					collectedCertifyVEXStatement = append(collectedCertifyVEXStatement, certifyVEXStatement)
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				return collectedCertifyVEXStatement, nil
			})
		if err != nil {
			return nil, err
		}
		aggregateCertifyVEXStatement = append(aggregateCertifyVEXStatement, result.([]*model.CertifyVEXStatement)...)
	}
	return aggregateCertifyVEXStatement, nil
}

func setCertifyVEXStatementValues(sb *strings.Builder, certifyVEXStatementSpec *model.CertifyVEXStatementSpec, firstMatch *bool, queryValues map[string]any) {
	if certifyVEXStatementSpec.KnownSince != nil {
		matchProperties(sb, *firstMatch, "certifyVEXStatement", knownSince, "$"+knownSince)
		*firstMatch = false
		queryValues[knownSince] = certifyVEXStatementSpec.KnownSince
	}
	if certifyVEXStatementSpec.Justification != nil {
		matchProperties(sb, *firstMatch, "certifyVEXStatement", justification, "$"+justification)
		*firstMatch = false
		queryValues["justification"] = certifyVEXStatementSpec.Justification
	}
	if certifyVEXStatementSpec.Origin != nil {
		matchProperties(sb, *firstMatch, "certifyVEXStatement", origin, "$"+origin)
		*firstMatch = false
		queryValues[origin] = certifyVEXStatementSpec.Origin
	}
	if certifyVEXStatementSpec.Collector != nil {
		matchProperties(sb, *firstMatch, "certifyVEXStatement", collector, "$"+collector)
		*firstMatch = false
		queryValues[collector] = certifyVEXStatementSpec.Collector
	}
}
