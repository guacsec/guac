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
	"time"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j/dbtype"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (c *neo4jClient) CertifyVEXStatement(ctx context.Context, certifyVEXStatementSpec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {

	// TODO: Fix validation
	querySubjectAll := true
	// querySubjectAll, err := helper.ValidatePackageOrArtifactQueryInput(certifyVEXStatementSpec.Subject)
	// if err != nil {
	// 	return nil, err
	// }

	// TODO: Fix validation
	queryVulnAll := true
	// queryVulnAll, err := helper.ValidateCveOrGhsaQueryInput(certifyVEXStatementSpec.Vulnerability)
	// if err != nil {
	// 	return nil, err
	// }

	queryAll := false
	if querySubjectAll && queryVulnAll {
		queryAll = true
	}

	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	aggregateCertifyVEXStatement := []*model.CertifyVEXStatement{}

	if queryAll || (querySubjectAll && certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Cve != nil) ||
		(queryVulnAll && certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Package != nil) ||
		(certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Package != nil &&
			certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Cve != nil) {

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

		if certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Package != nil {
			setPkgMatchValues(&sb, certifyVEXStatementSpec.Subject.Package, false, &firstMatch, queryValues)
		}
		if certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Cve != nil {
			setCveMatchValues(&sb, certifyVEXStatementSpec.Vulnerability.Cve, &firstMatch, queryValues)
		}
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

					pkgQualifiers := result.Record().Values[5]
					subPath := result.Record().Values[4]
					version := result.Record().Values[3]
					nameString := result.Record().Values[2].(string)
					namespaceString := result.Record().Values[1].(string)
					typeString := result.Record().Values[0].(string)

					pkg := generateModelPackage(typeString, namespaceString, nameString, version, subPath, pkgQualifiers)

					idStr := result.Record().Values[8].(string)
					yearStr := result.Record().Values[7].(int)
					cve := generateModelCve(yearStr, idStr)

					certifyVEXStatementNode := dbtype.Node{}
					if result.Record().Values[1] != nil {
						certifyVEXStatementNode = result.Record().Values[6].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyVEXStatement Node not found in neo4j")
					}

					certifyVEXStatement, err := generateModelCertifyVEXStatement(pkg, cve, certifyVEXStatementNode.Props[status].(string),
						certifyVEXStatementNode.Props[statement].(string), certifyVEXStatementNode.Props[statusNotes].(string),
						certifyVEXStatementNode.Props[justification].(string), certifyVEXStatementNode.Props[origin].(string),
						certifyVEXStatementNode.Props[collector].(string), certifyVEXStatementNode.Props[knownSince].(time.Time))

					if err != nil {
						return nil, gqlerror.Errorf("generateModelCertifyVEXStatement failed due to error: %w", err)
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

	if queryAll || (querySubjectAll && certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Ghsa != nil) ||
		(queryVulnAll && certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Package != nil) ||
		(certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Package != nil &&
			certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Ghsa != nil) {

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

		if certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Package != nil {
			setPkgMatchValues(&sb, certifyVEXStatementSpec.Subject.Package, false, &firstMatch, queryValues)
		}
		if certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Ghsa != nil {
			setGhsaMatchValues(&sb, certifyVEXStatementSpec.Vulnerability.Ghsa, &firstMatch, queryValues)
		}
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
					pkgQualifiers := result.Record().Values[5]
					subPath := result.Record().Values[4]
					version := result.Record().Values[3]
					nameString := result.Record().Values[2].(string)
					namespaceString := result.Record().Values[1].(string)
					typeString := result.Record().Values[0].(string)

					pkg := generateModelPackage(typeString, namespaceString, nameString, version, subPath, pkgQualifiers)

					idStr := result.Record().Values[7].(string)
					ghsa := generateModelGhsa(idStr)

					certifyVEXStatementNode := dbtype.Node{}
					if result.Record().Values[1] != nil {
						certifyVEXStatementNode = result.Record().Values[6].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyVEXStatement Node not found in neo4j")
					}

					certifyVEXStatement, err := generateModelCertifyVEXStatement(pkg, ghsa, certifyVEXStatementNode.Props[status].(string),
						certifyVEXStatementNode.Props[statement].(string), certifyVEXStatementNode.Props[statusNotes].(string),
						certifyVEXStatementNode.Props[justification].(string), certifyVEXStatementNode.Props[origin].(string),
						certifyVEXStatementNode.Props[collector].(string), certifyVEXStatementNode.Props[knownSince].(time.Time))

					if err != nil {
						return nil, gqlerror.Errorf("generateModelCertifyVEXStatement failed due to error: %w", err)
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

	if queryAll || (querySubjectAll && certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Osv != nil) ||
		(queryVulnAll && certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Package != nil) ||
		(certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Package != nil &&
			certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Osv != nil) {

		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		// query ghsa
		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, certifyVuln, osvID.id"

		// query with pkgVersion
		query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
			"-[:subject]-(certifyVEXStatement:CertifyVEXStatement)-[:about]-(osvID:OsvID)<-[:OsvHasID]" +
			"-(rootOsv:Osv)"
		sb.WriteString(query)

		if certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Package != nil {
			setPkgMatchValues(&sb, certifyVEXStatementSpec.Subject.Package, false, &firstMatch, queryValues)
		}
		if certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Osv != nil {
			setOSVMatchValues(&sb, certifyVEXStatementSpec.Vulnerability.Osv, &firstMatch, queryValues)
		}
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
					pkgQualifiers := result.Record().Values[5]
					subPath := result.Record().Values[4]
					version := result.Record().Values[3]
					nameString := result.Record().Values[2].(string)
					namespaceString := result.Record().Values[1].(string)
					typeString := result.Record().Values[0].(string)

					pkg := generateModelPackage(typeString, namespaceString, nameString, version, subPath, pkgQualifiers)

					id := result.Record().Values[7].(string)
					osv := generateModelOsv(id)

					certifyVEXStatementNode := dbtype.Node{}
					if result.Record().Values[1] != nil {
						certifyVEXStatementNode = result.Record().Values[6].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyVEXStatement Node not found in neo4j")
					}

					certifyVEXStatement, err := generateModelCertifyVEXStatement(pkg, osv, certifyVEXStatementNode.Props[status].(string),
						certifyVEXStatementNode.Props[statement].(string), certifyVEXStatementNode.Props[statusNotes].(string),
						certifyVEXStatementNode.Props[justification].(string), certifyVEXStatementNode.Props[origin].(string),
						certifyVEXStatementNode.Props[collector].(string), certifyVEXStatementNode.Props[knownSince].(time.Time))

					if err != nil {
						return nil, gqlerror.Errorf("generateModelCertifyVEXStatement failed due to error: %w", err)
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

	if queryAll || (querySubjectAll && certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Cve != nil) ||
		(queryVulnAll && certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Artifact != nil) ||
		(certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Artifact != nil &&
			certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Cve != nil) {

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

		if certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Artifact != nil {
			setArtifactMatchValues(&sb, certifyVEXStatementSpec.Subject.Artifact, false, &firstMatch, queryValues)
		}
		if certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Cve != nil {
			setCveMatchValues(&sb, certifyVEXStatementSpec.Vulnerability.Cve, &firstMatch, queryValues)
		}
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
					algorithm := result.Record().Values[0].(string)
					digest := result.Record().Values[1].(string)
					artifact := generateModelArtifact(algorithm, digest)

					idStr := result.Record().Values[4].(string)
					yearStr := result.Record().Values[3].(int)
					cve := generateModelCve(yearStr, idStr)

					certifyVEXStatementNode := dbtype.Node{}
					if result.Record().Values[1] != nil {
						certifyVEXStatementNode = result.Record().Values[2].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyVEXStatement Node not found in neo4j")
					}

					certifyVEXStatement, err := generateModelCertifyVEXStatement(artifact, cve, certifyVEXStatementNode.Props[status].(string),
						certifyVEXStatementNode.Props[statement].(string), certifyVEXStatementNode.Props[statusNotes].(string),
						certifyVEXStatementNode.Props[justification].(string), certifyVEXStatementNode.Props[origin].(string),
						certifyVEXStatementNode.Props[collector].(string), certifyVEXStatementNode.Props[knownSince].(time.Time))

					if err != nil {
						return nil, gqlerror.Errorf("generateModelCertifyVEXStatement failed due to error: %w", err)
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

	if queryAll || (querySubjectAll && certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Ghsa != nil) ||
		(queryVulnAll && certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Artifact != nil) ||
		(certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Artifact != nil &&
			certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Ghsa != nil) {

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

		if certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Artifact != nil {
			setArtifactMatchValues(&sb, certifyVEXStatementSpec.Subject.Artifact, false, &firstMatch, queryValues)
		}
		if certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Ghsa != nil {
			setGhsaMatchValues(&sb, certifyVEXStatementSpec.Vulnerability.Ghsa, &firstMatch, queryValues)
		}
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
					algorithm := result.Record().Values[0].(string)
					digest := result.Record().Values[1].(string)
					artifact := generateModelArtifact(algorithm, digest)

					idStr := result.Record().Values[3].(string)
					ghsa := generateModelGhsa(idStr)

					certifyVEXStatementNode := dbtype.Node{}
					if result.Record().Values[1] != nil {
						certifyVEXStatementNode = result.Record().Values[2].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyVEXStatement Node not found in neo4j")
					}

					certifyVEXStatement, err := generateModelCertifyVEXStatement(artifact, ghsa, certifyVEXStatementNode.Props[status].(string),
						certifyVEXStatementNode.Props[statement].(string), certifyVEXStatementNode.Props[statusNotes].(string),
						certifyVEXStatementNode.Props[justification].(string), certifyVEXStatementNode.Props[origin].(string),
						certifyVEXStatementNode.Props[collector].(string), certifyVEXStatementNode.Props[knownSince].(time.Time))

					if err != nil {
						return nil, gqlerror.Errorf("generateModelCertifyVEXStatement failed due to error: %w", err)
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

	if queryAll || (querySubjectAll && certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Osv != nil) ||
		(queryVulnAll && certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Artifact != nil) ||
		(certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Artifact != nil &&
			certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Osv != nil) {

		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		// query ghsa
		returnValue := " RETURN a.algorithm, a.digest, certifyVEXStatement, osvID.id"

		// query artifact
		query := "MATCH (a:Artifact)" +
			"-[:subject]-(certifyVEXStatement:CertifyVEXStatement)-[:about]-(osvID:OsvID)<-[:OsvHasID]" +
			"-(rootOsv:Osv)"
		sb.WriteString(query)

		if certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Artifact != nil {
			setArtifactMatchValues(&sb, certifyVEXStatementSpec.Subject.Artifact, false, &firstMatch, queryValues)
		}
		if certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Osv != nil {
			setOSVMatchValues(&sb, certifyVEXStatementSpec.Vulnerability.Osv, &firstMatch, queryValues)
		}
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
					algorithm := result.Record().Values[0].(string)
					digest := result.Record().Values[1].(string)
					artifact := generateModelArtifact(algorithm, digest)

					id := result.Record().Values[7].(string)
					osv := generateModelOsv(id)

					certifyVEXStatementNode := dbtype.Node{}
					if result.Record().Values[1] != nil {
						certifyVEXStatementNode = result.Record().Values[2].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyVEXStatement Node not found in neo4j")
					}

					certifyVEXStatement, err := generateModelCertifyVEXStatement(artifact, osv, certifyVEXStatementNode.Props[status].(string),
						certifyVEXStatementNode.Props[statement].(string), certifyVEXStatementNode.Props[statusNotes].(string),
						certifyVEXStatementNode.Props[justification].(string), certifyVEXStatementNode.Props[origin].(string),
						certifyVEXStatementNode.Props[collector].(string), certifyVEXStatementNode.Props[knownSince].(time.Time))

					if err != nil {
						return nil, gqlerror.Errorf("generateModelCertifyVEXStatement failed due to error: %w", err)
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
		queryValues[knownSince] = certifyVEXStatementSpec.KnownSince.UTC()
	}
	if certifyVEXStatementSpec.Status != nil {
		matchProperties(sb, *firstMatch, "certifyVEXStatement", status, "$"+status)
		*firstMatch = false
		queryValues["status"] = certifyVEXStatementSpec.Status.String()
	}
	if certifyVEXStatementSpec.Statement != nil {
		matchProperties(sb, *firstMatch, "certifyVEXStatement", statement, "$"+statement)
		*firstMatch = false
		queryValues["statement"] = certifyVEXStatementSpec.Statement
	}
	if certifyVEXStatementSpec.StatusNotes != nil {
		matchProperties(sb, *firstMatch, "certifyVEXStatement", statusNotes, "$"+statusNotes)
		*firstMatch = false
		queryValues["statusNotes"] = certifyVEXStatementSpec.StatusNotes
	}
	if certifyVEXStatementSpec.VexJustification != nil {
		matchProperties(sb, *firstMatch, "certifyVEXStatement", justification, "$"+justification)
		*firstMatch = false
		queryValues["justification"] = certifyVEXStatementSpec.VexJustification.String()
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

func generateModelCertifyVEXStatement(subject model.PackageOrArtifact, vuln model.Vulnerability, status, statement, statusNotes, justification, origin, collector string, knownSince time.Time) (*model.CertifyVEXStatement, error) {
	vexStatus, err := convertStatusToEnum(status)
	if err != nil {
		return nil, fmt.Errorf("convertStatusToEnum failed with error: %w", err)
	}

	vexJustification, err := convertJustificationToEnum(justification)
	if err != nil {
		return nil, fmt.Errorf("convertJustificationToEnum failed with error: %w", err)
	}

	certifyVEXStatement := model.CertifyVEXStatement{
		Subject:          subject,
		Vulnerability:    vuln,
		Status:           vexStatus,
		VexJustification: vexJustification,
		Statement:        statement,
		StatusNotes:      statusNotes,
		KnownSince:       knownSince,
		Origin:           origin,
		Collector:        collector,
	}
	return &certifyVEXStatement, nil
}

func convertStatusToEnum(status string) (model.VexStatus, error) {
	if status == model.VexStatusNotAffected.String() {
		return model.VexStatusAffected, nil
	}
	if status == model.VexStatusAffected.String() {
		return model.VexStatusAffected, nil
	}
	if status == model.VexStatusFixed.String() {
		return model.VexStatusFixed, nil
	}
	if status == model.VexStatusUnderInvestigation.String() {
		return model.VexStatusUnderInvestigation, nil
	}
	return model.VexStatusAffected, fmt.Errorf("failed to convert status to enum")
}

func convertJustificationToEnum(justification string) (model.VexJustification, error) {
	if justification == model.VexJustificationNotProvided.String() {
		return model.VexJustificationNotProvided, nil
	}
	if justification == model.VexJustificationComponentNotPresent.String() {
		return model.VexJustificationComponentNotPresent, nil
	}
	if justification == model.VexJustificationVulnerableCodeNotPresent.String() {
		return model.VexJustificationVulnerableCodeNotPresent, nil
	}
	if justification == model.VexJustificationVulnerableCodeNotInExecutePath.String() {
		return model.VexJustificationVulnerableCodeNotInExecutePath, nil
	}
	if justification == model.VexJustificationVulnerableCodeCannotBeControlledByAdversary.String() {
		return model.VexJustificationVulnerableCodeCannotBeControlledByAdversary, nil
	}
	if justification == model.VexJustificationInlineMitigationsAlreadyExist.String() {
		return model.VexJustificationInlineMitigationsAlreadyExist, nil
	}
	if justification == model.VexJustificationNotProvided.String() {
		return model.VexJustificationNotProvided, nil
	}
	return model.VexJustificationNotProvided, fmt.Errorf("failed to convert justification to enum")

}

func (c *neo4jClient) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInput, vexStatement model.VexStatementInputSpec) (*model.CertifyVEXStatement, error) {

	err := helper.ValidatePackageOrArtifactInput(&subject, "IngestVEXStatement")
	if err != nil {
		return nil, err
	}
	err = helper.ValidateVulnerabilityIngestionInput(vulnerability, "IngestVEXStatement", false)
	if err != nil {
		return nil, err
	}
	panic(fmt.Errorf("not implemented: IngestVEXStatement - IngestVEXStatement"))
}
