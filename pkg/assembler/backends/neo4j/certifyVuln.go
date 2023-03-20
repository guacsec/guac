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
	"time"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j/dbtype"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

const (
	dbUri          string = "dbUri"
	dbVersion      string = "dbVersion"
	scannerUri     string = "scannerUri"
	scannerVersion string = "scannerVersion"
)

// Query CertifyVuln

func (c *neo4jClient) CertifyVuln(ctx context.Context, certifyVulnSpec *model.CertifyVulnSpec) ([]*model.CertifyVuln, error) {

	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	queryAll, err := helper.ValidateOsvCveOrGhsaQueryInput(certifyVulnSpec.Vulnerability)
	if err != nil {
		return nil, err
	}

	aggregateCertifyVuln := []*model.CertifyVuln{}

	if queryAll || (certifyVulnSpec.Vulnerability != nil && certifyVulnSpec.Vulnerability.Cve != nil) {

		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		// query CVE
		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, certifyVuln, cveYear.year, cveID.id"

		// query with pkgVersion
		query := "MATCH (rootPkg:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
			"-[:subject]-(certifyVuln:CertifyVuln)-[:is_vuln_to]-(cveID:CveID)<-[:CveHasID]" +
			"-(cveYear:CveYear)<-[:CveIsYear]-(rootCve:Cve)"
		sb.WriteString(query)

		setPkgMatchValues(&sb, certifyVulnSpec.Package, false, &firstMatch, queryValues)
		if certifyVulnSpec.Vulnerability != nil && certifyVulnSpec.Vulnerability.Cve != nil {
			setCveMatchValues(&sb, certifyVulnSpec.Vulnerability.Cve, &firstMatch, queryValues)
		}
		setCertifyVulnValues(&sb, certifyVulnSpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedCertifyVuln := []*model.CertifyVuln{}

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

					certifyVulnNode := dbtype.Node{}
					if result.Record().Values[1] != nil {
						certifyVulnNode = result.Record().Values[6].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyVuln Node not found in neo4j")
					}

					certifyVuln := generateModelCertifyVuln(pkg, cve, certifyVulnNode.Props[timeScanned].(time.Time), certifyVulnNode.Props[dbUri].(string),
						certifyVulnNode.Props[dbVersion].(string), certifyVulnNode.Props[scannerUri].(string), certifyVulnNode.Props[scannerVersion].(string),
						certifyVulnNode.Props[origin].(string), certifyVulnNode.Props[collector].(string))

					collectedCertifyVuln = append(collectedCertifyVuln, certifyVuln)
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				return collectedCertifyVuln, nil
			})
		if err != nil {
			return nil, err
		}
		aggregateCertifyVuln = append(aggregateCertifyVuln, result.([]*model.CertifyVuln)...)
	}

	if queryAll || (certifyVulnSpec.Vulnerability != nil && certifyVulnSpec.Vulnerability.Ghsa != nil) {

		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		// query ghsa
		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, certifyVuln, ghsaID.id"

		// query with pkgVersion
		query := "MATCH (rootPkg:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
			"-[:subject]-(certifyVuln:CertifyVuln)-[:is_vuln_to]-(ghsaID:GhsaID)<-[:GhsaHasID]" +
			"-(rootGhsa:Ghsa)"
		sb.WriteString(query)

		setPkgMatchValues(&sb, certifyVulnSpec.Package, false, &firstMatch, queryValues)
		if certifyVulnSpec.Vulnerability != nil && certifyVulnSpec.Vulnerability.Ghsa != nil {
			setGhsaMatchValues(&sb, certifyVulnSpec.Vulnerability.Ghsa, &firstMatch, queryValues)
		}
		setCertifyVulnValues(&sb, certifyVulnSpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedCertifyVuln := []*model.CertifyVuln{}

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

					certifyVulnNode := dbtype.Node{}
					if result.Record().Values[1] != nil {
						certifyVulnNode = result.Record().Values[6].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyVuln Node not found in neo4j")
					}

					certifyVuln := generateModelCertifyVuln(pkg, ghsa, certifyVulnNode.Props[timeScanned].(time.Time), certifyVulnNode.Props[dbUri].(string),
						certifyVulnNode.Props[dbVersion].(string), certifyVulnNode.Props[scannerUri].(string), certifyVulnNode.Props[scannerVersion].(string),
						certifyVulnNode.Props[origin].(string), certifyVulnNode.Props[collector].(string))

					collectedCertifyVuln = append(collectedCertifyVuln, certifyVuln)
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				return collectedCertifyVuln, nil
			})
		if err != nil {
			return nil, err
		}
		aggregateCertifyVuln = append(aggregateCertifyVuln, result.([]*model.CertifyVuln)...)
	}

	if queryAll || (certifyVulnSpec.Vulnerability != nil && certifyVulnSpec.Vulnerability.Osv != nil) {

		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		// query ghsa
		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, certifyVuln, osvID.id"

		// query with pkgVersion
		//(root:Osv)-[:OsvHasID]->(osvID:OsvID)
		query := "MATCH (rootPkg:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
			"-[:subject]-(certifyVuln:CertifyVuln)-[:is_vuln_to]-(osvID:OsvID)<-[:OsvHasID]" +
			"-(rootOsv:Osv)"
		sb.WriteString(query)

		setPkgMatchValues(&sb, certifyVulnSpec.Package, false, &firstMatch, queryValues)
		if certifyVulnSpec.Vulnerability != nil && certifyVulnSpec.Vulnerability.Osv != nil {
			setOSVMatchValues(&sb, certifyVulnSpec.Vulnerability.Osv, &firstMatch, queryValues)
		}
		setCertifyVulnValues(&sb, certifyVulnSpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedCertifyVuln := []*model.CertifyVuln{}

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

					certifyVulnNode := dbtype.Node{}
					if result.Record().Values[1] != nil {
						certifyVulnNode = result.Record().Values[6].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyVuln Node not found in neo4j")
					}

					certifyVuln := generateModelCertifyVuln(pkg, osv, certifyVulnNode.Props[timeScanned].(time.Time), certifyVulnNode.Props[dbUri].(string),
						certifyVulnNode.Props[dbVersion].(string), certifyVulnNode.Props[scannerUri].(string), certifyVulnNode.Props[scannerVersion].(string),
						certifyVulnNode.Props[origin].(string), certifyVulnNode.Props[collector].(string))

					collectedCertifyVuln = append(collectedCertifyVuln, certifyVuln)
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				return collectedCertifyVuln, nil
			})
		if err != nil {
			return nil, err
		}
		aggregateCertifyVuln = append(aggregateCertifyVuln, result.([]*model.CertifyVuln)...)
	}
	return aggregateCertifyVuln, nil
}

func setCertifyVulnValues(sb *strings.Builder, certifyVulnSpec *model.CertifyVulnSpec, firstMatch *bool, queryValues map[string]any) {
	if certifyVulnSpec.TimeScanned != nil {
		matchProperties(sb, *firstMatch, "certifyVuln", timeScanned, "$"+timeScanned)
		*firstMatch = false
		queryValues[timeScanned] = certifyVulnSpec.TimeScanned.UTC()
	}
	if certifyVulnSpec.DbURI != nil {
		matchProperties(sb, *firstMatch, "certifyVuln", dbUri, "$"+dbUri)
		*firstMatch = false
		queryValues[dbUri] = certifyVulnSpec.DbURI
	}
	if certifyVulnSpec.DbVersion != nil {
		matchProperties(sb, *firstMatch, "certifyVuln", dbVersion, "$"+dbVersion)
		*firstMatch = false
		queryValues[dbVersion] = certifyVulnSpec.DbVersion
	}
	if certifyVulnSpec.ScannerURI != nil {
		matchProperties(sb, *firstMatch, "certifyVuln", scannerUri, "$"+scannerUri)
		*firstMatch = false
		queryValues[scannerUri] = certifyVulnSpec.ScannerURI
	}
	if certifyVulnSpec.ScannerVersion != nil {
		matchProperties(sb, *firstMatch, "certifyVuln", scannerVersion, "$"+scannerVersion)
		*firstMatch = false
		queryValues[scannerVersion] = certifyVulnSpec.ScannerVersion
	}
	if certifyVulnSpec.Origin != nil {
		matchProperties(sb, *firstMatch, "certifyVuln", origin, "$"+origin)
		*firstMatch = false
		queryValues[origin] = certifyVulnSpec.Origin
	}
	if certifyVulnSpec.Collector != nil {
		matchProperties(sb, *firstMatch, "certifyVuln", collector, "$"+collector)
		*firstMatch = false
		queryValues[collector] = certifyVulnSpec.Collector
	}
}

func generateModelCertifyVuln(pkg *model.Package, vuln model.OsvCveOrGhsa, timeScanned time.Time, dbUri, dbVersion, scannerUri,
	scannerVersion, origin, collector string) *model.CertifyVuln {

	metadata := &model.VulnerabilityMetaData{
		TimeScanned:    timeScanned,
		DbURI:          dbUri,
		DbVersion:      dbVersion,
		ScannerURI:     scannerUri,
		ScannerVersion: scannerVersion,
		Origin:         origin,
		Collector:      collector,
	}

	certifyVuln := model.CertifyVuln{
		Package:       pkg,
		Vulnerability: vuln,
		Metadata:      metadata,
	}
	return &certifyVuln
}

//  Ingest Vulnerability

func (c *neo4jClient) IngestVulnerability(ctx context.Context, pkg model.PkgInputSpec, vulnerability model.OsvCveOrGhsaInput, certifyVuln model.VulnerabilityMetaDataInput) (*model.CertifyVuln, error) {

	err := helper.ValidateOsvCveOrGhsaIngestionInput(vulnerability)
	if err != nil {
		return nil, err
	}

	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close()

	var sb strings.Builder
	var firstMatch bool = true
	queryValues := map[string]any{}

	queryValues[timeScanned] = certifyVuln.TimeScanned.UTC()
	queryValues[dbUri] = certifyVuln.DbURI
	queryValues[dbVersion] = certifyVuln.DbVersion
	queryValues[scannerUri] = certifyVuln.ScannerURI
	queryValues[scannerVersion] = certifyVuln.ScannerVersion
	queryValues[origin] = certifyVuln.Origin
	queryValues[collector] = certifyVuln.Collector

	// TODO: use generics here between PkgInputSpec and PkgSpecs?
	selectedPkgSpec := helper.ConvertPkgInputSpecToPkgSpec(&pkg)

	if vulnerability.Osv != nil {
		selectedOsvSepc := helper.ConvertOsvInputSpecToOsvSpec(vulnerability.Osv)

		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, certifyVuln, osvID.id"

		query := "MATCH (rootPkg:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)"

		sb.WriteString(query)
		setPkgMatchValues(&sb, selectedPkgSpec, false, &firstMatch, queryValues)

		query = "\nMATCH (rootOsv:Osv)-[:OsvHasID]->(osvID:OsvID)"
		sb.WriteString(query)
		firstMatch = true
		setOSVMatchValues(&sb, selectedOsvSepc, &firstMatch, queryValues)

		merge := "\nMERGE (version)<-[:subject]-(certifyVuln:CertifyVuln{timeScanned:$timeScanned,dbUri:$dbUri," +
			"dbVersion:$dbVersion,scannerUri:$scannerUri,scannerVersion:$scannerVersion,origin:$origin,collector:$collector})" +
			"-[:is_vuln_to]->(osvID)"
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

				id := record.Values[7].(string)
				osv := generateModelOsv(id)

				certifyVulnNode := dbtype.Node{}
				if record.Values[1] != nil {
					certifyVulnNode = record.Values[6].(dbtype.Node)
				} else {
					return nil, gqlerror.Errorf("certifyVuln Node not found in neo4j")
				}

				certifyVuln := generateModelCertifyVuln(pkg, osv, certifyVulnNode.Props[timeScanned].(time.Time), certifyVulnNode.Props[dbUri].(string),
					certifyVulnNode.Props[dbVersion].(string), certifyVulnNode.Props[scannerUri].(string), certifyVulnNode.Props[scannerVersion].(string),
					certifyVulnNode.Props[origin].(string), certifyVulnNode.Props[collector].(string))

				return certifyVuln, nil
			})
		if err != nil {
			return nil, err
		}

		return result.(*model.CertifyVuln), nil
	} else if vulnerability.Cve != nil {
		selectedCveSepc := helper.ConvertCveInputSpecToCveSpec(vulnerability.Cve)

		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, certifyVuln, cveYear.year, cveID.id"

		query := "MATCH (rootPkg:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)"

		sb.WriteString(query)
		setPkgMatchValues(&sb, selectedPkgSpec, false, &firstMatch, queryValues)

		query = "\nMATCH (rootCve:Cve)-[:CveIsYear]->(cveYear:CveYear)-[:CveHasID]->(cveID:CveID)"
		sb.WriteString(query)
		firstMatch = true
		setCveMatchValues(&sb, selectedCveSepc, &firstMatch, queryValues)

		merge := "\nMERGE (version)<-[:subject]-(certifyVuln:CertifyVuln{timeScanned:$timeScanned,dbUri:$dbUri," +
			"dbVersion:$dbVersion,scannerUri:$scannerUri,scannerVersion:$scannerVersion,origin:$origin,collector:$collector})" +
			"-[:is_vuln_to]->(cveID)"
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

				idStr := record.Values[8].(string)
				yearStr := record.Values[7].(int)
				cve := generateModelCve(yearStr, idStr)

				certifyVulnNode := dbtype.Node{}
				if record.Values[1] != nil {
					certifyVulnNode = record.Values[6].(dbtype.Node)
				} else {
					return nil, gqlerror.Errorf("certifyVuln Node not found in neo4j")
				}

				certifyVuln := generateModelCertifyVuln(pkg, cve, certifyVulnNode.Props[timeScanned].(time.Time), certifyVulnNode.Props[dbUri].(string),
					certifyVulnNode.Props[dbVersion].(string), certifyVulnNode.Props[scannerUri].(string), certifyVulnNode.Props[scannerVersion].(string),
					certifyVulnNode.Props[origin].(string), certifyVulnNode.Props[collector].(string))

				return certifyVuln, nil
			})
		if err != nil {
			return nil, err
		}

		return result.(*model.CertifyVuln), nil
	} else if vulnerability.Ghsa != nil {
		selectedGhsaSepc := helper.ConvertGhsaInputSpecToGhsaSpec(vulnerability.Ghsa)

		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, certifyVuln, ghsaID.id"

		query := "MATCH (rootPkg:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)"

		sb.WriteString(query)
		setPkgMatchValues(&sb, selectedPkgSpec, false, &firstMatch, queryValues)

		query = "\nMATCH (rootGhsa:Ghsa)-[:GhsaHasID]->(ghsaID:GhsaID)"
		sb.WriteString(query)
		firstMatch = true
		setGhsaMatchValues(&sb, selectedGhsaSepc, &firstMatch, queryValues)

		merge := "\nMERGE (version)<-[:subject]-(certifyVuln:CertifyVuln{timeScanned:$timeScanned,dbUri:$dbUri," +
			"dbVersion:$dbVersion,scannerUri:$scannerUri,scannerVersion:$scannerVersion,origin:$origin,collector:$collector})" +
			"-[:is_vuln_to]->(ghsaID)"
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

				idStr := record.Values[7].(string)
				ghsa := generateModelGhsa(idStr)

				certifyVulnNode := dbtype.Node{}
				if record.Values[1] != nil {
					certifyVulnNode = record.Values[6].(dbtype.Node)
				} else {
					return nil, gqlerror.Errorf("certifyVuln Node not found in neo4j")
				}

				certifyVuln := generateModelCertifyVuln(pkg, ghsa, certifyVulnNode.Props[timeScanned].(time.Time), certifyVulnNode.Props[dbUri].(string),
					certifyVulnNode.Props[dbVersion].(string), certifyVulnNode.Props[scannerUri].(string), certifyVulnNode.Props[scannerVersion].(string),
					certifyVulnNode.Props[origin].(string), certifyVulnNode.Props[collector].(string))

				return certifyVuln, nil
			})
		if err != nil {
			return nil, err
		}

		return result.(*model.CertifyVuln), nil
	} else {
		return nil, gqlerror.Errorf("package or source not specified for IngestOccurrence")
	}
}
