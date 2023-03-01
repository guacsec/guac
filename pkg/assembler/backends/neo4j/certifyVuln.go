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
	dbUri          string = "dbUri"
	dbVersion      string = "dbVersion"
	scannerUri     string = "scannerUri"
	scannerVersion string = "scannerVersion"
)

func (c *neo4jClient) CertifyVuln(ctx context.Context, certifyVulnSpec *model.CertifyVulnSpec) ([]*model.CertifyVuln, error) {
	err := checkCertifyVulnInputs(certifyVulnSpec)
	if err != nil {
		return nil, err
	}

	queryAll := false
	if certifyVulnSpec.Osv == nil && certifyVulnSpec.Cve == nil && certifyVulnSpec.Ghsa == nil {
		queryAll = true
	}
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	aggregateCertifyVuln := []*model.CertifyVuln{}

	if queryAll || certifyVulnSpec.Cve != nil {

		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		// query CVE
		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, certifyVuln, cveYear.year, cveID.id"

		// query with pkgVersion
		query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
			"-[:subject]-(certifyVuln:CertifyVuln)-[:is_vuln_to]-(cveID:CveID)<-[:CveHasID]" +
			"-(cveYear:CveYear)<-[:CveIsYear]-(rootCve:Cve)"
		sb.WriteString(query)

		setPkgMatchValues(&sb, certifyVulnSpec.Package, false, &firstMatch, queryValues)
		setCveMatchValues(&sb, certifyVulnSpec.Cve, &firstMatch, queryValues)
		setCertifyVulnValues(&sb, certifyVulnSpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

		if certifyVulnSpec.Package == nil || certifyVulnSpec.Package != nil && certifyVulnSpec.Package.Version == nil &&
			certifyVulnSpec.Package.Subpath == nil && len(certifyVulnSpec.Package.Qualifiers) == 0 &&
			!*certifyVulnSpec.Package.MatchOnlyEmptyQualifiers {

			sb.WriteString("\nUNION")
			// query without pkgVersion
			query = "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
				"-[:PkgHasName]->(name:PkgName)" +
				"-[:subject]-(certifyVuln:CertifyVuln)-[:about]-(cveID:CveID)<-[:CveHasID]" +
				"-(cveYear:CveYear)<-[:CveIsYear]-(rootCve:Cve)" +
				"\nWITH *, null AS version"
			sb.WriteString(query)

			firstMatch = true
			setPkgMatchValues(&sb, certifyVulnSpec.Package, false, &firstMatch, queryValues)
			setCveMatchValues(&sb, certifyVulnSpec.Cve, &firstMatch, queryValues)
			setCertifyVulnValues(&sb, certifyVulnSpec, &firstMatch, queryValues)
			sb.WriteString(returnValue)
		}

		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedCertifyVuln := []*model.CertifyVuln{}

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

					certifyVulnNode := dbtype.Node{}
					if result.Record().Values[1] != nil {
						certifyVulnNode = result.Record().Values[6].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyVuln Node not found in neo4j")
					}

					certifyVuln := &model.CertifyVuln{
						Package:        &pkg,
						Vulnerability:  cve,
						TimeScanned:    certifyVulnNode.Props[timeScanned].(string),
						DbURI:          certifyVulnNode.Props[dbUri].(string),
						DbVersion:      certifyVulnNode.Props[dbVersion].(string),
						ScannerURI:     certifyVulnNode.Props[scannerUri].(string),
						ScannerVersion: certifyVulnNode.Props[scannerVersion].(string),
						Origin:         certifyVulnNode.Props[origin].(string),
						Collector:      certifyVulnNode.Props[collector].(string),
					}
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

	if queryAll || certifyVulnSpec.Ghsa != nil {

		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		// query ghsa
		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, certifyVuln, ghsaID.id"

		// query with pkgVersion
		query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
			"-[:subject]-(certifyVuln:CertifyVuln)-[:about]-(ghsaID:GhsaID)<-[:GhsaHasID]" +
			"-(rootGhsa:Ghsa)"
		sb.WriteString(query)

		setPkgMatchValues(&sb, certifyVulnSpec.Package, false, &firstMatch, queryValues)
		setGhsaMatchValues(&sb, certifyVulnSpec.Ghsa, &firstMatch, queryValues)
		setCertifyVulnValues(&sb, certifyVulnSpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

		if certifyVulnSpec.Package == nil || certifyVulnSpec.Package != nil && certifyVulnSpec.Package.Version == nil &&
			certifyVulnSpec.Package.Subpath == nil && len(certifyVulnSpec.Package.Qualifiers) == 0 &&
			!*certifyVulnSpec.Package.MatchOnlyEmptyQualifiers {

			sb.WriteString("\nUNION")
			// query without pkgVersion
			query = "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
				"-[:PkgHasName]->(name:PkgName)" +
				"-[:subject]-(certifyVuln:CertifyVuln)-[:about]-(ghsaID:GhsaID)<-[:GhsaHasID]" +
				"-(rootGhsa:Ghsa)" +
				"\nWITH *, null AS version"
			sb.WriteString(query)

			firstMatch = true
			setPkgMatchValues(&sb, certifyVulnSpec.Package, false, &firstMatch, queryValues)
			setGhsaMatchValues(&sb, certifyVulnSpec.Ghsa, &firstMatch, queryValues)
			setCertifyVulnValues(&sb, certifyVulnSpec, &firstMatch, queryValues)
			sb.WriteString(returnValue)
		}

		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedCertifyVuln := []*model.CertifyVuln{}

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

					certifyVulnNode := dbtype.Node{}
					if result.Record().Values[1] != nil {
						certifyVulnNode = result.Record().Values[6].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyVuln Node not found in neo4j")
					}

					certifyVuln := &model.CertifyVuln{
						Package:        &pkg,
						Vulnerability:  ghsa,
						TimeScanned:    certifyVulnNode.Props[timeScanned].(string),
						DbURI:          certifyVulnNode.Props[dbUri].(string),
						DbVersion:      certifyVulnNode.Props[dbVersion].(string),
						ScannerURI:     certifyVulnNode.Props[scannerUri].(string),
						ScannerVersion: certifyVulnNode.Props[scannerVersion].(string),
						Origin:         certifyVulnNode.Props[origin].(string),
						Collector:      certifyVulnNode.Props[collector].(string),
					}
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

	if queryAll || certifyVulnSpec.Osv != nil {

		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		// query ghsa
		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, certifyVuln, osvID.id"

		// query with pkgVersion
		//(root:Osv)-[:OsvHasID]->(osvID:OsvID)
		query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
			"-[:subject]-(certifyVuln:CertifyVuln)-[:about]-(osvID:OsvID)<-[:OsvHasID]" +
			"-(rootOsv:Osv)"
		sb.WriteString(query)

		setPkgMatchValues(&sb, certifyVulnSpec.Package, false, &firstMatch, queryValues)
		setOSVMatchValues(&sb, certifyVulnSpec.Osv, &firstMatch, queryValues)
		setCertifyVulnValues(&sb, certifyVulnSpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

		if certifyVulnSpec.Package == nil || certifyVulnSpec.Package != nil && certifyVulnSpec.Package.Version == nil &&
			certifyVulnSpec.Package.Subpath == nil && len(certifyVulnSpec.Package.Qualifiers) == 0 &&
			!*certifyVulnSpec.Package.MatchOnlyEmptyQualifiers {

			sb.WriteString("\nUNION")
			// query without pkgVersion
			query = "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
				"-[:PkgHasName]->(name:PkgName)" +
				"-[:subject]-(certifyVuln:CertifyVuln)-[:about]-(osvID:OsvID)<-[:OsvHasID]" +
				"-(rootOsv:Osv)" +
				"\nWITH *, null AS version"
			sb.WriteString(query)

			firstMatch = true
			setPkgMatchValues(&sb, certifyVulnSpec.Package, false, &firstMatch, queryValues)
			setOSVMatchValues(&sb, certifyVulnSpec.Osv, &firstMatch, queryValues)
			setCertifyVulnValues(&sb, certifyVulnSpec, &firstMatch, queryValues)
			sb.WriteString(returnValue)
		}

		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedCertifyVuln := []*model.CertifyVuln{}

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

					osvId := &model.OSVId{
						ID: result.Record().Values[7].(string),
					}
					osv := &model.Osv{
						OsvID: []*model.OSVId{osvId},
					}

					certifyVulnNode := dbtype.Node{}
					if result.Record().Values[1] != nil {
						certifyVulnNode = result.Record().Values[6].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyVuln Node not found in neo4j")
					}

					certifyVuln := &model.CertifyVuln{
						Package:        &pkg,
						Vulnerability:  osv,
						TimeScanned:    certifyVulnNode.Props[timeScanned].(string),
						DbURI:          certifyVulnNode.Props[dbUri].(string),
						DbVersion:      certifyVulnNode.Props[dbVersion].(string),
						ScannerURI:     certifyVulnNode.Props[scannerUri].(string),
						ScannerVersion: certifyVulnNode.Props[scannerVersion].(string),
						Origin:         certifyVulnNode.Props[origin].(string),
						Collector:      certifyVulnNode.Props[collector].(string),
					}
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

// TODO (pxp928): combine with testing backend in shared utility
func checkCertifyVulnInputs(certifyVulnSpec *model.CertifyVulnSpec) error {
	invalidSubject := false
	if certifyVulnSpec.Osv != nil && certifyVulnSpec.Cve != nil && certifyVulnSpec.Ghsa != nil {
		invalidSubject = true
	}
	if certifyVulnSpec.Osv != nil && certifyVulnSpec.Cve != nil {
		invalidSubject = true
	}
	if certifyVulnSpec.Osv != nil && certifyVulnSpec.Ghsa != nil {
		invalidSubject = true
	}
	if certifyVulnSpec.Cve != nil && certifyVulnSpec.Ghsa != nil {
		invalidSubject = true
	}
	if invalidSubject {
		return gqlerror.Errorf("cannot specify more than one subject for CertifyVuln query")
	}
	return nil
}

func setCertifyVulnValues(sb *strings.Builder, certifyVulnSpec *model.CertifyVulnSpec, firstMatch *bool, queryValues map[string]any) {
	if certifyVulnSpec.TimeScanned != nil {
		matchProperties(sb, *firstMatch, "certifyVuln", timeScanned, "$"+timeScanned)
		*firstMatch = false
		queryValues[timeScanned] = certifyVulnSpec.TimeScanned
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
