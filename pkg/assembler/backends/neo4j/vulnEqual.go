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

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// TODO (pxp928): fix for new vulnerability
func (c *neo4jClient) VulnEqual(ctx context.Context, vulnEqualSpec *model.VulnEqualSpec) ([]*model.VulnEqual, error) {

	// // TODO: Fix validation
	// queryAll := true
	// // queryAll, err := helper.ValidateCveOrGhsaQueryInput(isVulnerabilitySpec.Vulnerability)
	// // if err != nil {
	// // 	return nil, err
	// // }

	// session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	// defer session.Close()

	// aggregateIsVulnerability := []*model.IsVulnerability{}

	// if queryAll || isVulnerabilitySpec.Vulnerability != nil && isVulnerabilitySpec.Vulnerability.Cve != nil {
	// 	var sb strings.Builder
	// 	var firstMatch bool = true
	// 	queryValues := map[string]any{}

	// 	// query CVE
	// 	query := "MATCH (root:Osv)-[:OsvHasID]->(osvID:OsvID)" +
	// 		"-[:subject]-(isVulnerability:IsVulnerability)-[:alias]-(cveID:CveID)<-[:CveHasID]" +
	// 		"-(cveYear:CveYear)<-[:CveIsYear]-(rootCve:Cve)"
	// 	sb.WriteString(query)

	// 	returnValue := " RETURN osvID.id, isVulnerability, cveYear.year, cveID.id"

	// 	setOSVMatchValues(&sb, isVulnerabilitySpec.Osv, &firstMatch, queryValues)
	// 	if isVulnerabilitySpec.Vulnerability != nil && isVulnerabilitySpec.Vulnerability.Cve != nil {
	// 		setCveMatchValues(&sb, isVulnerabilitySpec.Vulnerability.Cve, &firstMatch, queryValues)
	// 	}
	// 	setIsVulnerabilityValues(&sb, isVulnerabilitySpec, &firstMatch, queryValues)
	// 	sb.WriteString(returnValue)

	// 	result, err := session.ReadTransaction(
	// 		func(tx neo4j.Transaction) (interface{}, error) {

	// 			result, err := tx.Run(sb.String(), queryValues)
	// 			if err != nil {
	// 				return nil, err
	// 			}

	// 			collectedIsVulnerability := []*model.IsVulnerability{}

	// 			for result.Next() {
	// 				id := result.Record().Values[0].(string)
	// 				osv := generateModelOsv(id)

	// 				idStr := result.Record().Values[3].(string)
	// 				yearStr := result.Record().Values[3].(int)
	// 				cve := generateModelCve(yearStr, idStr)

	// 				isVulnerabilityNode := dbtype.Node{}
	// 				if result.Record().Values[1] != nil {
	// 					isVulnerabilityNode = result.Record().Values[6].(dbtype.Node)
	// 				} else {
	// 					return nil, gqlerror.Errorf("isVulnerability Node not found in neo4j")
	// 				}

	// 				isVulnerability := generateModelIsVulnerability(osv, cve, isVulnerabilityNode.Props[justification].(string),
	// 					isVulnerabilityNode.Props[origin].(string), isVulnerabilityNode.Props[collector].(string))

	// 				collectedIsVulnerability = append(collectedIsVulnerability, isVulnerability)
	// 			}
	// 			if err = result.Err(); err != nil {
	// 				return nil, err
	// 			}

	// 			return collectedIsVulnerability, nil
	// 		})
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	aggregateIsVulnerability = append(aggregateIsVulnerability, result.([]*model.IsVulnerability)...)
	// }

	// if queryAll || isVulnerabilitySpec.Vulnerability != nil && isVulnerabilitySpec.Vulnerability.Ghsa != nil {
	// 	var sb strings.Builder
	// 	var firstMatch bool = true
	// 	queryValues := map[string]any{}

	// 	// query GHSA
	// 	query := "MATCH (root:Osv)-[:OsvHasID]->(osvID:OsvID)" +
	// 		"-[:subject]-(isVulnerability:IsVulnerability)-[:alias]-(ghsaID:GhsaID)<-[:GhsaHasID]" +
	// 		"-(rootGhsa:Ghsa)"
	// 	sb.WriteString(query)

	// 	returnValue := " RETURN osvID.id, isVulnerability, ghsaID.id"

	// 	setOSVMatchValues(&sb, isVulnerabilitySpec.Osv, &firstMatch, queryValues)
	// 	if isVulnerabilitySpec.Vulnerability != nil && isVulnerabilitySpec.Vulnerability.Ghsa != nil {
	// 		setGhsaMatchValues(&sb, isVulnerabilitySpec.Vulnerability.Ghsa, &firstMatch, queryValues)
	// 	}
	// 	setIsVulnerabilityValues(&sb, isVulnerabilitySpec, &firstMatch, queryValues)
	// 	sb.WriteString(returnValue)

	// 	result, err := session.ReadTransaction(
	// 		func(tx neo4j.Transaction) (interface{}, error) {

	// 			result, err := tx.Run(sb.String(), queryValues)
	// 			if err != nil {
	// 				return nil, err
	// 			}

	// 			collectedIsVulnerability := []*model.IsVulnerability{}

	// 			for result.Next() {
	// 				id := result.Record().Values[0].(string)
	// 				osv := generateModelOsv(id)

	// 				idStr := result.Record().Values[2].(string)
	// 				ghsa := generateModelGhsa(idStr)

	// 				isVulnerabilityNode := dbtype.Node{}
	// 				if result.Record().Values[6] != nil {
	// 					isVulnerabilityNode = result.Record().Values[1].(dbtype.Node)
	// 				} else {
	// 					return nil, gqlerror.Errorf("isVulnerability Node not found in neo4j")
	// 				}

	// 				isVulnerability := generateModelIsVulnerability(osv, ghsa, isVulnerabilityNode.Props[justification].(string),
	// 					isVulnerabilityNode.Props[origin].(string), isVulnerabilityNode.Props[collector].(string))

	// 				collectedIsVulnerability = append(collectedIsVulnerability, isVulnerability)
	// 			}
	// 			if err = result.Err(); err != nil {
	// 				return nil, err
	// 			}

	// 			return collectedIsVulnerability, nil
	// 		})
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	aggregateIsVulnerability = append(aggregateIsVulnerability, result.([]*model.IsVulnerability)...)
	// }
	// return aggregateIsVulnerability, nil
	return []*model.VulnEqual{}, fmt.Errorf("not implemented - VulnEqual")
}

// func setIsVulnerabilityValues(sb *strings.Builder, isVulnerabilitySpec *model.IsVulnerabilitySpec, firstMatch *bool, queryValues map[string]any) {
// 	if isVulnerabilitySpec.Justification != nil {
// 		matchProperties(sb, *firstMatch, "isVulnerability", justification, "$"+justification)
// 		*firstMatch = false
// 		queryValues["justification"] = isVulnerabilitySpec.Justification
// 	}
// 	if isVulnerabilitySpec.Origin != nil {
// 		matchProperties(sb, *firstMatch, "isVulnerability", origin, "$"+origin)
// 		*firstMatch = false
// 		queryValues[origin] = isVulnerabilitySpec.Origin
// 	}
// 	if isVulnerabilitySpec.Collector != nil {
// 		matchProperties(sb, *firstMatch, "isVulnerability", collector, "$"+collector)
// 		*firstMatch = false
// 		queryValues[collector] = isVulnerabilitySpec.Collector
// 	}
// }

// func generateModelIsVulnerability(osv *model.Osv, vuln model.CveOrGhsa, justification, origin, collector string) *model.IsVulnerability {
// 	isVulnerability := model.IsVulnerability{
// 		Osv:           osv,
// 		Vulnerability: vuln,
// 		Justification: justification,
// 		Origin:        origin,
// 		Collector:     collector,
// 	}
// 	return &isVulnerability
// }

func (c *neo4jClient) IngestVulnEqual(ctx context.Context, vulnerability model.VulnerabilityInputSpec, otherVulnerability model.VulnerabilityInputSpec, vulnEqual model.VulnEqualInputSpec) (*model.VulnEqual, error) {
	return nil, fmt.Errorf("not implemented - IngestVulnEqual")
}

func (c *neo4jClient) IngestVulnEquals(ctx context.Context, vulnerabilities []*model.VulnerabilityInputSpec, otherVulnerabilities []*model.VulnerabilityInputSpec, vulnEquals []*model.VulnEqualInputSpec) ([]string, error) {
	return nil, fmt.Errorf("not implemented - IngestVulnEquals")
}
