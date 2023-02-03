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
	"github.com/guacsec/guac/pkg/assembler"
)

func registerAllCVE(client *neo4jClient) {
	topLevelCve := createTopLevelCve(client)
	client.registerCVE(topLevelCve, "1970", "CVE-2019-13110")
	client.registerCVE(topLevelCve, "2001", "CVE-2014-8139")
	client.registerCVE(topLevelCve, "1970", "CVE-2014-8140")
	client.registerCVE(topLevelCve, "2023", "CVE-2022-26499")
	client.registerCVE(topLevelCve, "1970", "CVE-2014-8140")
}

func createTopLevelCve(client *neo4jClient) cveNode {
	collectedCve := cveNode{}
	assemblerinput := assembler.AssemblerInput{
		Nodes: []assembler.GuacNode{collectedCve},
	}
	assembler.StoreGraph(assemblerinput, client.driver)
	return collectedCve
}

func (c *neo4jClient) registerCVE(topLevelCve cveNode, year, id string) {
	collectedYear := cveYear{year: year}
	collecteCveId := cveID{id: id}

	cveToYearEdge := cveToYear{topLevelCve, collectedYear}
	cveYearToIDEdge := cveYearToCveID{collectedYear, collecteCveId}
	assemblerinput := assembler.AssemblerInput{
		Nodes: []assembler.GuacNode{collectedYear, collecteCveId},
		Edges: []assembler.GuacEdge{cveToYearEdge, cveYearToIDEdge},
	}
	assembler.StoreGraph(assemblerinput, c.driver)
}

// cveNode represents the top level CVE->Year->CVEID
type cveNode struct {
}

func (cn cveNode) Type() string {
	return "Cve"
}

func (cn cveNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["cve"] = "cve"
	return properties
}

func (cn cveNode) PropertyNames() []string {
	fields := []string{"cve"}
	return fields
}

func (cn cveNode) IdentifiablePropertyNames() []string {
	return []string{"cve"}
}

type cveYear struct {
	year string
}

func (cy cveYear) Type() string {
	return "CveYear"
}

func (cy cveYear) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["year"] = cy.year
	return properties
}

func (cy cveYear) PropertyNames() []string {
	fields := []string{"year"}
	return fields
}

func (cy cveYear) IdentifiablePropertyNames() []string {
	return []string{"year"}
}

type cveID struct {
	id string
}

func (ci cveID) Type() string {
	return "CveID"
}

func (ci cveID) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["id"] = ci.id
	return properties
}

func (ci cveID) PropertyNames() []string {
	fields := []string{"id"}
	return fields
}

func (ci cveID) IdentifiablePropertyNames() []string {
	return []string{"id"}
}

type cveToYear struct {
	cve  cveNode
	year cveYear
}

func (e cveToYear) Type() string {
	return "CveIsYear"
}

func (e cveToYear) Nodes() (v, u assembler.GuacNode) {
	return e.cve, e.year
}

func (e cveToYear) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e cveToYear) PropertyNames() []string {
	return []string{}
}

func (e cveToYear) IdentifiablePropertyNames() []string {
	return []string{}
}

type cveYearToCveID struct {
	year  cveYear
	cveID cveID
}

func (e cveYearToCveID) Type() string {
	return "CveHasID"
}

func (e cveYearToCveID) Nodes() (v, u assembler.GuacNode) {
	return e.year, e.cveID
}

func (e cveYearToCveID) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e cveYearToCveID) PropertyNames() []string {
	return []string{}
}

func (e cveYearToCveID) IdentifiablePropertyNames() []string {
	return []string{}
}
