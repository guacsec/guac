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

func registerAllOSV(client *neo4jClient) error {
	err := client.registerOSV("CVE-2019-3456")
	if err != nil {
		return err
	}
	err = client.registerOSV("CVE-2014-53356")
	if err != nil {
		return err
	}
	err = client.registerOSV("CVE-2014-4432")
	if err != nil {
		return err
	}
	err = client.registerOSV("CVE-2022-9876")
	if err != nil {
		return err
	}
	err = client.registerOSV("CVE-2014-4432")
	if err != nil {
		return err
	}
	return nil
}

func (c *neo4jClient) registerOSV(id string) error {
	collectedOsv := osvNode{}
	collecteOsvId := osvID{id: id}

	osvToIDEdge := osvToID{collectedOsv, collecteOsvId}
	assemblerinput := assembler.AssemblerInput{
		Nodes: []assembler.GuacNode{collectedOsv, collecteOsvId},
		Edges: []assembler.GuacEdge{osvToIDEdge},
	}
	err := assembler.StoreGraph(assemblerinput, c.driver)
	if err != nil {
		return err
	}
	return nil
}

// osvNode presentes the top level OSV->OSVID
type osvNode struct {
}

func (ov osvNode) Type() string {
	return "Osv"
}

func (ov osvNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["osv"] = "osv"
	return properties
}

func (ov osvNode) PropertyNames() []string {
	fields := []string{"osv"}
	return fields
}

func (ov osvNode) IdentifiablePropertyNames() []string {
	return []string{"osv"}
}

type osvID struct {
	id string
}

func (oi osvID) Type() string {
	return "OsvID"
}

func (oi osvID) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["id"] = oi.id
	return properties
}

func (oi osvID) PropertyNames() []string {
	fields := []string{"id"}
	return fields
}

func (oi osvID) IdentifiablePropertyNames() []string {
	return []string{"id"}
}

type osvToID struct {
	osv osvNode
	id  osvID
}

func (e osvToID) Type() string {
	return "OsvHasID"
}

func (e osvToID) Nodes() (v, u assembler.GuacNode) {
	return e.osv, e.id
}

func (e osvToID) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e osvToID) PropertyNames() []string {
	return []string{}
}

func (e osvToID) IdentifiablePropertyNames() []string {
	return []string{}
}
