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

func registerAllGHSA(client *neo4jClient) error {
	err := client.registerGhsa("GHSA-h45f-rjvw-2rv2")
	if err != nil {
		return err
	}
	err = client.registerGhsa("GHSA-xrw3-wqph-3fxg")
	if err != nil {
		return err
	}
	err = client.registerGhsa("GHSA-8v4j-7jgf-5rg9")
	if err != nil {
		return err
	}
	err = client.registerGhsa("GHSA-h45f-rjvw-2rv2")
	if err != nil {
		return err
	}
	err = client.registerGhsa("GHSA-h45f-rjvw-2rv2")
	if err != nil {
		return err
	}
	return nil
}

func (c *neo4jClient) registerGhsa(id string) error {
	collectedGhsa := ghsaNode{}
	collecteGhsaId := ghsaID{id: id}

	ghsaToIDEdge := ghsaToID{collectedGhsa, collecteGhsaId}
	assemblerinput := assembler.AssemblerInput{
		Nodes: []assembler.GuacNode{collectedGhsa, collecteGhsaId},
		Edges: []assembler.GuacEdge{ghsaToIDEdge},
	}
	err := assembler.StoreGraph(assemblerinput, c.driver)
	if err != nil {
		return err
	}
	return nil
}

// ghsaNode represents the top level GHSA->GHSAID
type ghsaNode struct {
}

func (gn ghsaNode) Type() string {
	return "Ghsa"
}

func (gn ghsaNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["ghsa"] = "ghsa"
	return properties
}

func (gn ghsaNode) PropertyNames() []string {
	fields := []string{"ghsa"}
	return fields
}

func (gn ghsaNode) IdentifiablePropertyNames() []string {
	return []string{"ghsa"}
}

type ghsaID struct {
	id string
}

func (gi ghsaID) Type() string {
	return "GhsaID"
}

func (gi ghsaID) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["id"] = gi.id
	return properties
}

func (gi ghsaID) PropertyNames() []string {
	fields := []string{"id"}
	return fields
}

func (gi ghsaID) IdentifiablePropertyNames() []string {
	return []string{"id"}
}

type ghsaToID struct {
	ghsa ghsaNode
	id   ghsaID
}

func (e ghsaToID) Type() string {
	return "GhsaHasID"
}

func (e ghsaToID) Nodes() (v, u assembler.GuacNode) {
	return e.ghsa, e.id
}

func (e ghsaToID) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e ghsaToID) PropertyNames() []string {
	return []string{}
}

func (e ghsaToID) IdentifiablePropertyNames() []string {
	return []string{}
}
