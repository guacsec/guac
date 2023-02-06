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

// ghsaNode represents the top level GHSA->GHSAID
type ghsaNode struct {
}

func (gn *ghsaNode) Type() string {
	return "Ghsa"
}

func (gn *ghsaNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["ghsa"] = "ghsa"
	return properties
}

func (gn *ghsaNode) PropertyNames() []string {
	fields := []string{"ghsa"}
	return fields
}

func (gn *ghsaNode) IdentifiablePropertyNames() []string {
	return []string{"ghsa"}
}

type ghsaID struct {
	id string
}

func (gi *ghsaID) Type() string {
	return "GhsaID"
}

func (gi *ghsaID) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["id"] = gi.id
	return properties
}

func (gi *ghsaID) PropertyNames() []string {
	fields := []string{"id"}
	return fields
}

func (gi *ghsaID) IdentifiablePropertyNames() []string {
	return []string{"id"}
}

type ghsaToID struct {
	ghsa *ghsaNode
	id   *ghsaID
}

func (e *ghsaToID) Type() string {
	return "GhsaHasID"
}

func (e *ghsaToID) Nodes() (v, u assembler.GuacNode) {
	return e.ghsa, e.id
}

func (e *ghsaToID) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e *ghsaToID) PropertyNames() []string {
	return []string{}
}

func (e *ghsaToID) IdentifiablePropertyNames() []string {
	return []string{}
}
