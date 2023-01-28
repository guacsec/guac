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

package assembler

// IdentityForEdge is an edge that represents the fact that an
// `IdentityNode` is an identity for an `AttestationNode`.
type IdentityForEdge struct {
	IdentityNode    IdentityNode
	AttestationNode AttestationNode
}

func (e IdentityForEdge) Type() string {
	return "Identity"
}

func (e IdentityForEdge) Nodes() (v, u GuacNode) {
	return e.IdentityNode, e.AttestationNode
}

func (e IdentityForEdge) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e IdentityForEdge) PropertyNames() []string {
	return []string{}
}

func (e IdentityForEdge) IdentifiablePropertyNames() []string {
	return []string{}
}
