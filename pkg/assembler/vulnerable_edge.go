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

// VulnerableEdge is an edge that represents the fact that an
// artifact is vulnerable or not based on certification attestation
// This edge gets created when the attestation contains vulnerabilities
type VulnerableEdge struct {
	AttestationNode   AttestationNode
	VulnerabilityNode VulnerabilityNode
}

func (e VulnerableEdge) Type() string {
	return "Vulnerable"
}

func (e VulnerableEdge) Nodes() (v, u GuacNode) {
	return e.AttestationNode, e.VulnerabilityNode
}

func (e VulnerableEdge) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e VulnerableEdge) PropertyNames() []string {
	return []string{}
}

func (e VulnerableEdge) IdentifiablePropertyNames() []string {
	return []string{}
}
