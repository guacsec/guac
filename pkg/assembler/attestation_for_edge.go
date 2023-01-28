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

// AttestationForEdge is an edge that represents the fact that an
// `AttestationNode` is an attestation for an `ArtifactNode/PackageNode`.
// Only one of each side of the edge should be defined.
type AttestationForEdge struct {
	AttestationNode AttestationNode
	ForArtifact     ArtifactNode
	ForPackage      PackageNode
}

func (e AttestationForEdge) Type() string {
	return "Attestation"
}

func (e AttestationForEdge) Nodes() (v, u GuacNode) {
	uA, uP := isDefined(e.ForArtifact), isDefined(e.ForPackage)
	if uA == uP {
		panic("only one of package or artifact dependency node must be defined for Attestation relationship")
	}

	v = e.AttestationNode
	if uA {
		u = e.ForArtifact
	} else {
		u = e.ForPackage
	}

	return v, u
}

func (e AttestationForEdge) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e AttestationForEdge) PropertyNames() []string {
	return []string{}
}

func (e AttestationForEdge) IdentifiablePropertyNames() []string {
	return []string{}
}
