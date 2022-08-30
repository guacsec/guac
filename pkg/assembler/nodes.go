//
// Copyright 2022 The GUAC Authors.
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

// ArtifactNode is a node that represents an artifact
type ArtifactNode struct {
	Name     string
	Checksum string
}

func (an ArtifactNode) Type() string {
	return "Artifact"
}

func (an ArtifactNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["name"] = an.Name
	properties["checksum"] = an.Checksum
	return properties
}

func (an ArtifactNode) PropertyNames() []string {
	return []string{"name", "checksum"}
}

func (an ArtifactNode) IdentifiablePropertyNames() [][]string {
	// An artifact can be uniquely identified by checksum
	return [][]string{{"checksum"}}
}

// AttestationNode is a node that represents an attestation
type AttestationNode struct {
	// TODO(mihaimaruseac): Unsure what fields to store here
	File     string
	Checksum string
}

func (an AttestationNode) Type() string {
	return "Attestation"
}

func (an AttestationNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["file"] = an.File
	properties["checksum"] = an.Checksum
	return properties
}

func (an AttestationNode) PropertyNames() []string {
	return []string{"file", "checksum"}
}

func (an AttestationNode) IdentifiablePropertyNames() [][]string {
	// An attestation can be uniquely identified by filename?
	return [][]string{{"file"}}
}

// BuilderNode is a node that represents an attestation
type BuilderNode struct {
	BuilderType string
	BuilderId   string
}

func (bn BuilderNode) Type() string {
	return "Builder"
}

func (bn BuilderNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["type"] = bn.BuilderType
	properties["id"] = bn.BuilderId
	return properties
}

func (bn BuilderNode) PropertyNames() []string {
	return []string{"type", "id"}
}

func (bn BuilderNode) IdentifiablePropertyNames() [][]string {
	// A builder needs both type and id to be identified
	return [][]string{{"type", "id"}}
}

// AttestationEdge is an edge that represents the fact that an
// `AttestationNode` is an attestation for an `ArtifactNode`.
type AttestationEdge struct {
	AttestationNode AttestationNode
	ArtifactNode    ArtifactNode
}

func (e AttestationEdge) Type() string {
	return "Attestation"
}

func (e AttestationEdge) Nodes() (v, u GuacNode) {
	return e.AttestationNode, e.ArtifactNode
}

func (e AttestationEdge) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e AttestationEdge) PropertyNames() []string {
	return []string{}
}

func (e AttestationEdge) IdentifiablePropertyNames() [][]string {
	return [][]string{}
}

// BuiltByEdge is an edge that represents the fact that an
// `ArtifactNode` has been built by a `BuilderNode`
type BuiltByEdge struct {
	ArtifactNode ArtifactNode
	BuilderNode  BuilderNode
}

func (e BuiltByEdge) Type() string {
	return "BuiltBy"
}

func (e BuiltByEdge) Nodes() (v, u GuacNode) {
	return e.ArtifactNode, e.BuilderNode
}

func (e BuiltByEdge) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e BuiltByEdge) PropertyNames() []string {
	return []string{}
}

func (e BuiltByEdge) IdentifiablePropertyNames() [][]string {
	return [][]string{}
}

// DependsOnEdge is an edge that represents the fact that an
// `ArtifactNode` depends on another `ArtifactNode`
type DependsOnEdge struct {
	ArtifactNode ArtifactNode
	Dependency   ArtifactNode
}

func (e DependsOnEdge) Type() string {
	return "DependsOn"
}

func (e DependsOnEdge) Nodes() (v, u GuacNode) {
	return e.ArtifactNode, e.Dependency
}

func (e DependsOnEdge) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e DependsOnEdge) PropertyNames() []string {
	return []string{}
}

func (e DependsOnEdge) IdentifiablePropertyNames() [][]string {
	return [][]string{}
}
