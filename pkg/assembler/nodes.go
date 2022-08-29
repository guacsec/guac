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

func (an ArtifactNode) Attributes() []string {
	return []string{"name", "checksum"}
}

func (an ArtifactNode) IdentifiableAttributes() [][]string {
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

func (an AttestationNode) Attributes() []string {
	return []string{"file", "checksum"}
}

func (an AttestationNode) IdentifiableAttributes() [][]string {
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

func (bn BuilderNode) Attributes() []string {
	return []string{"type", "id"}
}

func (bn BuilderNode) IdentifiableAttributes() [][]string {
	// A builder needs both type and id to be identified
	return [][]string{{"type", "id"}}
}
