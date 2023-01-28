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

import "strings"

const (
	attestationFilePath = "filepath"
	attestationDigest   = "digest"
	attestationType     = "attestation_type"
)

// AttestationNode is a node that represents an attestation
type AttestationNode struct {
	// TODO(mihaimaruseac): Unsure what fields to store here
	FilePath        string
	Digest          string
	AttestationType string
	Payload         map[string]interface{}
	NodeData        objectMetadata
}

func (an AttestationNode) Type() string {
	return "Attestation"
}

func (an AttestationNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties[attestationFilePath] = an.FilePath
	properties[attestationDigest] = strings.ToLower(an.Digest)
	properties[attestationType] = an.AttestationType
	for k, v := range an.Payload {
		properties[k] = v
	}
	an.NodeData.addProperties(properties)

	return properties
}

func (an AttestationNode) PropertyNames() []string {
	fields := []string{attestationFilePath, attestationDigest, attestationType}
	for k := range an.Payload {
		fields = append(fields, k)
	}
	fields = append(fields, an.NodeData.getProperties()...)
	return fields
}

func (an AttestationNode) IdentifiablePropertyNames() []string {
	return []string{"digest"}
}
