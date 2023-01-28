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

import "strings"

const (
	identityId        = "id"
	identityDigest    = "digest"
	identityKey       = "key"
	identityKeyType   = "keyType"
	identityKeyScheme = "keyScheme"
)

// IdentityNode is a node that represents an identity
type IdentityNode struct {
	ID     string
	Digest string
	// base64 encoded
	Key       string
	KeyType   string
	KeyScheme string
	NodeData  objectMetadata
}

func (in IdentityNode) Type() string {
	return "Identity"
}

func (in IdentityNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties[identityId] = in.ID
	properties[identityDigest] = strings.ToLower(in.Digest)
	properties[identityKey] = in.Key
	properties[identityKeyType] = in.KeyType
	properties[identityKeyScheme] = in.KeyScheme
	in.NodeData.addProperties(properties)
	return properties
}

func (in IdentityNode) PropertyNames() []string {
	fields := []string{"id", "digest", "key", "keyType", "keyScheme"}
	fields = append(fields, in.NodeData.getProperties()...)
	return fields
}

func (in IdentityNode) IdentifiablePropertyNames() []string {
	// An identity can be uniquely identified by digest
	return []string{"digest"}
}
