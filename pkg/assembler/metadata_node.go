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

const (
	metadataType = "metadata_type"
	metaID       = "id"
)

// MetadataNode is a node that represents metadata about an artifact/package
type MetadataNode struct {
	MetadataType string
	ID           string
	Details      map[string]interface{}
}

func (mn MetadataNode) Type() string {
	return "Metadata"
}

func (mn MetadataNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties[metadataType] = mn.MetadataType
	properties[metaID] = mn.ID

	for k, v := range mn.Details {
		properties[k] = v
	}

	return properties
}

func (mn MetadataNode) PropertyNames() []string {
	fields := []string{metadataType, metaID}
	for k := range mn.Details {
		fields = append(fields, k)
	}

	return fields
}

func (mn MetadataNode) IdentifiablePropertyNames() []string {
	return []string{metadataType, metaID}
}
