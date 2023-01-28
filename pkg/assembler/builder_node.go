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
	builderType = "type"
	builderId   = "id"
)

// BuilderNode is a node that represents a builder for an artifact
type BuilderNode struct {
	BuilderType string
	BuilderId   string
	NodeData    objectMetadata
}

func (bn BuilderNode) Type() string {
	return "Builder"
}

func (bn BuilderNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties[builderType] = bn.BuilderType
	properties[builderId] = bn.BuilderId
	bn.NodeData.addProperties(properties)
	return properties
}

func (bn BuilderNode) PropertyNames() []string {
	fields := []string{builderType, builderId}
	fields = append(fields, bn.NodeData.getProperties()...)
	return fields
}

func (bn BuilderNode) IdentifiablePropertyNames() []string {
	// A builder needs both type and id to be identified
	return []string{builderType, builderId}
}
