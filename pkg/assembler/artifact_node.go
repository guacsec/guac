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

import (
	"strings"
)

const (
	digest = "digest"
	name   = "name"
	tags   = "tags"
)

// ArtifactNode is a node that represents an artifact
type ArtifactNode struct {
	Name     string
	Digest   string
	Tags     []string
	NodeData objectMetadata
}

func (an ArtifactNode) Type() string {
	return "Artifact"
}

func (an ArtifactNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties[name] = an.Name
	properties[digest] = strings.ToLower(an.Digest)
	properties[tags] = an.Tags
	an.NodeData.addProperties(properties)
	return properties
}

func (an ArtifactNode) PropertyNames() []string {
	fields := []string{name, digest, tags}
	fields = append(fields, an.NodeData.getProperties()...)
	return fields
}

func (an ArtifactNode) IdentifiablePropertyNames() []string {
	// An artifact can be uniquely identified by digest
	return []string{"digest"}
}
