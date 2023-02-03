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

package neo4jBackend

import (
	"github.com/guacsec/guac/pkg/assembler"
)

func registerAllBuilders(client *neo4jClient) {
	client.registerBuilder("https://github.com/Attestations/GitHubHostedActions@v1")
	client.registerBuilder("https://tekton.dev/chains/v2")
}

func (c *neo4jClient) registerBuilder(uri string) {

	collectedBuilder := builderNode{
		uri: uri,
	}
	assemblerinput := assembler.AssemblerInput{
		Nodes: []assembler.GuacNode{collectedBuilder},
	}
	assembler.StoreGraph(assemblerinput, c.driver)
}

// builderNode represents the builder
type builderNode struct {
	uri string
}

func (bn builderNode) Type() string {
	return "Builder"
}

func (bn builderNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["uri"] = bn.uri
	return properties
}

func (bn builderNode) PropertyNames() []string {
	fields := []string{"uri"}
	return fields
}

func (bn builderNode) IdentifiablePropertyNames() []string {
	return []string{"uri"}
}
