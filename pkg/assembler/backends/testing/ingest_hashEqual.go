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

package testing

import (
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func registerAllHashEqual(client *demoClient) {

	// strings.ToLower(string(checksum.Algorithm)) + ":" + checksum.Value
	client.registerHashEqual(client.artifacts[0], client.artifacts[1])
	client.registerHashEqual(client.artifacts[0], client.artifacts[2])
	client.registerHashEqual(client.artifacts[1], client.artifacts[2])
}

func (c *demoClient) registerHashEqual(artifact *model.Artifact, dependentArtifact *model.Artifact) {

	for _, a := range c.hashEquals {
		if a.Artifact == artifact && a.EqualArtifact == dependentArtifact {
			return
		}
	}
	newHashEqual := &model.HashEqual{
		Justification: "Testing Equal",
		Source:        "testing",
		Collector:     "testing",
		Artifact:      artifact,
		EqualArtifact: dependentArtifact,
	}
	c.hashEquals = append(c.hashEquals, newHashEqual)
}
