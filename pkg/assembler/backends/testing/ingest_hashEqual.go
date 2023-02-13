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
	"reflect"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func registerAllHashEqual(client *demoClient) {

	// strings.ToLower(string(checksum.Algorithm)) + ":" + checksum.Value
	client.registerHashEqual([]*model.Artifact{client.artifacts[0], client.artifacts[1], client.artifacts[2]}, "different algorithm for the same artifact")
	client.registerHashEqual([]*model.Artifact{{Digest: "5a787865sd676dacb0142afa0b83029cd7befd9", Algorithm: "sha1"},
		{Digest: "89bb0da1891646e58eb3e6ed24f3a6fc3c8eb5a0d44824cba581dfa34a0450cf", Algorithm: "sha256"}}, "these two are the same")
}

func (c *demoClient) registerHashEqual(artifacts []*model.Artifact, justification string) {

	for _, a := range c.hashEquals {
		if reflect.DeepEqual(a.Artifacts, artifacts) && a.Justification == justification {
			return
		}
	}

	newHashEqual := &model.HashEqual{
		Justification: justification,
		Artifacts:     artifacts,
		Origin:        "testing backend",
		Collector:     "testing backend",
	}
	c.hashEquals = append(c.hashEquals, newHashEqual)
}
