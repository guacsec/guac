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

package backend

import (
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func registerAllBuilders(client *demoClient) {
	client.registerBuilder("https://github.com/Attestations/GitHubHostedActions@v1")
	client.registerBuilder("https://tekton.dev/chains/v2")
}

func (c *demoClient) registerBuilder(uri string) {
	for _, b := range c.builders {
		if b.URI == uri {
			return
		}
	}
	newBuilder := &model.Builder{URI: uri}
	c.builders = append(c.builders, newBuilder)
}
