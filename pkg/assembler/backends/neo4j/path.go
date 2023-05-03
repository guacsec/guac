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

package neo4j

import (
	"context"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (c *neo4jClient) Path(ctx context.Context, subject string, target string, maxPathLength int, usingOnly []model.Edge) ([]model.Node, error) {
	panic(fmt.Errorf("not implemented: Path - path"))
}

func (c *neo4jClient) Neighbors(ctx context.Context, node string, usingOnly []model.Edge) ([]model.Node, error) {
	panic(fmt.Errorf("not implemented: Neighbors - neighbors"))
}

func (c *neo4jClient) Node(ctx context.Context, node string) (model.Node, error) {
	panic(fmt.Errorf("not implemented: Node - node"))
}

func (c *neo4jClient) Nodes(ctx context.Context, nodes []string) ([]model.Node, error) {
	panic(fmt.Errorf("not implemented: Nodes - nodes"))
}
