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

package arangodb

import (
	"context"
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (c *arangoClient) Path(ctx context.Context, startNodeID string, targetNodeID string, maxPathLength int, usingOnly []model.Edge) ([]model.Node, error) {
	panic(fmt.Errorf("not implemented: Path"))
}

func (c *arangoClient) Neighbors(ctx context.Context, nodeID string, usingOnly []model.Edge) ([]model.Node, error) {
	panic(fmt.Errorf("not implemented: Neighbors"))
}

func (c *arangoClient) Node(ctx context.Context, nodeID string) (model.Node, error) {
	idSplit := strings.Split(nodeID, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", nodeID)
	}
	switch idSplit[0] {
	case pkgVersionsStr, pkgNamesStr, pkgNamespacesStr, pkgTypesStr:
		return c.buildPackageResponseFromID(ctx, nodeID, nil)
	case srcNamesStr, srcNamespacesStr, srcTypesStr:
		return c.buildSourceResponseFromID(ctx, nodeID, nil)
	}
	return nil, nil
}

func (c *arangoClient) Nodes(ctx context.Context, nodeIDs []string) ([]model.Node, error) {
	panic(fmt.Errorf("not implemented: Nodes"))
}
