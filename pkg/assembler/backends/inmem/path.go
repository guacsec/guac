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

package inmem

import (
	"context"
	"strconv"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type edgeMap map[model.Edge]bool

func processUsingOnly(usingOnly []model.Edge) edgeMap {
	m := edgeMap{}
	allowedEdges := usingOnly
	if len(usingOnly) == 0 {
		allowedEdges = model.AllEdge
	}
	for _, edge := range allowedEdges {
		m[edge] = true
	}
	return m
}

func (c *demoClient) Path(ctx context.Context, source string, target string, maxPathLength int, usingOnly []model.Edge) ([]model.Node, error) {
	if maxPathLength <= 0 {
		return nil, gqlerror.Errorf("maxPathLength argument must be positive, got %d", maxPathLength)
	}

	sourceID, err := strconv.ParseUint(source, 10, 32)
	if err != nil {
		return nil, err
	}
	targetID, err := strconv.ParseUint(target, 10, 32)
	if err != nil {
		return nil, err
	}

	c.m.RLock()
	defer c.m.RUnlock()
	return c.bfs(uint32(sourceID), uint32(targetID), maxPathLength, processUsingOnly(usingOnly))
}

func (c *demoClient) Neighbors(ctx context.Context, source string, usingOnly []model.Edge) ([]model.Node, error) {
	id, err := strconv.ParseUint(source, 10, 32)
	if err != nil {
		return nil, err
	}

	c.m.RLock()
	neighbors, err := c.neighborsFromId(uint32(id), processUsingOnly(usingOnly))
	if err != nil {
		c.m.RUnlock()
		return nil, err
	}
	c.m.RUnlock()

	c.m.RLock()
	defer c.m.RUnlock()
	return c.buildModelNodes(neighbors)
}

func (c *demoClient) buildModelNodes(nodeIDs []uint32) ([]model.Node, error) {
	out := make([]model.Node, len(nodeIDs))

	for i, nodeID := range nodeIDs {
		node, ok := c.index[nodeID]
		if !ok {
			return nil, gqlerror.Errorf("Internal data error: got invalid node id %d", nodeID)
		}
		var err error

		out[i], err = node.BuildModelNode(c)
		if err != nil {
			return nil, err
		}
	}

	return out, nil
}

func (c *demoClient) neighborsFromId(id uint32, allowedEdges edgeMap) ([]uint32, error) {
	node, ok := c.index[id]
	if !ok {
		return nil, gqlerror.Errorf("ID does not match existing node")
	}
	return node.Neighbors(allowedEdges), nil
}

func (c *demoClient) bfs(from, to uint32, maxLength int, allowedEdges edgeMap) ([]model.Node, error) {
	queue := make([]uint32, 0) // the queue of nodes in bfs
	type dfsNode struct {
		expanded bool // true once all node neighbors are added to queue
		parent   uint32
		depth    int
	}
	nodeMap := map[uint32]dfsNode{}

	nodeMap[from] = dfsNode{}
	queue = append(queue, from)

	found := false
	for len(queue) > 0 {
		now := queue[0]
		queue = queue[1:]
		nowNode := nodeMap[now]

		if now == to {
			found = true
			break
		}

		if nowNode.depth >= maxLength {
			break
		}

		neighbors, err := c.neighborsFromId(now, allowedEdges)
		if err != nil {
			return nil, err
		}

		for _, next := range neighbors {
			dfsN, seen := nodeMap[next]
			if !seen {
				dfsN = dfsNode{
					parent: now,
					depth:  nowNode.depth + 1,
				}
				nodeMap[next] = dfsN
			}
			if !dfsN.expanded {
				queue = append(queue, next)
			}
		}

		nowNode.expanded = true
		nodeMap[now] = nowNode
	}

	if !found {
		return nil, gqlerror.Errorf("No path found up to specified length")
	}

	reversedPath := []uint32{}
	now := to
	for now != from {
		reversedPath = append(reversedPath, now)
		now = nodeMap[now].parent
	}
	reversedPath = append(reversedPath, now)

	// reverse path
	path := make([]uint32, len(reversedPath))
	for i, x := range reversedPath {
		path[len(reversedPath)-i-1] = x
	}

	return c.buildModelNodes(path)
}

func (c *demoClient) Node(ctx context.Context, source string) (model.Node, error) {
	id, err := strconv.ParseUint(source, 10, 32)
	if err != nil {
		return nil, err
	}

	c.m.RLock()
	defer c.m.RUnlock()
	node, ok := c.index[uint32(id)]
	if !ok {
		return nil, gqlerror.Errorf("Node: got invalid node id %d", id)
	}

	out, err := node.BuildModelNode(c)
	if err != nil {
		return nil, gqlerror.Errorf("Node: could not build node: %v", err)
	}

	return out, nil
}

func (c *demoClient) Nodes(ctx context.Context, ids []string) ([]model.Node, error) {
	rv := make([]model.Node, 0, len(ids))
	for _, id := range ids {
		n, err := c.Node(ctx, id)
		if err != nil {
			return nil, err
		}
		rv = append(rv, n)
	}
	return rv, nil
}
