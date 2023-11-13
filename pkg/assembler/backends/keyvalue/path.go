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

package keyvalue

import (
	"context"
	"fmt"
	"strings"

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
	c.m.RLock()
	defer c.m.RUnlock()
	return c.bfs(ctx, source, target, maxPathLength, processUsingOnly(usingOnly))
}

func (c *demoClient) Neighbors(ctx context.Context, source string, usingOnly []model.Edge) ([]model.Node, error) {
	c.m.RLock()
	neighbors, err := c.neighborsFromId(ctx, source, processUsingOnly(usingOnly))
	if err != nil {
		c.m.RUnlock()
		return nil, err
	}
	c.m.RUnlock()

	c.m.RLock()
	defer c.m.RUnlock()
	return c.Nodes(ctx, neighbors)
}

func (c *demoClient) neighborsFromId(ctx context.Context, id string, allowedEdges edgeMap) ([]string, error) {
	var k string
	if err := c.kv.Get(ctx, indexCol, id, &k); err != nil {
		return nil, fmt.Errorf("%w : id not found in index %q", err, id)
	}

	sub := strings.SplitN(k, ":", 2)
	if len(sub) != 2 {
		return nil, fmt.Errorf("Bad value was stored in index map: %v", k)
	}

	node := typeColMap(sub[0])
	if err := c.kv.Get(ctx, sub[0], sub[1], &node); err != nil {
		return nil, err
	}

	return node.Neighbors(allowedEdges), nil
}

func (c *demoClient) bfs(ctx context.Context, from, to string, maxLength int, allowedEdges edgeMap) ([]model.Node, error) {
	queue := make([]string, 0) // the queue of nodes in bfs
	type dfsNode struct {
		expanded bool // true once all node neighbors are added to queue
		parent   string
		depth    int
	}
	nodeMap := map[string]dfsNode{}

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

		neighbors, err := c.neighborsFromId(ctx, now, allowedEdges)
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

	reversedPath := []string{}
	now := to
	for now != from {
		reversedPath = append(reversedPath, now)
		now = nodeMap[now].parent
	}
	reversedPath = append(reversedPath, now)

	// reverse path
	path := make([]string, len(reversedPath))
	for i, x := range reversedPath {
		path[len(reversedPath)-i-1] = x
	}

	return c.Nodes(ctx, path)
}

func (c *demoClient) Node(ctx context.Context, id string) (model.Node, error) {
	c.m.RLock()
	defer c.m.RUnlock()

	var k string
	if err := c.kv.Get(ctx, indexCol, id, &k); err != nil {
		return nil, fmt.Errorf("%w : id not found in index %q", err, id)
	}

	sub := strings.SplitN(k, ":", 2)
	if len(sub) != 2 {
		return nil, fmt.Errorf("Bad value was stored in index map: %v", k)
	}

	node := typeColMap(sub[0])
	if err := c.kv.Get(ctx, sub[0], sub[1], &node); err != nil {
		return nil, err
	}

	out, err := node.BuildModelNode(ctx, c)
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
