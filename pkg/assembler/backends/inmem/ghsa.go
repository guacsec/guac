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
	"strings"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// TODO: convert to unit test
// func registerAllGHSA(client *demoClient) {
// 	ctx := context.Background()

// 	inputs := []model.GHSAInputSpec{{
// 		GhsaID: "GHSA-h45f-rjvw-2rv2",
// 	}, {
// 		GhsaID: "GHSA-xrw3-wqph-3fxg",
// 	}, {
// 		GhsaID: "GHSA-8v4j-7jgf-5rg9",
// 	}}
// 	for _, input := range inputs {
// 		_, err := client.IngestGhsa(ctx, &input)
// 		if err != nil {
// 			log.Printf("Error in ingesting: %v\n", err)
// 		}
// 	}
// }

const ghsa string = "ghsa"

// Internal data: osv
type ghsaMap map[string]*ghsaNode
type ghsaNode struct {
	id      uint32
	typeKey string
	ghsaIDs ghsaIDMap
}
type ghsaIDMap map[string]*ghsaIDNode
type ghsaIDNode struct {
	id               uint32
	parent           uint32
	ghsaID           string
	certifyVulnLinks []uint32
	equalVulnLinks   []uint32
	vexLinks         []uint32
}

func (n *ghsaIDNode) ID() uint32 { return n.id }
func (n *ghsaNode) ID() uint32   { return n.id }

func (n *ghsaNode) Neighbors() []uint32 {
	out := make([]uint32, 0, len(n.ghsaIDs))
	for _, v := range n.ghsaIDs {
		out = append(out, v.id)
	}
	return out
}

func (n *ghsaIDNode) Neighbors() []uint32 {
	out := make([]uint32, 0, 1+len(n.certifyVulnLinks)+len(n.equalVulnLinks)+len(n.vexLinks))
	out = append(out, n.certifyVulnLinks...)
	out = append(out, n.equalVulnLinks...)
	out = append(out, n.vexLinks...)
	out = append(out, n.parent)
	return out
}

func (n *ghsaIDNode) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildGhsaResponse(n.id, nil)
}
func (n *ghsaNode) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildGhsaResponse(n.id, nil)
}

// certifyVulnerability back edges
func (n *ghsaIDNode) setVulnerabilityLinks(id uint32) {
	n.certifyVulnLinks = append(n.certifyVulnLinks, id)
}

// isVulnerability back edges
func (n *ghsaIDNode) setEqualVulnLinks(id uint32) {
	n.equalVulnLinks = append(n.equalVulnLinks, id)
}

// certifyVexStatement back edges
func (n *ghsaIDNode) setVexLinks(id uint32) {
	n.vexLinks = append(n.vexLinks, id)
}

// Ingest GHSA
func (c *demoClient) IngestGhsa(ctx context.Context, input *model.GHSAInputSpec) (*model.Ghsa, error) {
	ghsaStruct, hasGhsa := c.ghsas[ghsa]
	if !hasGhsa {
		ghsaStruct = &ghsaNode{
			id:      c.getNextID(),
			typeKey: ghsa,
			ghsaIDs: ghsaIDMap{},
		}
		c.index[ghsaStruct.id] = ghsaStruct
		c.ghsas[ghsa] = ghsaStruct
	}
	ghsaIDs := ghsaStruct.ghsaIDs
	ghsaID := strings.ToLower(input.GhsaID)

	ghsaIDStruct, hasGhsaID := ghsaIDs[ghsaID]
	if !hasGhsaID {
		ghsaIDStruct = &ghsaIDNode{
			id:     c.getNextID(),
			parent: ghsaStruct.id,
			ghsaID: ghsaID,
		}
		c.index[ghsaIDStruct.id] = ghsaIDStruct
		ghsaIDs[ghsaID] = ghsaIDStruct
	}

	// build return GraphQL type
	return c.buildGhsaResponse(ghsaIDStruct.id, nil)
}

// Query GHSA
func (c *demoClient) Ghsa(ctx context.Context, filter *model.GHSASpec) ([]*model.Ghsa, error) {
	if filter != nil && filter.ID != nil {
		id, err := strconv.Atoi(*filter.ID)
		if err != nil {
			return nil, err
		}
		osv, err := c.buildGhsaResponse(uint32(id), filter)
		if err != nil {
			return nil, err
		}
		return []*model.Ghsa{osv}, nil
	}
	out := []*model.Ghsa{}
	for _, ghsaNode := range c.ghsas {
		ghsaIDList := []*model.GHSAId{}
		if filter != nil && filter.GhsaID != nil {
			ghsaIDNode, hasGhsaIDNode := ghsaNode.ghsaIDs[strings.ToLower(*filter.GhsaID)]
			if hasGhsaIDNode {
				ghsaIDList = append(ghsaIDList, &model.GHSAId{
					ID:     nodeID(ghsaIDNode.id),
					GhsaID: ghsaIDNode.ghsaID,
				})
			}
		} else {
			for _, ghsaIDNode := range ghsaNode.ghsaIDs {
				ghsaIDList = append(ghsaIDList, &model.GHSAId{
					ID:     nodeID(ghsaIDNode.id),
					GhsaID: ghsaIDNode.ghsaID,
				})
			}
		}
		if len(ghsaIDList) > 0 {
			out = append(out, &model.Ghsa{
				ID:      nodeID(ghsaNode.id),
				GhsaIds: ghsaIDList,
			})
		}
	}
	return out, nil
}

// Builds a model.Ghsa to send as GraphQL response, starting from id.
// The optional filter allows restricting output (on selection operations).
func (c *demoClient) buildGhsaResponse(id uint32, filter *model.GHSASpec) (*model.Ghsa, error) {
	if filter != nil && filter.ID != nil {
		filteredID, err := strconv.Atoi(*filter.ID)
		if err != nil {
			return nil, err
		}
		if uint32(filteredID) != id {
			return nil, nil
		}
	}

	node, ok := c.index[id]
	if !ok {
		return nil, gqlerror.Errorf("ID does not match existing node")
	}

	ghsaIDList := []*model.GHSAId{}
	if ghsaIDNode, ok := node.(*ghsaIDNode); ok {
		if filter != nil && noMatch(toLower(filter.GhsaID), ghsaIDNode.ghsaID) {
			return nil, nil
		}
		ghsaIDList = append(ghsaIDList, &model.GHSAId{
			ID:     nodeID(ghsaIDNode.id),
			GhsaID: ghsaIDNode.ghsaID,
		})
		node = c.index[ghsaIDNode.parent]
	}

	ghsaNode, ok := node.(*ghsaNode)
	if !ok {
		return nil, gqlerror.Errorf("ID does not match expected node type for ghsa root")
	}
	s := model.Ghsa{
		ID:      nodeID(ghsaNode.id),
		GhsaIds: ghsaIDList,
	}
	return &s, nil
}

func getGhsaIDFromInput(c *demoClient, input model.GHSAInputSpec) (uint32, error) {
	ghsaStruct, hasGhsa := c.ghsas[ghsa]
	if !hasGhsa {
		return 0, gqlerror.Errorf("ghsa type \"%s\" not found", ghsa)
	}
	ghsaIDs := ghsaStruct.ghsaIDs
	ghsaID := strings.ToLower(input.GhsaID)

	ghsaIDStruct, hasGhsaID := ghsaIDs[ghsaID]
	if !hasGhsaID {
		return 0, gqlerror.Errorf("ghsa id \"%s\" not found", input.GhsaID)
	}

	return ghsaIDStruct.id, nil
}
