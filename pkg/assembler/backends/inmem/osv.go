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
// func registerAllOSV(client *demoClient) {
// 	ctx := context.Background()

// 	inputs := []model.OSVInputSpec{{
// 		OsvID: "CVE-2019-13110",
// 	}, {
// 		OsvID: "CVE-2014-8139",
// 	}, {
// 		OsvID: "CVE-2014-8140",
// 	}, {
// 		OsvID: "CVE-2022-26499",
// 	}, {
// 		OsvID: "GHSA-h45f-rjvw-2rv2",
// 	}}
// 	for _, input := range inputs {
// 		_, err := client.IngestOsv(ctx, &input)
// 		if err != nil {
// 			log.Printf("Error in ingesting: %v\n", err)
// 		}
// 	}
// }

// Internal data: osv
type osvMap map[string]*osvNode
type osvNode struct {
	id               uint32
	osvID            string
	certifyVulnLinks []uint32
	equalVulnLinks   []uint32
	vexLinks         []uint32
}

func (n *osvNode) ID() uint32 { return n.id }

func (n *osvNode) Neighbors(allowedEdges edgeMap) []uint32 {
	out := []uint32{}
	if allowedEdges[model.EdgeOsvCertifyVuln] {
		out = append(out, n.certifyVulnLinks...)
	}
	if allowedEdges[model.EdgeOsvIsVulnerability] {
		out = append(out, n.equalVulnLinks...)
	}
	if allowedEdges[model.EdgeOsvCertifyVexStatement] {
		out = append(out, n.vexLinks...)
	}
	return out
}

func (n *osvNode) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildOsvResponse(n.id, nil)
}

// certifyVulnerability back edges
func (n *osvNode) setVulnerabilityLinks(id uint32) {
	n.certifyVulnLinks = append(n.certifyVulnLinks, id)
}

// isVulnerability back edges
func (n *osvNode) setEqualVulnLinks(id uint32) {
	n.equalVulnLinks = append(n.equalVulnLinks, id)
}

// certifyVexStatement back edges
func (n *osvNode) setVexLinks(id uint32) {
	n.vexLinks = append(n.vexLinks, id)
}

// Ingest OSV
func (c *demoClient) IngestOsv(ctx context.Context, input *model.OSVInputSpec) (*model.Osv, error) {
	return c.ingestOsv(ctx, input, true)
}

func (c *demoClient) ingestOsv(ctx context.Context, input *model.OSVInputSpec, readOnly bool) (*model.Osv, error) {
	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)
	osvID := strings.ToLower(input.OsvID)

	osvIDStruct, hasOsvID := c.osvs[osvID]
	if !hasOsvID {
		if readOnly {
			c.m.RUnlock()
			o, err := c.ingestOsv(ctx, input, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return o, err
		}
		osvIDStruct = &osvNode{
			id:    c.getNextID(),
			osvID: osvID,
		}
		c.index[osvIDStruct.id] = osvIDStruct
		c.osvs[osvID] = osvIDStruct
	}

	// build return GraphQL type
	return c.buildOsvResponse(osvIDStruct.id, nil)
}

// Query OSV
func (c *demoClient) Osv(ctx context.Context, filter *model.OSVSpec) ([]*model.Osv, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	if filter != nil && filter.ID != nil {
		id, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, err
		}
		osv, err := c.buildOsvResponse(uint32(id), filter)
		if err != nil {
			return nil, err
		}
		return []*model.Osv{osv}, nil
	}
	var out []*model.Osv
	if filter != nil && filter.OsvID != nil {
		osvNode, hasOsvIDNode := c.osvs[strings.ToLower(*filter.OsvID)]
		if hasOsvIDNode {
			out = append(out, &model.Osv{
				ID:    nodeID(osvNode.id),
				OsvID: osvNode.osvID,
			})
		}
	} else {
		for _, osvNode := range c.osvs {
			out = append(out, &model.Osv{
				ID:    nodeID(osvNode.id),
				OsvID: osvNode.osvID,
			})
		}
	}
	return out, nil
}

func (c *demoClient) exactOSV(filter *model.OSVSpec) (*osvNode, error) {
	if filter == nil {
		return nil, nil
	}
	if filter.ID != nil {
		id64, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, err
		}
		id := uint32(id64)
		if node, ok := c.index[id]; ok {
			if o, ok := node.(*osvNode); ok {
				return o, nil
			}
		}
	}
	if filter.OsvID != nil {
		if node, ok := c.osvs[strings.ToLower(*filter.OsvID)]; ok {
			return node, nil
		}
	}
	return nil, nil
}

// Builds a model.osv to send as GraphQL response, starting from id.
// The optional filter allows restricting output (on selection operations).
func (c *demoClient) buildOsvResponse(id uint32, filter *model.OSVSpec) (*model.Osv, error) {
	if filter != nil && filter.ID != nil {
		filteredID, err := strconv.ParseUint(*filter.ID, 10, 32)
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

	var osv *model.Osv
	if osvNode, ok := node.(*osvNode); ok {
		if filter != nil && noMatch(toLower(filter.OsvID), osvNode.osvID) {
			return nil, nil
		}
		osv = &model.Osv{
			ID:    nodeID(osvNode.id),
			OsvID: osvNode.osvID,
		}
	}

	return osv, nil
}

func getOsvIDFromInput(c *demoClient, input model.OSVInputSpec) (uint32, error) {
	osvID := strings.ToLower(input.OsvID)

	osvIDStruct, hasOsvID := c.osvs[osvID]
	if !hasOsvID {
		return 0, gqlerror.Errorf("osv id \"%s\" not found", input.OsvID)
	}

	return osvIDStruct.id, nil
}
