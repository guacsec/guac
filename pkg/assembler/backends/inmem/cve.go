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

// func registerAllCVE(client *demoClient) {
// 	ctx := context.Background()

// 	inputs := []model.CVEInputSpec{{
// 		Year:  2019,
// 		CveID: "CVE-2019-13110",
// 	}, {
// 		Year:  2014,
// 		CveID: "CVE-2014-8139",
// 	}, {
// 		Year:  2014,
// 		CveID: "CVE-2014-8140",
// 	}, {
// 		Year:  2022,
// 		CveID: "CVE-2022-26499",
// 	}, {
// 		Year:  2014,
// 		CveID: "CVE-2014-8140",
// 	}}
// 	for _, input := range inputs {
// 		_, err := client.IngestCve(ctx, &input)
// 		if err != nil {
// 			log.Printf("Error in ingesting: %v\n", err)
// 		}
// 	}
// }

// Internal data: osv
type cveMap map[int]*cveNode
type cveNode struct {
	id     uint32
	year   int
	cveIDs cveIDMap
}
type cveIDMap map[string]*cveIDNode
type cveIDNode struct {
	id               uint32
	parent           uint32
	cveID            string
	certifyVulnLinks []uint32
	equalVulnLinks   []uint32
	vexLinks         []uint32
}

func (n *cveIDNode) ID() uint32 { return n.id }
func (n *cveNode) ID() uint32   { return n.id }

func (n *cveNode) Neighbors() []uint32 {
	out := make([]uint32, 0, len(n.cveIDs))
	for _, v := range n.cveIDs {
		out = append(out, v.id)
	}
	return out
}

func (n *cveIDNode) Neighbors() []uint32 {
	out := make([]uint32, 0, 1+len(n.certifyVulnLinks)+len(n.equalVulnLinks)+len(n.vexLinks))
	out = append(out, n.certifyVulnLinks...)
	out = append(out, n.equalVulnLinks...)
	out = append(out, n.vexLinks...)
	out = append(out, n.parent)
	return out
}

func (n *cveIDNode) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildCveResponse(n.id, nil)
}
func (n *cveNode) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildCveResponse(n.id, nil)
}

// certifyVulnerability back edges
func (n *cveIDNode) setVulnerabilityLinks(id uint32) {
	n.certifyVulnLinks = append(n.certifyVulnLinks, id)
}

// isVulnerability back edges
func (n *cveIDNode) setEqualVulnLinks(id uint32) {
	n.equalVulnLinks = append(n.equalVulnLinks, id)
}

// certifyVexStatement back edges
func (n *cveIDNode) setVexLinks(id uint32) {
	n.vexLinks = append(n.vexLinks, id)
}

// Ingest CVE
func (c *demoClient) IngestCve(ctx context.Context, input *model.CVEInputSpec) (*model.Cve, error) {
	return c.ingestCve(ctx, input, true)
}

func (c *demoClient) ingestCve(ctx context.Context, input *model.CVEInputSpec, readOnly bool) (*model.Cve, error) {
	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)
	cveStruct, hasCve := c.cves[input.Year]
	if !hasCve {
		cveStruct = &cveNode{
			id:     c.getNextID(),
			year:   input.Year,
			cveIDs: cveIDMap{},
		}
		c.index[cveStruct.id] = cveStruct
		c.cves[input.Year] = cveStruct
	}
	cveIDs := cveStruct.cveIDs
	cveID := strings.ToLower(input.CveID)

	cveIDStruct, hasCveID := cveIDs[cveID]
	if !hasCveID {
		if readOnly {
			c.m.RUnlock()
			cve, err := c.ingestCve(ctx, input, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return cve, err
		}
		cveIDStruct = &cveIDNode{
			id:     c.getNextID(),
			parent: cveStruct.id,
			cveID:  cveID,
		}
		c.index[cveIDStruct.id] = cveIDStruct
		cveIDs[cveID] = cveIDStruct
	}

	// build return GraphQL type
	return c.buildCveResponse(cveIDStruct.id, nil)
}

// Query CVE
func (c *demoClient) Cve(ctx context.Context, filter *model.CVESpec) ([]*model.Cve, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	if filter != nil && filter.ID != nil {
		id, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, err
		}
		osv, err := c.buildCveResponse(uint32(id), filter)
		if err != nil {
			return nil, err
		}
		return []*model.Cve{osv}, nil
	}
	out := []*model.Cve{}

	if filter != nil && filter.Year != nil {
		foundCveNode, ok := c.cves[*filter.Year]
		if ok {
			cveIDList := buildCveID(foundCveNode, filter)
			if len(cveIDList) > 0 {
				out = append(out, &model.Cve{
					ID:     nodeID(foundCveNode.id),
					Year:   foundCveNode.year,
					CveIds: cveIDList,
				})
			}
		}
	} else {
		for _, cveNode := range c.cves {
			cveIDList := buildCveID(cveNode, filter)
			if len(cveIDList) > 0 {
				out = append(out, &model.Cve{
					ID:     nodeID(cveNode.id),
					Year:   cveNode.year,
					CveIds: cveIDList,
				})
			}
		}
	}
	return out, nil
}

func (c *demoClient) exactCVE(filter *model.CVESpec) (*cveIDNode, error) {
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
			if c, ok := node.(*cveIDNode); ok {
				return c, nil
			}
		}
	}
	if filter.Year != nil && filter.CveID != nil {
		if year, ok := c.cves[*filter.Year]; ok {
			if node, ok := year.cveIDs[*filter.CveID]; ok {
				return node, nil
			}
		}
	}
	return nil, nil
}

func buildCveID(foundCveNode *cveNode, filter *model.CVESpec) []*model.CVEId {
	cveIDList := []*model.CVEId{}
	if filter != nil && filter.CveID != nil {
		cveIDNode, hasCveIDNode := foundCveNode.cveIDs[strings.ToLower(*filter.CveID)]
		if hasCveIDNode {
			cveIDList = append(cveIDList, &model.CVEId{
				ID:    nodeID(cveIDNode.id),
				CveID: cveIDNode.cveID,
			})
		}
	} else {
		for _, cveIDNode := range foundCveNode.cveIDs {
			cveIDList = append(cveIDList, &model.CVEId{
				ID:    nodeID(cveIDNode.id),
				CveID: cveIDNode.cveID,
			})
		}
	}
	return cveIDList
}

// Builds a model.Cve to send as GraphQL response, starting from id.
// The optional filter allows restricting output (on selection operations).
func (c *demoClient) buildCveResponse(id uint32, filter *model.CVESpec) (*model.Cve, error) {
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

	cveIDList := []*model.CVEId{}
	if cveIDNode, ok := node.(*cveIDNode); ok {
		if filter != nil && noMatch(toLower(filter.CveID), cveIDNode.cveID) {
			return nil, nil
		}
		cveIDList = append(cveIDList, &model.CVEId{
			ID:    nodeID(cveIDNode.id),
			CveID: cveIDNode.cveID,
		})
		node = c.index[cveIDNode.parent]
	}

	cveNode, ok := node.(*cveNode)
	if !ok {
		return nil, gqlerror.Errorf("ID does not match expected node type for cve root")
	}
	s := model.Cve{
		ID:     nodeID(cveNode.id),
		Year:   cveNode.year,
		CveIds: cveIDList,
	}
	return &s, nil
}

func getCveIDFromInput(c *demoClient, input model.CVEInputSpec) (uint32, error) {
	cveStruct, hasCve := c.cves[input.Year]
	if !hasCve {
		return 0, gqlerror.Errorf("cve year \"%d\" not found", input.Year)
	}
	cveIDs := cveStruct.cveIDs
	cveID := strings.ToLower(input.CveID)

	cveIDStruct, hasCveID := cveIDs[cveID]
	if !hasCveID {
		return 0, gqlerror.Errorf("cve id \"%s\" not found", input.CveID)
	}

	return cveIDStruct.id, nil
}
