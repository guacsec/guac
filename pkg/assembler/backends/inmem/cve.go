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

// Internal data: csv
type cveMap map[string]*cveNode
type cveNode struct {
	id               uint32
	year             int
	cveID            string
	certifyVulnLinks []uint32
	equalVulnLinks   []uint32
	vexLinks         []uint32
}

func (n *cveNode) ID() uint32 { return n.id }

func (n *cveNode) Neighbors(allowedEdges edgeMap) []uint32 {
	out := []uint32{}
	if allowedEdges[model.EdgeCertifyVuln] {
		out = append(out, n.certifyVulnLinks...)
	}
	if allowedEdges[model.EdgeIsVulnerability] {
		out = append(out, n.equalVulnLinks...)
	}
	if allowedEdges[model.EdgeCertifyVexStatement] {
		out = append(out, n.vexLinks...)
	}
	return out
}

func (n *cveNode) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildCveResponse(n.id, nil)
}

// certifyVulnerability back edges
func (n *cveNode) setVulnerabilityLinks(id uint32) {
	n.certifyVulnLinks = append(n.certifyVulnLinks, id)
}

// isVulnerability back edges
func (n *cveNode) setEqualVulnLinks(id uint32) {
	n.equalVulnLinks = append(n.equalVulnLinks, id)
}

// certifyVexStatement back edges
func (n *cveNode) setVexLinks(id uint32) {
	n.vexLinks = append(n.vexLinks, id)
}

// Ingest CVE
func (c *demoClient) IngestCve(ctx context.Context, input *model.CVEInputSpec) (*model.Cve, error) {
	return c.ingestCve(ctx, input, true)
}

func (c *demoClient) ingestCve(ctx context.Context, input *model.CVEInputSpec, readOnly bool) (*model.Cve, error) {
	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)
	cveID := strings.ToLower(input.CveID)

	cveIDStruct, hasCveID := c.cves[cveID]
	if !hasCveID {
		if readOnly {
			c.m.RUnlock()
			cve, err := c.ingestCve(ctx, input, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return cve, err
		}
		cveIDStruct = &cveNode{
			id:    c.getNextID(),
			cveID: cveID,
			year:  input.Year,
		}
		c.index[cveIDStruct.id] = cveIDStruct
		c.cves[cveID] = cveIDStruct
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

	var out []*model.Cve
	if filter != nil && filter.CveID != nil {
		foundCveNode, ok := c.cves[strings.ToLower(*filter.CveID)]
		if ok {
			out = append(out, &model.Cve{
				ID:    nodeID(foundCveNode.id),
				Year:  foundCveNode.year,
				CveID: foundCveNode.cveID,
			})
		}
	} else {
		for _, cveNode := range c.cves {
			if filter == nil || filter.Year == nil || *filter.Year == cveNode.year {
				out = append(out, &model.Cve{
					ID:    nodeID(cveNode.id),
					Year:  cveNode.year,
					CveID: cveNode.cveID,
				})
			}
		}
	}
	return out, nil
}

func (c *demoClient) exactCVE(filter *model.CVESpec) (*cveNode, error) {
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
			if c, ok := node.(*cveNode); ok {
				return c, nil
			}
		}
	}
	if filter.CveID != nil {
		if node, ok := c.cves[strings.ToLower(*filter.CveID)]; ok {
			return node, nil
		}
	}
	return nil, nil
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

	var csv *model.Cve
	if cveIDNode, ok := node.(*cveNode); ok {
		if filter != nil && (noMatch(toLower(filter.CveID), cveIDNode.cveID) ||
			(filter.Year != nil && *filter.Year != cveIDNode.year)) {
			return nil, nil
		}
		csv = &model.Cve{
			ID:    nodeID(cveIDNode.id),
			Year:  cveIDNode.year,
			CveID: cveIDNode.cveID,
		}
	}

	return csv, nil
}

func getCveIDFromInput(c *demoClient, input model.CVEInputSpec) (uint32, error) {
	cveID := strings.ToLower(input.CveID)

	cveIDStruct, hasCveID := c.cves[cveID]
	if !hasCveID {
		return 0, gqlerror.Errorf("cve id \"%s\" not found", input.CveID)
	}

	return cveIDStruct.id, nil
}
