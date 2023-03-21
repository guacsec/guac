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
	"context"
	"log"
	"strconv"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func registerAllCVE(client *demoClient) {
	ctx := context.Background()

	inputs := []model.CVEInputSpec{{
		Year:  2019,
		CveID: "CVE-2019-13110",
	}, {
		Year:  2014,
		CveID: "CVE-2014-8139",
	}, {
		Year:  2014,
		CveID: "CVE-2014-8140",
	}, {
		Year:  2022,
		CveID: "CVE-2022-26499",
	}, {
		Year:  2014,
		CveID: "CVE-2014-8140",
	}}
	for _, input := range inputs {
		_, err := client.IngestCve(ctx, &input)
		if err != nil {
			log.Printf("Error in ingesting: %v\n", err)
		}
	}
}

// Internal data: osv
type cveMap map[int]*cveNode
type cveNode struct {
	id     uint32
	year   int
	cveIDs cveIDMap
}
type cveIDMap map[string]*cveIDNode
type cveIDNode struct {
	id              uint32
	parent          uint32
	cveID           string
	certifyVulnLink []uint32
	equalVulnLink   []uint32
}

func (n *cveIDNode) getID() uint32 { return n.id }
func (n *cveNode) getID() uint32   { return n.id }

// certifyVulnerability back edges
func (n *cveIDNode) setVulnerabilityLink(id uint32) {
	n.certifyVulnLink = append(n.certifyVulnLink, id)
}
func (n *cveIDNode) getVulnerabilityLink() []uint32 { return n.certifyVulnLink }

// isVulnerability back edges
func (n *cveIDNode) setEqualVulnLink(id uint32) {
	n.equalVulnLink = append(n.equalVulnLink, id)
}
func (n *cveIDNode) gettEqualVulnLink() []uint32 { return n.equalVulnLink }

// Ingest CVE
func (c *demoClient) IngestCve(ctx context.Context, input *model.CVEInputSpec) (*model.Cve, error) {
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
	if filter != nil && filter.ID != nil {
		id, err := strconv.Atoi(*filter.ID)
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

// TODO: remove
func filterCVEID(cve *model.Cve, cveSpec *model.CVESpec) (*model.Cve, error) {
	var cveID []*model.CVEId
	for _, id := range cve.CveIds {
		if cveSpec.CveID == nil || id.ID == strings.ToLower(*cveSpec.CveID) {
			cveID = append(cveID, id)
		}
	}
	if len(cveID) == 0 {
		return nil, nil
	}
	return &model.Cve{
		Year:   cve.Year,
		CveIds: cveID,
	}, nil
}
