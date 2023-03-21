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

// TODO: convert to unit test
func registerAllOSV(client *demoClient) {
	ctx := context.Background()

	inputs := []model.OSVInputSpec{{
		OsvID: "CVE-2019-13110",
	}, {
		OsvID: "CVE-2014-8139",
	}, {
		OsvID: "CVE-2014-8140",
	}, {
		OsvID: "CVE-2022-26499",
	}, {
		OsvID: "GHSA-h45f-rjvw-2rv2",
	}}
	for _, input := range inputs {
		_, err := client.IngestOsv(ctx, &input)
		if err != nil {
			log.Printf("Error in ingesting: %v\n", err)
		}
	}
}

const osv string = "osv"

// Internal data: osv
type osvMap map[string]*osvNode
type osvNode struct {
	id      uint32
	typeKey string
	osvIDs  osvIDMap
}
type osvIDMap map[string]*osvIDNode
type osvIDNode struct {
	id              uint32
	parent          uint32
	osvID           string
	certifyVulnLink []uint32
	equalVulnLink   []uint32
}

func (n *osvIDNode) getID() uint32 { return n.id }
func (n *osvNode) getID() uint32   { return n.id }

func (n *osvNode) neighbors() []uint32 {
	out := make([]uint32, 0, len(n.osvIDs))
	for _, v := range n.osvIDs {
		out = append(out, v.id)
	}
	return out
}

func (n *osvIDNode) neighbors() []uint32 {
	out := make([]uint32, 0, 1+len(n.certifyVulnLink)+len(n.equalVulnLink))
	out = append(out, n.certifyVulnLink...)
	out = append(out, n.equalVulnLink...)
	out = append(out, n.parent)
	return out
}

func (n *osvIDNode) buildModelNode(c *demoClient) (model.Node, error) {
	return c.buildOsvResponse(n.id, nil)
}
func (n *osvNode) buildModelNode(c *demoClient) (model.Node, error) {
	return c.buildOsvResponse(n.id, nil)
}

// certifyVulnerability back edges
func (n *osvIDNode) setVulnerabilityLink(id uint32) {
	n.certifyVulnLink = append(n.certifyVulnLink, id)
}
func (n *osvIDNode) getVulnerabilityLink() []uint32 { return n.certifyVulnLink }

// isVulnerability back edges
func (n *osvIDNode) setEqualVulnLink(id uint32) {
	n.equalVulnLink = append(n.equalVulnLink, id)
}
func (n *osvIDNode) gettEqualVulnLink() []uint32 { return n.equalVulnLink }

// Ingest OSV
func (c *demoClient) IngestOsv(ctx context.Context, input *model.OSVInputSpec) (*model.Osv, error) {
	osvStruct, hasOsv := c.osvs[osv]
	if !hasOsv {
		osvStruct = &osvNode{
			id:      c.getNextID(),
			typeKey: osv,
			osvIDs:  osvIDMap{},
		}
		c.index[osvStruct.id] = osvStruct
		c.osvs[osv] = osvStruct
	}
	osvIDs := osvStruct.osvIDs
	osvID := strings.ToLower(input.OsvID)

	osvIDStruct, hasOsvID := osvIDs[osvID]
	if !hasOsvID {
		osvIDStruct = &osvIDNode{
			id:     c.getNextID(),
			parent: osvStruct.id,
			osvID:  osvID,
		}
		c.index[osvIDStruct.id] = osvIDStruct
		osvIDs[osvID] = osvIDStruct
	}

	// build return GraphQL type
	return c.buildOsvResponse(osvIDStruct.id, nil)
}

// Query OSV
func (c *demoClient) Osv(ctx context.Context, filter *model.OSVSpec) ([]*model.Osv, error) {
	if filter != nil && filter.ID != nil {
		id, err := strconv.Atoi(*filter.ID)
		if err != nil {
			return nil, err
		}
		osv, err := c.buildOsvResponse(uint32(id), filter)
		if err != nil {
			return nil, err
		}
		return []*model.Osv{osv}, nil
	}
	out := []*model.Osv{}
	for _, osvNode := range c.osvs {
		osvIDList := []*model.OSVId{}
		if filter != nil && filter.OsvID != nil {
			osvIDNode, hasOsvIDNode := osvNode.osvIDs[strings.ToLower(*filter.OsvID)]
			if hasOsvIDNode {
				osvIDList = append(osvIDList, &model.OSVId{
					ID:    nodeID(osvIDNode.id),
					OsvID: osvIDNode.osvID,
				})
			}
		} else {
			for _, osvIDNode := range osvNode.osvIDs {
				osvIDList = append(osvIDList, &model.OSVId{
					ID:    nodeID(osvIDNode.id),
					OsvID: osvIDNode.osvID,
				})
			}
		}
		if len(osvIDList) > 0 {
			out = append(out, &model.Osv{
				ID:     nodeID(osvNode.id),
				OsvIds: osvIDList,
			})
		}
	}
	return out, nil
}

// Builds a model.osv to send as GraphQL response, starting from id.
// The optional filter allows restricting output (on selection operations).
func (c *demoClient) buildOsvResponse(id uint32, filter *model.OSVSpec) (*model.Osv, error) {
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

	osvIDList := []*model.OSVId{}
	if osvIDNode, ok := node.(*osvIDNode); ok {
		if filter != nil && noMatch(toLower(filter.OsvID), osvIDNode.osvID) {
			return nil, nil
		}
		osvIDList = append(osvIDList, &model.OSVId{
			ID:    nodeID(osvIDNode.id),
			OsvID: osvIDNode.osvID,
		})
		node = c.index[osvIDNode.parent]
	}

	osvNode, ok := node.(*osvNode)
	if !ok {
		return nil, gqlerror.Errorf("ID does not match expected node type for osv root")
	}
	s := model.Osv{
		ID:     nodeID(osvNode.id),
		OsvIds: osvIDList,
	}
	return &s, nil
}

func getOsvIDFromInput(c *demoClient, input model.OSVInputSpec) (uint32, error) {
	osvStruct, hasOsv := c.osvs[osv]
	if !hasOsv {
		return 0, gqlerror.Errorf("osv type \"%s\" not found", osv)
	}
	osvIDs := osvStruct.osvIDs
	osvID := strings.ToLower(input.OsvID)

	osvIDStruct, hasOsvID := osvIDs[osvID]
	if !hasOsvID {
		return 0, gqlerror.Errorf("osv id \"%s\" not found", input.OsvID)
	}

	return osvIDStruct.id, nil
}

// TODO: remove
func filterOSVID(osv *model.Osv, osvSpec *model.OSVSpec) (*model.Osv, error) {
	var osvID []*model.OSVId
	for _, id := range osv.OsvIds {
		if osvSpec.OsvID == nil || id.OsvID == strings.ToLower(*osvSpec.OsvID) {
			osvID = append(osvID, id)
		}
	}
	if len(osvID) == 0 {
		return nil, nil
	}
	return &model.Osv{
		OsvIds: osvID,
	}, nil
}
