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
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

type vulnerabilityMetadataList []*vulnerabilityMetadataLink
type vulnerabilityMetadataLink struct {
	id              uint32
	vulnerabilityID uint32
	scoreType       model.VulnerabilityScoreType
	scoreValue      float64
	timestamp       time.Time
	origin          string
	collector       string
}

func (n *vulnerabilityMetadataLink) ID() uint32 { return n.id }

func (n *vulnerabilityMetadataLink) Neighbors(allowedEdges edgeMap) []uint32 {
	out := make([]uint32, 0, 1)
	if allowedEdges[model.EdgeVulnMetadataVulnerability] {
		out = append(out, n.vulnerabilityID)
	}
	return out
}

func (n *vulnerabilityMetadataLink) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildVulnerabilityMetadata(n, nil, true)
}

// Ingest VulnerabilityMetadata
func (c *demoClient) IngestBulkVulnerabilityMetadata(ctx context.Context, vulnerabilities []*model.VulnerabilityInputSpec, vulnerabilityMetadataList []*model.VulnerabilityMetadataInputSpec) ([]string, error) {
	var modelVulnMetadataIDList []string
	for i := range vulnerabilityMetadataList {
		vulnMetadata, err := c.IngestVulnerabilityMetadata(ctx, *vulnerabilities[i], *vulnerabilityMetadataList[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestVulnerabilityMetadata failed with err: %v", err)
		}
		modelVulnMetadataIDList = append(modelVulnMetadataIDList, vulnMetadata)
	}
	return modelVulnMetadataIDList, nil
}

func (c *demoClient) IngestVulnerabilityMetadata(ctx context.Context, vulnerability model.VulnerabilityInputSpec, vulnerabilityMetadata model.VulnerabilityMetadataInputSpec) (string, error) {
	return c.ingestVulnerabilityMetadata(ctx, vulnerability, vulnerabilityMetadata, true)
}

func (c *demoClient) ingestVulnerabilityMetadata(ctx context.Context, vulnerability model.VulnerabilityInputSpec, vulnerabilityMetadata model.VulnerabilityMetadataInputSpec, readOnly bool) (string, error) {
	funcName := "IngestVulnerabilityMetadata"
	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var vulnerabilityLinks []uint32

	vulnID, err := getVulnerabilityIDFromInput(c, vulnerability)
	if err != nil {
		return "", gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	foundVulnNode, err := byID[*vulnIDNode](vulnID, c)
	if err != nil {
		return "", gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	vulnerabilityLinks = foundVulnNode.vulnMetadataLinks

	searchIDs := vulnerabilityLinks

	// Don't insert duplicates
	duplicate := false
	var collectedVulnMetadataLink *vulnerabilityMetadataLink
	for _, id := range searchIDs {
		v, err := byID[*vulnerabilityMetadataLink](id, c)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		vulnMatch := false
		if vulnID != 0 && vulnID == v.vulnerabilityID {
			vulnMatch = true
		}
		if vulnMatch && vulnerabilityMetadata.Timestamp.Equal(v.timestamp) && vulnerabilityMetadata.ScoreType == v.scoreType &&
			floatEqual(vulnerabilityMetadata.ScoreValue, v.scoreValue) &&
			vulnerabilityMetadata.Origin == v.origin && vulnerabilityMetadata.Collector == v.collector {

			collectedVulnMetadataLink = v
			duplicate = true
			break
		}
	}

	if !duplicate {
		if readOnly {
			c.m.RUnlock()
			cv, err := c.ingestVulnerabilityMetadata(ctx, vulnerability, vulnerabilityMetadata, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return cv, err
		}
		// store the link
		collectedVulnMetadataLink = &vulnerabilityMetadataLink{
			id:              c.getNextID(),
			vulnerabilityID: vulnID,
			timestamp:       vulnerabilityMetadata.Timestamp,
			scoreType:       vulnerabilityMetadata.ScoreType,
			scoreValue:      (vulnerabilityMetadata.ScoreValue),
			origin:          vulnerabilityMetadata.Origin,
			collector:       vulnerabilityMetadata.Collector,
		}
		c.index[collectedVulnMetadataLink.id] = collectedVulnMetadataLink
		c.vulnerabilityMetadatas = append(c.vulnerabilityMetadatas, collectedVulnMetadataLink)
		// set the backlinks
		foundVulnNode.setVulnMetadataLinks(collectedVulnMetadataLink.id)
	}

	return nodeID(collectedVulnMetadataLink.id), nil
}

// Query VulnerabilityMetadata
func (c *demoClient) VulnerabilityMetadata(ctx context.Context, filter *model.VulnerabilityMetadataSpec) ([]*model.VulnerabilityMetadata, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	funcName := "VulnerabilityMetadata"

	if filter != nil && filter.ID != nil {
		id64, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: invalid ID %s", funcName, err)
		}
		id := uint32(id64)
		link, err := byID[*vulnerabilityMetadataLink](id, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		foundVulnMetadata, err := c.buildVulnerabilityMetadata(link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.VulnerabilityMetadata{foundVulnMetadata}, nil
	}

	var search []uint32
	foundOne := false
	if !foundOne && filter != nil && filter.Vulnerability != nil {

		exactVuln, err := c.exactVulnerability(filter.Vulnerability)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactVuln != nil {
			search = append(search, exactVuln.vulnMetadataLinks...)
			foundOne = true
		}
	}

	var out []*model.VulnerabilityMetadata
	if foundOne {
		for _, id := range search {
			link, err := byID[*vulnerabilityMetadataLink](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addVulnMetadataMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.vulnerabilityMetadatas {
			var err error
			out, err = c.addVulnMetadataMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}

	return out, nil
}

func (c *demoClient) addVulnMetadataMatch(out []*model.VulnerabilityMetadata,
	filter *model.VulnerabilityMetadataSpec,
	link *vulnerabilityMetadataLink) ([]*model.VulnerabilityMetadata, error) {

	if filter != nil && filter.Timestamp != nil && !filter.Timestamp.Equal(link.timestamp) {
		return out, nil
	}
	if filter != nil && filter.Comparator != nil {
		if filter.ScoreValue == nil {
			return out, gqlerror.Errorf("comparator set without a vulnerability score being specified")
		}
		switch *filter.Comparator {
		case model.ComparatorEqual:
			if link.scoreValue != *filter.ScoreValue {
				return out, nil
			}
		case model.ComparatorGreater, model.ComparatorGreaterEqual:
			if link.scoreValue < *filter.ScoreValue {
				return out, nil
			}
		case model.ComparatorLess, model.ComparatorLessEqual:
			if link.scoreValue > *filter.ScoreValue {
				return out, nil
			}
		}
	} else {
		if filter != nil && noMatchFloat(filter.ScoreValue, link.scoreValue) {
			return out, nil
		}
	}
	if filter != nil && filter.ScoreType != nil && *filter.ScoreType != link.scoreType {
		return out, nil
	}
	if filter != nil && noMatch(filter.Collector, link.collector) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Origin, link.origin) {
		return out, nil
	}

	foundVulnMetadata, err := c.buildVulnerabilityMetadata(link, filter, false)
	if err != nil {
		return nil, fmt.Errorf("failed to build vuln metadata node from link")
	}
	if foundVulnMetadata == nil || reflect.ValueOf(foundVulnMetadata.Vulnerability).IsNil() {
		return out, nil
	}
	return append(out, foundVulnMetadata), nil
}

func (c *demoClient) buildVulnerabilityMetadata(link *vulnerabilityMetadataLink, filter *model.VulnerabilityMetadataSpec, ingestOrIDProvided bool) (*model.VulnerabilityMetadata, error) {
	var vuln *model.Vulnerability
	var err error

	if filter != nil && filter.Vulnerability != nil {
		if filter.Vulnerability != nil && link.vulnerabilityID != 0 {
			vuln, err = c.buildVulnResponse(link.vulnerabilityID, filter.Vulnerability)
			if err != nil {
				return nil, err
			}
			if filter.Vulnerability.NoVuln != nil && !*filter.Vulnerability.NoVuln {
				if vuln != nil {
					if vuln.Type == noVulnType {
						vuln = nil
					}
				}
			}
		}
	} else {
		if link.vulnerabilityID != 0 {
			vuln, err = c.buildVulnResponse(link.vulnerabilityID, nil)
			if err != nil {
				return nil, err
			}
		}
	}

	if link.vulnerabilityID != 0 {
		if vuln == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve vuln via vulnID")
		} else if vuln == nil && !ingestOrIDProvided {
			return nil, nil
		}
	}

	vulnMetadata := &model.VulnerabilityMetadata{
		ID:            nodeID(link.id),
		Vulnerability: vuln,
		Timestamp:     link.timestamp,
		ScoreType:     model.VulnerabilityScoreType(link.scoreType),
		ScoreValue:    link.scoreValue,
		Origin:        link.origin,
		Collector:     link.collector,
	}

	return vulnMetadata, nil
}
