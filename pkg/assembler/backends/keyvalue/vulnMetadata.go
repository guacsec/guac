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
	"errors"
	"fmt"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

type vulnerabilityMetadataLink struct {
	ThisID          string
	VulnerabilityID string
	ScoreType       model.VulnerabilityScoreType
	ScoreValue      float64
	Timestamp       time.Time
	Origin          string
	Collector       string
	DocumentRef     string
}

func (n *vulnerabilityMetadataLink) ID() string { return n.ThisID }
func (n *vulnerabilityMetadataLink) Key() string {
	return hashKey(strings.Join([]string{
		n.VulnerabilityID,
		string(n.ScoreType),
		fmt.Sprint(n.ScoreValue), // TODO check that fmt.Sprint(float64) is stable for small diffs (epsilon) fmt.Sprintf("%.2f", f)
		timeKey(n.Timestamp),
		n.Origin,
		n.Collector,
		n.DocumentRef,
	}, ":"))
}

func (n *vulnerabilityMetadataLink) Neighbors(allowedEdges edgeMap) []string {
	if allowedEdges[model.EdgeVulnMetadataVulnerability] {
		return []string{n.VulnerabilityID}
	}
	return nil
}

func (n *vulnerabilityMetadataLink) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildVulnerabilityMetadata(ctx, n, nil, true)
}

// Ingest VulnerabilityMetadata
func (c *demoClient) IngestBulkVulnerabilityMetadata(ctx context.Context, vulnerabilities []*model.IDorVulnerabilityInput, vulnerabilityMetadataList []*model.VulnerabilityMetadataInputSpec) ([]string, error) {
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

func (c *demoClient) IngestVulnerabilityMetadata(ctx context.Context, vulnerability model.IDorVulnerabilityInput, vulnerabilityMetadata model.VulnerabilityMetadataInputSpec) (string, error) {
	return c.ingestVulnerabilityMetadata(ctx, vulnerability, vulnerabilityMetadata, true)
}

func (c *demoClient) ingestVulnerabilityMetadata(ctx context.Context, vulnerability model.IDorVulnerabilityInput, vulnerabilityMetadata model.VulnerabilityMetadataInputSpec, readOnly bool) (string, error) {
	funcName := "IngestVulnerabilityMetadata"

	in := &vulnerabilityMetadataLink{
		Timestamp:   vulnerabilityMetadata.Timestamp,
		ScoreType:   vulnerabilityMetadata.ScoreType,
		ScoreValue:  (vulnerabilityMetadata.ScoreValue),
		Origin:      vulnerabilityMetadata.Origin,
		Collector:   vulnerabilityMetadata.Collector,
		DocumentRef: vulnerabilityMetadata.DocumentRef,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	foundVulnNode, err := c.returnFoundVulnerability(ctx, &vulnerability)
	if err != nil {
		return "", gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	in.VulnerabilityID = foundVulnNode.ID()

	out, err := byKeykv[*vulnerabilityMetadataLink](ctx, vulnMDCol, in.Key(), c)
	if err == nil {
		return out.ThisID, nil
	}
	if !errors.Is(err, kv.NotFoundError) {
		return "", err
	}

	if readOnly {
		c.m.RUnlock()
		cv, err := c.ingestVulnerabilityMetadata(ctx, vulnerability, vulnerabilityMetadata, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return cv, err
	}

	in.ThisID = c.getNextID()
	if err := c.addToIndex(ctx, vulnMDCol, in); err != nil {
		return "", err
	}
	if err := foundVulnNode.setVulnMetadataLinks(ctx, in.ThisID, c); err != nil {
		return "", err
	}
	if err := setkv(ctx, vulnMDCol, in, c); err != nil {
		return "", err
	}

	return in.ThisID, nil
}

// Query VulnerabilityMetadata

func (c *demoClient) VulnerabilityMetadataList(ctx context.Context, vulnerabilityMetadataSpec model.VulnerabilityMetadataSpec, after *string, first *int) (*model.VulnerabilityMetadataConnection, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	funcName := "VulnerabilityMetadata"

	if vulnerabilityMetadataSpec.ID != nil {
		link, err := byIDkv[*vulnerabilityMetadataLink](ctx, *vulnerabilityMetadataSpec.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		foundVulnMetadata, err := c.buildVulnerabilityMetadata(ctx, link, &vulnerabilityMetadataSpec, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}

		return &model.VulnerabilityMetadataConnection{
			TotalCount: 1,
			PageInfo: &model.PageInfo{
				HasNextPage: false,
				StartCursor: ptrfrom.String(foundVulnMetadata.ID),
				EndCursor:   ptrfrom.String(foundVulnMetadata.ID),
			},
			Edges: []*model.VulnerabilityMetadataEdge{
				{
					Cursor: foundVulnMetadata.ID,
					Node:   foundVulnMetadata,
				},
			},
		}, nil
	}

	edges := make([]*model.VulnerabilityMetadataEdge, 0)
	hasNextPage := false
	numNodes := 0
	totalCount := 0

	var search []string
	foundOne := false
	if !foundOne && vulnerabilityMetadataSpec.Vulnerability != nil {
		exactVuln, err := c.exactVulnerability(ctx, vulnerabilityMetadataSpec.Vulnerability)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactVuln != nil {
			search = append(search, exactVuln.VulnMetadataLinks...)
			foundOne = true
		}
	}

	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*vulnerabilityMetadataLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			vmd, err := c.vulnMetadataIfMatch(ctx, &vulnerabilityMetadataSpec, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}

			edges = append(edges, &model.VulnerabilityMetadataEdge{
				Cursor: vmd.ID,
				Node:   vmd,
			})
		}
	} else {
		currentPage := false

		// If no cursor present start from the top
		if after == nil {
			currentPage = true
		}

		var done bool
		scn := c.kv.Keys(vulnMDCol)
		for !done {
			var vmdKeys []string
			var err error
			vmdKeys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}

			sort.Strings(vmdKeys)
			totalCount = len(vmdKeys)

			for i, vmdk := range vmdKeys {
				link, err := byKeykv[*vulnerabilityMetadataLink](ctx, vulnMDCol, vmdk, c)
				if err != nil {
					return nil, err
				}
				vmd, err := c.vulnMetadataIfMatch(ctx, &vulnerabilityMetadataSpec, link)
				if err != nil {
					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
				}

				if after != nil && !currentPage {
					if vmd.ID == *after {
						totalCount = len(vmdKeys) - (i + 1)
						currentPage = true
					}
					continue
				}

				if first != nil {
					if numNodes < *first {
						edges = append(edges, &model.VulnerabilityMetadataEdge{
							Cursor: vmd.ID,
							Node:   vmd,
						})
						numNodes++
					} else if numNodes == *first {
						hasNextPage = true
					}
				} else {
					edges = append(edges, &model.VulnerabilityMetadataEdge{
						Cursor: vmd.ID,
						Node:   vmd,
					})
				}
			}
		}
	}

	if len(edges) != 0 {
		return &model.VulnerabilityMetadataConnection{
			TotalCount: totalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: hasNextPage,
				StartCursor: ptrfrom.String(edges[0].Node.ID),
				EndCursor:   ptrfrom.String(edges[numNodes-1].Node.ID),
			},
			Edges: edges,
		}, nil
	}
	return nil, nil
}

func (c *demoClient) VulnerabilityMetadata(ctx context.Context, filter *model.VulnerabilityMetadataSpec) ([]*model.VulnerabilityMetadata, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	funcName := "VulnerabilityMetadata"

	if filter != nil && filter.ID != nil {
		link, err := byIDkv[*vulnerabilityMetadataLink](ctx, *filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		foundVulnMetadata, err := c.buildVulnerabilityMetadata(ctx, link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.VulnerabilityMetadata{foundVulnMetadata}, nil
	}

	var search []string
	foundOne := false
	if !foundOne && filter != nil && filter.Vulnerability != nil {

		exactVuln, err := c.exactVulnerability(ctx, filter.Vulnerability)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactVuln != nil {
			search = append(search, exactVuln.VulnMetadataLinks...)
			foundOne = true
		}
	}

	var out []*model.VulnerabilityMetadata
	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*vulnerabilityMetadataLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			vmd, err := c.vulnMetadataIfMatch(ctx, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out = append(out, vmd)
		}
	} else {
		var done bool
		scn := c.kv.Keys(vulnMDCol)
		for !done {
			var vmdKeys []string
			var err error
			vmdKeys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}
			for _, vmdk := range vmdKeys {
				link, err := byKeykv[*vulnerabilityMetadataLink](ctx, vulnMDCol, vmdk, c)
				if err != nil {
					return nil, err
				}
				vmd, err := c.vulnMetadataIfMatch(ctx, filter, link)
				if err != nil {
					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
				}
				out = append(out, vmd)
			}
		}
	}

	return out, nil
}

func (c *demoClient) vulnMetadataIfMatch(ctx context.Context, filter *model.VulnerabilityMetadataSpec,
	link *vulnerabilityMetadataLink) (*model.VulnerabilityMetadata, error) {

	if filter != nil && filter.Comparator != nil {
		if filter.ScoreValue == nil {
			return nil, gqlerror.Errorf("comparator set without a vulnerability score being specified")
		}
		switch *filter.Comparator {
		case model.ComparatorEqual:
			if link.ScoreValue != *filter.ScoreValue {
				return nil, nil
			}
		case model.ComparatorGreater, model.ComparatorGreaterEqual:
			if link.ScoreValue < *filter.ScoreValue {
				return nil, nil
			}
		case model.ComparatorLess, model.ComparatorLessEqual:
			if link.ScoreValue > *filter.ScoreValue {
				return nil, nil
			}
		}
	} else {
		if filter != nil && noMatchFloat(filter.ScoreValue, link.ScoreValue) {
			return nil, nil
		}
	}
	if filter != nil && filter.ScoreType != nil && *filter.ScoreType != link.ScoreType {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Collector, link.Collector) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Origin, link.Origin) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.DocumentRef, link.DocumentRef) {
		return nil, nil
	}

	foundVulnMetadata, err := c.buildVulnerabilityMetadata(ctx, link, filter, false)
	if err != nil {
		return nil, fmt.Errorf("failed to build vuln metadata node from link")
	}
	if foundVulnMetadata == nil || reflect.ValueOf(foundVulnMetadata.Vulnerability).IsNil() {
		return nil, nil
	}
	return foundVulnMetadata, nil
}

func (c *demoClient) buildVulnerabilityMetadata(ctx context.Context, link *vulnerabilityMetadataLink, filter *model.VulnerabilityMetadataSpec, ingestOrIDProvided bool) (*model.VulnerabilityMetadata, error) {
	var vuln *model.Vulnerability
	var err error

	if filter != nil && filter.Vulnerability != nil {
		if filter.Vulnerability != nil && link.VulnerabilityID != "" {
			vuln, err = c.buildVulnResponse(ctx, link.VulnerabilityID, filter.Vulnerability)
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
		if link.VulnerabilityID != "" {
			vuln, err = c.buildVulnResponse(ctx, link.VulnerabilityID, nil)
			if err != nil {
				return nil, err
			}
		}
	}

	if link.VulnerabilityID != "" {
		if vuln == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve vuln via vulnID")
		} else if vuln == nil && !ingestOrIDProvided {
			return nil, nil
		}
	}

	vulnMetadata := &model.VulnerabilityMetadata{
		ID:            link.ThisID,
		Vulnerability: vuln,
		Timestamp:     link.Timestamp,
		ScoreType:     model.VulnerabilityScoreType(link.ScoreType),
		ScoreValue:    link.ScoreValue,
		Origin:        link.Origin,
		Collector:     link.Collector,
		DocumentRef:   link.DocumentRef,
	}

	return vulnMetadata, nil
}
