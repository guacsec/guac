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
	"slices"
	"sort"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// Internal data: link between equal vulnerabilities (vulnEqual)
type vulnerabilityEqualLink struct {
	ThisID          string
	Vulnerabilities []string
	Justification   string
	Origin          string
	Collector       string
	DocumentRef     string
}

func (n *vulnerabilityEqualLink) ID() string { return n.ThisID }
func (n *vulnerabilityEqualLink) Key() string {
	return hashKey(strings.Join([]string{
		fmt.Sprint(n.Vulnerabilities),
		n.Justification,
		n.Origin,
		n.Collector,
		n.DocumentRef,
	}, ":"))
}

func (n *vulnerabilityEqualLink) Neighbors(allowedEdges edgeMap) []string {
	if allowedEdges[model.EdgeVulnEqualVulnerability] {
		return n.Vulnerabilities
	}
	return nil
}

func (n *vulnerabilityEqualLink) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.convVulnEqual(ctx, n)
}

// Ingest IngestVulnEqual

func (c *demoClient) IngestVulnEquals(ctx context.Context, vulnerabilities []*model.IDorVulnerabilityInput, otherVulnerabilities []*model.IDorVulnerabilityInput, vulnEquals []*model.VulnEqualInputSpec) ([]string, error) {
	var modelHashEqualsIDs []string
	for i := range vulnEquals {
		vulnEqual, err := c.IngestVulnEqual(ctx, *vulnerabilities[i], *otherVulnerabilities[i], *vulnEquals[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestVulnEqual failed with err: %v", err)
		}
		modelHashEqualsIDs = append(modelHashEqualsIDs, vulnEqual)
	}
	return modelHashEqualsIDs, nil
}

func (c *demoClient) IngestVulnEqual(ctx context.Context, vulnerability model.IDorVulnerabilityInput, otherVulnerability model.IDorVulnerabilityInput, vulnEqual model.VulnEqualInputSpec) (string, error) {
	return c.ingestVulnEqual(ctx, vulnerability, otherVulnerability, vulnEqual, true)
}

func (c *demoClient) ingestVulnEqual(ctx context.Context, vulnerability model.IDorVulnerabilityInput, otherVulnerability model.IDorVulnerabilityInput, vulnEqual model.VulnEqualInputSpec, readOnly bool) (string, error) {
	funcName := "ingestVulnEqual"

	in := &vulnerabilityEqualLink{
		Justification: vulnEqual.Justification,
		Origin:        vulnEqual.Origin,
		Collector:     vulnEqual.Collector,
		DocumentRef:   vulnEqual.DocumentRef,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	vIDs := make([]string, 0, 2)
	vs := make([]*vulnIDNode, 0, 2)
	for _, vi := range []model.IDorVulnerabilityInput{vulnerability, otherVulnerability} {
		v, err := c.returnFoundVulnerability(ctx, &vi)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		vs = append(vs, v)
		vIDs = append(vIDs, v.ThisID)
	}
	slices.Sort(vIDs)
	in.Vulnerabilities = vIDs

	out, err := byKeykv[*vulnerabilityEqualLink](ctx, vulnEqCol, in.Key(), c)
	if err == nil {
		return out.ThisID, nil
	}
	if !errors.Is(err, kv.NotFoundError) {
		return "", err
	}

	if readOnly {
		c.m.RUnlock()
		cp, err := c.ingestVulnEqual(ctx, vulnerability, otherVulnerability, vulnEqual, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return cp, err
	}

	in.ThisID = c.getNextID()
	if err := c.addToIndex(ctx, vulnEqCol, in); err != nil {
		return "", err
	}
	for _, v := range vs {
		if err := v.setVulnEqualLinks(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	}
	if err := setkv(ctx, vulnEqCol, in, c); err != nil {
		return "", err
	}

	return in.ThisID, nil
}

func (c *demoClient) convVulnEqual(ctx context.Context, in *vulnerabilityEqualLink) (*model.VulnEqual, error) {
	out := &model.VulnEqual{
		ID:            in.ThisID,
		Justification: in.Justification,
		Origin:        in.Origin,
		Collector:     in.Collector,
		DocumentRef:   in.DocumentRef,
	}
	for _, id := range in.Vulnerabilities {
		v, err := c.buildVulnResponse(ctx, id, nil)
		if err != nil {
			return nil, err
		}
		out.Vulnerabilities = append(out.Vulnerabilities, v)
	}
	return out, nil
}

// Query VulnEqual

func (c *demoClient) VulnEqualList(ctx context.Context, vulnEqualSpec model.VulnEqualSpec, after *string, first *int) (*model.VulnEqualConnection, error) {
	funcName := "VulnEqual"
	c.m.RLock()
	defer c.m.RUnlock()
	if vulnEqualSpec.ID != nil {
		link, err := byIDkv[*vulnerabilityEqualLink](ctx, *vulnEqualSpec.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		ve, err := c.convVulnEqual(ctx, link)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return &model.VulnEqualConnection{
			TotalCount: 1,
			PageInfo: &model.PageInfo{
				HasNextPage: false,
				StartCursor: ptrfrom.String(ve.ID),
				EndCursor:   ptrfrom.String(ve.ID),
			},
			Edges: []*model.VulnEqualEdge{
				{
					Cursor: ve.ID,
					Node:   ve,
				},
			},
		}, nil
	}

	edges := make([]*model.VulnEqualEdge, 0)
	hasNextPage := false
	numNodes := 0
	totalCount := 0

	var search []string
	foundOne := false
	for _, v := range vulnEqualSpec.Vulnerabilities {
		if !foundOne {
			exactVuln, err := c.exactVulnerability(ctx, v)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			if exactVuln != nil {
				search = append(search, exactVuln.VulnEqualLinks...)
				foundOne = true
				break
			}
		}
	}

	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*vulnerabilityEqualLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			ve, err := c.vulnIfMatch(ctx, &vulnEqualSpec, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			if ve == nil {
				continue
			}

			edges = append(edges, &model.VulnEqualEdge{
				Cursor: ve.ID,
				Node:   ve,
			})
		}
	} else {
		currentPage := false

		// If no cursor present start from the top
		if after == nil {
			currentPage = true
		}

		var done bool
		scn := c.kv.Keys(vulnEqCol)
		for !done {
			var veKeys []string
			var err error
			veKeys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}

			sort.Strings(veKeys)
			totalCount = len(veKeys)

			for i, vek := range veKeys {
				link, err := byKeykv[*vulnerabilityEqualLink](ctx, vulnEqCol, vek, c)
				if err != nil {
					return nil, err
				}
				ve, err := c.vulnIfMatch(ctx, &vulnEqualSpec, link)
				if err != nil {
					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
				}

				if ve == nil {
					continue
				}

				if after != nil && !currentPage {
					if ve.ID == *after {
						totalCount = len(veKeys) - (i + 1)
						currentPage = true
					}
					continue
				}

				if first != nil {
					if numNodes < *first {
						edges = append(edges, &model.VulnEqualEdge{
							Cursor: ve.ID,
							Node:   ve,
						})
						numNodes++
					} else if numNodes == *first {
						hasNextPage = true
					}
				} else {
					edges = append(edges, &model.VulnEqualEdge{
						Cursor: ve.ID,
						Node:   ve,
					})
				}
			}
		}
	}

	if len(edges) != 0 {
		return &model.VulnEqualConnection{
			TotalCount: totalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: hasNextPage,
				StartCursor: ptrfrom.String(edges[0].Node.ID),
				EndCursor:   ptrfrom.String(edges[max(numNodes-1, 0)].Node.ID),
			},
			Edges: edges,
		}, nil
	}
	return nil, nil
}

func (c *demoClient) VulnEqual(ctx context.Context, filter *model.VulnEqualSpec) ([]*model.VulnEqual, error) {
	funcName := "VulnEqual"
	c.m.RLock()
	defer c.m.RUnlock()
	if filter.ID != nil {
		link, err := byIDkv[*vulnerabilityEqualLink](ctx, *filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		ve, err := c.convVulnEqual(ctx, link)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.VulnEqual{ve}, nil
	}

	var search []string
	foundOne := false
	for _, v := range filter.Vulnerabilities {
		if !foundOne {
			exactVuln, err := c.exactVulnerability(ctx, v)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			if exactVuln != nil {
				search = append(search, exactVuln.VulnEqualLinks...)
				foundOne = true
				break
			}
		}
	}

	var out []*model.VulnEqual
	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*vulnerabilityEqualLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			ve, err := c.vulnIfMatch(ctx, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out = append(out, ve)
		}
	} else {
		var done bool
		scn := c.kv.Keys(vulnEqCol)
		for !done {
			var veKeys []string
			var err error
			veKeys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}
			for _, vek := range veKeys {
				link, err := byKeykv[*vulnerabilityEqualLink](ctx, vulnEqCol, vek, c)
				if err != nil {
					return nil, err
				}
				ve, err := c.vulnIfMatch(ctx, filter, link)
				if err != nil {
					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
				}
				out = append(out, ve)
			}
		}
	}
	return out, nil
}

func (c *demoClient) vulnIfMatch(ctx context.Context, filter *model.VulnEqualSpec, link *vulnerabilityEqualLink) (
	*model.VulnEqual, error,
) {
	if noMatch(filter.Justification, link.Justification) ||
		noMatch(filter.Origin, link.Origin) ||
		noMatch(filter.Collector, link.Collector) ||
		noMatch(filter.DocumentRef, link.DocumentRef) {
		return nil, nil
	}
	for _, vs := range filter.Vulnerabilities {
		if vs == nil {
			continue
		}
		found := false
		for _, vid := range link.Vulnerabilities {
			v, err := c.buildVulnResponse(ctx, vid, vs)
			if err != nil {
				return nil, err
			}
			if v != nil {
				found = true
			}
		}
		if !found {
			return nil, nil
		}
	}
	ve, err := c.convVulnEqual(ctx, link)
	if err != nil {
		return nil, err
	}
	return ve, nil
}
