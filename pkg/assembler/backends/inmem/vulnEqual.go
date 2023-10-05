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
	"slices"
	"strconv"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// Internal data: link between equal vulnerabilities (vulnEqual)
type (
	vulnerabilityEqualList []*vulnerabilityEqualLink
	vulnerabilityEqualLink struct {
		id              uint32
		vulnerabilities []uint32
		justification   string
		origin          string
		collector       string
	}
)

func (n *vulnerabilityEqualLink) ID() uint32 { return n.id }

func (n *vulnerabilityEqualLink) Neighbors(allowedEdges edgeMap) []uint32 {
	out := make([]uint32, 0, 2)
	if len(n.vulnerabilities) > 0 && allowedEdges[model.EdgeVulnEqualVulnerability] {
		out = append(out, n.vulnerabilities...)
	}
	return out
}

func (n *vulnerabilityEqualLink) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.convVulnEqual(n)
}

// Ingest IngestVulnEqual

func (c *demoClient) IngestVulnEquals(ctx context.Context, vulnerabilities []*model.VulnerabilityInputSpec, otherVulnerabilities []*model.VulnerabilityInputSpec, vulnEquals []*model.VulnEqualInputSpec) ([]string, error) {
	var modelHashEqualsIDs []string
	for i := range vulnEquals {
		vulnEqual, err := c.IngestVulnEqual(ctx, *vulnerabilities[i], *otherVulnerabilities[i], *vulnEquals[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestVulnEqual failed with err: %v", err)
		}
		modelHashEqualsIDs = append(modelHashEqualsIDs, vulnEqual.ID)
	}
	return modelHashEqualsIDs, nil
}

func (c *demoClient) IngestVulnEqual(ctx context.Context, vulnerability model.VulnerabilityInputSpec, otherVulnerability model.VulnerabilityInputSpec, vulnEqual model.VulnEqualInputSpec) (*model.VulnEqual, error) {
	return c.ingestVulnEqual(ctx, vulnerability, otherVulnerability, vulnEqual, true)
}

func (c *demoClient) ingestVulnEqual(ctx context.Context, vulnerability model.VulnerabilityInputSpec, otherVulnerability model.VulnerabilityInputSpec, vulnEqual model.VulnEqualInputSpec, readOnly bool) (*model.VulnEqual, error) {
	funcName := "ingestVulnEqual"
	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	vIDs := make([]uint32, 0, 2)
	for _, vi := range []model.VulnerabilityInputSpec{vulnerability, otherVulnerability} {
		vid, err := getVulnerabilityIDFromInput(c, vi)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		vIDs = append(vIDs, vid)
	}
	slices.Sort(vIDs)

	vs := make([]*vulnIDNode, 0, 2)
	for _, vID := range vIDs {
		v, _ := byID[*vulnIDNode](vID, c)
		vs = append(vs, v)
	}

	for _, id := range vs[0].vulnEqualLinks {
		ve, err := byID[*vulnerabilityEqualLink](id, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if slices.Equal(ve.vulnerabilities, vIDs) &&
			ve.justification == vulnEqual.Justification &&
			ve.origin == vulnEqual.Origin &&
			ve.collector == vulnEqual.Collector {
			return c.convVulnEqual(ve)
		}
	}

	if readOnly {
		c.m.RUnlock()
		cp, err := c.ingestVulnEqual(ctx, vulnerability, otherVulnerability, vulnEqual, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return cp, err
	}

	ve := &vulnerabilityEqualLink{
		id:              c.getNextID(),
		vulnerabilities: vIDs,
		justification:   vulnEqual.Justification,
		origin:          vulnEqual.Origin,
		collector:       vulnEqual.Collector,
	}
	c.index[ve.id] = ve
	for _, v := range vs {
		v.setVulnEqualLinks(ve.id)
	}
	c.vulnerabilityEquals = append(c.vulnerabilityEquals, ve)

	return c.convVulnEqual(ve)
}

func (c *demoClient) convVulnEqual(in *vulnerabilityEqualLink) (*model.VulnEqual, error) {
	out := &model.VulnEqual{
		ID:            nodeID(in.id),
		Justification: in.justification,
		Origin:        in.origin,
		Collector:     in.collector,
	}
	for _, id := range in.vulnerabilities {
		v, err := c.buildVulnResponse(id, nil)
		if err != nil {
			return nil, err
		}
		out.Vulnerabilities = append(out.Vulnerabilities, v)
	}
	return out, nil
}

// Query VulnEqual
func (c *demoClient) VulnEqual(ctx context.Context, filter *model.VulnEqualSpec) ([]*model.VulnEqual, error) {
	funcName := "VulnEqual"
	c.m.RLock()
	defer c.m.RUnlock()
	if filter.ID != nil {
		id64, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: invalid ID %s", funcName, err)
		}
		id := uint32(id64)
		link, err := byID[*vulnerabilityEqualLink](id, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		ve, err := c.convVulnEqual(link)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.VulnEqual{ve}, nil
	}

	var search []uint32
	foundOne := false
	for _, v := range filter.Vulnerabilities {
		if !foundOne {
			exactVuln, err := c.exactVulnerability(v)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			if exactVuln != nil {
				search = append(search, exactVuln.vulnEqualLinks...)
				foundOne = true
				break
			}
		}
	}

	var out []*model.VulnEqual
	if foundOne {
		for _, id := range search {
			link, err := byID[*vulnerabilityEqualLink](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addVulnIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.vulnerabilityEquals {
			var err error
			out, err = c.addVulnIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}
	return out, nil
}

func (c *demoClient) addVulnIfMatch(out []*model.VulnEqual,
	filter *model.VulnEqualSpec, link *vulnerabilityEqualLink) (
	[]*model.VulnEqual, error,
) {
	if noMatch(filter.Justification, link.justification) ||
		noMatch(filter.Origin, link.origin) ||
		noMatch(filter.Collector, link.collector) {
		return out, nil
	}
	for _, vs := range filter.Vulnerabilities {
		if vs == nil {
			continue
		}
		found := false
		for _, vid := range link.vulnerabilities {
			v, err := c.buildVulnResponse(vid, vs)
			if err != nil {
				return nil, err
			}
			if v != nil {
				found = true
			}
		}
		if !found {
			return out, nil
		}
	}
	ve, err := c.convVulnEqual(link)
	if err != nil {
		return nil, err
	}
	return append(out, ve), nil
}
