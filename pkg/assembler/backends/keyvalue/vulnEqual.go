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
	"slices"
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
}

func (n *vulnerabilityEqualLink) ID() string { return n.ThisID }
func (n *vulnerabilityEqualLink) Key() string {
	return strings.Join([]string{
		fmt.Sprint(n.Vulnerabilities),
		n.Justification,
		n.Origin,
		n.Collector,
	}, ":")
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

func (c *demoClient) IngestVulnEquals(ctx context.Context, vulnerabilities []*model.VulnerabilityInputSpec, otherVulnerabilities []*model.VulnerabilityInputSpec, vulnEquals []*model.VulnEqualInputSpec) ([]string, error) {
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

func (c *demoClient) IngestVulnEqual(ctx context.Context, vulnerability model.VulnerabilityInputSpec, otherVulnerability model.VulnerabilityInputSpec, vulnEqual model.VulnEqualInputSpec) (string, error) {
	return c.ingestVulnEqual(ctx, vulnerability, otherVulnerability, vulnEqual, true)
}

func (c *demoClient) ingestVulnEqual(ctx context.Context, vulnerability model.VulnerabilityInputSpec, otherVulnerability model.VulnerabilityInputSpec, vulnEqual model.VulnEqualInputSpec, readOnly bool) (string, error) {
	funcName := "ingestVulnEqual"

	in := &vulnerabilityEqualLink{
		Justification: vulnEqual.Justification,
		Origin:        vulnEqual.Origin,
		Collector:     vulnEqual.Collector,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	vIDs := make([]string, 0, 2)
	vs := make([]*vulnIDNode, 0, 2)
	for _, vi := range []model.VulnerabilityInputSpec{vulnerability, otherVulnerability} {
		v, err := c.getVulnerabilityFromInput(ctx, vi)
		if err != nil {
			return "", gqlerror.Errorf("%v :: %v", funcName, err)
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
			out, err = c.addVulnIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		veKeys, err := c.kv.Keys(ctx, vulnEqCol)
		if err != nil {
			return nil, err
		}
		for _, vek := range veKeys {
			link, err := byKeykv[*vulnerabilityEqualLink](ctx, vulnEqCol, vek, c)
			if err != nil {
				return nil, err
			}
			out, err = c.addVulnIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}
	return out, nil
}

func (c *demoClient) addVulnIfMatch(ctx context.Context, out []*model.VulnEqual,
	filter *model.VulnEqualSpec, link *vulnerabilityEqualLink) (
	[]*model.VulnEqual, error,
) {
	if noMatch(filter.Justification, link.Justification) ||
		noMatch(filter.Origin, link.Origin) ||
		noMatch(filter.Collector, link.Collector) {
		return out, nil
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
			return out, nil
		}
	}
	ve, err := c.convVulnEqual(ctx, link)
	if err != nil {
		return nil, err
	}
	return append(out, ve), nil
}
