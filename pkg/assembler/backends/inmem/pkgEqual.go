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

	"github.com/vektah/gqlparser/v2/gqlerror"
	"golang.org/x/exp/slices"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type pkgEqualList []*pkgEqualStruct
type pkgEqualStruct struct {
	id            uint32
	pkgs          []uint32
	justification string
	origin        string
	collector     string
}

func (n *pkgEqualStruct) ID() uint32 { return n.id }

func (n *pkgEqualStruct) Neighbors(allowedEdges edgeMap) []uint32 {
	if allowedEdges[model.EdgePkgEqualPackage] {
		return n.pkgs
	}
	return []uint32{}
}

func (n *pkgEqualStruct) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.convPkgEqual(n)
}

// Ingest PkgEqual

func (c *demoClient) IngestPkgEquals(ctx context.Context, pkgs []*model.PkgInputSpec, otherPackages []*model.PkgInputSpec, pkgEquals []*model.PkgEqualInputSpec) ([]string, error) {
	var modelPkgEqualsIDs []string
	for i := range pkgEquals {
		pkgEqual, err := c.IngestPkgEqual(ctx, *pkgs[i], *otherPackages[i], *pkgEquals[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestPkgEqual failed with err: %v", err)
		}
		modelPkgEqualsIDs = append(modelPkgEqualsIDs, pkgEqual.ID)
	}
	return modelPkgEqualsIDs, nil
}

func (c *demoClient) convPkgEqual(in *pkgEqualStruct) (*model.PkgEqual, error) {
	out := &model.PkgEqual{
		ID:            nodeID(in.id),
		Justification: in.justification,
		Origin:        in.origin,
		Collector:     in.collector,
	}
	for _, id := range in.pkgs {
		p, err := c.buildPackageResponse(id, nil)
		if err != nil {
			return nil, err
		}
		out.Packages = append(out.Packages, p)
	}
	return out, nil
}

func (c *demoClient) IngestPkgEqual(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, pkgEqual model.PkgEqualInputSpec) (*model.PkgEqual, error) {
	return c.ingestPkgEqual(ctx, pkg, depPkg, pkgEqual, true)
}

func (c *demoClient) ingestPkgEqual(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, pkgEqual model.PkgEqualInputSpec, readOnly bool) (*model.PkgEqual, error) {
	funcName := "IngestPkgEqual"
	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	pIDs := make([]uint32, 0, 2)
	for _, pi := range []model.PkgInputSpec{pkg, depPkg} {
		pid, err := getPackageIDFromInput(c, pi, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion})
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		pIDs = append(pIDs, pid)
	}
	slices.Sort(pIDs)

	ps := make([]*pkgVersionNode, 0, 2)
	for _, pID := range pIDs {
		p, _ := byID[*pkgVersionNode](pID, c)
		ps = append(ps, p)
	}

	for _, id := range ps[0].pkgEquals {
		cp, err := byID[*pkgEqualStruct](id, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if slices.Equal(cp.pkgs, pIDs) &&
			cp.justification == pkgEqual.Justification &&
			cp.origin == pkgEqual.Origin &&
			cp.collector == pkgEqual.Collector {
			return c.convPkgEqual(cp)
		}
	}

	if readOnly {
		c.m.RUnlock()
		cp, err := c.ingestPkgEqual(ctx, pkg, depPkg, pkgEqual, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return cp, err
	}

	cp := &pkgEqualStruct{
		id:            c.getNextID(),
		pkgs:          pIDs,
		justification: pkgEqual.Justification,
		origin:        pkgEqual.Origin,
		collector:     pkgEqual.Collector,
	}
	c.index[cp.id] = cp
	for _, p := range ps {
		p.setPkgEquals(cp.id)
	}
	c.pkgEquals = append(c.pkgEquals, cp)

	return c.convPkgEqual(cp)
}

// Query PkgEqual

func (c *demoClient) PkgEqual(ctx context.Context, filter *model.PkgEqualSpec) ([]*model.PkgEqual, error) {
	funcName := "PkgEqual"
	c.m.RLock()
	defer c.m.RUnlock()
	if filter.ID != nil {
		id64, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: invalid ID %s", funcName, err)
		}
		id := uint32(id64)
		link, err := byID[*pkgEqualStruct](id, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		pe, err := c.convPkgEqual(link)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.PkgEqual{pe}, nil
	}

	var search []uint32
	foundOne := false
	for _, p := range filter.Packages {
		if !foundOne {
			exactPackage, err := c.exactPackageVersion(p)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			if exactPackage != nil {
				search = append(search, exactPackage.pkgEquals...)
				foundOne = true
				break
			}
		}
	}

	var out []*model.PkgEqual
	if foundOne {
		for _, id := range search {
			link, err := byID[*pkgEqualStruct](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addCPIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.pkgEquals {
			var err error
			out, err = c.addCPIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}
	return out, nil
}

func (c *demoClient) addCPIfMatch(out []*model.PkgEqual,
	filter *model.PkgEqualSpec, link *pkgEqualStruct) (
	[]*model.PkgEqual, error) {

	if noMatch(filter.Justification, link.justification) ||
		noMatch(filter.Origin, link.origin) ||
		noMatch(filter.Collector, link.collector) {
		return out, nil
	}
	for _, ps := range filter.Packages {
		if ps == nil {
			continue
		}
		found := false
		for _, pid := range link.pkgs {
			p, err := c.buildPackageResponse(pid, ps)
			if err != nil {
				return nil, err
			}
			if p != nil {
				found = true
			}
		}
		if !found {
			return out, nil
		}
	}
	pe, err := c.convPkgEqual(link)
	if err != nil {
		return nil, err
	}
	return append(out, pe), nil
}
