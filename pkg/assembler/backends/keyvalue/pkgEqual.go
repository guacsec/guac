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

type pkgEqualStruct struct {
	ThisID        string
	Pkgs          []string
	Justification string
	Origin        string
	Collector     string
}

func (n *pkgEqualStruct) ID() string { return n.ThisID }
func (n *pkgEqualStruct) Key() string {
	return strings.Join([]string{
		fmt.Sprint(n.Pkgs),
		n.Justification,
		n.Origin,
		n.Collector,
	}, ":")
}

func (n *pkgEqualStruct) Neighbors(allowedEdges edgeMap) []string {
	if allowedEdges[model.EdgePkgEqualPackage] {
		return n.Pkgs
	}
	return nil
}

func (n *pkgEqualStruct) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.convPkgEqual(ctx, n)
}

// Ingest PkgEqual

func (c *demoClient) IngestPkgEquals(ctx context.Context, pkgs []*model.PkgInputSpec, otherPackages []*model.PkgInputSpec, pkgEquals []*model.PkgEqualInputSpec) ([]string, error) {
	var modelPkgEqualsIDs []string
	for i := range pkgEquals {
		pkgEqual, err := c.IngestPkgEqualID(ctx, *pkgs[i], *otherPackages[i], *pkgEquals[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestPkgEqual failed with err: %v", err)
		}
		modelPkgEqualsIDs = append(modelPkgEqualsIDs, pkgEqual)
	}
	return modelPkgEqualsIDs, nil
}

func (c *demoClient) convPkgEqual(ctx context.Context, in *pkgEqualStruct) (*model.PkgEqual, error) {
	out := &model.PkgEqual{
		ID:            in.ThisID,
		Justification: in.Justification,
		Origin:        in.Origin,
		Collector:     in.Collector,
	}
	for _, id := range in.Pkgs {
		p, err := c.buildPackageResponse(ctx, id, nil)
		if err != nil {
			return nil, err
		}
		out.Packages = append(out.Packages, p)
	}
	return out, nil
}

func (c *demoClient) IngestPkgEqualID(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, pkgEqual model.PkgEqualInputSpec) (string, error) {
	return c.ingestPkgEqual(ctx, pkg, depPkg, pkgEqual, true)
}

func (c *demoClient) ingestPkgEqual(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, pkgEqual model.PkgEqualInputSpec, readOnly bool) (string, error) {
	funcName := "IngestPkgEqual"

	in := &pkgEqualStruct{
		Justification: pkgEqual.Justification,
		Origin:        pkgEqual.Origin,
		Collector:     pkgEqual.Collector,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	pIDs := make([]string, 0, 2)
	ps := make([]*pkgVersion, 0, 2)
	for _, pi := range []model.PkgInputSpec{pkg, depPkg} {
		p, err := c.getPackageVerFromInput(ctx, pi)
		if err != nil {
			return "", gqlerror.Errorf("%v :: %v", funcName, err)
		}
		ps = append(ps, p)
		pIDs = append(pIDs, p.ThisID)
	}
	slices.Sort(pIDs)
	in.Pkgs = pIDs

	out, err := byKeykv[*pkgEqualStruct](ctx, pkgEqCol, in.Key(), c)
	if err == nil {
		return out.ThisID, nil
	}
	if !errors.Is(err, kv.NotFoundError) {
		return "", err
	}

	if readOnly {
		c.m.RUnlock()
		cp, err := c.ingestPkgEqual(ctx, pkg, depPkg, pkgEqual, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return cp, err
	}

	in.ThisID = c.getNextID()
	if err := c.addToIndex(ctx, pkgEqCol, in); err != nil {
		return "", err
	}
	for _, p := range ps {
		if err := p.setPkgEquals(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	}
	if err := setkv(ctx, pkgEqCol, in, c); err != nil {
		return "", err
	}

	return in.ThisID, nil
}

// Query PkgEqual

func (c *demoClient) PkgEqual(ctx context.Context, filter *model.PkgEqualSpec) ([]*model.PkgEqual, error) {
	funcName := "PkgEqual"
	c.m.RLock()
	defer c.m.RUnlock()
	if filter.ID != nil {
		link, err := byIDkv[*pkgEqualStruct](ctx, *filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		pe, err := c.convPkgEqual(ctx, link)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.PkgEqual{pe}, nil
	}

	var search []string
	for _, p := range filter.Packages {
		pkgs, err := c.findPackageVersion(ctx, p)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		for _, pkg := range pkgs {
			search = append(search, pkg.PkgEquals...)
		}
	}

	var out []*model.PkgEqual
	if len(search) > 0 {
		for _, id := range search {
			link, err := byIDkv[*pkgEqualStruct](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addCPIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		peKeys, err := c.kv.Keys(ctx, pkgEqCol)
		if err != nil {
			return nil, err
		}
		for _, pek := range peKeys {
			link, err := byKeykv[*pkgEqualStruct](ctx, pkgEqCol, pek, c)
			if err != nil {
				return nil, err
			}
			out, err = c.addCPIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}
	return out, nil
}

func (c *demoClient) addCPIfMatch(ctx context.Context, out []*model.PkgEqual,
	filter *model.PkgEqualSpec, link *pkgEqualStruct) (
	[]*model.PkgEqual, error,
) {
	if noMatch(filter.Justification, link.Justification) ||
		noMatch(filter.Origin, link.Origin) ||
		noMatch(filter.Collector, link.Collector) {
		return out, nil
	}
	for _, ps := range filter.Packages {
		if ps == nil {
			continue
		}
		found := false
		for _, pid := range link.Pkgs {
			p, err := c.buildPackageResponse(ctx, pid, ps)
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
	pe, err := c.convPkgEqual(ctx, link)
	if err != nil {
		return nil, err
	}
	return append(out, pe), nil
}
