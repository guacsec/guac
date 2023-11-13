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
	"strings"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
)

// Internal data: link between packages and dependent packages (isDependency)
type isDependencyLink struct {
	ThisID         string
	PackageID      string
	DepPackageID   string
	VersionRange   string
	DependencyType model.DependencyType
	Justification  string
	Origin         string
	Collector      string
}

func (n *isDependencyLink) ID() string { return n.ThisID }
func (n *isDependencyLink) Key() string {
	return strings.Join([]string{
		n.PackageID,
		n.DepPackageID,
		n.VersionRange,
		string(n.DependencyType),
		n.Justification,
		n.Origin,
		n.Collector,
	}, ":")
}

func (n *isDependencyLink) Neighbors(allowedEdges edgeMap) []string {
	if allowedEdges[model.EdgeIsDependencyPackage] {
		return []string{n.PackageID, n.DepPackageID}
	}
	return []string{}
}

func (n *isDependencyLink) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildIsDependency(ctx, n, nil, true)
}

// Ingest IngestDependencies

func (c *demoClient) IngestDependencies(ctx context.Context, pkgs []*model.PkgInputSpec, depPkgs []*model.PkgInputSpec, depPkgMatchType model.MatchFlags, dependencies []*model.IsDependencyInputSpec) ([]*model.IsDependency, error) {
	// TODO(LUMJJB): match flags

	var modelIsDependencies []*model.IsDependency
	for i := range dependencies {
		isDependency, err := c.IngestDependency(ctx, *pkgs[i], *depPkgs[i], depPkgMatchType, *dependencies[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestDependency failed with err: %v", err)
		}
		modelIsDependencies = append(modelIsDependencies, isDependency)
	}
	return modelIsDependencies, nil
}

// Ingest IsDependency
func (c *demoClient) IngestDependency(ctx context.Context, packageArg model.PkgInputSpec, dependentPackageArg model.PkgInputSpec, depPkgMatchType model.MatchFlags, dependency model.IsDependencyInputSpec) (*model.IsDependency, error) {
	return c.ingestDependency(ctx, packageArg, dependentPackageArg, depPkgMatchType, dependency, true)
}

func (c *demoClient) ingestDependency(ctx context.Context, packageArg model.PkgInputSpec, dependentPackageArg model.PkgInputSpec, depPkgMatchType model.MatchFlags, dependency model.IsDependencyInputSpec, readOnly bool) (*model.IsDependency, error) {
	funcName := "IngestDependency"

	inLink := &isDependencyLink{
		VersionRange:   dependency.VersionRange,
		DependencyType: dependency.DependencyType,
		Justification:  dependency.Justification,
		Origin:         dependency.Origin,
		Collector:      dependency.Collector,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	// for IsDependency the dependent package will return the ID at the
	// packageName node. VersionRange will be used to specify the versions are
	// the attestation relates to
	foundPkgVersion, err := c.getPackageVerFromInput(ctx, packageArg)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	inLink.PackageID = foundPkgVersion.ThisID

	depPkg, err := c.getPackageNameOrVerFromInput(ctx, dependentPackageArg, depPkgMatchType)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	inLink.DepPackageID = depPkg.ID()

	outLink, err := byKeykv[*isDependencyLink](ctx, isDepCol, inLink.Key(), c)
	if err == nil {
		return c.buildIsDependency(ctx, outLink, nil, true)
	}
	if !errors.Is(err, kv.NotFoundError) {
		return nil, err
	}

	if readOnly {
		c.m.RUnlock()
		d, err := c.ingestDependency(ctx, packageArg, dependentPackageArg, depPkgMatchType, dependency, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return d, err
	}

	inLink.ThisID = c.getNextID()
	if err := c.addToIndex(ctx, isDepCol, inLink); err != nil {
		return nil, err
	}
	if err := foundPkgVersion.setIsDependencyLinks(ctx, inLink.ThisID, c); err != nil {
		return nil, err
	}
	if err := depPkg.setIsDependencyLinks(ctx, inLink.ThisID, c); err != nil {
		return nil, err
	}
	if err := setkv(ctx, isDepCol, inLink, c); err != nil {
		return nil, err
	}
	outLink = inLink

	return c.buildIsDependency(ctx, outLink, nil, true)
}

// Query IsDependency
func (c *demoClient) IsDependency(ctx context.Context, filter *model.IsDependencySpec) ([]*model.IsDependency, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	funcName := "IsDependency"

	if filter != nil && filter.ID != nil {
		link, err := byIDkv[*isDependencyLink](ctx, *filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		foundIsDependency, err := c.buildIsDependency(ctx, link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.IsDependency{foundIsDependency}, nil
	}

	var search []string
	foundOne := false
	if filter != nil && filter.Package != nil {
		pkgs, err := c.findPackageVersion(ctx, filter.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		foundOne = len(pkgs) > 0
		for _, pkg := range pkgs {
			search = append(search, pkg.IsDependencyLinks...)
		}
	}
	if !foundOne && filter != nil && filter.DependencyPackage != nil {
		if filter.DependencyPackage.Version == nil { // FIXME this logic isn't exactly correct
			exactPackage, err := c.exactPackageName(ctx, filter.DependencyPackage)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			if exactPackage != nil {
				search = append(search, exactPackage.IsDependencyLinks...)
				foundOne = true
			}
		} else {
			pkgs, err := c.findPackageVersion(ctx, filter.DependencyPackage)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			foundOne = len(pkgs) > 0
			for _, pkg := range pkgs {
				search = append(search, pkg.IsDependencyLinks...)
			}
		}
	}

	var out []*model.IsDependency
	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*isDependencyLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addDepIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		depKeys, err := c.kv.Keys(ctx, isDepCol)
		if err != nil {
			return nil, err
		}
		for _, depKey := range depKeys {
			link, err := byKeykv[*isDependencyLink](ctx, isDepCol, depKey, c)
			if err != nil {
				return nil, err
			}
			out, err = c.addDepIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}

	return out, nil
}

func (c *demoClient) buildIsDependency(ctx context.Context, link *isDependencyLink, filter *model.IsDependencySpec, ingestOrIDProvided bool) (*model.IsDependency, error) {
	var p *model.Package
	var dep *model.Package
	var err error
	if filter != nil {
		p, err = c.buildPackageResponse(ctx, link.PackageID, filter.Package)
		if err != nil {
			return nil, err
		}
	} else {
		p, err = c.buildPackageResponse(ctx, link.PackageID, nil)
		if err != nil {
			return nil, err
		}
	}
	if filter != nil && filter.DependencyPackage != nil {
		depPkgFilter := &model.PkgSpec{Type: filter.DependencyPackage.Type, Namespace: filter.DependencyPackage.Namespace,
			Name: filter.DependencyPackage.Name}
		dep, err = c.buildPackageResponse(ctx, link.DepPackageID, depPkgFilter)
		if err != nil {
			return nil, err
		}
	} else {
		dep, err = c.buildPackageResponse(ctx, link.DepPackageID, nil)
		if err != nil {
			return nil, err
		}
	}

	// if package not found during ingestion or if ID is provided in filter, send error. On query do not send error to continue search
	if p == nil && ingestOrIDProvided {
		return nil, gqlerror.Errorf("failed to retrieve package via packageID")
	} else if p == nil && !ingestOrIDProvided {
		return nil, nil
	}
	// if dependent package not found during ingestion or if ID is provided in filter, send error. On query do not send error to continue search
	if dep == nil && ingestOrIDProvided {
		return nil, gqlerror.Errorf("failed to retrieve dependent package via dependent packageID")
	} else if dep == nil && !ingestOrIDProvided {
		return nil, nil
	}

	foundIsDependency := model.IsDependency{
		ID:                link.ThisID,
		Package:           p,
		DependencyPackage: dep,
		VersionRange:      link.VersionRange,
		DependencyType:    link.DependencyType,
		Justification:     link.Justification,
		Origin:            link.Origin,
		Collector:         link.Collector,
	}
	return &foundIsDependency, nil
}

func (c *demoClient) addDepIfMatch(ctx context.Context, out []*model.IsDependency,
	filter *model.IsDependencySpec, link *isDependencyLink) (
	[]*model.IsDependency, error) {
	if filter != nil && noMatch(filter.Justification, link.Justification) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Origin, link.Origin) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Collector, link.Collector) {
		return out, nil
	}
	if filter != nil && noMatch(filter.VersionRange, link.VersionRange) {
		return out, nil
	}
	if filter != nil && filter.DependencyType != nil && *filter.DependencyType != link.DependencyType {
		return out, nil
	}

	foundIsDependency, err := c.buildIsDependency(ctx, link, filter, false)
	if err != nil {
		return nil, err
	}
	if foundIsDependency == nil {
		return out, nil
	}
	return append(out, foundIsDependency), nil
}
