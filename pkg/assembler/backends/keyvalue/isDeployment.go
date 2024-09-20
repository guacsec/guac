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

// import (
// 	"context"
// 	"errors"
// 	"sort"
// 	"strings"
// 	"time"

// 	"github.com/guacsec/guac/internal/testing/ptrfrom"

// 	"github.com/vektah/gqlparser/v2/gqlerror"

// 	"github.com/guacsec/guac/pkg/assembler/backends/helper"
// 	"github.com/guacsec/guac/pkg/assembler/graphql/model"
// 	"github.com/guacsec/guac/pkg/assembler/kv"
// )

// // Internal data: link between packages and deployment(isDeployment)
// type isDeploymentLink struct {
// 	ThisID             string
// 	PackageID          string
// 	DeployedSince      time.Time
// 	DeployedUntil      time.Time
// 	DeploymentMetadata []string
// 	Origin             string
// 	Collector          string
// }

// func (n *isDeploymentLink) ID() string { return n.ThisID }
// func (n *isDeploymentLink) Key() string {
// 	return hashKey(strings.Join([]string{
// 		n.PackageID,
// 		n.DepPackageID,
// 		string(n.DependencyType),
// 		n.Origin,
// 		n.Collector,
// 	}, ":"))
// }

// func (n *isDeploymentLink) Neighbors(allowedEdges edgeMap) []string {
// 	if allowedEdges[model.EdgeIsDependencyPackage] {
// 		return []string{n.PackageID, n.PackageID}
// 	}
// 	return []string{}
// }

// func (n *isDeploymentLink) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
// 	return c.buildIsDeployment(ctx, n, nil, true)
// }

// // Ingest IngestDependencies

// func (c *demoClient) IngestDeployments(ctx context.Context, pkgs []*model.IDorPkgInput, depPkgs []*model.IDorPkgInput, deployments []*model.IsDeployedInputSpec) ([]string, error) {
// 	// TODO(LUMJJB): match flags

// 	var modelIsDeployments []string
// 	for i := range deployments {
// 		isDeployment, err := c.IngestDeployment(ctx, *pkgs[i], *depPkgs[i], *deployments[i])
// 		if err != nil {
// 			return nil, gqlerror.Errorf("IngestDeployment failed with err: %v", err)
// 		}
// 		modelIsDeployments = append(modelIsDeployments, isDeployment)
// 	}
// 	return modelIsDeployments, nil
// }

// // Ingest IsDependency
// func (c *demoClient) IngestDeployment(ctx context.Context, packageArg model.IDorPkgInput, dependentPackageArg model.IDorPkgInput, dependency model.IsDependencyInputSpec) (string, error) {
// 	return c.ingestDeployment(ctx, packageArg, dependentPackageArg, dependency, true)
// }

// func (c *demoClient) ingestDeployment(ctx context.Context, packageArg model.IDorPkgInput, dependentPackageArg model.IDorPkgInput, dependency model.IsDependencyInputSpec, readOnly bool) (string, error) {
// 	funcName := "IngestDeployment"

// 	inLink := &isDependencyLink{
// 		DependencyType: dependency.DependencyType,
// 		Justification:  dependency.Justification,
// 		Origin:         dependency.Origin,
// 		Collector:      dependency.Collector,
// 		DocumentRef:    dependency.DocumentRef,
// 	}
// 	helper.FixDependencyType(&inLink.DependencyType)

// 	lock(&c.m, readOnly)
// 	defer unlock(&c.m, readOnly)

// 	var depPkg *pkgVersion
// 	var err error
// 	depPkg, err = c.returnFoundPkgVersion(ctx, &dependentPackageArg)
// 	if err != nil {
// 		return "", gqlerror.Errorf("%v ::  %s", funcName, err)
// 	}
// 	inLink.DepPackageID = depPkg.ID()

// 	foundPkgVersion, err := c.returnFoundPkgVersion(ctx, &packageArg)
// 	if err != nil {
// 		return "", gqlerror.Errorf("%v ::  %s", funcName, err)
// 	}
// 	inLink.PackageID = foundPkgVersion.ID()

// 	outLink, err := byKeykv[*isDependencyLink](ctx, isDepCol, inLink.Key(), c)
// 	if err == nil {
// 		return outLink.ThisID, nil
// 	}
// 	if !errors.Is(err, kv.NotFoundError) {
// 		return "", err
// 	}

// 	if readOnly {
// 		c.m.RUnlock()
// 		d, err := c.ingestDependency(ctx, packageArg, dependentPackageArg, dependency, false)
// 		c.m.RLock() // relock so that defer unlock does not panic
// 		return d, err
// 	}

// 	inLink.ThisID = c.getNextID()
// 	if err := c.addToIndex(ctx, isDepCol, inLink); err != nil {
// 		return "", err
// 	}
// 	if err := foundPkgVersion.setIsDependencyLinks(ctx, inLink.ThisID, c); err != nil {
// 		return "", err
// 	}
// 	if err := depPkg.setIsDependencyLinks(ctx, inLink.ThisID, c); err != nil {
// 		return "", err
// 	}
// 	if err := setkv(ctx, isDepCol, inLink, c); err != nil {
// 		return "", err
// 	}
// 	outLink = inLink

// 	return outLink.ThisID, nil
// }

// // Query IsDependency

// func (c *demoClient) IsDeploymentList(ctx context.Context, isDependencySpec model.IsDependencySpec, after *string, first *int) (*model.IsDependencyConnection, error) {
// 	c.m.RLock()
// 	defer c.m.RUnlock()
// 	funcName := "IsDeployment"

// 	if isDependencySpec.ID != nil {
// 		link, err := byIDkv[*isDependencyLink](ctx, *isDependencySpec.ID, c)
// 		if err != nil {
// 			// Not found
// 			return nil, nil
// 		}
// 		foundIsDependency, err := c.buildIsDependency(ctx, link, &isDependencySpec, true)
// 		if err != nil {
// 			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
// 		}

// 		return &model.IsDependencyConnection{
// 			TotalCount: 1,
// 			PageInfo: &model.PageInfo{
// 				HasNextPage: false,
// 				StartCursor: ptrfrom.String(foundIsDependency.ID),
// 				EndCursor:   ptrfrom.String(foundIsDependency.ID),
// 			},
// 			Edges: []*model.IsDependencyEdge{
// 				{
// 					Cursor: foundIsDependency.ID,
// 					Node:   foundIsDependency,
// 				},
// 			},
// 		}, nil
// 	}

// 	edges := make([]*model.IsDependencyEdge, 0)
// 	hasNextPage := false
// 	numNodes := 0
// 	totalCount := 0
// 	addToCount := 0

// 	var search []string
// 	foundOne := false
// 	if isDependencySpec.Package != nil {
// 		pkgs, err := c.findPackageVersion(ctx, isDependencySpec.Package)
// 		if err != nil {
// 			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
// 		}
// 		foundOne = len(pkgs) > 0
// 		for _, pkg := range pkgs {
// 			search = append(search, pkg.IsDependencyLinks...)
// 		}
// 	}
// 	// Dont search on DependencyPackage as it can be either package-name or package-version

// 	if foundOne {
// 		for _, id := range search {
// 			link, err := byIDkv[*isDependencyLink](ctx, id, c)
// 			if err != nil {
// 				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
// 			}
// 			dep, err := c.depIfMatch(ctx, &isDependencySpec, link)
// 			if err != nil {
// 				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
// 			}
// 			if dep == nil {
// 				continue
// 			}

// 			if (after != nil && dep.ID > *after) || after == nil {
// 				addToCount += 1

// 				if first != nil {
// 					if numNodes < *first {
// 						edges = append(edges, &model.IsDependencyEdge{
// 							Cursor: dep.ID,
// 							Node:   dep,
// 						})
// 						numNodes++
// 					} else if numNodes == *first {
// 						hasNextPage = true
// 					}
// 				} else {
// 					edges = append(edges, &model.IsDependencyEdge{
// 						Cursor: dep.ID,
// 						Node:   dep,
// 					})
// 				}
// 			}
// 		}
// 	} else {
// 		currentPage := false

// 		// If no cursor present start from the top
// 		if after == nil {
// 			currentPage = true
// 		}

// 		var done bool
// 		scn := c.kv.Keys(isDepCol)
// 		for !done {
// 			var depKeys []string
// 			var err error
// 			depKeys, done, err = scn.Scan(ctx)
// 			if err != nil {
// 				return nil, err
// 			}

// 			sort.Strings(depKeys)
// 			totalCount = len(depKeys)

// 			for i, depKey := range depKeys {
// 				link, err := byKeykv[*isDependencyLink](ctx, isDepCol, depKey, c)
// 				if err != nil {
// 					return nil, err
// 				}
// 				dep, err := c.depIfMatch(ctx, &isDependencySpec, link)
// 				if err != nil {
// 					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
// 				}

// 				if dep == nil {
// 					continue
// 				}

// 				if after != nil && !currentPage {
// 					if dep.ID == *after {
// 						totalCount = len(depKeys) - (i + 1)
// 						currentPage = true
// 					}
// 					continue
// 				}

// 				if first != nil {
// 					if numNodes < *first {
// 						edges = append(edges, &model.IsDependencyEdge{
// 							Cursor: dep.ID,
// 							Node:   dep,
// 						})
// 						numNodes++
// 					} else if numNodes == *first {
// 						hasNextPage = true
// 					}
// 				} else {
// 					edges = append(edges, &model.IsDependencyEdge{
// 						Cursor: dep.ID,
// 						Node:   dep,
// 					})
// 				}
// 			}
// 		}
// 	}

// 	if len(edges) != 0 {
// 		return &model.IsDependencyConnection{
// 			TotalCount: totalCount + addToCount,
// 			PageInfo: &model.PageInfo{
// 				HasNextPage: hasNextPage,
// 				StartCursor: ptrfrom.String(edges[0].Node.ID),
// 				EndCursor:   ptrfrom.String(edges[max(numNodes-1, 0)].Node.ID),
// 			},
// 			Edges: edges,
// 		}, nil
// 	}
// 	return nil, nil
// }

// func (c *demoClient) IsDeployment(ctx context.Context, filter *model.IsDeploymentSpec) ([]*model.IsDependency, error) {
// 	c.m.RLock()
// 	defer c.m.RUnlock()
// 	funcName := "IsDependency"

// 	if filter != nil && filter.ID != nil {
// 		link, err := byIDkv[*isDependencyLink](ctx, *filter.ID, c)
// 		if err != nil {
// 			// Not found
// 			return nil, nil
// 		}
// 		foundIsDependency, err := c.buildIsDependency(ctx, link, filter, true)
// 		if err != nil {
// 			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
// 		}
// 		return []*model.IsDependency{foundIsDependency}, nil
// 	}

// 	var search []string
// 	foundOne := false
// 	if filter != nil && filter.Package != nil {
// 		pkgs, err := c.findPackageVersion(ctx, filter.Package)
// 		if err != nil {
// 			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
// 		}
// 		foundOne = len(pkgs) > 0
// 		for _, pkg := range pkgs {
// 			search = append(search, pkg.IsDependencyLinks...)
// 		}
// 	}
// 	// todo: can add search on DependencyPackage as will be package-version

// 	var out []*model.IsDependency
// 	if foundOne {
// 		for _, id := range search {
// 			link, err := byIDkv[*isDependencyLink](ctx, id, c)
// 			if err != nil {
// 				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
// 			}
// 			dep, err := c.depIfMatch(ctx, filter, link)
// 			if err != nil {
// 				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
// 			}
// 			if dep == nil {
// 				continue
// 			}

// 			out = append(out, dep)
// 		}
// 	} else {
// 		var done bool
// 		scn := c.kv.Keys(isDepCol)
// 		for !done {
// 			var depKeys []string
// 			var err error
// 			depKeys, done, err = scn.Scan(ctx)
// 			if err != nil {
// 				return nil, err
// 			}
// 			for _, depKey := range depKeys {
// 				link, err := byKeykv[*isDependencyLink](ctx, isDepCol, depKey, c)
// 				if err != nil {
// 					return nil, err
// 				}
// 				dep, err := c.depIfMatch(ctx, filter, link)
// 				if err != nil {
// 					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
// 				}
// 				if dep == nil {
// 					continue
// 				}

// 				out = append(out, dep)
// 			}
// 		}
// 	}

// 	return out, nil
// }

// func (c *demoClient) buildIsDeployment(ctx context.Context, link *isDependencyLink, filter *model.IsDependencySpec, ingestOrIDProvided bool) (*model.IsDependency, error) {
// 	var p *model.Package
// 	var dep *model.Package
// 	var err error
// 	if filter != nil {
// 		p, err = c.buildPackageResponse(ctx, link.PackageID, filter.Package)
// 	} else {
// 		p, err = c.buildPackageResponse(ctx, link.PackageID, nil)
// 	}
// 	if err != nil {
// 		return nil, err
// 	}
// 	if filter != nil {
// 		dep, err = c.buildPackageResponse(ctx, link.DepPackageID, filter.DependencyPackage)
// 	} else {
// 		dep, err = c.buildPackageResponse(ctx, link.DepPackageID, nil)
// 	}
// 	if err != nil {
// 		return nil, err
// 	}

// 	// if package not found during ingestion or if ID is provided in filter, send error. On query do not send error to continue search
// 	if p == nil && ingestOrIDProvided {
// 		return nil, gqlerror.Errorf("failed to retrieve package via packageID")
// 	} else if p == nil && !ingestOrIDProvided {
// 		return nil, nil
// 	}
// 	// if dependent package not found during ingestion or if ID is provided in filter, send error. On query do not send error to continue search
// 	if dep == nil && ingestOrIDProvided {
// 		return nil, gqlerror.Errorf("failed to retrieve dependent package via dependent packageID")
// 	} else if dep == nil && !ingestOrIDProvided {
// 		return nil, nil
// 	}

// 	foundIsDependency := model.IsDependency{
// 		ID:                link.ThisID,
// 		Package:           p,
// 		DependencyPackage: dep,
// 		DependencyType:    link.DependencyType,
// 		Justification:     link.Justification,
// 		Origin:            link.Origin,
// 		Collector:         link.Collector,
// 		DocumentRef:       link.DocumentRef,
// 	}
// 	return &foundIsDependency, nil
// }

// func (c *demoClient) depIfMatch(ctx context.Context, filter *model.IsDependencySpec, link *isDependencyLink) (
// 	*model.IsDependency, error) {
// 	if noMatchIsDep(filter, link) {
// 		return nil, nil
// 	}

// 	foundIsDependency, err := c.buildIsDependency(ctx, link, filter, false)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if foundIsDependency == nil {
// 		return nil, nil
// 	}
// 	return foundIsDependency, nil
// }

// func noMatchIsDep(filter *model.IsDependencySpec, link *isDependencyLink) bool {
// 	if filter != nil {
// 		return noMatch(filter.Justification, link.Justification) ||
// 			noMatch(filter.Origin, link.Origin) ||
// 			noMatch(filter.Collector, link.Collector) ||
// 			noMatch(filter.DocumentRef, link.DocumentRef) ||
// 			(filter.DependencyType != nil && *filter.DependencyType != link.DependencyType)
// 	} else {
// 		return false
// 	}
// }

// func (c *demoClient) matchDependencies(ctx context.Context, filters []*model.IsDependencySpec, depLinkIDs []string) bool {
// 	var depLinks []*isDependencyLink
// 	if len(filters) > 0 {
// 		for _, depLinkID := range depLinkIDs {
// 			link, err := byIDkv[*isDependencyLink](ctx, depLinkID, c)
// 			if err != nil {
// 				return false
// 			}
// 			depLinks = append(depLinks, link)
// 		}

// 		for _, filter := range filters {
// 			if filter == nil {
// 				continue
// 			}
// 			if filter.ID != nil {
// 				// Check by ID if present
// 				if !helper.IsIDPresent(*filter.ID, depLinkIDs) {
// 					return false
// 				}
// 			} else {
// 				// Otherwise match spec information
// 				match := false
// 				for _, depLink := range depLinks {
// 					if !noMatchIsDep(filter, depLink) &&
// 						(filter.Package == nil || c.matchPackages(ctx, []*model.PkgSpec{filter.Package}, []string{depLink.PackageID})) &&
// 						(filter.DependencyPackage == nil || c.matchPackages(ctx, []*model.PkgSpec{filter.DependencyPackage}, []string{depLink.DepPackageID})) {
// 						match = true
// 						break
// 					}
// 				}
// 				if !match {
// 					return false
// 				}
// 			}
// 		}
// 	}
// 	return true
// }
