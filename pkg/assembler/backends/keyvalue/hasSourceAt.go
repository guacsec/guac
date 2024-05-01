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
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"sort"
	"strings"
	"time"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
)

// Internal data: link between sources and packages (HasSourceAt)
type srcMapLink struct {
	ThisID        string
	SourceID      string
	PackageID     string
	KnownSince    time.Time
	Justification string
	Origin        string
	Collector     string
	DocumentRef   string
}

func (n *srcMapLink) ID() string { return n.ThisID }
func (n *srcMapLink) Key() string {
	return hashKey(strings.Join([]string{
		n.SourceID,
		n.PackageID,
		timeKey(n.KnownSince),
		n.Justification,
		n.Origin,
		n.Collector,
		n.DocumentRef,
	}, ":"))
}

func (n *srcMapLink) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 2)
	if allowedEdges[model.EdgeHasSourceAtPackage] {
		out = append(out, n.PackageID)
	}
	if allowedEdges[model.EdgeHasSourceAtSource] {
		out = append(out, n.SourceID)
	}
	return out
}

func (n *srcMapLink) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildHasSourceAt(ctx, n, nil, true)
}

// Ingest HasSourceAt

func (c *demoClient) IngestHasSourceAts(ctx context.Context, pkgs []*model.IDorPkgInput, pkgMatchType *model.MatchFlags, sources []*model.IDorSourceInput, hasSourceAts []*model.HasSourceAtInputSpec) ([]string, error) {
	var modelHasMetadataIDs []string

	for i := range hasSourceAts {
		hasMetadata, err := c.IngestHasSourceAt(ctx, *pkgs[i], *pkgMatchType, *sources[i], *hasSourceAts[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestHasSourceAt failed with err: %v", err)
		}
		modelHasMetadataIDs = append(modelHasMetadataIDs, hasMetadata)
	}
	return modelHasMetadataIDs, nil
}

func (c *demoClient) IngestHasSourceAt(ctx context.Context, packageArg model.IDorPkgInput, pkgMatchType model.MatchFlags, source model.IDorSourceInput, hasSourceAt model.HasSourceAtInputSpec) (string, error) {
	return c.ingestHasSourceAt(ctx, packageArg, pkgMatchType, source, hasSourceAt, true)
}

func (c *demoClient) ingestHasSourceAt(ctx context.Context, packageArg model.IDorPkgInput, pkgMatchType model.MatchFlags, source model.IDorSourceInput, hasSourceAt model.HasSourceAtInputSpec, readOnly bool) (string, error) {
	funcName := "IngestHasSourceAt"

	in := &srcMapLink{
		KnownSince:    hasSourceAt.KnownSince.UTC(),
		Justification: hasSourceAt.Justification,
		Origin:        hasSourceAt.Origin,
		Collector:     hasSourceAt.Collector,
		DocumentRef:   hasSourceAt.DocumentRef,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var pkgNameOrVersionNode pkgNameOrVersion
	var err error
	in.PackageID, pkgNameOrVersionNode, err = c.returnFoundPkgBasedOnMatchType(ctx, &packageArg, &pkgMatchType)
	if err != nil {
		return "", gqlerror.Errorf("%v ::  %s", funcName, err)
	}

	srcName, err := c.returnFoundSource(ctx, &source)
	if err != nil {
		return "", gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	in.SourceID = srcName.ThisID

	out, err := byKeykv[*srcMapLink](ctx, hsaCol, in.Key(), c)
	if err == nil {
		return out.ThisID, nil
	}
	if !errors.Is(err, kv.NotFoundError) {
		return "", err
	}

	if readOnly {
		c.m.RUnlock()
		s, err := c.ingestHasSourceAt(ctx, packageArg, pkgMatchType, source, hasSourceAt, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return s, err
	}

	in.ThisID = c.getNextID()

	if err := c.addToIndex(ctx, hsaCol, in); err != nil {
		return "", err
	}
	// set the backlinks
	if err := pkgNameOrVersionNode.setSrcMapLinks(ctx, in.ThisID, c); err != nil {
		return "", err
	}
	if err := srcName.setSrcMapLinks(ctx, in.ThisID, c); err != nil {
		return "", err
	}
	if err := setkv(ctx, hsaCol, in, c); err != nil {
		return "", err
	}

	return in.ThisID, nil
}

// Query HasSourceAt

func (c *demoClient) HasSourceAtList(ctx context.Context, hasSourceAtSpec model.HasSourceAtSpec, after *string, first *int) (*model.HasSourceAtConnection, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	funcName := "HasSourceAt"
	if hasSourceAtSpec.ID != nil {
		link, err := byIDkv[*srcMapLink](ctx, *hasSourceAtSpec.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		foundHasSourceAt, err := c.buildHasSourceAt(ctx, link, &hasSourceAtSpec, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return &model.HasSourceAtConnection{
			TotalCount: 1,
			PageInfo: &model.PageInfo{
				HasNextPage: false,
				StartCursor: ptrfrom.String(foundHasSourceAt.ID),
				EndCursor:   ptrfrom.String(foundHasSourceAt.ID),
			},
			Edges: []*model.HasSourceAtEdge{
				{
					Cursor: foundHasSourceAt.ID,
					Node:   foundHasSourceAt,
				},
			},
		}, nil
	}

	edges := make([]*model.HasSourceAtEdge, 0)
	hasNextPage := false
	numNodes := 0
	totalCount := 0

	// Cant really search for an exact Pkg, as these can be linked to either
	// names or versions, only search Source backedges.
	var search []string
	foundOne := false
	if hasSourceAtSpec.Source != nil {
		exactSource, err := c.exactSource(ctx, hasSourceAtSpec.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.SrcMapLinks...)
			foundOne = true
		}
	}

	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*srcMapLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			src, err := c.srcIfMatch(ctx, &hasSourceAtSpec, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}

			edges = append(edges, &model.HasSourceAtEdge{
				Cursor: src.ID,
				Node:   src,
			})
		}
	} else {
		currentPage := false

		// If no cursor present start from the top
		if after == nil {
			currentPage = true
		}
		var done bool
		scn := c.kv.Keys(hsaCol)
		for !done {
			var hsaKeys []string
			var err error
			hsaKeys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}

			sort.Strings(hsaKeys)
			totalCount = len(hsaKeys)

			for i, hsak := range hsaKeys {
				link, err := byKeykv[*srcMapLink](ctx, hsaCol, hsak, c)
				if err != nil {
					return nil, err
				}
				src, err := c.srcIfMatch(ctx, &hasSourceAtSpec, link)
				if err != nil {
					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
				}

				if after != nil && !currentPage {
					if src.ID == *after {
						totalCount = len(hsaKeys) - (i + 1)
						currentPage = true
					}
					continue
				}

				if first != nil {
					if numNodes < *first {
						edges = append(edges, &model.HasSourceAtEdge{
							Cursor: src.ID,
							Node:   src,
						})
						numNodes++
					} else if numNodes == *first {
						hasNextPage = true
					}
				} else {
					edges = append(edges, &model.HasSourceAtEdge{
						Cursor: src.ID,
						Node:   src,
					})
				}
			}
		}
	}

	if len(edges) != 0 {
		return &model.HasSourceAtConnection{
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

func (c *demoClient) HasSourceAt(ctx context.Context, filter *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	funcName := "HasSourceAt"
	if filter != nil && filter.ID != nil {
		link, err := byIDkv[*srcMapLink](ctx, *filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		foundHasSourceAt, err := c.buildHasSourceAt(ctx, link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.HasSourceAt{foundHasSourceAt}, nil
	}

	// Cant really search for an exact Pkg, as these can be linked to either
	// names or versions, only search Source backedges.
	var search []string
	foundOne := false
	if filter != nil && filter.Source != nil {
		exactSource, err := c.exactSource(ctx, filter.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.SrcMapLinks...)
			foundOne = true
		}
	}

	var out []*model.HasSourceAt
	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*srcMapLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			src, err := c.srcIfMatch(ctx, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out = append(out, src)
		}
	} else {
		var done bool
		scn := c.kv.Keys(hsaCol)
		for !done {
			var hsaKeys []string
			var err error
			hsaKeys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}
			for _, hsak := range hsaKeys {
				link, err := byKeykv[*srcMapLink](ctx, hsaCol, hsak, c)
				if err != nil {
					return nil, err
				}
				src, err := c.srcIfMatch(ctx, filter, link)
				if err != nil {
					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
				}
				out = append(out, src)
			}
		}
	}

	return out, nil
}

func (c *demoClient) buildHasSourceAt(ctx context.Context, link *srcMapLink, filter *model.HasSourceAtSpec, ingestOrIDProvided bool) (*model.HasSourceAt, error) {
	var p *model.Package
	var s *model.Source
	var err error
	if filter != nil {
		p, err = c.buildPackageResponse(ctx, link.PackageID, filter.Package)
		if err != nil {
			return nil, err
		}
		s, err = c.buildSourceResponse(ctx, link.SourceID, filter.Source)
		if err != nil {
			return nil, err
		}
	} else {
		p, err = c.buildPackageResponse(ctx, link.PackageID, nil)
		if err != nil {
			return nil, err
		}
		s, err = c.buildSourceResponse(ctx, link.SourceID, nil)
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
	// if source not found during ingestion or if ID is provided in filter, send error. On query do not send error to continue search
	if s == nil && ingestOrIDProvided {
		return nil, gqlerror.Errorf("failed to retrieve source via sourceID")
	} else if s == nil && !ingestOrIDProvided {
		return nil, nil
	}

	newHSA := model.HasSourceAt{
		ID:            link.ThisID,
		Package:       p,
		Source:        s,
		KnownSince:    link.KnownSince,
		Justification: link.Justification,
		Origin:        link.Origin,
		Collector:     link.Collector,
		DocumentRef:   link.DocumentRef,
	}
	return &newHSA, nil
}

func (c *demoClient) srcIfMatch(ctx context.Context, filter *model.HasSourceAtSpec, link *srcMapLink) (
	*model.HasSourceAt, error) {
	if filter != nil && noMatch(filter.Justification, link.Justification) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Origin, link.Origin) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Collector, link.Collector) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.DocumentRef, link.DocumentRef) {
		return nil, nil
	}
	if filter != nil && filter.KnownSince != nil && !filter.KnownSince.Equal(link.KnownSince) {
		return nil, nil
	}
	foundHasSourceAt, err := c.buildHasSourceAt(ctx, link, filter, false)
	if err != nil {
		return nil, err
	}
	if foundHasSourceAt == nil {
		return nil, nil
	}
	return foundHasSourceAt, nil
}
