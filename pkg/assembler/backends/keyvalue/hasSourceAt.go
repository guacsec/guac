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
}

func (n *srcMapLink) ID() string { return n.ThisID }
func (n *srcMapLink) Key() string {
	return strings.Join([]string{
		n.SourceID,
		n.PackageID,
		timeKey(n.KnownSince),
		n.Justification,
		n.Origin,
		n.Collector,
	}, ":")
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

func (c *demoClient) IngestHasSourceAts(ctx context.Context, pkgs []*model.PkgInputSpec, pkgMatchType *model.MatchFlags, sources []*model.SourceInputSpec, hasSourceAts []*model.HasSourceAtInputSpec) ([]string, error) {
	var modelHasMetadataIDs []string

	for i := range hasSourceAts {
		hasMetadata, err := c.IngestHasSourceAt(ctx, *pkgs[i], *pkgMatchType, *sources[i], *hasSourceAts[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestHasSourceAt failed with err: %v", err)
		}
		modelHasMetadataIDs = append(modelHasMetadataIDs, hasMetadata.ID)
	}
	return modelHasMetadataIDs, nil
}

func (c *demoClient) IngestHasSourceAt(ctx context.Context, packageArg model.PkgInputSpec, pkgMatchType model.MatchFlags, source model.SourceInputSpec, hasSourceAt model.HasSourceAtInputSpec) (*model.HasSourceAt, error) {
	return c.ingestHasSourceAt(ctx, packageArg, pkgMatchType, source, hasSourceAt, true)
}

func (c *demoClient) ingestHasSourceAt(ctx context.Context, packageArg model.PkgInputSpec, pkgMatchType model.MatchFlags, source model.SourceInputSpec, hasSourceAt model.HasSourceAtInputSpec, readOnly bool) (*model.HasSourceAt, error) {
	funcName := "IngestHasSourceAt"

	in := &srcMapLink{
		KnownSince:    hasSourceAt.KnownSince.UTC(),
		Justification: hasSourceAt.Justification,
		Origin:        hasSourceAt.Origin,
		Collector:     hasSourceAt.Collector,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	srcName, err := c.getSourceNameFromInput(ctx, source)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	in.SourceID = srcName.ThisID

	pkgNameOrVersionNode, err := c.getPackageNameOrVerFromInput(ctx, packageArg, pkgMatchType)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	in.PackageID = pkgNameOrVersionNode.ID()

	out, err := byKeykv[*srcMapLink](ctx, hsaCol, in.Key(), c)
	if err == nil {
		return c.buildHasSourceAt(ctx, out, nil, true)
	}
	if !errors.Is(err, kv.NotFoundError) {
		return nil, err
	}

	if readOnly {
		c.m.RUnlock()
		s, err := c.ingestHasSourceAt(ctx, packageArg, pkgMatchType, source, hasSourceAt, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return s, err
	}

	in.ThisID = c.getNextID()

	if err := c.addToIndex(ctx, hsaCol, in); err != nil {
		return nil, err
	}
	// set the backlinks
	if err := pkgNameOrVersionNode.setSrcMapLinks(ctx, in.ThisID, c); err != nil {
		return nil, err
	}
	if err := srcName.setSrcMapLinks(ctx, in.ThisID, c); err != nil {
		return nil, err
	}
	if err := setkv(ctx, hsaCol, in, c); err != nil {
		return nil, err
	}

	return c.buildHasSourceAt(ctx, in, nil, true)
}

// Query HasSourceAt
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
			out, err = c.addSrcIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		hsaKeys, err := c.kv.Keys(ctx, hsaCol)
		if err != nil {
			return nil, err
		}
		for _, hsak := range hsaKeys {
			link, err := byKeykv[*srcMapLink](ctx, hsaCol, hsak, c)
			if err != nil {
				return nil, err
			}
			out, err = c.addSrcIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
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
	}
	return &newHSA, nil
}

func (c *demoClient) addSrcIfMatch(ctx context.Context, out []*model.HasSourceAt,
	filter *model.HasSourceAtSpec, link *srcMapLink) (
	[]*model.HasSourceAt, error) {
	if filter != nil && noMatch(filter.Justification, link.Justification) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Origin, link.Origin) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Collector, link.Collector) {
		return out, nil
	}
	if filter != nil && filter.KnownSince != nil && !filter.KnownSince.Equal(link.KnownSince) {
		return out, nil
	}
	foundHasSourceAt, err := c.buildHasSourceAt(ctx, link, filter, false)
	if err != nil {
		return nil, err
	}
	if foundHasSourceAt == nil {
		return out, nil
	}
	return append(out, foundHasSourceAt), nil
}
