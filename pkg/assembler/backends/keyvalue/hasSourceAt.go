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
	"time"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Internal data: link between sources and packages (HasSourceAt)
type hasSrcList []*srcMapLink
type srcMapLink struct {
	id            string
	sourceID      string
	packageID     string
	knownSince    time.Time
	justification string
	origin        string
	collector     string
}

func (n *srcMapLink) ID() string { return n.id }

func (n *srcMapLink) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 2)
	if allowedEdges[model.EdgeHasSourceAtPackage] {
		out = append(out, n.packageID)
	}
	if allowedEdges[model.EdgeHasSourceAtSource] {
		out = append(out, n.sourceID)
	}
	return out
}

func (n *srcMapLink) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildHasSourceAt(n, nil, true)
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
	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	sourceID, err := getSourceIDFromInput(c, source)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	srcName, err := byID[*srcNameNode](sourceID, c)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	sourceHasSourceLinks := srcName.srcMapLinks

	packageID, err := getPackageIDFromInput(c, packageArg, pkgMatchType)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	pkgNameOrVersionNode, err := byID[pkgNameOrVersion](packageID, c)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	packageHasSourceLinks := pkgNameOrVersionNode.getSrcMapLinks()

	var searchIDs []string
	if len(packageHasSourceLinks) < len(sourceHasSourceLinks) {
		searchIDs = packageHasSourceLinks
	} else {
		searchIDs = sourceHasSourceLinks
	}

	// Don't insert duplicates
	duplicate := false
	collectedSrcMapLink := srcMapLink{}
	for _, id := range searchIDs {
		v, err := byID[*srcMapLink](id, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		if packageID == v.packageID && sourceID == v.sourceID && hasSourceAt.Justification == v.justification &&
			hasSourceAt.Origin == v.origin && hasSourceAt.Collector == v.collector && hasSourceAt.KnownSince.Equal(v.knownSince) {
			collectedSrcMapLink = *v
			duplicate = true
			break
		}
	}
	if !duplicate {
		if readOnly {
			c.m.RUnlock()
			s, err := c.ingestHasSourceAt(ctx, packageArg, pkgMatchType, source, hasSourceAt, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return s, err
		}
		// store the link
		collectedSrcMapLink = srcMapLink{
			id:            c.getNextID(),
			sourceID:      sourceID,
			packageID:     packageID,
			knownSince:    hasSourceAt.KnownSince.UTC(),
			justification: hasSourceAt.Justification,
			origin:        hasSourceAt.Origin,
			collector:     hasSourceAt.Collector,
		}
		c.index[collectedSrcMapLink.id] = &collectedSrcMapLink
		c.hasSources = append(c.hasSources, &collectedSrcMapLink)
		// set the backlinks
		pkgNameOrVersionNode.setSrcMapLinks(collectedSrcMapLink.id)
		srcName.setSrcMapLinks(collectedSrcMapLink.id)
	}

	// build return GraphQL type
	foundHasSourceAt, err := c.buildHasSourceAt(&collectedSrcMapLink, nil, true)
	if err != nil {
		return nil, err
	}
	return foundHasSourceAt, nil
}

// Query HasSourceAt
func (c *demoClient) HasSourceAt(ctx context.Context, filter *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	funcName := "HasSourceAt"
	if filter != nil && filter.ID != nil {
		link, err := byID[*srcMapLink](*filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		foundHasSourceAt, err := c.buildHasSourceAt(link, filter, true)
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
		exactSource, err := c.exactSource(filter.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.srcMapLinks...)
			foundOne = true
		}
	}

	var out []*model.HasSourceAt
	if foundOne {
		for _, id := range search {
			link, err := byID[*srcMapLink](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addSrcIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.hasSources {
			var err error
			out, err = c.addSrcIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}

	return out, nil
}

func (c *demoClient) buildHasSourceAt(link *srcMapLink, filter *model.HasSourceAtSpec, ingestOrIDProvided bool) (*model.HasSourceAt, error) {
	var p *model.Package
	var s *model.Source
	var err error
	if filter != nil {
		p, err = c.buildPackageResponse(link.packageID, filter.Package)
		if err != nil {
			return nil, err
		}
		s, err = c.buildSourceResponse(link.sourceID, filter.Source)
		if err != nil {
			return nil, err
		}
	} else {
		p, err = c.buildPackageResponse(link.packageID, nil)
		if err != nil {
			return nil, err
		}
		s, err = c.buildSourceResponse(link.sourceID, nil)
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
		ID:            link.id,
		Package:       p,
		Source:        s,
		KnownSince:    link.knownSince,
		Justification: link.justification,
		Origin:        link.origin,
		Collector:     link.collector,
	}
	return &newHSA, nil
}

func (c *demoClient) addSrcIfMatch(out []*model.HasSourceAt,
	filter *model.HasSourceAtSpec, link *srcMapLink) (
	[]*model.HasSourceAt, error) {
	if filter != nil && noMatch(filter.Justification, link.justification) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Origin, link.origin) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Collector, link.collector) {
		return out, nil
	}
	if filter != nil && filter.KnownSince != nil && !filter.KnownSince.Equal(link.knownSince) {
		return out, nil
	}
	foundHasSourceAt, err := c.buildHasSourceAt(link, filter, false)
	if err != nil {
		return nil, err
	}
	if foundHasSourceAt == nil {
		return out, nil
	}
	return append(out, foundHasSourceAt), nil
}
