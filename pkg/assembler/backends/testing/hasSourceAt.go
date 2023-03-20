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

package testing

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// Internal data: link between sources and packages (HasSourceAt)
type hasSrcList []*srcMapLink
type srcMapLink struct {
	id            uint32
	sourceID      uint32
	packageID     uint32
	knownSince    time.Time
	justification string
	origin        string
	collector     string
}

func (n *srcMapLink) getID() uint32 { return n.id }

// Ingest HasSourceAt
func (c *demoClient) IngestHasSourceAt(ctx context.Context, packageArg model.PkgInputSpec, pkgMatchType model.MatchFlags, source model.SourceInputSpec, hasSourceAt model.HasSourceAtInputSpec) (*model.HasSourceAt, error) {
	// Note: This assumes that the package and source have already been
	// ingested (and should error otherwise).

	sourceID, err := getSourceIDFromInput(c, source)
	if err != nil {
		return nil, err
	}

	packageID, err := getPackageIDFromInput(c, packageArg, pkgMatchType)
	if err != nil {
		return nil, err
	}

	// Don't insert duplicates
	duplicate := false
	collectedSrcMapLink := srcMapLink{}
	for _, v := range c.hasSources {
		if *packageID == v.packageID && *sourceID == v.sourceID && hasSourceAt.Justification == v.justification &&
			hasSourceAt.Origin == v.origin && hasSourceAt.Collector == v.collector && hasSourceAt.KnownSince.UTC() == v.knownSince {
			collectedSrcMapLink = *v
			duplicate = true
			break
		}
	}
	if !duplicate {
		// store the link
		collectedSrcMapLink = srcMapLink{
			id:            c.getNextID(),
			sourceID:      *sourceID,
			packageID:     *packageID,
			knownSince:    hasSourceAt.KnownSince.UTC(),
			justification: hasSourceAt.Justification,
			origin:        hasSourceAt.Origin,
			collector:     hasSourceAt.Collector,
		}
		c.index[collectedSrcMapLink.id] = &collectedSrcMapLink
		c.hasSources = append(c.hasSources, &collectedSrcMapLink)
		// set the backlinks
		c.index[*packageID].(pkgNameOrVersion).setSrcMapLink(collectedSrcMapLink.id)
		c.index[*sourceID].(*srcNameNode).setSrcMapLink(collectedSrcMapLink.id)
	}

	// build return GraphQL type
	foundHasSourceAt, err := buildHasSourceAt(c, &collectedSrcMapLink, nil, true)
	if err != nil {
		return nil, err
	}
	return foundHasSourceAt, nil
}

// Query HasSourceAt

func (c *demoClient) HasSourceAt(ctx context.Context, filter *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {
	out := []*model.HasSourceAt{}

	if filter != nil && filter.ID != nil {
		id, err := strconv.Atoi(*filter.ID)
		if err != nil {
			return nil, err
		}
		node, ok := c.index[uint32(id)]
		if !ok {
			return nil, gqlerror.Errorf("ID does not match existing node")
		}
		if link, ok := node.(*srcMapLink); ok {
			foundHasSourceAt, err := buildHasSourceAt(c, link, filter, true)
			if err != nil {
				return nil, err
			}
			return []*model.HasSourceAt{foundHasSourceAt}, nil
		} else {
			return nil, gqlerror.Errorf("ID does not match expected node type for hasSourceAt")
		}
	}

	for _, link := range c.hasSources {
		if filter != nil && noMatch(filter.Justification, link.justification) {
			continue
		}
		if filter != nil && noMatch(filter.Origin, link.origin) {
			continue
		}
		if filter != nil && noMatch(filter.Collector, link.collector) {
			continue
		}
		if filter != nil && filter.KnownSince != nil && !reflect.DeepEqual(filter.KnownSince.UTC(), link.knownSince) {
			continue
		}
		foundHasSourceAt, err := buildHasSourceAt(c, link, filter, false)
		if err != nil {
			return nil, err
		}
		if foundHasSourceAt == nil {
			continue
		}
		out = append(out, foundHasSourceAt)
	}

	return out, nil
}

func buildHasSourceAt(c *demoClient, link *srcMapLink, filter *model.HasSourceAtSpec, ingestOrIDProvided bool) (*model.HasSourceAt, error) {
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
		ID:            fmt.Sprintf("%d", link.id),
		Package:       p,
		Source:        s,
		KnownSince:    link.knownSince,
		Justification: link.justification,
		Origin:        link.origin,
		Collector:     link.collector,
	}
	return &newHSA, nil
}
