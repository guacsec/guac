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
type hasSrcMaps map[uint32]*srcMapLink
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

	srcNamespace, srcHasNamespace := c.sources[source.Type]
	if !srcHasNamespace {
		return nil, gqlerror.Errorf("Source type \"%s\" not found", source.Type)
	}
	srcName, srcHasName := srcNamespace.namespaces[source.Namespace]
	if !srcHasName {
		return nil, gqlerror.Errorf("Source namespace \"%s\" not found", source.Namespace)
	}
	found := false
	var sourceID uint32
	for _, src := range srcName.names {
		if src.name != source.Name {
			continue
		}
		if noMatchInput(source.Tag, src.tag) {
			continue
		}
		if noMatchInput(source.Commit, src.commit) {
			continue
		}
		if found {
			return nil, gqlerror.Errorf("More than one source matches input")
		}
		sourceID = src.id
		found = true
	}
	if !found {
		return nil, gqlerror.Errorf("No source matches input")
	}

	pkgNamespace, pkgHasNamespace := c.packages[packageArg.Type]
	if !pkgHasNamespace {
		return nil, gqlerror.Errorf("Package type \"%s\" not found", packageArg.Type)
	}
	pkgName, pkgHasName := pkgNamespace.namespaces[nilToEmpty(packageArg.Namespace)]
	if !pkgHasName {
		return nil, gqlerror.Errorf("Package namespace \"%s\" not found", nilToEmpty(packageArg.Namespace))
	}
	pkgVersion, pkgHasVersion := pkgName.names[packageArg.Name]
	if !pkgHasVersion {
		return nil, gqlerror.Errorf("Package name \"%s\" not found", packageArg.Name)
	}
	var packageID uint32
	if pkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
		packageID = pkgVersion.id
	} else {
		found = false
		for _, version := range pkgVersion.versions {
			if noMatchInput(packageArg.Version, version.version) {
				continue
			}
			if noMatchInput(packageArg.Subpath, version.subpath) {
				continue
			}
			if !reflect.DeepEqual(version.qualifiers, getQualifiersFromInput(packageArg.Qualifiers)) {
				continue
			}
			if found {
				return nil, gqlerror.Errorf("More than one package matches input")
			}
			packageID = version.id
			found = true
		}
		if !found {
			return nil, gqlerror.Errorf("No package matches input")
		}
	}

	// Don't insert duplicates
	duplicate := false
	collectedSrcMapLink := srcMapLink{}
	for _, v := range c.hasSourceMaps {
		if packageID == v.packageID && sourceID == v.sourceID && hasSourceAt.Justification == v.justification &&
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
			sourceID:      sourceID,
			packageID:     packageID,
			knownSince:    hasSourceAt.KnownSince.UTC(),
			justification: hasSourceAt.Justification,
			origin:        hasSourceAt.Origin,
			collector:     hasSourceAt.Collector,
		}
		c.index[collectedSrcMapLink.id] = &collectedSrcMapLink
		c.hasSourceMaps[collectedSrcMapLink.id] = &collectedSrcMapLink
		// set the backlinks
		c.index[packageID].(pkgNameOrVersion).setSrcMapLink(collectedSrcMapLink.id)
		c.index[sourceID].(*srcNameNode).setSrcMapLink(collectedSrcMapLink.id)
	}

	// build return GraphQL type
	p, err := c.buildPackageResponse(packageID, nil)
	if err != nil {
		return nil, err
	}
	s, err := c.buildSourceResponse(sourceID, nil)
	if err != nil {
		return nil, err
	}
	out := model.HasSourceAt{
		ID:            fmt.Sprintf("%d", collectedSrcMapLink.id),
		Package:       p,
		Source:        s,
		KnownSince:    collectedSrcMapLink.knownSince,
		Justification: collectedSrcMapLink.justification,
		Origin:        collectedSrcMapLink.origin,
		Collector:     collectedSrcMapLink.collector,
	}

	return &out, nil
}

// Query HasSourceAt

func (c *demoClient) HasSourceAt(ctx context.Context, filter *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {
	out := []*model.HasSourceAt{}

	if filter != nil && filter.ID != nil {
		id, err := strconv.Atoi(*filter.ID)
		if err != nil {
			return nil, err
		}
		mapLink := c.hasSourceMaps[uint32(id)]
		p, err := c.buildPackageResponse(mapLink.packageID, filter.Package)
		if err != nil {
			return nil, err
		}
		if p == nil {
			return nil, gqlerror.Errorf("package not found for specified hasSourceAt ID")
		}
		s, err := c.buildSourceResponse(mapLink.sourceID, filter.Source)
		if err != nil {
			return nil, err
		}
		if s == nil {
			return nil, gqlerror.Errorf("source not found for specified hasSourceAt ID")
		}
		newHSA := model.HasSourceAt{
			ID:            fmt.Sprintf("%d", mapLink.id),
			Package:       p,
			Source:        s,
			KnownSince:    mapLink.knownSince,
			Justification: mapLink.justification,
			Origin:        mapLink.origin,
			Collector:     mapLink.collector,
		}
		return []*model.HasSourceAt{&newHSA}, nil
	}

	for _, mapLink := range c.hasSourceMaps {
		if filter != nil && noMatch(filter.Justification, mapLink.justification) {
			continue
		}
		if filter != nil && noMatch(filter.Origin, mapLink.origin) {
			continue
		}
		if filter != nil && noMatch(filter.Collector, mapLink.collector) {
			continue
		}
		var p *model.Package
		var s *model.Source
		var err error
		if filter != nil {
			p, err = c.buildPackageResponse(mapLink.packageID, filter.Package)
			if err != nil {
				return nil, err
			}
			s, err = c.buildSourceResponse(mapLink.sourceID, filter.Source)
			if err != nil {
				return nil, err
			}
		} else {
			p, err = c.buildPackageResponse(mapLink.packageID, nil)
			if err != nil {
				return nil, err
			}
			s, err = c.buildSourceResponse(mapLink.sourceID, nil)
			if err != nil {
				return nil, err
			}
		}
		if p == nil {
			continue
		}
		if s == nil {
			continue
		}
		newHSA := model.HasSourceAt{
			ID:            fmt.Sprintf("%d", mapLink.id),
			Package:       p,
			Source:        s,
			KnownSince:    mapLink.knownSince,
			Justification: mapLink.justification,
			Origin:        mapLink.origin,
			Collector:     mapLink.collector,
		}
		out = append(out, &newHSA)
	}

	return out, nil
}
