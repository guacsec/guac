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
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/vektah/gqlparser/v2/gqlerror"
	"golang.org/x/exp/slices"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type hasSBOMList []*hasSBOMStruct
type hasSBOMStruct struct {
	id                   uint32
	pkg                  uint32
	artifact             uint32
	uri                  string
	algorithm            string
	digest               string
	downloadLocation     string
	origin               string
	collector            string
	knownSince           time.Time
	includedSoftware     []uint32
	includedDependencies []uint32
	includedOccurrences  []uint32
}

func (n *hasSBOMStruct) ID() uint32 { return n.id }

func (n *hasSBOMStruct) Neighbors(allowedEdges edgeMap) []uint32 {
	out := []uint32{}
	if n.pkg != 0 && allowedEdges[model.EdgeHasSbomPackage] {
		out = append(out, n.pkg)
	}
	if n.artifact != 0 && allowedEdges[model.EdgeHasSbomArtifact] {
		out = append(out, n.artifact)
	}
	if allowedEdges[model.EdgeHasSbomIncludedSoftware] {
		out = append(out, n.includedSoftware...)
	}
	if allowedEdges[model.EdgeHasSbomIncludedDependencies] {
		out = append(out, n.includedDependencies...)
	}
	if allowedEdges[model.EdgeHasSbomIncludedOccurrences] {
		out = append(out, n.includedOccurrences...)
	}
	return sortAndRemoveDups(out)
}

func (n *hasSBOMStruct) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.convHasSBOM(n)
}

// Ingest HasSBOM

func (c *demoClient) IngestHasSBOMs(ctx context.Context, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec, includes []*model.HasSBOMIncludesInputSpec) ([]*model.HasSbom, error) {
	var modelHasSboms []*model.HasSbom

	for i := range hasSBOMs {
		var hasSBOM *model.HasSbom
		var err error
		if len(subjects.Packages) > 0 {
			subject := model.PackageOrArtifactInput{Package: subjects.Packages[i]}
			hasSBOM, err = c.IngestHasSbom(ctx, subject, *hasSBOMs[i], *includes[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestHasSbom failed with err: %v", err)
			}
		} else {
			subject := model.PackageOrArtifactInput{Artifact: subjects.Artifacts[i]}
			hasSBOM, err = c.IngestHasSbom(ctx, subject, *hasSBOMs[i], *includes[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestHasSbom failed with err: %v", err)
			}
		}
		modelHasSboms = append(modelHasSboms, hasSBOM)
	}
	return modelHasSboms, nil
}

func (c *demoClient) IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, input model.HasSBOMInputSpec, includes model.HasSBOMIncludesInputSpec) (*model.HasSbom, error) {
	funcName := "IngestHasSbom"

	var softwareIDs []uint32
	var dependencyIDs []uint32
	var occurrenceIDs []uint32
	var err error

	if includes.Software != nil {
		if softwareIDs, err = parseIDs(includes.Software); err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		for _, id := range softwareIDs {
			if err := c.validateSoftwareId(funcName, id); err != nil {
				return nil, err
			}
		}
		softwareIDs = sortAndRemoveDups(softwareIDs)
	}
	if includes.Dependencies != nil {
		if dependencyIDs, err = parseIDs(includes.Dependencies); err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		for _, id := range dependencyIDs {
			if _, err := byID[*isDependencyLink](id, c); err != nil {
				return nil, gqlerror.Errorf("%v :: dependency id %d is not an ingested isDependency", funcName, id)
			}
		}
		dependencyIDs = sortAndRemoveDups(dependencyIDs)
	}
	if includes.Occurrences != nil {
		if occurrenceIDs, err = parseIDs(includes.Occurrences); err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		for _, id := range occurrenceIDs {
			if isOccurrence, err := byID[*isOccurrenceStruct](id, c); isOccurrence == nil || err != nil {
				return nil, gqlerror.Errorf("%v :: occurrence id %d is not an ingested isOccurrence", funcName, id)
			}
		}
		occurrenceIDs = sortAndRemoveDups(occurrenceIDs)
	}
	return c.ingestHasSbom(ctx, subject, input, softwareIDs, dependencyIDs, occurrenceIDs, true)
}

func (c *demoClient) ingestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, input model.HasSBOMInputSpec, includedSoftware, includedDependencies, includedOccurrences []uint32, readOnly bool) (*model.HasSbom, error) {
	funcName := "IngestHasSbom"
	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var search []uint32
	var packageID uint32
	var pkg *pkgVersionNode
	var artID uint32
	var art *artStruct
	if subject.Package != nil {
		pmt := model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}
		var err error
		packageID, err = getPackageIDFromInput(c, *subject.Package, pmt)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		pkg, err = byID[*pkgVersionNode](packageID, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		search = pkg.hasSBOMs
	} else {
		var err error
		art, err = c.artifactByKey(subject.Artifact.Algorithm, subject.Artifact.Digest)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		artID = art.id
		search = art.hasSBOMs
	}

	algorithm := strings.ToLower(input.Algorithm)
	digest := strings.ToLower(input.Digest)

	for _, id := range search {
		h, err := byID[*hasSBOMStruct](id, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		if h.pkg == packageID &&
			h.artifact == artID &&
			h.uri == input.URI &&
			h.algorithm == algorithm &&
			h.digest == digest &&
			h.downloadLocation == input.DownloadLocation &&
			h.origin == input.Origin &&
			h.collector == input.Collector &&
			input.KnownSince.Equal(h.knownSince) &&
			slices.Equal(h.includedSoftware, includedSoftware) &&
			slices.Equal(h.includedDependencies, includedDependencies) &&
			slices.Equal(h.includedOccurrences, includedOccurrences) {
			return c.convHasSBOM(h)
		}
	}

	if readOnly {
		c.m.RUnlock()
		b, err := c.ingestHasSbom(ctx, subject, input, includedSoftware, includedDependencies, includedOccurrences, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return b, err
	}

	h := &hasSBOMStruct{
		id:                   c.getNextID(),
		pkg:                  packageID,
		artifact:             artID,
		uri:                  input.URI,
		algorithm:            algorithm,
		digest:               digest,
		downloadLocation:     input.DownloadLocation,
		origin:               input.Origin,
		collector:            input.Collector,
		knownSince:           input.KnownSince.UTC(),
		includedSoftware:     includedSoftware,
		includedDependencies: includedDependencies,
		includedOccurrences:  includedOccurrences,
	}
	c.index[h.id] = h
	c.hasSBOMs = append(c.hasSBOMs, h)
	if packageID != 0 {
		pkg.setHasSBOM(h.id)
	} else {
		art.setHasSBOMs(h.id)
	}
	return c.convHasSBOM(h)
}

func (c *demoClient) convHasSBOM(in *hasSBOMStruct) (*model.HasSbom, error) {
	out := &model.HasSbom{
		ID:               nodeID(in.id),
		URI:              in.uri,
		Algorithm:        in.algorithm,
		Digest:           in.digest,
		DownloadLocation: in.downloadLocation,
		Origin:           in.origin,
		Collector:        in.collector,
		KnownSince:       in.knownSince.UTC(),
	}
	if in.pkg != 0 {
		p, err := c.buildPackageResponse(in.pkg, nil)
		if err != nil {
			return nil, err
		}
		out.Subject = p
	} else {
		art, err := byID[*artStruct](in.artifact, c)
		if err != nil {
			return nil, err
		}
		out.Subject = c.convArtifact(art)
	}
	if len(in.includedSoftware) > 0 {
		out.IncludedSoftware = make([]model.PackageOrArtifact, 0, len(in.includedSoftware))
		for _, id := range in.includedSoftware {
			switch node := c.index[id].(type) {
			case *pkgVersionNode:
				if pkg, err := c.buildPackageResponse(id, nil); err != nil {
					return nil, err
				} else {
					out.IncludedSoftware = append(out.IncludedSoftware, pkg)
				}
			case *artStruct:
				if art, err := c.buildArtifactResponse(id, nil); err != nil {
					return nil, err
				} else {
					out.IncludedSoftware = append(out.IncludedSoftware, art)
				}
			default:
				return nil, fmt.Errorf("expected Package or Artifact, found %s", reflect.TypeOf(node))
			}
		}
	}
	if len(in.includedDependencies) > 0 {
		out.IncludedDependencies = make([]*model.IsDependency, 0, len(in.includedDependencies))
		for _, id := range in.includedDependencies {
			switch node := c.index[id].(type) {
			case *isDependencyLink:
				if isDep, err := c.buildIsDependency(node, nil, true); err != nil {
					return nil, err
				} else {
					out.IncludedDependencies = append(out.IncludedDependencies, isDep)
				}
			default:
				return nil, fmt.Errorf("expected IsDependency, found %s", reflect.TypeOf(node))
			}
		}
	}
	if len(in.includedOccurrences) > 0 {
		out.IncludedOccurrences = make([]*model.IsOccurrence, 0, len(in.includedOccurrences))
		for _, id := range in.includedOccurrences {
			switch node := c.index[id].(type) {
			case *isOccurrenceStruct:
				if isOcc, err := c.convOccurrence(node); err != nil {
					return nil, err
				} else {
					out.IncludedOccurrences = append(out.IncludedOccurrences, isOcc)
				}
			default:
				return nil, fmt.Errorf("expected IsOccurrence, found %s", reflect.TypeOf(node))
			}
		}
	}
	return out, nil
}

// Query HasSBOM

func (c *demoClient) HasSBOM(ctx context.Context, filter *model.HasSBOMSpec) ([]*model.HasSbom, error) {
	funcName := "HasSBOM"
	c.m.RLock()
	defer c.m.RUnlock()

	if filter != nil && filter.ID != nil {
		id64, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: invalid ID %v", funcName, err)
		}
		id := uint32(id64)
		link, err := byID[*hasSBOMStruct](id, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		sb, err := c.convHasSBOM(link)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.HasSbom{sb}, nil
	}

	var search []uint32
	foundOne := false
	if filter != nil && filter.Subject != nil && filter.Subject.Package != nil {
		pkgs, err := c.findPackageVersion(filter.Subject.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		foundOne = len(pkgs) > 0
		for _, pkg := range pkgs {
			search = append(search, pkg.hasSBOMs...)
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Artifact != nil {
		exactArt, err := c.artifactExact(filter.Subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactArt != nil {
			search = exactArt.hasSBOMs
			foundOne = true
		}
	}

	var out []*model.HasSbom
	if foundOne {
		for _, id := range search {
			link, err := byID[*hasSBOMStruct](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addHasSBOMIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.hasSBOMs {
			var err error
			out, err = c.addHasSBOMIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}

	return out, nil
}

func (c *demoClient) addHasSBOMIfMatch(out []*model.HasSbom,
	filter *model.HasSBOMSpec, link *hasSBOMStruct) (
	[]*model.HasSbom, error) {

	if filter != nil {
		if noMatch(filter.URI, link.uri) ||
			noMatch(toLower(filter.Algorithm), link.algorithm) ||
			noMatch(toLower(filter.Digest), link.digest) ||
			noMatch(filter.DownloadLocation, link.downloadLocation) ||
			noMatch(filter.Origin, link.origin) ||
			noMatch(filter.Collector, link.collector) ||
			(filter.KnownSince != nil && filter.KnownSince.After(link.knownSince)) {
			return out, nil
		}
		// collect packages and artifacts from included software
		pkgs, artifacts, err := c.getPackageVersionAndArtifacts(link.includedSoftware)
		if err != nil {
			return out, err
		}

		pkgFilters, artFilters := getPackageAndArtifactFilters(filter.IncludedSoftware)

		if !c.matchPackages(pkgFilters, pkgs) || !c.matchArtifacts(artFilters, artifacts) ||
			!c.matchDependencies(filter.IncludedDependencies, link.includedDependencies) ||
			!c.matchOccurrences(filter.IncludedOccurrences, link.includedOccurrences) {
			return out, nil
		}

		if filter.Subject != nil {
			if filter.Subject.Package != nil {
				if link.pkg == 0 {
					return out, nil
				}
				p, err := c.buildPackageResponse(link.pkg, filter.Subject.Package)
				if err != nil {
					return nil, err
				}
				if p == nil {
					return out, nil
				}
			} else if filter.Subject.Artifact != nil {
				if link.artifact == 0 {
					return out, nil
				}
				if !c.artifactMatch(link.artifact, filter.Subject.Artifact) {
					return out, nil
				}
			}
		}
	}
	sb, err := c.convHasSBOM(link)
	if err != nil {
		return nil, err
	}
	return append(out, sb), nil
}

func getPackageAndArtifactFilters(filters []*model.PackageOrArtifactSpec) (pkgs []*model.PkgSpec, arts []*model.ArtifactSpec) {
	for _, pkgOrArtSpec := range filters {
		if pkgOrArtSpec.Package != nil {
			pkgs = append(pkgs, pkgOrArtSpec.Package)
		} else if pkgOrArtSpec.Artifact != nil {
			arts = append(arts, pkgOrArtSpec.Artifact)
		}
	}
	return
}

func (c *demoClient) validateSoftwareId(funcName string, id uint32) error {
	node, ok := c.index[id]
	if !ok {
		return gqlerror.Errorf("%v :: software id %d is invalid", funcName, id)
	}
	if _, ok = node.(*pkgVersionNode); !ok {
		_, ok = node.(*artStruct)
	}
	if !ok {
		return gqlerror.Errorf("%v :: software id %d is neither an ingested Package nor an ingested Artifact", funcName, id)
	}
	return nil
}
