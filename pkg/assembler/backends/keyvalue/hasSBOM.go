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
	"strings"
	"time"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type hasSBOMList []*hasSBOMStruct
type hasSBOMStruct struct {
	id               string
	pkg              string
	artifact         string
	uri              string
	algorithm        string
	digest           string
	downloadLocation string
	origin           string
	collector        string
	knownSince       time.Time
}

func (n *hasSBOMStruct) ID() string { return n.id }

func (n *hasSBOMStruct) Neighbors(allowedEdges edgeMap) []string {
	if n.pkg != "" && allowedEdges[model.EdgeHasSbomPackage] {
		return []string{n.pkg}
	}
	if allowedEdges[model.EdgeHasSbomArtifact] {
		return []string{n.artifact}
	}
	return []string{}
}

func (n *hasSBOMStruct) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.convHasSBOM(n)
}

// Ingest HasSBOM

func (c *demoClient) IngestHasSBOMs(ctx context.Context, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec) ([]*model.HasSbom, error) {
	var modelHasSboms []*model.HasSbom

	for i := range hasSBOMs {
		var hasSBOM *model.HasSbom
		var err error
		if len(subjects.Packages) > 0 {
			subject := model.PackageOrArtifactInput{Package: subjects.Packages[i]}
			hasSBOM, err = c.IngestHasSbom(ctx, subject, *hasSBOMs[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestHasSbom failed with err: %v", err)
			}
		} else {
			subject := model.PackageOrArtifactInput{Artifact: subjects.Artifacts[i]}
			hasSBOM, err = c.IngestHasSbom(ctx, subject, *hasSBOMs[i])
			if err != nil {
				return nil, gqlerror.Errorf("IngestHasSbom failed with err: %v", err)
			}
		}
		modelHasSboms = append(modelHasSboms, hasSBOM)
	}
	return modelHasSboms, nil
}

func (c *demoClient) IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, input model.HasSBOMInputSpec) (*model.HasSbom, error) {
	return c.ingestHasSbom(ctx, subject, input, true)
}

func (c *demoClient) ingestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, input model.HasSBOMInputSpec, readOnly bool) (*model.HasSbom, error) {
	funcName := "IngestHasSbom"
	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var search []string
	var packageID string
	var pkg *pkgVersionNode
	var artID string
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
		art, err = c.artifactByInput(ctx, subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		artID = art.ID()
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
			input.KnownSince.Equal(h.knownSince) {
			return c.convHasSBOM(h)
		}
	}

	if readOnly {
		c.m.RUnlock()
		b, err := c.ingestHasSbom(ctx, subject, input, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return b, err
	}

	h := &hasSBOMStruct{
		id:               c.getNextID(),
		pkg:              packageID,
		artifact:         artID,
		uri:              input.URI,
		algorithm:        algorithm,
		digest:           digest,
		downloadLocation: input.DownloadLocation,
		origin:           input.Origin,
		collector:        input.Collector,
		knownSince:       input.KnownSince.UTC(),
	}
	c.index[h.id] = h
	c.hasSBOMs = append(c.hasSBOMs, h)
	if packageID != "" {
		pkg.setHasSBOM(h.id)
	} else {
		art.setHasSBOMs(h.id)
	}
	return c.convHasSBOM(h)
}

func (c *demoClient) convHasSBOM(in *hasSBOMStruct) (*model.HasSbom, error) {
	out := &model.HasSbom{
		ID:               in.id,
		URI:              in.uri,
		Algorithm:        in.algorithm,
		Digest:           in.digest,
		DownloadLocation: in.downloadLocation,
		Origin:           in.origin,
		Collector:        in.collector,
		KnownSince:       in.knownSince.UTC(),
	}
	if in.pkg != "" {
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
	return out, nil
}

// Query HasSBOM

func (c *demoClient) HasSBOM(ctx context.Context, filter *model.HasSBOMSpec) ([]*model.HasSbom, error) {
	funcName := "HasSBOM"
	c.m.RLock()
	defer c.m.RUnlock()

	if filter != nil && filter.ID != nil {
		link, err := byID[*hasSBOMStruct](*filter.ID, c)
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

	var search []string
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
		exactArt, err := c.artifactExact(ctx, filter.Subject.Artifact)
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
			out, err = c.addHasSBOMIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.hasSBOMs {
			var err error
			out, err = c.addHasSBOMIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}

	return out, nil
}

func (c *demoClient) addHasSBOMIfMatch(ctx context.Context, out []*model.HasSbom,
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
		if filter.Subject != nil {
			if filter.Subject.Package != nil {
				if link.pkg == "" {
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
				if link.artifact == "" {
					return out, nil
				}
				if !c.artifactMatch(ctx, link.artifact, filter.Subject.Artifact) {
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
