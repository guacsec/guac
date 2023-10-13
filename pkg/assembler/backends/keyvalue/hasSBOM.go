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
	"strings"
	"time"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
)

type hasSBOMStruct struct {
	ThisID           string
	Pkg              string
	Artifact         string
	URI              string
	Algorithm        string
	Digest           string
	DownloadLocation string
	Origin           string
	Collector        string
	KnownSince       time.Time
}

func (n *hasSBOMStruct) ID() string { return n.ThisID }
func (n *hasSBOMStruct) Key() string {
	return strings.Join([]string{
		n.Pkg,
		n.Artifact,
		n.URI,
		n.Algorithm,
		n.Digest,
		n.DownloadLocation,
		n.Origin,
		n.Collector,
		fmt.Sprint(n.KnownSince.Unix()),
	}, ":")
}

func (n *hasSBOMStruct) Neighbors(allowedEdges edgeMap) []string {
	if n.Pkg != "" && allowedEdges[model.EdgeHasSbomPackage] {
		return []string{n.Pkg}
	}
	if n.Artifact != "" && allowedEdges[model.EdgeHasSbomArtifact] {
		return []string{n.Artifact}
	}
	return []string{}
}

func (n *hasSBOMStruct) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.convHasSBOM(ctx, n)
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
	algorithm := strings.ToLower(input.Algorithm)
	digest := strings.ToLower(input.Digest)

	in := &hasSBOMStruct{
		URI:              input.URI,
		Algorithm:        algorithm,
		Digest:           digest,
		DownloadLocation: input.DownloadLocation,
		Origin:           input.Origin,
		Collector:        input.Collector,
		KnownSince:       input.KnownSince.UTC(),
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var pkg *pkgVersion
	var art *artStruct

	if subject.Package != nil {
		var err error
		pkg, err = c.getPackageVerFromInput(ctx, *subject.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.Pkg = pkg.ThisID
	} else {
		var err error
		art, err = c.artifactByInput(ctx, subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.Artifact = art.ThisID
	}

	out, err := byKeykv[*hasSBOMStruct](ctx, hasSBOMCol, in.Key(), c)
	if err == nil {
		return c.convHasSBOM(ctx, out)
	}
	if !errors.Is(err, kv.NotFoundError) {
		return nil, err
	}

	if readOnly {
		c.m.RUnlock()
		b, err := c.ingestHasSbom(ctx, subject, input, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return b, err
	}

	in.ThisID = c.getNextID()

	if err := c.addToIndex(ctx, hasSBOMCol, in); err != nil {
		return nil, err
	}

	if pkg != nil {
		if err := pkg.setHasSBOM(ctx, in.ThisID, c); err != nil {
			return nil, err
		}
	} else {
		if err := art.setHasSBOMs(ctx, in.ThisID, c); err != nil {
			return nil, err
		}
	}

	if err := setkv(ctx, hasSBOMCol, in, c); err != nil {
		return nil, err
	}

	return c.convHasSBOM(ctx, in)
}

func (c *demoClient) convHasSBOM(ctx context.Context, in *hasSBOMStruct) (*model.HasSbom, error) {
	out := &model.HasSbom{
		ID:               in.ThisID,
		URI:              in.URI,
		Algorithm:        in.Algorithm,
		Digest:           in.Digest,
		DownloadLocation: in.DownloadLocation,
		Origin:           in.Origin,
		Collector:        in.Collector,
		KnownSince:       in.KnownSince.UTC(),
	}
	if in.Pkg != "" {
		p, err := c.buildPackageResponse(ctx, in.Pkg, nil)
		if err != nil {
			return nil, err
		}
		out.Subject = p
	} else {
		art, err := c.artifactModelByID(ctx, in.Artifact)
		if err != nil {
			return nil, err
		}
		out.Subject = art
	}
	return out, nil
}

// Query HasSBOM

func (c *demoClient) HasSBOM(ctx context.Context, filter *model.HasSBOMSpec) ([]*model.HasSbom, error) {
	funcName := "HasSBOM"
	c.m.RLock()
	defer c.m.RUnlock()

	if filter != nil && filter.ID != nil {
		link, err := byIDkv[*hasSBOMStruct](ctx, *filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		sb, err := c.convHasSBOM(ctx, link)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.HasSbom{sb}, nil
	}

	var search []string
	foundOne := false
	if filter != nil && filter.Subject != nil && filter.Subject.Package != nil {
		pkgs, err := c.findPackageVersion(ctx, filter.Subject.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		foundOne = len(pkgs) > 0
		for _, pkg := range pkgs {
			search = append(search, pkg.HasSBOMs...)
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Artifact != nil {
		exactArt, err := c.artifactExact(ctx, filter.Subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactArt != nil {
			search = exactArt.HasSBOMs
			foundOne = true
		}
	}

	var out []*model.HasSbom
	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*hasSBOMStruct](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addHasSBOMIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		hsks, err := c.kv.Keys(ctx, hasSBOMCol)
		if err != nil {
			return nil, err
		}
		for _, hsk := range hsks {
			link, err := byKeykv[*hasSBOMStruct](ctx, hasSBOMCol, hsk, c)
			if err != nil {
				return nil, err
			}
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
		if noMatch(filter.URI, link.URI) ||
			noMatch(toLower(filter.Algorithm), link.Algorithm) ||
			noMatch(toLower(filter.Digest), link.Digest) ||
			noMatch(filter.DownloadLocation, link.DownloadLocation) ||
			noMatch(filter.Origin, link.Origin) ||
			noMatch(filter.Collector, link.Collector) ||
			(filter.KnownSince != nil && filter.KnownSince.After(link.KnownSince)) {
			return out, nil
		}
		if filter.Subject != nil {
			if filter.Subject.Package != nil {
				if link.Pkg == "" {
					return out, nil
				}
				p, err := c.buildPackageResponse(ctx, link.Pkg, filter.Subject.Package)
				if err != nil {
					return nil, err
				}
				if p == nil {
					return out, nil
				}
			} else if filter.Subject.Artifact != nil {
				if link.Artifact == "" {
					return out, nil
				}
				if !c.artifactMatch(ctx, link.Artifact, filter.Subject.Artifact) {
					return out, nil
				}
			}
		}
	}
	sb, err := c.convHasSBOM(ctx, link)
	if err != nil {
		return nil, err
	}
	return append(out, sb), nil
}
