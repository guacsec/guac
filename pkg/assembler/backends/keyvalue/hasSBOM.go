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

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
)

type hasSBOMStruct struct {
	ThisID               string
	Pkg                  string
	Artifact             string
	URI                  string
	Algorithm            string
	Digest               string
	DownloadLocation     string
	Origin               string
	Collector            string
	KnownSince           time.Time
	IncludedSoftware     []string
	IncludedDependencies []string
	IncludedOccurrences  []string
}

func (n *hasSBOMStruct) ID() string { return n.ThisID }
func (n *hasSBOMStruct) Key() string {
	return hashKey(strings.Join([]string{
		n.Pkg,
		n.Artifact,
		n.URI,
		n.Algorithm,
		n.Digest,
		n.DownloadLocation,
		n.Origin,
		n.Collector,
		timeKey(n.KnownSince),
		fmt.Sprint(n.IncludedSoftware),
		fmt.Sprint(n.IncludedDependencies),
		fmt.Sprint(n.IncludedOccurrences),
	}, ":"))
}

func (n *hasSBOMStruct) Neighbors(allowedEdges edgeMap) []string {
	var out []string
	if n.Pkg != "" && allowedEdges[model.EdgeHasSbomPackage] {
		out = append(out, n.Pkg)
	}
	if n.Artifact != "" && allowedEdges[model.EdgeHasSbomArtifact] {
		out = append(out, n.Artifact)
	}
	if allowedEdges[model.EdgeHasSbomIncludedSoftware] {
		out = append(out, n.IncludedSoftware...)
	}
	if allowedEdges[model.EdgeHasSbomIncludedDependencies] {
		out = append(out, n.IncludedDependencies...)
	}
	if allowedEdges[model.EdgeHasSbomIncludedOccurrences] {
		out = append(out, n.IncludedOccurrences...)
	}
	return helper.SortAndRemoveDups(out)
}

func (n *hasSBOMStruct) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.convHasSBOM(ctx, n)
}

// Ingest HasSBOM

func (c *demoClient) IngestHasSBOMs(ctx context.Context, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec, includes []*model.HasSBOMIncludesInputSpec) ([]string, error) {
	var modelHasSboms []string

	for i := range hasSBOMs {
		var hasSBOM string
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

func (c *demoClient) IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, input model.HasSBOMInputSpec, includes model.HasSBOMIncludesInputSpec) (string, error) {
	funcName := "IngestHasSbom"

	c.m.RLock()
	for _, id := range includes.Software {
		if err := c.validateSoftwareId(ctx, funcName, id); err != nil {
			c.m.RUnlock()
			return "", err
		}
	}
	for _, id := range includes.Dependencies {
		if _, err := byIDkv[*isDependencyLink](ctx, id, c); err != nil {
			c.m.RUnlock()
			return "", gqlerror.Errorf("%v :: dependency id %v is not an ingested isDependency", funcName, id)
		}
	}
	for _, id := range includes.Occurrences {
		if _, err := byIDkv[*isOccurrenceStruct](ctx, id, c); err != nil {
			c.m.RUnlock()
			return "", gqlerror.Errorf("%v :: occurrence id %v is not an ingested isOccurrence", funcName, id)
		}
	}
	c.m.RUnlock()

	softwareIDs := helper.SortAndRemoveDups(includes.Software)
	dependencyIDs := helper.SortAndRemoveDups(includes.Dependencies)
	occurrenceIDs := helper.SortAndRemoveDups(includes.Occurrences)
	return c.ingestHasSbom(ctx, subject, input, softwareIDs, dependencyIDs, occurrenceIDs, true)
}

func (c *demoClient) validateSoftwareId(ctx context.Context, funcName string, id string) error {
	if _, err := byIDkv[*pkgVersion](ctx, id, c); err != nil {
		if _, err := byIDkv[*artStruct](ctx, id, c); err != nil {
			return gqlerror.Errorf("%v :: software id %v is neither an ingested Package nor an ingested Artifact", funcName, id)
		}
	}
	return nil
}

func (c *demoClient) ingestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, input model.HasSBOMInputSpec, includedSoftware, includedDependencies, includedOccurrences []string, readOnly bool) (string, error) {
	funcName := "IngestHasSbom"
	algorithm := strings.ToLower(input.Algorithm)
	digest := strings.ToLower(input.Digest)

	in := &hasSBOMStruct{
		URI:                  input.URI,
		Algorithm:            algorithm,
		Digest:               digest,
		DownloadLocation:     input.DownloadLocation,
		Origin:               input.Origin,
		Collector:            input.Collector,
		KnownSince:           input.KnownSince.UTC(),
		IncludedSoftware:     includedSoftware,
		IncludedDependencies: includedDependencies,
		IncludedOccurrences:  includedOccurrences,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var pkg *pkgVersion
	var art *artStruct

	if subject.Package != nil {
		var err error
		pkg, err = c.returnFoundPkgVersion(ctx, subject.Package)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.Pkg = pkg.ID()
	} else {
		var err error
		art, err = c.returnFoundArtifact(ctx, subject.Artifact)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.Artifact = art.ID()
	}

	out, err := byKeykv[*hasSBOMStruct](ctx, hasSBOMCol, in.Key(), c)
	if err == nil {
		return out.ThisID, nil
	}
	if !errors.Is(err, kv.NotFoundError) {
		return "", err
	}

	if readOnly {
		c.m.RUnlock()
		b, err := c.ingestHasSbom(ctx, subject, input, includedSoftware, includedDependencies, includedOccurrences, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return b, err
	}

	in.ThisID = c.getNextID()

	if err := c.addToIndex(ctx, hasSBOMCol, in); err != nil {
		return "", err
	}

	if pkg != nil {
		if err := pkg.setHasSBOM(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	} else {
		if err := art.setHasSBOMs(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	}

	if err := setkv(ctx, hasSBOMCol, in, c); err != nil {
		return "", err
	}

	return in.ThisID, nil
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
	if len(in.IncludedSoftware) > 0 {
		out.IncludedSoftware = make([]model.PackageOrArtifact, 0, len(in.IncludedSoftware))
		for _, id := range in.IncludedSoftware {
			p, err := c.buildPackageResponse(ctx, id, nil)
			if err != nil {
				art, err := c.artifactModelByID(ctx, id)
				if err != nil {
					return nil, fmt.Errorf("expected Package or Artifact: %w", err)
				}
				out.IncludedSoftware = append(out.IncludedSoftware, art)
			} else {
				out.IncludedSoftware = append(out.IncludedSoftware, p)
			}
		}
	}
	if len(in.IncludedDependencies) > 0 {
		out.IncludedDependencies = make([]*model.IsDependency, 0, len(in.IncludedDependencies))
		for _, id := range in.IncludedDependencies {
			link, err := byIDkv[*isDependencyLink](ctx, id, c)
			if err != nil {
				return nil, fmt.Errorf("expected IsDependency: %w", err)
			}
			isDep, err := c.buildIsDependency(ctx, link, nil, true)
			if err != nil {
				return nil, err
			}
			out.IncludedDependencies = append(out.IncludedDependencies, isDep)
		}
	}
	if len(in.IncludedOccurrences) > 0 {
		out.IncludedOccurrences = make([]*model.IsOccurrence, 0, len(in.IncludedOccurrences))
		for _, id := range in.IncludedOccurrences {
			link, err := byIDkv[*isOccurrenceStruct](ctx, id, c)
			if err != nil {
				return nil, fmt.Errorf("expected IsDependency: %w", err)
			}
			isOcc, err := c.convOccurrence(ctx, link)
			if err != nil {
				return nil, err
			}
			out.IncludedOccurrences = append(out.IncludedOccurrences, isOcc)
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
		var done bool
		scn := c.kv.Keys(hasSBOMCol)
		for !done {
			var hsks []string
			var err error
			hsks, done, err = scn.Scan(ctx)
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
		// collect packages and artifacts from included software
		pkgs, artifacts, err := c.getPackageVersionAndArtifacts(ctx, link.IncludedSoftware)
		if err != nil {
			return out, err
		}

		pkgFilters, artFilters := helper.GetPackageAndArtifactFilters(filter.IncludedSoftware)
		if !c.matchPackages(ctx, pkgFilters, pkgs) || !c.matchArtifacts(ctx, artFilters, artifacts) ||
			!c.matchDependencies(ctx, filter.IncludedDependencies, link.IncludedDependencies) ||
			!c.matchOccurrences(ctx, filter.IncludedOccurrences, link.IncludedOccurrences) {
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
