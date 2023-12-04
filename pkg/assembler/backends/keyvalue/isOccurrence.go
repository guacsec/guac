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

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
)

// Internal isOccurrence

type isOccurrenceStruct struct {
	ThisID        string
	Pkg           string
	Source        string
	Artifact      string
	Justification string
	Origin        string
	Collector     string
}

func (n *isOccurrenceStruct) ID() string { return n.ThisID }

func (n *isOccurrenceStruct) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 3)
	if n.Pkg != "" && allowedEdges[model.EdgeIsOccurrencePackage] {
		out = append(out, n.Pkg)
	}
	if n.Source != "" && allowedEdges[model.EdgeIsOccurrenceSource] {
		out = append(out, n.Source)
	}
	if allowedEdges[model.EdgeIsOccurrenceArtifact] {
		out = append(out, n.Artifact)
	}
	return out
}

func (n *isOccurrenceStruct) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.convOccurrence(ctx, n)
}

func (n *isOccurrenceStruct) Key() string {
	return strings.Join([]string{
		n.Pkg,
		n.Source,
		n.Artifact,
		n.Justification,
		n.Origin,
		n.Collector,
	}, ":")
}

// Ingest IngestOccurrences

func (c *demoClient) IngestOccurrences(ctx context.Context, subjects model.PackageOrSourceInputs, artifacts []*model.ArtifactInputSpec, occurrences []*model.IsOccurrenceInputSpec) ([]string, error) {
	var modelIsOccurrences []string

	for i := range occurrences {
		var isOccurrence string
		var err error
		if len(subjects.Packages) > 0 {
			subject := model.PackageOrSourceInput{Package: subjects.Packages[i]}
			isOccurrence, err = c.IngestOccurrence(ctx, subject, *artifacts[i], *occurrences[i])
			if err != nil {
				return nil, gqlerror.Errorf("ingestOccurrence failed with err: %v", err)
			}
		} else {
			subject := model.PackageOrSourceInput{Source: subjects.Sources[i]}
			isOccurrence, err = c.IngestOccurrence(ctx, subject, *artifacts[i], *occurrences[i])
			if err != nil {
				return nil, gqlerror.Errorf("ingestOccurrence failed with err: %v", err)
			}
		}
		modelIsOccurrences = append(modelIsOccurrences, isOccurrence)
	}
	return modelIsOccurrences, nil
}

// Ingest IsOccurrence

func (c *demoClient) IngestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, artifact model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec) (string, error) {
	return c.ingestOccurrence(ctx, subject, artifact, occurrence, true)
}

func (c *demoClient) ingestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, artifact model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec, readOnly bool) (string, error) {
	funcName := "IngestOccurrence"

	in := &isOccurrenceStruct{
		Justification: occurrence.Justification,
		Origin:        occurrence.Origin,
		Collector:     occurrence.Collector,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	a, err := c.artifactByInput(ctx, &artifact)
	if err != nil {
		return "", gqlerror.Errorf("%v :: Artifact not found %s", funcName, err)
	}
	in.Artifact = a.ThisID

	var pkgVer *pkgVersion
	if subject.Package != nil {
		var err error
		pkgVer, err = c.getPackageVerFromInput(ctx, *subject.Package)
		if err != nil {
			return "", gqlerror.Errorf("IngestOccurrence :: %v", err)
		}
		in.Pkg = pkgVer.ThisID
	}

	var src *srcNameNode
	if subject.Source != nil {
		var err error
		src, err = c.getSourceNameFromInput(ctx, *subject.Source)
		if err != nil {
			return "", gqlerror.Errorf("IngestOccurrence :: %v", err)
		}
		in.Source = src.ThisID
	}

	out, err := byKeykv[*isOccurrenceStruct](ctx, occCol, in.Key(), c)
	if err == nil {
		return out.ThisID, nil
	}
	if !errors.Is(err, kv.NotFoundError) {
		return "", err
	}

	if readOnly {
		c.m.RUnlock()
		o, err := c.ingestOccurrence(ctx, subject, artifact, occurrence, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return o, err
	}
	in.ThisID = c.getNextID()
	if err := c.addToIndex(ctx, occCol, in); err != nil {
		return "", err
	}
	if err := a.setOccurrences(ctx, in.ThisID, c); err != nil {
		return "", err
	}
	if pkgVer != nil {
		if err := pkgVer.setOccurrenceLinks(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	} else {
		if err := src.setOccurrenceLinks(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	}
	if err := setkv(ctx, occCol, in, c); err != nil {
		return "", err
	}

	return in.ThisID, nil
}

func (c *demoClient) convOccurrence(ctx context.Context, in *isOccurrenceStruct) (*model.IsOccurrence, error) {
	a, err := c.artifactModelByID(ctx, in.Artifact)
	if err != nil {
		return nil, err
	}
	o := &model.IsOccurrence{
		ID:            in.ThisID,
		Artifact:      a,
		Justification: in.Justification,
		Origin:        in.Origin,
		Collector:     in.Collector,
	}
	if in.Pkg != "" {
		p, err := c.buildPackageResponse(ctx, in.Pkg, nil)
		if err != nil {
			return nil, err
		}
		o.Subject = p
	} else {
		s, err := c.buildSourceResponse(ctx, in.Source, nil)
		if err != nil {
			return nil, err
		}
		o.Subject = s
	}
	return o, nil
}

func (c *demoClient) artifactMatch(ctx context.Context, aID string, artifactSpec *model.ArtifactSpec) bool {
	if artifactSpec.Digest == nil && artifactSpec.Algorithm == nil {
		return true
	}
	a, _ := c.artifactExact(ctx, artifactSpec)
	if a != nil && a.ID() == aID {
		return true
	}
	m, err := byIDkv[*artStruct](ctx, aID, c)
	if err != nil {
		return false
	}
	if artifactSpec.Digest != nil && strings.ToLower(*artifactSpec.Digest) == m.Digest {
		return true
	}
	if artifactSpec.Algorithm != nil && strings.ToLower(*artifactSpec.Algorithm) == m.Algorithm {
		return true
	}
	return false
}

// Query IsOccurrence

func (c *demoClient) IsOccurrence(ctx context.Context, filter *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {
	funcName := "IsOccurrence"

	c.m.RLock()
	defer c.m.RUnlock()

	if filter != nil && filter.ID != nil {
		link, err := byIDkv[*isOccurrenceStruct](ctx, *filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		o, err := c.convOccurrence(ctx, link)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.IsOccurrence{o}, nil
	}

	var search []string
	foundOne := false
	if filter != nil && filter.Artifact != nil {
		exactArtifact, err := c.artifactExact(ctx, filter.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactArtifact != nil {
			search = append(search, exactArtifact.Occurrences...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Package != nil {
		pkgs, err := c.findPackageVersion(ctx, filter.Subject.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		foundOne = len(pkgs) > 0
		for _, pkg := range pkgs {
			search = append(search, pkg.Occurrences...)
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Source != nil {
		exactSource, err := c.exactSource(ctx, filter.Subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.Occurrences...)
			foundOne = true
		}
	}

	var out []*model.IsOccurrence
	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*isOccurrenceStruct](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addOccIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		occKeys, err := c.kv.Keys(ctx, occCol)
		if err != nil {
			return nil, err
		}
		for _, ok := range occKeys {
			link, err := byKeykv[*isOccurrenceStruct](ctx, occCol, ok, c)
			if err != nil {
				return nil, err
			}
			out, err = c.addOccIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}
	return out, nil
}

func (c *demoClient) addOccIfMatch(ctx context.Context, out []*model.IsOccurrence,
	filter *model.IsOccurrenceSpec, link *isOccurrenceStruct) (
	[]*model.IsOccurrence, error) {

	if noMatch(filter.Justification, link.Justification) ||
		noMatch(filter.Origin, link.Origin) ||
		noMatch(filter.Collector, link.Collector) {
		return out, nil
	}
	if filter.Artifact != nil && !c.artifactMatch(ctx, link.Artifact, filter.Artifact) {
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
		} else if filter.Subject.Source != nil {
			if link.Source == "" {
				return out, nil
			}
			s, err := c.buildSourceResponse(ctx, link.Source, filter.Subject.Source)
			if err != nil {
				return nil, err
			}
			if s == nil {
				return out, nil
			}
		}
	}
	o, err := c.convOccurrence(ctx, link)
	if err != nil {
		return nil, err
	}
	return append(out, o), nil
}

func (c *demoClient) matchOccurrences(ctx context.Context, filters []*model.IsOccurrenceSpec, occLinkIDs []string) bool {
	var occLinks []*isOccurrenceStruct
	if len(filters) > 0 {
		for _, occLinkID := range occLinkIDs {
			link, err := byIDkv[*isOccurrenceStruct](ctx, occLinkID, c)
			if err != nil {
				return false
			}
			occLinks = append(occLinks, link)
		}

		for _, filter := range filters {
			if filter == nil {
				continue
			}
			if filter.ID != nil {
				// Check by ID if present
				if !helper.IsIDPresent(*filter.ID, occLinkIDs) {
					return false
				}
			} else {
				// Otherwise match spec information
				match := false
				for _, link := range occLinks {
					if !noMatch(filter.Justification, link.Justification) &&
						!noMatch(filter.Origin, link.Origin) &&
						!noMatch(filter.Collector, link.Collector) &&
						c.matchArtifacts(ctx, []*model.ArtifactSpec{filter.Artifact}, []string{link.Artifact}) {

						if filter.Subject != nil {
							if filter.Subject.Package != nil && !c.matchPackages(ctx, []*model.PkgSpec{filter.Subject.Package}, []string{link.Pkg}) {
								continue
							} else if filter.Subject.Source != nil {
								src, err := c.exactSource(ctx, filter.Subject.Source)
								if err != nil || src == nil {
									continue
								}
							}
						}
						match = true
						break
					}
				}
				if !match {
					return false
				}
			}
		}
	}
	return true
}
