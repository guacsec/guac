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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Internal isOccurrence

type isOccurrenceList []*isOccurrenceStruct
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

func (c *demoClient) isOccurrenceByKey(ctx context.Context, k string) (*isOccurrenceStruct, error) {
	strval, err := c.kv.Get(ctx, occCol, k)
	if err != nil {
		return nil, err
	}
	out := &isOccurrenceStruct{}
	if err = json.Unmarshal([]byte(strval), out); err != nil {
		return nil, err
	}
	return out, nil
}

// Ingest IngestOccurrences

func (c *demoClient) IngestOccurrences(ctx context.Context, subjects model.PackageOrSourceInputs, artifacts []*model.ArtifactInputSpec, occurrences []*model.IsOccurrenceInputSpec) ([]*model.IsOccurrence, error) {
	var modelIsOccurrences []*model.IsOccurrence

	for i := range occurrences {
		var isOccurrence *model.IsOccurrence
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

func (c *demoClient) IngestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, artifact model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec) (*model.IsOccurrence, error) {
	return c.ingestOccurrence(ctx, subject, artifact, occurrence, true)
}

func (c *demoClient) ingestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, artifact model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec, readOnly bool) (*model.IsOccurrence, error) {
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
		return nil, gqlerror.Errorf("%v :: Artifact not found %s", funcName, err)
	}
	in.Artifact = a.ThisID

	var packageID string
	if subject.Package != nil {
		var pmt model.MatchFlags
		pmt.Pkg = model.PkgMatchTypeSpecificVersion
		pid, err := getPackageIDFromInput(c, *subject.Package, pmt)
		if err != nil {
			return nil, gqlerror.Errorf("IngestOccurrence :: %v", err)
		}
		packageID = pid
		in.Pkg = pid
	}

	var sourceID string
	if subject.Source != nil {
		sid, err := getSourceIDFromInput(c, *subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("IngestOccurrence :: %v", err)
		}
		sourceID = sid
		in.Source = sid
	}

	out, err := c.isOccurrenceByKey(ctx, in.Key())
	if err == nil {
		//fmt.Printf("return existing: %q %q %q\n", in.Artifact, out.Artifact, out.ThisID)
		return c.convOccurrence(ctx, out)
	}
	// FIXME, redis should catch key error and convert to these
	// if !errors.Is(err, kv.KeyError) && !errors.Is(err, kv.CollectionError) {
	// 	return nil, err
	// }

	if readOnly {
		c.m.RUnlock()
		o, err := c.ingestOccurrence(ctx, subject, artifact, occurrence, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return o, err
	}
	in.ThisID = c.getNextID()
	if err := c.kv.Set(ctx, indexCol, in.ThisID, in.Key()); err != nil {
		fmt.Printf("error 1 %v\n", err)
		return nil, err
	}
	c.artifactSetOccurrences(ctx, in.Artifact, in.ThisID)
	if packageID != "" {
		p, err := byID[*pkgVersionNode](packageID, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		p.setOccurrenceLinks(in.ThisID)
	} else {
		s, err := byID[*srcNameNode](sourceID, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		s.setOccurrenceLinks(in.ThisID)
	}
	byteval, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	if err := c.kv.Set(ctx, occCol, in.Key(), string(byteval)); err != nil {
		fmt.Printf("error 2 %v\n", err)
		return nil, err
	}

	return c.convOccurrence(ctx, in)
}

func (c *demoClient) convOccurrence(ctx context.Context, in *isOccurrenceStruct) (*model.IsOccurrence, error) {
	a, err := c.artifactModelByID(ctx, in.Artifact)
	if err != nil {
		fmt.Printf("error 6 %v\n", err)
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
		p, err := c.buildPackageResponse(in.Pkg, nil)
		if err != nil {
			fmt.Printf("error 7 %v\n", err)
			return nil, err
		}
		o.Subject = p
	} else {
		s, err := c.buildSourceResponse(in.Source, nil)
		if err != nil {
			fmt.Printf("error 8 %v\n", err)
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
	m, err := byIDkv[*artStruct](ctx, aID, artCol, c)
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
		link, err := byIDkv[*isOccurrenceStruct](ctx, *filter.ID, occCol, c)
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
		pkgs, err := c.findPackageVersion(filter.Subject.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		foundOne = len(pkgs) > 0
		for _, pkg := range pkgs {
			search = append(search, pkg.occurrences...)
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Source != nil {
		exactSource, err := c.exactSource(filter.Subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.occurrences...)
			foundOne = true
		}
	}

	var out []*model.IsOccurrence
	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*isOccurrenceStruct](ctx, id, occCol, c)
			if err != nil {
				fmt.Printf("error 4 %v\n", err)
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
			link, err := c.isOccurrenceByKey(ctx, ok)
			if err != nil {
				fmt.Printf("error 3 %v\n", err)
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
			p, err := c.buildPackageResponse(link.Pkg, filter.Subject.Package)
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
			s, err := c.buildSourceResponse(link.Source, filter.Subject.Source)
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
