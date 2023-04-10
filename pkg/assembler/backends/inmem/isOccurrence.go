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
	"strconv"
	"strings"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Internal isOccurrence

type isOccurrenceList []*isOccurrenceStruct
type isOccurrenceStruct struct {
	id            uint32
	pkg           uint32
	source        uint32
	artifact      uint32
	justification string
	origin        string
	collector     string
}

func (n *isOccurrenceStruct) ID() uint32 { return n.id }

func (n *isOccurrenceStruct) Neighbors(allowedEdges edgeMap) []uint32 {
	out := make([]uint32, 0, 3)
	if n.pkg != 0 && allowedEdges[model.EdgeIsOccurrencePackage] {
		out = append(out, n.pkg)
	}
	if n.source != 0 && allowedEdges[model.EdgeIsOccurrenceSource] {
		out = append(out, n.source)
	}
	if allowedEdges[model.EdgeIsOccurrenceArtifact] {
		out = append(out, n.artifact)
	}
	return out
}

func (n *isOccurrenceStruct) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.convOccurrence(n), nil
}

// TODO convert to unit tests
// func registerAllIsOccurrence(client *demoClient) error {
// 	// pkg:conan/openssl.org/openssl@3.0.3?user=bincrafters&channel=stable
// 	// "conan", "openssl.org", "openssl", "3.0.3", "", "user=bincrafters", "channel=stable"
// 	selectedType := "conan"
// 	selectedNameSpace := "openssl.org"
// 	selectedName := "openssl"
// 	selectedVersion := "3.0.3"
// 	qualifierA := "bincrafters"
// 	qualifierB := "stable"
// 	selectedQualifiers := []*model.PackageQualifierSpec{{Key: "user", Value: &qualifierA}, {Key: "channel", Value: &qualifierB}}
// 	selectedPkgSpec := &model.PkgSpec{Type: &selectedType, Namespace: &selectedNameSpace, Name: &selectedName, Version: &selectedVersion, Qualifiers: selectedQualifiers}
// 	selectedPackage, err := client.Packages(context.TODO(), selectedPkgSpec)
// 	if err != nil {
// 		return err
// 	}
// 	_, err = client.registerIsOccurrence(selectedPackage[0], nil, &model.Artifact{Digest: "5a787865sd676dacb0142afa0b83029cd7befd9", Algorithm: "sha1"}, "this artifact is an occurrence of this package", "inmem backend", "inmem backend")
// 	if err != nil {
// 		return err
// 	}
// 	// "git", "github", "github.com/guacsec/guac", "tag=v0.0.1"
// 	selectedSourceType := "git"
// 	selectedSourceNameSpace := "github"
// 	selectedSourceName := "github.com/guacsec/guac"
// 	selectedTag := "v0.0.1"
// 	selectedSourceSpec := &model.SourceSpec{Type: &selectedSourceType, Namespace: &selectedSourceNameSpace, Name: &selectedSourceName, Tag: &selectedTag}
// 	//selectedSource, err := client.Sources(context.TODO(), selectedSourceSpec)
// 	_, err = client.Sources(context.TODO(), selectedSourceSpec)
// 	if err != nil {
// 		return err
// 	}
// 	//_, err = client.registerIsOccurrence(nil, selectedSource[0], client.artifacts[0], "this artifact is an occurrence of this source", "inmem backend", "inmem backend")
// 	if err != nil {
// 		return err
// 	}
// }

// Ingest IsOccurrence
func (c *demoClient) IngestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, artifact model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec) (*model.IsOccurrence, error) {
	return c.ingestOccurrence(ctx, subject, artifact, occurrence, true)
}

func (c *demoClient) ingestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, artifact model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec, readOnly bool) (*model.IsOccurrence, error) {
	funcName := "IngestOccurrence"
	if err := helper.ValidatePackageOrSourceInput(&subject, "IngestOccurrence"); err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	a, err := c.artifactByKey(artifact.Algorithm, artifact.Digest)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: Artifact not found %s", funcName, err)
	}

	var packageID uint32
	if subject.Package != nil {
		var pmt model.MatchFlags
		pmt.Pkg = model.PkgMatchTypeSpecificVersion
		pid, err := getPackageIDFromInput(c, *subject.Package, pmt)
		if err != nil {
			return nil, gqlerror.Errorf("IngestOccurrence :: %v", err)
		}
		packageID = pid
	}

	var sourceID uint32
	if subject.Source != nil {
		sid, err := getSourceIDFromInput(c, *subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("IngestOccurrence :: %v", err)
		}
		sourceID = sid
	}

	// could search backedges for pkg/src or artifiact, just do artifact
	for _, id := range a.occurrences {
		o, _ := byID[*isOccurrenceStruct](id, c)
		if o.pkg == packageID &&
			o.source == sourceID &&
			o.artifact == a.id &&
			o.justification == occurrence.Justification &&
			o.origin == occurrence.Origin &&
			o.collector == occurrence.Collector {
			return c.convOccurrence(o), nil
		}
	}
	if readOnly {
		c.m.RUnlock()
		o, err := c.ingestOccurrence(ctx, subject, artifact, occurrence, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return o, err
	}
	o := &isOccurrenceStruct{
		id:            c.getNextID(),
		pkg:           packageID,
		source:        sourceID,
		artifact:      a.id,
		justification: occurrence.Justification,
		origin:        occurrence.Origin,
		collector:     occurrence.Collector,
	}
	c.index[o.id] = o
	a.setOccurrences(o.id)
	if packageID != 0 {
		p, _ := byID[*pkgVersionNode](packageID, c)
		p.setOccurrenceLinks(o.id)
	} else {
		s, _ := byID[*srcNameNode](sourceID, c)
		s.setOccurrenceLinks(o.id)
	}
	c.occurrences = append(c.occurrences, o)

	return c.convOccurrence(o), nil
}

func (c *demoClient) convOccurrence(in *isOccurrenceStruct) *model.IsOccurrence {
	a, _ := byID[*artStruct](in.artifact, c)
	o := &model.IsOccurrence{
		ID:            nodeID(in.id),
		Artifact:      c.convArtifact(a),
		Justification: in.justification,
		Origin:        in.origin,
		Collector:     in.collector,
	}
	if in.pkg != 0 {
		p, _ := c.buildPackageResponse(in.pkg, nil)
		o.Subject = p
	} else {
		s, _ := c.buildSourceResponse(in.source, nil)
		o.Subject = s
	}
	return o
}

func (c *demoClient) artifactMatch(aID uint32, artifactSpec *model.ArtifactSpec) bool {
	if artifactSpec.Digest == nil && artifactSpec.Algorithm == nil {
		return true
	}
	a, _ := c.artifactExact(artifactSpec)
	if a != nil && a.id == aID {
		return true
	}
	m, _ := byID[*artStruct](aID, c)
	if artifactSpec.Digest != nil && strings.ToLower(*artifactSpec.Digest) == m.digest {
		return true
	}
	if artifactSpec.Algorithm != nil && strings.ToLower(*artifactSpec.Algorithm) == m.algorithm {
		return true
	}
	return false
}

// Query IsOccurrence

func (c *demoClient) IsOccurrence(ctx context.Context, filter *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {
	funcName := "IsOccurrence"
	if err := helper.ValidatePackageOrSourceQueryFilter(filter.Subject); err != nil {
		return nil, err
	}

	c.m.RLock()
	defer c.m.RUnlock()

	if filter != nil && filter.ID != nil {
		id64, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: invalid ID %s", funcName, err)
		}
		id := uint32(id64)
		link, err := byID[*isOccurrenceStruct](id, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		return []*model.IsOccurrence{c.convOccurrence(link)}, nil
	}

	var search []uint32
	foundOne := false
	if filter != nil && filter.Artifact != nil {
		exactArtifact, err := c.artifactExact(filter.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactArtifact != nil {
			search = append(search, exactArtifact.occurrences...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Package != nil {
		exactPackage, err := c.exactPackageVersion(filter.Subject.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactPackage != nil {
			search = append(search, exactPackage.occurrences...)
			foundOne = true
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
			link, err := byID[*isOccurrenceStruct](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addOccIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.occurrences {
			var err error
			out, err = c.addOccIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}
	return out, nil
}

func (c *demoClient) addOccIfMatch(out []*model.IsOccurrence,
	filter *model.IsOccurrenceSpec, link *isOccurrenceStruct) (
	[]*model.IsOccurrence, error) {

	if noMatch(filter.Justification, link.justification) ||
		noMatch(filter.Origin, link.origin) ||
		noMatch(filter.Collector, link.collector) {
		return out, nil
	}
	if filter.Artifact != nil && !c.artifactMatch(link.artifact, filter.Artifact) {
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
		} else if filter.Subject.Source != nil {
			if link.source == 0 {
				return out, nil
			}
			s, err := c.buildSourceResponse(link.source, filter.Subject.Source)
			if err != nil {
				return nil, err
			}
			if s == nil {
				return out, nil
			}
		}
	}
	return append(out, c.convOccurrence(link)), nil
}
