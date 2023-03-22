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
	"errors"
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

func (n *isOccurrenceStruct) Neighbors() []uint32 {
	out := make([]uint32, 0, 3)
	if n.pkg != 0 {
		out = append(out, n.pkg)
	}
	if n.source != 0 {
		out = append(out, n.source)
	}
	out = append(out, n.artifact)
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
	err := helper.ValidatePackageOrSourceInput(&subject, "IngestOccurrence")
	if err != nil {
		return nil, err
	}

	a, err := c.artifactByKey(artifact.Algorithm, artifact.Digest)
	if err != nil {
		return nil, gqlerror.Errorf("IngestOccurrence :: Artifact not found")
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
		o, _ := c.occurrenceByID(id)
		if o.pkg == packageID &&
			o.source == sourceID &&
			o.artifact == a.id &&
			o.justification == occurrence.Justification &&
			o.origin == occurrence.Origin &&
			o.collector == occurrence.Collector {
			return c.convOccurrence(o), nil
		}
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
		p, _ := c.pkgVersionByID(packageID)
		p.setOccurrenceLinks(o.id)
	} else {
		s, _ := c.sourceByID(sourceID)
		s.setOccurrenceLinks(o.id)
	}
	c.occurrences = append(c.occurrences, o)

	return c.convOccurrence(o), nil
}

func (c *demoClient) occurrenceByID(id uint32) (*isOccurrenceStruct, error) {
	o, ok := c.index[id]
	if !ok {
		return nil, errors.New("could not find occurrence")
	}
	a, ok := o.(*isOccurrenceStruct)
	if !ok {
		return nil, errors.New("not an occurrence")
	}
	return a, nil
}

func (c *demoClient) convOccurrence(in *isOccurrenceStruct) *model.IsOccurrence {
	a, _ := c.artifactByID(in.artifact)
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
	m, _ := c.artifactByID(aID)
	if artifactSpec.Digest != nil && strings.ToLower(*artifactSpec.Digest) == m.digest {
		return true
	}
	if artifactSpec.Algorithm != nil && strings.ToLower(*artifactSpec.Algorithm) == m.algorithm {
		return true
	}
	return false
}

// Query IsOccurrence

func (c *demoClient) IsOccurrence(ctx context.Context, ioSpec *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {
	err := helper.ValidatePackageOrSourceQueryFilter(ioSpec.Subject)
	if err != nil {
		return nil, err
	}

	if ioSpec.ID != nil {
		id64, err := strconv.ParseUint(*ioSpec.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("IsOccurrence :: invalid ID %s", err)
		}
		id := uint32(id64)
		o, err := c.occurrenceByID(id)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		return []*model.IsOccurrence{c.convOccurrence(o)}, nil
	}

	var rv []*model.IsOccurrence
	// TODO if any of the pkg/src/artifact are specified, ony search those backedges
	for _, o := range c.occurrences {
		if noMatch(ioSpec.Justification, o.justification) ||
			noMatch(ioSpec.Origin, o.origin) ||
			noMatch(ioSpec.Collector, o.collector) {
			continue
		}
		if ioSpec.Artifact != nil && !c.artifactMatch(o.artifact, ioSpec.Artifact) {
			continue
		}
		if ioSpec.Subject != nil {
			if ioSpec.Subject.Package != nil {
				if o.pkg == 0 {
					continue
				}
				p, err := c.buildPackageResponse(o.pkg, ioSpec.Subject.Package)
				if err != nil {
					return nil, err
				}
				if p == nil {
					continue
				}
			} else if ioSpec.Subject.Source != nil {
				if o.source == 0 {
					continue
				}
				s, err := c.buildSourceResponse(o.source, ioSpec.Subject.Source)
				if err != nil {
					return nil, err
				}
				if s == nil {
					continue
				}
			}
		}
		rv = append(rv, c.convOccurrence(o))
	}

	return rv, nil
}
