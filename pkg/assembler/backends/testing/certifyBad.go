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
	"strings"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// Internal data: link that a package/source/artifact is bad
type badList []*badLink
type badLink struct {
	id            uint32
	packageID     uint32
	artifactID    uint32
	sourceID      uint32
	justification string
	origin        string
	collector     string
}

func (n *badLink) getID() uint32 { return n.id }

// Ingest CertifyBad
func (c *demoClient) IngestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyBad model.CertifyBadInputSpec) (*model.CertifyBad, error) {

	err := helper.ValidatePackageSourceOrArtifactInput(&subject, "bad subject")
	if err != nil {
		return nil, err
	}

	if subject.Package != nil {
		var selectedPkgSpec *model.PkgSpec
		if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
			selectedPkgSpec = helper.ConvertPkgInputSpecToPkgSpec(subject.Package)

		} else {
			selectedPkgSpec = &model.PkgSpec{
				Type:      &subject.Package.Type,
				Namespace: subject.Package.Namespace,
				Name:      &subject.Package.Name,
			}
		}
		collectedPkg, err := c.Packages(ctx, selectedPkgSpec)
		if err != nil {
			return nil, err
		}
		if len(collectedPkg) != 1 {
			return nil, gqlerror.Errorf(
				"IngestCertifyBad :: multiple packages found")
		}
		return c.registerCertifyBad(
			collectedPkg[0],
			nil,
			nil,
			certifyBad.Justification,
			certifyBad.Origin,
			certifyBad.Collector)
	}

	if subject.Source != nil {
		sourceSpec := helper.ConvertSrcInputSpecToSrcSpec(subject.Source)

		sources, err := c.Sources(ctx, sourceSpec)
		if err != nil {
			return nil, err
		}
		if len(sources) != 1 {
			return nil, gqlerror.Errorf(
				"IngestCertifyBad :: source argument must match one"+
					" single source repository, found %d",
				len(sources))
		}
		return c.registerCertifyBad(
			nil,
			sources[0],
			nil,
			certifyBad.Justification,
			certifyBad.Origin,
			certifyBad.Collector)
	}

	if subject.Artifact != nil {
		collectedArt, err := c.Artifacts(ctx, &model.ArtifactSpec{Algorithm: &subject.Artifact.Algorithm, Digest: &subject.Artifact.Digest})
		if err != nil {
			return nil, err
		}
		if len(collectedArt) != 1 {
			return nil, gqlerror.Errorf(
				"IngestCertifyBad :: multiple artifacts found")
		}
		return c.registerCertifyBad(
			nil,
			nil,
			collectedArt[0],
			certifyBad.Justification,
			certifyBad.Origin,
			certifyBad.Collector)
	}
	// it should never reach here else it failed
	return nil, gqlerror.Errorf("IngestCertifyBad failed")
}

// Query CertifyBad

func (c *demoClient) CertifyBad(ctx context.Context, certifyBadSpec *model.CertifyBadSpec) ([]*model.CertifyBad, error) {

	err := helper.ValidatePackageSourceOrArtifactQueryFilter(certifyBadSpec.Subject)
	if err != nil {
		return nil, err
	}

	var foundCertifyBad []*model.CertifyBad

	for _, h := range c.certifyBad {
		matchOrSkip := true

		if certifyBadSpec.Justification != nil && h.Justification != *certifyBadSpec.Justification {
			matchOrSkip = false
		}
		if certifyBadSpec.Collector != nil && h.Collector != *certifyBadSpec.Collector {
			matchOrSkip = false
		}
		if certifyBadSpec.Origin != nil && h.Origin != *certifyBadSpec.Origin {
			matchOrSkip = false
		}

		if !queryAll {
			if certifyBadSpec.Subject != nil && certifyBadSpec.Subject.Package != nil && h.Subject != nil {
				if val, ok := h.Subject.(*model.Package); ok {
					if certifyBadSpec.Subject.Package.Type == nil || val.Type == *certifyBadSpec.Subject.Package.Type {
						newPkg := filterPackageNamespace(val, certifyBadSpec.Subject.Package)
						if newPkg == nil {
							matchOrSkip = false
						}
					}
				} else {
					matchOrSkip = false
				}
			}

			if certifyBadSpec.Subject != nil && certifyBadSpec.Subject.Source != nil && h.Subject != nil {
				if val, ok := h.Subject.(*model.Source); ok {
					if certifyBadSpec.Subject.Source.Type == nil || val.Type == *certifyBadSpec.Subject.Source.Type {
						newSource, err := filterSourceNamespace(val, certifyBadSpec.Subject.Source)
						if err != nil {
							return nil, err
						}
						if newSource == nil {
							matchOrSkip = false
						}
					}
				} else {
					matchOrSkip = false
				}
			}

			if certifyBadSpec.Subject != nil && certifyBadSpec.Subject.Artifact != nil && h.Subject != nil {
				if val, ok := h.Subject.(*model.Artifact); ok {
					queryArt := &model.Artifact{
						Algorithm: strings.ToLower(*certifyBadSpec.Subject.Artifact.Algorithm),
						Digest:    strings.ToLower(*certifyBadSpec.Subject.Artifact.Digest),
					}
					if *queryArt != *val {
						matchOrSkip = false
					}
				} else {
					matchOrSkip = false
				}
			}
		}

		if matchOrSkip {
			foundCertifyBad = append(foundCertifyBad, h)
		}
	}

	return foundCertifyBad, nil
}
