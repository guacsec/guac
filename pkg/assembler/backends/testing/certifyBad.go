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
	"strings"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func registerAllCertifyBad(client *demoClient) error {
	// pkg:conan/openssl.org/openssl@3.0.3?user=bincrafters&channel=stable
	// "conan", "openssl.org", "openssl", "3.0.3", "", "user=bincrafters", "channel=stable"
	selectedType := "conan"
	selectedNameSpace := "openssl.org"
	selectedName := "openssl"
	selectedVersion := "3.0.3"
	qualifierA := "bincrafters"
	qualifierB := "stable"
	selectedQualifiers := []*model.PackageQualifierSpec{{Key: "user", Value: &qualifierA}, {Key: "channel", Value: &qualifierB}}
	selectedPkgSpec := &model.PkgSpec{Type: &selectedType, Namespace: &selectedNameSpace, Name: &selectedName, Version: &selectedVersion, Qualifiers: selectedQualifiers}
	selectedPackage, err := client.Packages(context.TODO(), selectedPkgSpec)
	if err != nil {
		return err
	}
	_, err = client.registerCertifyBad(selectedPackage[0], nil, nil, "this openssl package is a typosquatting", "testing backend", "testing backend")
	if err != nil {
		return err
	}
	// "git", "github", "github.com/guacsec/guac", "tag=v0.0.1"
	selectedSourceType := "git"
	selectedSourceNameSpace := "github"
	selectedSourceName := "github.com/guacsec/guac"
	selectedTag := "v0.0.1"
	selectedSourceSpec := &model.SourceSpec{Type: &selectedSourceType, Namespace: &selectedSourceNameSpace, Name: &selectedSourceName, Tag: &selectedTag}
	selectedSource, err := client.Sources(context.TODO(), selectedSourceSpec)
	if err != nil {
		return err
	}
	_, err = client.registerCertifyBad(nil, selectedSource[0], nil, "this source is associated with a bad author", "testing backend", "testing backend")
	if err != nil {
		return err
	}

	_, err = client.registerCertifyBad(nil, nil, &model.Artifact{Digest: "5a787865sd676dacb0142afa0b83029cd7befd9", Algorithm: "sha1"}, "this artifact is associated with a bad package", "testing backend", "testing backend")
	if err != nil {
		return err
	}

	return nil
}

// Ingest CertifyBad

func (c *demoClient) registerCertifyBad(selectedPackage *model.Package, selectedSource *model.Source, selectedArtifact *model.Artifact, justification, origin, collector string) (*model.CertifyBad, error) {

	if selectedPackage != nil && selectedSource != nil && selectedArtifact != nil {
		return nil, fmt.Errorf("cannot specify package, source or artifact together for CertifyBad")
	}

	for _, bad := range c.certifyBad {
		if bad.Justification == justification {
			if val, ok := bad.Subject.(model.Package); ok {
				if reflect.DeepEqual(val, *selectedPackage) {
					return bad, nil
				}
			} else if val, ok := bad.Subject.(model.Source); ok {
				if reflect.DeepEqual(val, *selectedSource) {
					return bad, nil
				}
			} else if val, ok := bad.Subject.(model.Artifact); ok {
				if reflect.DeepEqual(val, *selectedArtifact) {
					return bad, nil
				}
			}
		}
	}

	newCertifyBad := &model.CertifyBad{
		Justification: justification,
		Origin:        origin,
		Collector:     collector,
	}
	if selectedPackage != nil {
		newCertifyBad.Subject = selectedPackage
	} else if selectedSource != nil {
		newCertifyBad.Subject = selectedSource
	} else {
		newCertifyBad.Subject = selectedArtifact
	}

	c.certifyBad = append(c.certifyBad, newCertifyBad)
	return newCertifyBad, nil
}

func (c *demoClient) IngestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyBad model.CertifyBadInputSpec) (*model.CertifyBad, error) {

	err := helper.CheckCertifyBadIngestionInput(subject)
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
	return nil, nil
}

// Query CertifyBad

func (c *demoClient) CertifyBad(ctx context.Context, certifyBadSpec *model.CertifyBadSpec) ([]*model.CertifyBad, error) {

	queryAll, err := helper.CheckCertifyBadQueryInput(certifyBadSpec.Subject)
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
