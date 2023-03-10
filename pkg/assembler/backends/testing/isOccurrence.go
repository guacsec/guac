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

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func registerAllIsOccurrence(client *demoClient) error {
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
	_, err = client.registerIsOccurrence(selectedPackage[0], nil, &model.Artifact{Digest: "5a787865sd676dacb0142afa0b83029cd7befd9", Algorithm: "sha1"}, "this artifact is an occurrence of this package", "testing backend", "testing backend")
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
	_, err = client.registerIsOccurrence(nil, selectedSource[0], client.artifacts[0], "this artifact is an occurrence of this source", "testing backend", "testing backend")
	if err != nil {
		return err
	}
	return nil
}

// Ingest IsOccurrence

func (c *demoClient) registerIsOccurrence(selectedPackage *model.Package, selectedSource *model.Source, artifact *model.Artifact, justification, origin, collector string) (*model.IsOccurrence, error) {

	if selectedPackage != nil && selectedSource != nil {
		return nil, fmt.Errorf("cannot specify both package and source for IsOccurrence")
	}

	for _, occurrence := range c.isOccurrence {
		if reflect.DeepEqual(occurrence.Artifact, artifact) && occurrence.Justification == justification {
			if val, ok := occurrence.Subject.(model.Package); ok {
				if reflect.DeepEqual(val, *selectedPackage) {
					return occurrence, nil
				}
			} else if val, ok := occurrence.Subject.(model.Source); ok {
				if reflect.DeepEqual(val, *selectedSource) {
					return occurrence, nil
				}
			}
		}
	}

	newIsOccurrence := &model.IsOccurrence{
		Justification: justification,
		Artifact:      artifact,
		Origin:        origin,
		Collector:     collector,
	}
	if selectedPackage != nil {
		newIsOccurrence.Subject = selectedPackage
	} else {
		newIsOccurrence.Subject = selectedSource
	}

	c.isOccurrence = append(c.isOccurrence, newIsOccurrence)
	return newIsOccurrence, nil
}

func (c *demoClient) IngestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, artifact model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec) (*model.IsOccurrence, error) {

	err := helper.CheckOccurrenceIngestionInput(subject)
	if err != nil {
		return nil, err
	}

	collectedArt, err := c.Artifacts(ctx, &model.ArtifactSpec{Algorithm: &artifact.Algorithm, Digest: &artifact.Digest})
	if err != nil {
		return nil, err
	}
	if len(collectedArt) != 1 {
		return nil, gqlerror.Errorf(
			"IngestOccurrence :: multiple artifacts found")
	}

	if subject.Package != nil {
		selectedPkgSpec := helper.ConvertPkgInputSpecToPkgSpec(subject.Package)

		collectedPkg, err := c.Packages(ctx, selectedPkgSpec)
		if err != nil {
			return nil, err
		}

		if len(collectedPkg) != 1 {
			return nil, gqlerror.Errorf(
				"IngestOccurrence :: multiple packages found")
		}
		return c.registerIsOccurrence(
			collectedPkg[0],
			nil,
			collectedArt[0],
			occurrence.Justification,
			occurrence.Origin,
			occurrence.Collector)
	}

	if subject.Source != nil {
		sourceSpec := helper.ConvertSrcInputSpecToSrcSpec(subject.Source)

		sources, err := c.Sources(ctx, sourceSpec)
		if err != nil {
			return nil, err
		}
		if len(sources) != 1 {
			return nil, gqlerror.Errorf(
				"IngestOccurrence :: source argument must match one"+
					" single source repository, found %d",
				len(sources))
		}
		return c.registerIsOccurrence(
			nil,
			sources[0],
			collectedArt[0],
			occurrence.Justification,
			occurrence.Origin,
			occurrence.Collector)
	}
	return nil, nil
}

// Query IsOccurrence

func (c *demoClient) IsOccurrence(ctx context.Context, isOccurrenceSpec *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {

	queryAll, err := helper.CheckOccurrenceQueryInput(isOccurrenceSpec.Subject)
	if err != nil {
		return nil, err
	}

	var isOccurrences []*model.IsOccurrence

	for _, h := range c.isOccurrence {
		matchOrSkip := true

		if isOccurrenceSpec.Justification != nil && h.Justification != *isOccurrenceSpec.Justification {
			matchOrSkip = false
		}
		if isOccurrenceSpec.Collector != nil && h.Collector != *isOccurrenceSpec.Collector {
			matchOrSkip = false
		}
		if isOccurrenceSpec.Origin != nil && h.Origin != *isOccurrenceSpec.Origin {
			matchOrSkip = false
		}

		if !queryAll {
			if isOccurrenceSpec.Subject.Package != nil && h.Subject != nil {
				if val, ok := h.Subject.(*model.Package); ok {
					if isOccurrenceSpec.Subject.Package.Type == nil || val.Type == *isOccurrenceSpec.Subject.Package.Type {
						newPkg := filterPackageNamespace(val, isOccurrenceSpec.Subject.Package)
						if newPkg == nil {
							matchOrSkip = false
						}
					}
				} else {
					matchOrSkip = false
				}
			}

			if isOccurrenceSpec.Subject.Source != nil && h.Subject != nil {
				if val, ok := h.Subject.(*model.Source); ok {
					if isOccurrenceSpec.Subject.Source.Type == nil || val.Type == *isOccurrenceSpec.Subject.Source.Type {
						newSource, err := filterSourceNamespace(val, isOccurrenceSpec.Subject.Source)
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
		}

		if matchOrSkip {
			isOccurrences = append(isOccurrences, h)
		}
	}

	return isOccurrences, nil
}
