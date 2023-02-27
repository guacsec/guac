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
	err = client.registerIsOccurrence(selectedPackage[0], nil, &model.Artifact{Digest: "5a787865sd676dacb0142afa0b83029cd7befd9", Algorithm: "sha1"}, "this artifact is an occurrence of this package")
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
	err = client.registerIsOccurrence(nil, selectedSource[0], client.artifacts[0], "this artifact is an occurrence of this source")
	if err != nil {
		return err
	}
	return nil
}

// Ingest IsOccurrence

func (c *demoClient) registerIsOccurrence(selectedPackage *model.Package, selectedSource *model.Source, artifact *model.Artifact, justification string) error {

	if selectedPackage != nil && selectedSource != nil {
		return fmt.Errorf("cannot specify both package and source for IsOccurrence")
	}

	for _, occurrence := range c.isOccurrence {
		if occurrence.OccurrenceArtifact == artifact && occurrence.Justification == justification {
			if val, ok := occurrence.Subject.(model.Package); ok {
				if &val == selectedPackage {
					return nil
				}
			} else if val, ok := occurrence.Subject.(model.Source); ok {
				if &val == selectedSource {
					return nil
				}
			}
		}
	}

	newIsOccurrence := &model.IsOccurrence{
		Justification:      justification,
		OccurrenceArtifact: artifact,
		Origin:             "testing backend",
		Collector:          "testing backend",
	}
	if selectedPackage != nil {
		newIsOccurrence.Subject = selectedPackage
	} else {
		newIsOccurrence.Subject = selectedSource
	}

	c.isOccurrence = append(c.isOccurrence, newIsOccurrence)
	return nil
}

// Query IsOccurrence

func (c *demoClient) IsOccurrence(ctx context.Context, isOccurrenceSpec *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {

	if isOccurrenceSpec.Package != nil && isOccurrenceSpec.Source != nil {
		return nil, gqlerror.Errorf("cannot specify both package and source for IsOccurrence")
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

		if isOccurrenceSpec.Package != nil && h.Subject != nil {
			if val, ok := h.Subject.(*model.Package); ok {
				if isOccurrenceSpec.Package.Type == nil || val.Type == *isOccurrenceSpec.Package.Type {
					newPkg := filterPackageNamespace(val, isOccurrenceSpec.Package)
					if newPkg == nil {
						matchOrSkip = false
					}
				}
			} else {
				matchOrSkip = false
			}
		}

		if isOccurrenceSpec.Source != nil && h.Subject != nil {
			if val, ok := h.Subject.(*model.Source); ok {
				if isOccurrenceSpec.Source.Type == nil || val.Type == *isOccurrenceSpec.Source.Type {
					newSource, err := filterSourceNamespace(val, isOccurrenceSpec.Source)
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

		if matchOrSkip {
			isOccurrences = append(isOccurrences, h)
		}
	}

	return isOccurrences, nil
}
