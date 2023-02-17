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
	err = client.registerIsOccurrence(selectedPackage[0], nil, []*model.Artifact{{Digest: "5a787865sd676dacb0142afa0b83029cd7befd9", Algorithm: "sha1"},
		{Digest: "89bb0da1891646e58eb3e6ed24f3a6fc3c8eb5a0d44824cba581dfa34a0450cf", Algorithm: "sha256"}}, "this artifact is an occurrence of this package")
	if err != nil {
		return err
	}
	// "git", "github", "github.com/guacsec/guac", "tag=v0.0.1"
	selectedSourceType := "git"
	selectedSourceNameSpace := "github"
	selectedSourceName := "github.com/guacsec/guac"
	selectedTag := "v0.0.1"
	selectedSourceQualifiers := &model.SourceQualifierInput{Tag: &selectedTag}
	selectedSourceSpec := &model.SourceSpec{Type: &selectedSourceType, Namespace: &selectedSourceNameSpace, Name: &selectedSourceName, Qualifier: selectedSourceQualifiers}
	selectedSource, err := client.Sources(context.TODO(), selectedSourceSpec)
	if err != nil {
		return err
	}
	err = client.registerIsOccurrence(nil, selectedSource[0], []*model.Artifact{client.artifacts[0]}, "this artifact is an occurrence of this source")
	if err != nil {
		return err
	}
	return nil
}

// Ingest IsOccurrence

func (c *demoClient) registerIsOccurrence(selectedPackage *model.Package, selectedSource *model.Source, artifacts []*model.Artifact, justification string) error {

	if selectedPackage != nil && selectedSource != nil {
		return fmt.Errorf("cannot specify both package and source for IsOccurrence")
	}

	for _, occurrence := range c.isOccurrence {
		if reflect.DeepEqual(occurrence.OccurrenceArtifacts, artifacts) && occurrence.Justification == justification &&
			occurrence.Package == selectedPackage || occurrence.Source == selectedSource {
			return nil
		}
	}

	newIsOccurrence := &model.IsOccurrence{
		Justification:       justification,
		Package:             selectedPackage,
		Source:              selectedSource,
		OccurrenceArtifacts: artifacts,
		Origin:              "testing backend",
		Collector:           "testing backend",
	}
	c.isOccurrence = append(c.isOccurrence, newIsOccurrence)
	return nil
}

// Query IsOccurrence

func (c *demoClient) IsOccurrences(ctx context.Context, isOccurrenceSpec *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {

	if isOccurrenceSpec.Package != nil && isOccurrenceSpec.Source != nil {
		return nil, gqlerror.Errorf("cannot specify both package and source for IsOccurrence")
	}

	var isOccurrences []*model.IsOccurrence

	justificationMatchOrSkip := false
	collectorMatchOrSkip := false
	originMatchOrSkip := false
	for _, h := range c.isOccurrence {
		if isOccurrenceSpec.Justification == nil || h.Justification == *isOccurrenceSpec.Justification {
			justificationMatchOrSkip = true
		}
		if isOccurrenceSpec.Collector == nil || h.Collector == *isOccurrenceSpec.Collector {
			collectorMatchOrSkip = true
		}
		if isOccurrenceSpec.Origin == nil || h.Origin == *isOccurrenceSpec.Origin {
			originMatchOrSkip = true
		}

		if justificationMatchOrSkip && collectorMatchOrSkip && originMatchOrSkip {
			if isOccurrenceSpec.Package == nil && isOccurrenceSpec.Source == nil {
				isOccurrences = append(isOccurrences, h)
			} else if isOccurrenceSpec.Package != nil && h.Package != nil {
				if isOccurrenceSpec.Package.Type == nil || h.Package.Type == *isOccurrenceSpec.Package.Type {
					newPkg := filterPackageNamespace(h.Package, isOccurrenceSpec.Package)
					if newPkg != nil {
						isOccurrences = append(isOccurrences, h)
					}
				}
			} else if isOccurrenceSpec.Source != nil && h.Source != nil {
				if isOccurrenceSpec.Source.Type == nil || h.Source.Type == *isOccurrenceSpec.Source.Type {
					newSource, err := filterSourceNamespace(h.Source, isOccurrenceSpec.Source)
					if err != nil {
						return nil, err
					}
					if newSource != nil {
						isOccurrences = append(isOccurrences, h)
					}
				}
			}
		}
	}

	return isOccurrences, nil
}
