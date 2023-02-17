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

func registerAllhasSBOM(client *demoClient) error {
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
	err = client.registerHasSBOM(selectedPackage[0], nil, "uri:location of SBOM")
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
	err = client.registerHasSBOM(nil, selectedSource[0], "uri:location of SBOM")
	if err != nil {
		return err
	}
	return nil
}

// Ingest HasSBOM

func (c *demoClient) registerHasSBOM(selectedPackage *model.Package, selectedSource *model.Source, uri string) error {

	if selectedPackage != nil && selectedSource != nil {
		return fmt.Errorf("cannot specify both package and source for HasSBOM")
	}
	for _, h := range c.hasSBOM {
		if h.URI == uri && h.Package == selectedPackage || h.Source == selectedSource {
			return nil
		}
	}
	newHasSBOM := &model.HasSbom{
		Package:   selectedPackage,
		Source:    selectedSource,
		URI:       uri,
		Origin:    "testing backend",
		Collector: "testing backend",
	}
	c.hasSBOM = append(c.hasSBOM, newHasSBOM)
	return nil
}

// Query HasSBOM

func (c *demoClient) HasSBOMs(ctx context.Context, hasSBOMSpec *model.HasSBOMSpec) ([]*model.HasSbom, error) {

	if hasSBOMSpec.Package != nil && hasSBOMSpec.Source != nil {
		return nil, gqlerror.Errorf("cannot specify both package and source for HasSBOM")
	}

	var collectedHasSBOM []*model.HasSbom

	uriMatchOrSkip := false
	collectorMatchOrSkip := false
	originMatchOrSkip := false
	for _, h := range c.hasSBOM {
		if hasSBOMSpec.URI == nil || h.URI == *hasSBOMSpec.URI {
			uriMatchOrSkip = true
		}
		if hasSBOMSpec.Collector == nil || h.Collector == *hasSBOMSpec.Collector {
			collectorMatchOrSkip = true
		}
		if hasSBOMSpec.Origin == nil || h.Origin == *hasSBOMSpec.Origin {
			originMatchOrSkip = true
		}

		if uriMatchOrSkip && collectorMatchOrSkip && originMatchOrSkip {
			if hasSBOMSpec.Package == nil && hasSBOMSpec.Source == nil {
				collectedHasSBOM = append(collectedHasSBOM, h)
			} else if hasSBOMSpec.Package != nil && h.Package != nil {
				if hasSBOMSpec.Package.Type == nil || h.Package.Type == *hasSBOMSpec.Package.Type {
					newPkg := filterPackageNamespace(h.Package, hasSBOMSpec.Package)
					if newPkg != nil {
						collectedHasSBOM = append(collectedHasSBOM, h)
					}
				}
			} else if hasSBOMSpec.Source != nil && h.Source != nil {
				if hasSBOMSpec.Source.Type == nil || h.Source.Type == *hasSBOMSpec.Source.Type {
					newSource, err := filterSourceNamespace(h.Source, hasSBOMSpec.Source)
					if err != nil {
						return nil, err
					}
					if newSource != nil {
						collectedHasSBOM = append(collectedHasSBOM, h)
					}
				}
			}
		}
	}

	return collectedHasSBOM, nil
}
