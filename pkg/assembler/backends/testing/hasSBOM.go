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
	_, err = client.registerHasSBOM(selectedPackage[0], nil, "uri:location of SBOM", "testing backend", "testing backend")
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
	_, err = client.registerHasSBOM(nil, selectedSource[0], "uri:location of SBOM", "testing backend", "testing backend")
	if err != nil {
		return err
	}
	return nil
}

// Ingest HasSBOM

func (c *demoClient) registerHasSBOM(selectedPackage *model.Package, selectedSource *model.Source, uri, origin, collector string) (*model.HasSbom, error) {

	if selectedPackage != nil && selectedSource != nil {
		return nil, fmt.Errorf("cannot specify both package and source for HasSBOM")
	}
	for _, h := range c.hasSBOM {
		if h.URI == uri {
			if val, ok := h.Subject.(model.Package); ok {
				if reflect.DeepEqual(val, *selectedPackage) {
					return h, nil
				}
			} else if val, ok := h.Subject.(model.Source); ok {
				if reflect.DeepEqual(val, *selectedSource) {
					return h, nil
				}
			}
		}
	}

	newHasSBOM := &model.HasSbom{
		URI:       uri,
		Origin:    origin,
		Collector: collector,
	}
	if selectedPackage != nil {
		newHasSBOM.Subject = selectedPackage
	} else {
		newHasSBOM.Subject = selectedSource
	}

	c.hasSBOM = append(c.hasSBOM, newHasSBOM)
	return newHasSBOM, nil
}

func (c *demoClient) IngestHasSbom(ctx context.Context, subject model.PackageOrSourceInput, hasSbom model.HasSBOMInputSpec) (*model.HasSbom, error) {
	err := helper.ValidatePackageOrSourceInput(&subject, "IngestHasSbom")
	if err != nil {
		return nil, err
	}

	if subject.Package != nil {
		selectedPkgSpec := helper.ConvertPkgInputSpecToPkgSpec(subject.Package)

		collectedPkg, err := c.Packages(ctx, selectedPkgSpec)
		if err != nil {
			return nil, err
		}

		if len(collectedPkg) != 1 {
			return nil, gqlerror.Errorf(
				"IngestHasSbom :: multiple packages found")
		}
		return c.registerHasSBOM(
			collectedPkg[0],
			nil,
			hasSbom.URI,
			hasSbom.Origin,
			hasSbom.Collector)
	}

	if subject.Source != nil {
		sourceSpec := helper.ConvertSrcInputSpecToSrcSpec(subject.Source)

		sources, err := c.Sources(ctx, sourceSpec)
		if err != nil {
			return nil, err
		}
		if len(sources) != 1 {
			return nil, gqlerror.Errorf(
				"IngestHasSbom :: source argument must match one"+
					" single source repository, found %d",
				len(sources))
		}
		return c.registerHasSBOM(
			nil,
			sources[0],
			hasSbom.URI,
			hasSbom.Origin,
			hasSbom.Collector)
	}
	// it should never reach here else it failed
	return nil, gqlerror.Errorf("IngestHasSBOM failed")
}

// Query HasSBOM

func (c *demoClient) HasSBOM(ctx context.Context, hasSBOMSpec *model.HasSBOMSpec) ([]*model.HasSbom, error) {

	queryAll, err := helper.ValidatePackageOrSourceQueryInput(hasSBOMSpec.Subject)
	if err != nil {
		return nil, err
	}

	var collectedHasSBOM []*model.HasSbom

	for _, h := range c.hasSBOM {
		matchOrSkip := true

		if hasSBOMSpec.URI != nil && h.URI != *hasSBOMSpec.URI {
			matchOrSkip = false
		}
		if hasSBOMSpec.Collector != nil && h.Collector != *hasSBOMSpec.Collector {
			matchOrSkip = false
		}
		if hasSBOMSpec.Origin != nil && h.Origin != *hasSBOMSpec.Origin {
			matchOrSkip = false
		}

		if !queryAll {
			if hasSBOMSpec.Subject != nil && hasSBOMSpec.Subject.Package != nil && h.Subject != nil {
				if val, ok := h.Subject.(*model.Package); ok {
					if hasSBOMSpec.Subject.Package.Type == nil || val.Type == *hasSBOMSpec.Subject.Package.Type {
						newPkg := filterPackageNamespace(val, hasSBOMSpec.Subject.Package)
						if newPkg == nil {
							matchOrSkip = false
						}
					}
				} else {
					matchOrSkip = false
				}
			}

			if hasSBOMSpec.Subject != nil && hasSBOMSpec.Subject.Source != nil && h.Subject != nil {
				if val, ok := h.Subject.(*model.Source); ok {
					if hasSBOMSpec.Subject.Source.Type == nil || val.Type == *hasSBOMSpec.Subject.Source.Type {
						newSource, err := filterSourceNamespace(val, hasSBOMSpec.Subject.Source)
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
			collectedHasSBOM = append(collectedHasSBOM, h)
		}
	}

	return collectedHasSBOM, nil
}
