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
	"time"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func registerAllHasSourceAt(client *demoClient) error {
	// pkg:pypi/django@1.11.1
	// client.registerPackage("pypi", "", "django", "1.11.1", "")
	selectedType := "pypi"
	selectedNameSpace := ""
	selectedName := "django"
	selectedVersion := "1.11.1"
	selectedSubpath := ""
	selectedPkgSpec := &model.PkgSpec{Type: &selectedType, Namespace: &selectedNameSpace, Name: &selectedName, Version: &selectedVersion, Subpath: &selectedSubpath}
	selectedPackage, err := client.Packages(context.TODO(), selectedPkgSpec)
	if err != nil {
		return err
	}

	// "git", "github", "https://github.com/django/django", "tag=1.11.1"
	selectedSourceType := "git"
	selectedSourceNameSpace := "github"
	selectedSourceName := "https://github.com/django/django"
	selectedTag := "1.11.1"
	selectedSourceQualifiers := &model.SourceQualifierInput{Tag: &selectedTag}
	selectedSourceSpec := &model.SourceSpec{Type: &selectedSourceType, Namespace: &selectedSourceNameSpace, Name: &selectedSourceName, Qualifier: selectedSourceQualifiers}
	selectedSource, err := client.Sources(context.TODO(), selectedSourceSpec)
	if err != nil {
		return err
	}
	err = client.registerHasSourceAt(selectedPackage[0], selectedSource[0], time.Now(), "django located at the following source based on deps.dev")
	if err != nil {
		return err
	}
	// pkg:pypi/kubetest@0.9.5
	// client.registerPackage("pypi", "", "kubetest", "0.9.5", "")

	selectedType = "pypi"
	selectedNameSpace = ""
	selectedName = "kubetest"
	selectedVersion = "0.9.5"
	selectedSubpath = ""
	selectedPkgSpec = &model.PkgSpec{Type: &selectedType, Namespace: &selectedNameSpace, Name: &selectedName, Version: &selectedVersion, Subpath: &selectedSubpath}
	selectedPackage, err = client.Packages(context.TODO(), selectedPkgSpec)
	if err != nil {
		return err
	}

	// "git", "github", "https://github.com/vapor-ware/kubetest", "tag=0.9.5"
	// client.registerSource("git", "github", "https://github.com/vapor-ware/kubetest", "tag=0.9.5")

	selectedSourceType = "git"
	selectedSourceNameSpace = "github"
	selectedSourceName = "https://github.com/vapor-ware/kubetest"
	selectedTag = "0.9.5"
	selectedSourceQualifiers = &model.SourceQualifierInput{Tag: &selectedTag}
	selectedSourceSpec = &model.SourceSpec{Type: &selectedSourceType, Namespace: &selectedSourceNameSpace, Name: &selectedSourceName, Qualifier: selectedSourceQualifiers}
	selectedSource, err = client.Sources(context.TODO(), selectedSourceSpec)
	if err != nil {
		return err
	}
	err = client.registerHasSourceAt(selectedPackage[0], selectedSource[0], time.Now(), "kubetest located at the following source based on deps.dev")
	if err != nil {
		return err
	}
	return nil
}

// Ingest HasSourceAt

func (c *demoClient) registerHasSourceAt(selectedPackage *model.Package, selectedSource *model.Source, since time.Time, justification string) error {

	if selectedPackage == nil || selectedSource == nil {
		return fmt.Errorf("package or source is nil")
	}

	for _, h := range c.hasSourceAt {
		if h.Justification == justification && h.Package == selectedPackage && h.Source == selectedSource {
			return nil
		}
	}
	newHasSourceAt := &model.HasSourceAt{
		Package:       selectedPackage,
		Source:        selectedSource,
		KnownSince:    since.String(),
		Justification: justification,
		Origin:        "testing backend",
		Collector:     "testing backend",
	}
	c.hasSourceAt = append(c.hasSourceAt, newHasSourceAt)
	return nil
}

// Query HasSourceAt

func (c *demoClient) HasSourceAt(ctx context.Context, hasSourceAtSpec *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {

	var collectedHasSourceAt []*model.HasSourceAt

	for _, h := range c.hasSourceAt {
		matchOrSkip := true

		if hasSourceAtSpec.Justification != nil && h.Justification != *hasSourceAtSpec.Justification {
			matchOrSkip = false
		}
		if hasSourceAtSpec.Collector != nil && h.Collector != *hasSourceAtSpec.Collector {
			matchOrSkip = false
		}
		if hasSourceAtSpec.Origin != nil && h.Origin != *hasSourceAtSpec.Origin {
			matchOrSkip = false
		}

		if hasSourceAtSpec.Package != nil && h.Package != nil {
			if hasSourceAtSpec.Package.Type == nil || h.Package.Type == *hasSourceAtSpec.Package.Type {
				newPkg := filterPackageNamespace(h.Package, hasSourceAtSpec.Package)
				if newPkg == nil {
					matchOrSkip = false
				}
			}
		}

		if hasSourceAtSpec.Source != nil && h.Source != nil {
			if hasSourceAtSpec.Source.Type == nil || h.Source.Type == *hasSourceAtSpec.Source.Type {
				newSource, err := filterSourceNamespace(h.Source, hasSourceAtSpec.Source)
				if err != nil {
					return nil, err
				}
				if newSource == nil {
					matchOrSkip = false
				}
			}
		}

		if matchOrSkip {
			collectedHasSourceAt = append(collectedHasSourceAt, h)
		}
	}
	return collectedHasSourceAt, nil
}
