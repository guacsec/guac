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
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func registerAllHasSLSA(client *demoClient) error {
	// pkg:pypi/django@1.11.1
	// client.registerPackage("pypi", "", "django", "1.11.1", "")
	selectedType := "pypi"
	selectedNameSpace := ""
	selectedName := "django"
	selectedVersion := "1.11.1"
	selectedSubpath := ""
	selectedPkgSpec := &model.PkgSpec{
		Type:      &selectedType,
		Namespace: &selectedNameSpace,
		Name:      &selectedName,
		Version:   &selectedVersion,
		Subpath:   &selectedSubpath,
	}
	selectedPackage, err := client.Packages(context.TODO(), selectedPkgSpec)
	if err != nil {
		return err
	}

	// "git", "github", "https://github.com/django/django", "tag=1.11.1"
	selectedSourceType := "git"
	selectedSourceNameSpace := "github"
	selectedSourceName := "https://github.com/django/django"
	selectedTag := "1.11.1"
	selectedSourceSpec := &model.SourceSpec{
		Type:      &selectedSourceType,
		Namespace: &selectedSourceNameSpace,
		Name:      &selectedSourceName,
		Tag:       &selectedTag,
	}
	selectedSource, err := client.Sources(context.TODO(), selectedSourceSpec)
	if err != nil {
		return err
	}
	predicateValues := []*model.SLSAPredicate{
		{
			Key:   "buildDefinition.externalParameters.repository",
			Value: "https://github.com/octocat/hello-world",
		},
		{
			Key:   "buildDefinition.externalParameters.ref",
			Value: "refs/heads/main",
		},
		{
			Key:   "buildDefinition.resolvedDependencies.uri",
			Value: "git+https://github.com/octocat/hello-world@refs/heads/main",
		},
	}

	builder := &model.Builder{
		URI: "https://github.com/Attestations/GitHubHostedActions@v1",
	}

	err = client.registerHasSLSA(
		selectedPackage[0], nil, nil, nil, selectedSource, nil, builder,
		"https://github.com/Attestations/GitHubActionsWorkflow@v1",
		predicateValues, "v1", time.Now(), time.Now())
	if err != nil {
		return err
	}
	return nil
}

// Ingest HasSlsa

func (c *demoClient) registerHasSLSA(
	selectedPackage *model.Package, selectedSource *model.Source, selectedArtifact *model.Artifact,
	builtFromPackages []*model.Package, builtFromSouces []*model.Source, builtFromArtifacts []*model.Artifact,
	builtBy *model.Builder, buildType string,
	predicate []*model.SLSAPredicate, slsaVersion string,
	startOn time.Time, finishOn time.Time) error {
	for _, h := range c.hasSLSA {
		slsa := h.Slsa
		if slsa.BuildType == buildType && slsa.SlsaVersion == slsaVersion {
			if val, ok := h.Subject.(model.Package); ok {
				if &val == selectedPackage {
					return nil
				}
			} else if val, ok := h.Subject.(model.Source); ok {
				if &val == selectedSource {
					return nil
				}
			} else if val, ok := h.Subject.(model.Artifact); ok {
				if &val == selectedArtifact {
					return nil
				}
			}
		}
	}

	materials := []model.PackageSourceOrArtifact{}
	for _, pack := range builtFromPackages {
		materials = append(materials, pack)
	}
	for _, source := range builtFromSouces {
		materials = append(materials, source)
	}
	for _, art := range builtFromArtifacts {
		materials = append(materials, art)
	}
	newSlsa := &model.Slsa{
		BuiltFrom:     materials,
		BuiltBy:       builtBy,
		BuildType:     buildType,
		SlsaPredicate: predicate,
		SlsaVersion:   slsaVersion,
		StartedOn:     startOn,
		FinishedOn:    finishOn,
		Origin:        "testing backend",
		Collector:     "testing backend",
	}

	newHasSlsa := &model.HasSlsa{Slsa: newSlsa}
	if selectedPackage != nil {
		newHasSlsa.Subject = selectedPackage
	} else if selectedSource != nil {
		newHasSlsa.Subject = selectedSource
	} else {
		newHasSlsa.Subject = selectedArtifact
	}

	c.hasSLSA = append(c.hasSLSA, newHasSlsa)
	return nil
}

// Query HasSlsa

func (c *demoClient) HasSlsa(ctx context.Context, hasSLSASpec *model.HasSLSASpec) ([]*model.HasSlsa, error) {
	subjectsDefined := 0
	// TODO(mihaimaruseac): Revisit e2e
	if hasSLSASpec.Subject != nil {
		if hasSLSASpec.Subject.Package != nil {
			subjectsDefined = subjectsDefined + 1
		}
		if hasSLSASpec.Subject.Source != nil {
			subjectsDefined = subjectsDefined + 1
		}
		if hasSLSASpec.Subject.Artifact != nil {
			subjectsDefined = subjectsDefined + 1
		}
	}
	if subjectsDefined > 1 {
		return nil, gqlerror.Errorf("Must specify at most one subject (package, source, or artifact)")
	}

	var collectedHasSLSA []*model.HasSlsa

	for _, h := range c.hasSLSA {
		matchOrSkip := true

		slsa := h.Slsa
		if hasSLSASpec.BuildType != nil && slsa.BuildType != *hasSLSASpec.BuildType {
			matchOrSkip = false
		}
		if hasSLSASpec.SlsaVersion != nil && slsa.SlsaVersion != *hasSLSASpec.SlsaVersion {
			matchOrSkip = false
		}
		if hasSLSASpec.Collector != nil && slsa.Collector != *hasSLSASpec.Collector {
			matchOrSkip = false
		}
		if hasSLSASpec.Origin != nil && slsa.Origin != *hasSLSASpec.Origin {
			matchOrSkip = false
		}

		if hasSLSASpec.BuiltBy != nil && slsa.BuiltBy != nil {
			if hasSLSASpec.BuiltBy.URI != nil && slsa.BuiltBy.URI != *hasSLSASpec.BuiltBy.URI {
				matchOrSkip = false
			}
		}

		if hasSLSASpec.Subject != nil && hasSLSASpec.Subject.Package != nil && h.Subject != nil {
			if val, ok := h.Subject.(*model.Package); ok {
				if hasSLSASpec.Subject.Package.Type == nil || val.Type == *hasSLSASpec.Subject.Package.Type {
					newPkg := filterPackageNamespace(val, hasSLSASpec.Subject.Package)
					if newPkg == nil {
						matchOrSkip = false
					}
				}
			} else {
				matchOrSkip = false
			}
		}

		if hasSLSASpec.Subject != nil && hasSLSASpec.Subject.Source != nil && h.Subject != nil {
			if val, ok := h.Subject.(*model.Source); ok {
				if hasSLSASpec.Subject.Source.Type == nil || val.Type == *hasSLSASpec.Subject.Source.Type {
					newSource, err := filterSourceNamespace(val, hasSLSASpec.Subject.Source)
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

		if hasSLSASpec.Subject != nil && hasSLSASpec.Subject.Artifact != nil && h.Subject != nil {
			if val, ok := h.Subject.(*model.Artifact); ok {
				queryArt := &model.Artifact{
					Algorithm: strings.ToLower(*hasSLSASpec.Subject.Artifact.Algorithm),
					Digest:    strings.ToLower(*hasSLSASpec.Subject.Artifact.Digest),
				}
				if *queryArt != *val {
					matchOrSkip = false
				}
			} else {
				matchOrSkip = false
			}
		}

		if matchOrSkip {
			collectedHasSLSA = append(collectedHasSLSA, h)
		}
	}

	return collectedHasSLSA, nil
}

func (c *demoClient) IngestSLSA(ctx context.Context, subject model.PackageSourceOrArtifactInput, slsa model.SLSAInputSpec) (*model.HasSlsa, error) {
	subjectsDefined := 0
	if subject.Package != nil {
		subjectsDefined = subjectsDefined + 1
	}
	if subject.Source != nil {
		subjectsDefined = subjectsDefined + 1
	}
	if subject.Artifact != nil {
		subjectsDefined = subjectsDefined + 1
	}
	if subjectsDefined > 1 {
		return nil, gqlerror.Errorf("Must specify at most one subject (package, source, or artifact)")
	}

	if subject.Package != nil {
		return c.ingestSLSAPackage(ctx, subject.Package, slsa)
	} else if subject.Source != nil {
		return c.ingestSLSASource(ctx, subject.Source, slsa)
	} else if subject.Artifact != nil {
		return c.ingestSLSAArtifact(ctx, subject.Artifact, slsa)
	}
	return nil, gqlerror.Errorf("Must specify exactly one subject (package, source, or artifact)")
}

func (c *demoClient) ingestSLSAPackage(ctx context.Context, pkg *model.PkgInputSpec, slsa model.SLSAInputSpec) (*model.HasSlsa, error) {
	panic(fmt.Errorf("not implemented: IngestSlsa - ingestSLSAPackage"))
}

func (c *demoClient) ingestSLSASource(ctx context.Context, source *model.SourceInputSpec, slsa model.SLSAInputSpec) (*model.HasSlsa, error) {
	panic(fmt.Errorf("not implemented: IngestSlsa - ingestSLSASource"))
}

func (c *demoClient) ingestSLSAArtifact(ctx context.Context, artifact *model.ArtifactInputSpec, slsa model.SLSAInputSpec) (*model.HasSlsa, error) {
	panic(fmt.Errorf("not implemented: IngestSlsa - ingestSLSAArtifact"))
}
