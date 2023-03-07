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
	if hasSLSASpec.Package != nil {
		subjectsDefined = subjectsDefined + 1
	}
	if hasSLSASpec.Source != nil {
		subjectsDefined = subjectsDefined + 1
	}
	if hasSLSASpec.Artifact != nil {
		subjectsDefined = subjectsDefined + 1
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

		if hasSLSASpec.Package != nil && h.Subject != nil {
			if val, ok := h.Subject.(*model.Package); ok {
				if hasSLSASpec.Package.Type == nil || val.Type == *hasSLSASpec.Package.Type {
					newPkg := filterPackageNamespace(val, hasSLSASpec.Package)
					if newPkg == nil {
						matchOrSkip = false
					}
				}
			} else {
				matchOrSkip = false
			}
		}

		if hasSLSASpec.Source != nil && h.Subject != nil {
			if val, ok := h.Subject.(*model.Source); ok {
				if hasSLSASpec.Source.Type == nil || val.Type == *hasSLSASpec.Source.Type {
					newSource, err := filterSourceNamespace(val, hasSLSASpec.Source)
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

		if hasSLSASpec.Artifact != nil && h.Subject != nil {
			if val, ok := h.Subject.(*model.Artifact); ok {
				queryArt := &model.Artifact{
					Algorithm: strings.ToLower(*hasSLSASpec.Artifact.Algorithm),
					Digest:    strings.ToLower(*hasSLSASpec.Artifact.Digest),
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
	_, err := buildSLSA(&slsa)
	if err != nil {
		return nil, err
	}
	panic(fmt.Errorf("not implemented: IngestSlsa - ingestSLSAPackage"))
}

func (c *demoClient) ingestSLSASource(ctx context.Context, source *model.SourceInputSpec, slsa model.SLSAInputSpec) (*model.HasSlsa, error) {
	_, err := buildSLSA(&slsa)
	if err != nil {
		return nil, err
	}
	panic(fmt.Errorf("not implemented: IngestSlsa - ingestSLSASource"))
}

func (c *demoClient) ingestSLSAArtifact(ctx context.Context, artifact *model.ArtifactInputSpec, slsa model.SLSAInputSpec) (*model.HasSlsa, error) {
	newSlsa, err := buildSLSA(&slsa)
	if err != nil {
		return nil, err
	}

	newHasSlsa := &model.HasSlsa{
		Subject: generateModelArtifact(artifact),
		Slsa: newSlsa,
	}
	c.hasSLSA = append(c.hasSLSA, newHasSlsa)
	return newHasSlsa, nil
}

func buildSLSA(input *model.SLSAInputSpec) (*model.Slsa, error) {
	materials := []model.PackageSourceOrArtifact{}
	for _, m:= range input.BuiltFrom {
		material, err := processMaterialInput(m)
		if err != nil {
			return nil, err
		}
		materials = append(materials, material)
	}

	builder := model.Builder {URI: input.BuiltBy.URI}

	predicates := []*model.SLSAPredicate{}
	for _, p := range input.SlsaPredicate {
		predicate := model.SLSAPredicate{
			Key: p.Key,
			Value: p.Value,
		}
		predicates = append(predicates, &predicate)
	}

	slsa := model.Slsa{
		BuiltFrom:     materials,
		BuiltBy:       &builder,
		BuildType:     input.BuildType,
		SlsaPredicate: predicates,
		SlsaVersion:   input.SlsaVersion,
		StartedOn:     input.StartedOn,
		FinishedOn:    input.FinishedOn,
		Origin:        input.Origin,
		Collector:     input.Collector,
	}
	return &slsa, nil
}

// TODO(mihaimaruseac): Extract common utilities to common (separate PR!)
// This is very large and surely can be split, but we need several refactors
// before. Hence, separate PR!
func processMaterialInput(material *model.PackageSourceOrArtifactInput) (model.PackageSourceOrArtifact, error) {
	valuesDefined := 0
	if material.Package != nil {
		valuesDefined = valuesDefined + 1
	}
	if material.Source != nil {
		valuesDefined = valuesDefined + 1
	}
	if material.Artifact != nil {
		valuesDefined = valuesDefined + 1
	}
	if valuesDefined > 1 {
		return nil, gqlerror.Errorf("Must specify at most one package, source, or artifact for a specific material")
	}

	if material.Package != nil {
		var version *model.PackageVersion
		if material.Package.Version != nil ||
		   material.Package.Subpath != nil ||
		   material.Package.Qualifiers != nil {
			version = &model.PackageVersion{}
			if material.Package.Version != nil {
				version.Version = *material.Package.Version
			}
			if material.Package.Subpath != nil {
				version.Subpath = *material.Package.Subpath
			}
			if material.Package.Qualifiers != nil {
				var qualifiers []*model.PackageQualifier
				for _, q := range material.Package.Qualifiers {
					qual := model.PackageQualifier{
						Key: q.Key,
						Value: q.Value,
					}
					qualifiers = append(qualifiers, &qual)
				}
				version.Qualifiers = qualifiers
			}
		}

		var versions []*model.PackageVersion
		if version != nil {
			versions = append(versions, version)
		}

		name := &model.PackageName{
			Name:     material.Package.Name,
			Versions: versions,
		}

		namespace := &model.PackageNamespace{
			Namespace: *material.Package.Namespace,
			Names:     []*model.PackageName{name},
		}

		pkg := model.Package{
			Type:       material.Package.Type,
			Namespaces: []*model.PackageNamespace{namespace},
		}

		return &pkg, nil
	} else if material.Source != nil {
		var tag *string
		tagValue := material.Source.Tag
		if tagValue != nil {
			tagStr := *tagValue
			tag = &tagStr
		}

		var commit *string
		commitValue := material.Source.Commit
		if commitValue != nil {
			commitStr := *commitValue
			commit = &commitStr
		}

		name := &model.SourceName{
			Name:   material.Source.Name,
			Tag:    tag,
			Commit: commit,
		}

		namespace := &model.SourceNamespace{
			Namespace: material.Source.Namespace,
			Names:     []*model.SourceName{name},
		}

		source := model.Source{
			Type:       material.Source.Type,
			Namespaces: []*model.SourceNamespace{namespace},
		}

		return &source, nil
	} else if material.Artifact != nil {
		artifact := generateModelArtifact(material.Artifact)
		return artifact, nil
	}

	return nil, gqlerror.Errorf("Must specify exactly one package, source, or artifact for a specific material")
}

// TODO(mihaimaruseac): Merge with neo4j similar(ish) implementation.
// In a separate PR, as this is already too large
func generateModelArtifact(inputArtifact *model.ArtifactInputSpec) *model.Artifact {
	return &model.Artifact{
		Algorithm: inputArtifact.Algorithm,
		Digest:    inputArtifact.Digest,
	}
}
