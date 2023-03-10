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

// Ingest HasSlsa

func (c *demoClient) IngestMaterials(
	ctx context.Context, materials []*model.PackageSourceOrArtifactInput,
) ([]model.PackageSourceOrArtifact, error) {
	output := []model.PackageSourceOrArtifact{}

	// For this backend, there's no optimization we can do, we need to
	// ingest everything sequentially
	for _, material := range materials {
		err := helper.ValidatePackageSourceOrArtifactInput(material, "each SLSA material")
		if err != nil {
			return nil, err
		}

		if material.Package != nil {
			pkg, err := c.IngestPackage(ctx, material.Package)
			if err != nil {
				return nil, err
			}
			output = append(output, pkg)
		} else if material.Source != nil {
			source, err := c.IngestSource(ctx, material.Source)
			if err != nil {
				return nil, err
			}
			output = append(output, source)
		} else if material.Artifact != nil {
			artifact, err := c.IngestArtifact(ctx, material.Artifact)
			if err != nil {
				return nil, err
			}
			output = append(output, artifact)
		}
	}

	return output, nil
}

func (c *demoClient) IngestSLSA(
	ctx context.Context, subject model.PackageSourceOrArtifactInput,
	builtFrom []*model.PackageSourceOrArtifactInput,
	builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec,
) (*model.HasSlsa, error) {
	// Since each mutation can also be called independently, we need to
	// validate again subject and materials
	err := helper.ValidatePackageSourceOrArtifactInput(&subject, "SLSA subject")
	if err != nil {
		return nil, err
	}
	for _, material := range builtFrom {
		err := helper.ValidatePackageSourceOrArtifactInput(material, "each SLSA material")
		if err != nil {
			return nil, err
		}
	}

	if subject.Package != nil {
		return c.ingestSLSAPackage(ctx, subject.Package, builtFrom, &builtBy, &slsa)
	} else if subject.Source != nil {
		return c.ingestSLSASource(ctx, subject.Source, builtFrom, &builtBy, &slsa)
	} else if subject.Artifact != nil {
		return c.ingestSLSAArtifact(ctx, subject.Artifact, builtFrom, &builtBy, &slsa)
	}
	return nil, gqlerror.Errorf("Impossible configuration for IngestSLSA")
}

func (c *demoClient) ingestSLSAPackage(
	ctx context.Context, pkg *model.PkgInputSpec,
	builtFrom []*model.PackageSourceOrArtifactInput,
	builtBy *model.BuilderInputSpec, slsa *model.SLSAInputSpec,
) (*model.HasSlsa, error) {
	for _, attestation := range c.hasSLSA {
		if p, ok := attestation.Subject.(*model.Package); ok {
			if packageMatch(p, pkg) &&
				slsaMatch(attestation.Slsa, builtFrom, builtBy, slsa) {
				return attestation, nil
			}
		}
	}

	subjects, err := c.Packages(ctx, helper.ConvertPkgInputSpecToPkgSpec(pkg))
	if err != nil {
		return nil, err
	}
	if len(subjects) != 1 {
		return nil, gqlerror.Errorf("Found %d packages matching subject", len(subjects))
	}

	newSlsa, err := buildSLSA(builtFrom, builtBy, slsa)
	if err != nil {
		return nil, err
	}

	newHasSlsa := &model.HasSlsa{
		Subject: subjects[0],
		Slsa:    newSlsa,
	}
	c.hasSLSA = append(c.hasSLSA, newHasSlsa)
	return newHasSlsa, nil
}

func (c *demoClient) ingestSLSASource(
	ctx context.Context, source *model.SourceInputSpec,
	builtFrom []*model.PackageSourceOrArtifactInput,
	builtBy *model.BuilderInputSpec, slsa *model.SLSAInputSpec,
) (*model.HasSlsa, error) {
	for _, attestation := range c.hasSLSA {
		if s, ok := attestation.Subject.(*model.Source); ok {
			if sourceMatch(s, source) &&
				slsaMatch(attestation.Slsa, builtFrom, builtBy, slsa) {
				return attestation, nil
			}
		}
	}

	subjects, err := c.Sources(ctx, helper.ConvertSrcInputSpecToSrcSpec(source))
	if err != nil {
		return nil, err
	}
	if len(subjects) != 1 {
		return nil, gqlerror.Errorf("Found %d sources matching subject", len(subjects))
	}

	newSlsa, err := buildSLSA(builtFrom, builtBy, slsa)
	if err != nil {
		return nil, err
	}

	newHasSlsa := &model.HasSlsa{
		Subject: subjects[0],
		Slsa:    newSlsa,
	}
	c.hasSLSA = append(c.hasSLSA, newHasSlsa)
	return newHasSlsa, nil
}

func (c *demoClient) ingestSLSAArtifact(
	ctx context.Context, artifact *model.ArtifactInputSpec,
	builtFrom []*model.PackageSourceOrArtifactInput,
	builtBy *model.BuilderInputSpec, slsa *model.SLSAInputSpec,
) (*model.HasSlsa, error) {
	for _, attestation := range c.hasSLSA {
		if a, ok := attestation.Subject.(*model.Artifact); ok {
			if artifactMatch(a, artifact) &&
				slsaMatch(attestation.Slsa, builtFrom, builtBy, slsa) {
				return attestation, nil
			}
		}
	}

	subjects, err := c.Artifacts(ctx, helper.ConvertArtInputSpecToArtSpec(artifact))
	if err != nil {
		return nil, err
	}
	if len(subjects) != 1 {
		return nil, gqlerror.Errorf("Found %d sources matching subject", len(subjects))
	}

	newSlsa, err := buildSLSA(builtFrom, builtBy, slsa)
	if err != nil {
		return nil, err
	}

	newHasSlsa := &model.HasSlsa{
		Subject: subjects[0],
		Slsa:    newSlsa,
	}
	c.hasSLSA = append(c.hasSLSA, newHasSlsa)
	return newHasSlsa, nil
}

func buildSLSA(
	builtFrom []*model.PackageSourceOrArtifactInput,
	builtBy *model.BuilderInputSpec, input *model.SLSAInputSpec,
) (*model.Slsa, error) {
	materials := []model.PackageSourceOrArtifact{}
	for _, m := range builtFrom {
		material, err := processMaterialInput(m)
		if err != nil {
			return nil, err
		}
		materials = append(materials, material)
	}

	builder := model.Builder{URI: builtBy.URI}

	predicates := []*model.SLSAPredicate{}
	for _, p := range input.SlsaPredicate {
		predicate := model.SLSAPredicate{
			Key:   p.Key,
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

func slsaMatch(
	slsa *model.Slsa,
	builtFrom []*model.PackageSourceOrArtifactInput,
	builtBy *model.BuilderInputSpec, input *model.SLSAInputSpec,
) bool {
	// Do fast checks first
	if slsa.Collector != input.Collector {
		return false
	}
	if slsa.Origin != input.Origin {
		return false
	}
	if slsa.FinishedOn != input.FinishedOn {
		return false
	}
	if slsa.StartedOn != input.StartedOn {
		return false
	}
	if slsa.SlsaVersion != input.SlsaVersion {
		return false
	}
	if slsa.BuildType != input.BuildType {
		return false
	}
	if slsa.BuiltBy.URI != builtBy.URI {
		return false
	}

	// TODO(mihaimaruseac): O(n*m), could be made O(n+m)
	for _, pred := range slsa.SlsaPredicate {
		found := false
		for _, inputPred := range input.SlsaPredicate {
			if pred.Key == inputPred.Key && pred.Value == inputPred.Value {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// TODO(mihaimaruseac): O(n*m), could be made O(n+m)
	for _, mat := range slsa.BuiltFrom {
		found := false
		if a, ok := mat.(*model.Artifact); ok {
			for _, inputMat := range builtFrom {
				if artifactMatch(a, inputMat.Artifact) {
					found = true
					break
				}
			}
		} else if s, ok := mat.(*model.Source); ok {
			for _, inputMat := range builtFrom {
				if sourceMatch(s, inputMat.Source) {
					found = true
					break
				}
			}
		} else if p, ok := mat.(*model.Package); ok {
			for _, inputMat := range builtFrom {
				if packageMatch(p, inputMat.Package) {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}

	return true
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
		return generateModelPackage(material.Package), nil
	} else if material.Source != nil {
		return generateModelSource(material.Source), nil
	} else if material.Artifact != nil {
		return generateModelArtifact(material.Artifact), nil
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

// TODO(mihaimaruseac): Also merge this with neo4j / extract to common.
func artifactMatch(artifact *model.Artifact, artifactInput *model.ArtifactInputSpec) bool {
	if artifactInput == nil {
		return false
	}

	if artifact.Algorithm != artifactInput.Algorithm {
		return false
	}
	if artifact.Digest != artifactInput.Digest {
		return false
	}
	return true
}

// TODO(mihaimaruseac): Merge with neo4j similar(ish) implementation.
// In a separate PR, as this is already too large
func generateModelSource(inputSource *model.SourceInputSpec) *model.Source {
	var tag *string
	tagValue := inputSource.Tag
	if tagValue != nil {
		tagStr := *tagValue
		tag = &tagStr
	}

	var commit *string
	commitValue := inputSource.Commit
	if commitValue != nil {
		commitStr := *commitValue
		commit = &commitStr
	}

	name := &model.SourceName{
		Name:   inputSource.Name,
		Tag:    tag,
		Commit: commit,
	}

	namespace := &model.SourceNamespace{
		Namespace: inputSource.Namespace,
		Names:     []*model.SourceName{name},
	}

	return &model.Source{
		Type:       inputSource.Type,
		Namespaces: []*model.SourceNamespace{namespace},
	}
}

// TODO(mihaimaruseac): Also merge this with neo4j / extract to common.
func sourceMatch(source *model.Source, sourceInput *model.SourceInputSpec) bool {
	if sourceInput == nil {
		return false
	}

	if source.Type != sourceInput.Type {
		return false
	}
	for _, ns := range source.Namespaces {
		if ns.Namespace != sourceInput.Namespace {
			continue
		}
		for _, n := range ns.Names {
			if n.Name != sourceInput.Name {
				continue
			}
			if !matchInputSpecWithDBField(sourceInput.Commit, n.Commit) {
				continue
			}
			if !matchInputSpecWithDBField(sourceInput.Tag, n.Tag) {
				continue
			}
			return true
		}
	}
	return false
}

// TODO(mihaimaruseac): Merge with neo4j similar(ish) implementation.
// In a separate PR, as this is already too large
func generateModelPackage(inputPackage *model.PkgInputSpec) *model.Package {
	var version *model.PackageVersion
	if inputPackage.Version != nil ||
		inputPackage.Subpath != nil ||
		inputPackage.Qualifiers != nil {
		version = &model.PackageVersion{}
		if inputPackage.Version != nil {
			version.Version = *inputPackage.Version
		}
		if inputPackage.Subpath != nil {
			version.Subpath = *inputPackage.Subpath
		}
		if inputPackage.Qualifiers != nil {
			var qualifiers []*model.PackageQualifier
			for _, q := range inputPackage.Qualifiers {
				qual := model.PackageQualifier{
					Key:   q.Key,
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
		Name:     inputPackage.Name,
		Versions: versions,
	}

	namespace := &model.PackageNamespace{
		Namespace: *inputPackage.Namespace,
		Names:     []*model.PackageName{name},
	}

	return &model.Package{
		Type:       inputPackage.Type,
		Namespaces: []*model.PackageNamespace{namespace},
	}
}

// TODO(mihaimaruseac): Also merge this with neo4j / extract to common.
func packageMatch(pkg *model.Package, pkgInput *model.PkgInputSpec) bool {
	if pkgInput == nil {
		return false
	}

	if pkg.Type != pkgInput.Type {
		return false
	}
	for _, ns := range pkg.Namespaces {
		if !matchInputSpecWithDBField(pkgInput.Namespace, &ns.Namespace) {
			continue
		}
		for _, n := range ns.Names {
			if n.Name != pkgInput.Name {
				continue
			}
			//TODO(mihaimaruseac): Test what happens here with version
			if pkgInput.Version == nil {
				return true
			}
			for _, v := range n.Versions {
				if !matchInputSpecWithDBField(pkgInput.Version, &v.Version) {
					continue
				}
				if !matchInputSpecWithDBField(pkgInput.Subpath, &v.Subpath) {
					continue
				}
				// TODO(mihaimaruseac): Linearize, extract to generics
				allQualifiersFound := true
				for _, q := range v.Qualifiers {
					qFound := false
					for _, iq := range pkgInput.Qualifiers {
						if q.Key == iq.Key && q.Value == iq.Value {
							qFound = true
							break
						}
					}
					if !qFound {
						allQualifiersFound = false
						break
					}
				}
				if allQualifiersFound {
					return true
				}
			}
			return false
		}
	}
	return false
}
