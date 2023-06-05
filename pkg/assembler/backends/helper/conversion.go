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

package helper

import (
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// TODO: maybe use generics for PkgInputSpec and PkgSpec?
func ConvertPkgInputSpecToPkgSpec[T model.PkgSpec](pkgInput *model.PkgInputSpec) *T {
	qualifiers := convertQualifierInputToQualifierSpec(pkgInput.Qualifiers)
	matchEmpty := false
	if len(qualifiers) == 0 {
		matchEmpty = true
	}
	var version string = ""
	if pkgInput.Version != nil {
		version = *pkgInput.Version
	}
	var subpath string = ""
	if pkgInput.Subpath != nil {
		subpath = *pkgInput.Subpath
	}
	pkgSpec := T{
		Type:                     &pkgInput.Type,
		Namespace:                pkgInput.Namespace,
		Name:                     &pkgInput.Name,
		Version:                  &version,
		Subpath:                  &subpath,
		Qualifiers:               qualifiers,
		MatchOnlyEmptyQualifiers: &matchEmpty,
	}
	return &pkgSpec
}

func convertQualifierInputToQualifierSpec(qualifiers []*model.PackageQualifierInputSpec) []*model.PackageQualifierSpec {
	pkgQualifiers := []*model.PackageQualifierSpec{}
	for _, quali := range qualifiers {
		pkgQualifier := &model.PackageQualifierSpec{
			Key:   quali.Key,
			Value: &quali.Value,
		}
		pkgQualifiers = append(pkgQualifiers, pkgQualifier)
	}
	return pkgQualifiers
}

// TODO: maybe use generics for SourceInputSpec and SourceSpec?
func ConvertSrcInputSpecToSrcSpec[T model.SourceSpec](srcInput *model.SourceInputSpec) *T {
	var tag string = ""
	if srcInput.Tag != nil {
		tag = *srcInput.Tag
	}
	var commit string = ""
	if srcInput.Commit != nil {
		commit = *srcInput.Commit
	}
	srcSpec := T{
		Type:      &srcInput.Type,
		Namespace: &srcInput.Namespace,
		Name:      &srcInput.Name,
		Tag:       &tag,
		Commit:    &commit,
	}
	return &srcSpec
}

// TODO: maybe use generics for OSVInputSpec and OSVSpec?
func ConvertOsvInputSpecToOsvSpec[T model.OSVSpec](osvInput *model.OSVInputSpec) *T {
	osvID := strings.ToLower(osvInput.OsvID)
	osvSpec := T{
		OsvID: &osvID,
	}
	return &osvSpec
}

// TODO: maybe use generics for GHSAInputSpec and GHSASpec?
func ConvertGhsaInputSpecToGhsaSpec[T model.GHSASpec](ghsaInput *model.GHSAInputSpec) *T {
	ghsaID := strings.ToLower(ghsaInput.GhsaID)
	ghsaSpec := T{
		GhsaID: &ghsaID,
	}
	return &ghsaSpec
}

// TODO: maybe use generics for CVEInputSpec and CVESpec?
func ConvertCveInputSpecToCveSpec[T model.CVESpec](cveInput *model.CVEInputSpec) *T {
	cveID := strings.ToLower(cveInput.CveID)
	cveSpec := T{
		Year:  &cveInput.Year,
		CveID: &cveID,
	}
	return &cveSpec
}

type ArtifactOrSourceSpec interface {
	model.ArtifactSpec
	model.SourceSpec
}

// TODO: maybe use generics for ArtifactInputSpec and ArtifactSpec?
func ConvertArtInputSpecToArtSpec[T model.ArtifactSpec](artInput *model.ArtifactInputSpec) *T {
	artSpec := T{
		Algorithm: &artInput.Algorithm,
		Digest:    &artInput.Digest,
	}
	return &artSpec
}

func ConvertBuilderInputSpecToBuilderSpec[T model.BuilderSpec](input *model.BuilderInputSpec) *T {
	uri := input.URI
	output := T{
		URI: &uri,
	}
	return &output
}
