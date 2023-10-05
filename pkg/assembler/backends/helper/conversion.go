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
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// TODO: maybe use generics for PkgInputSpec and PkgSpec?
func ConvertPkgInputSpecToPkgSpec(pkgInput *model.PkgInputSpec) *model.PkgSpec {
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
	pkgSpec := model.PkgSpec{
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
func ConvertSrcInputSpecToSrcSpec(srcInput *model.SourceInputSpec) *model.SourceSpec {
	var tag string = ""
	if srcInput.Tag != nil {
		tag = *srcInput.Tag
	}
	var commit string = ""
	if srcInput.Commit != nil {
		commit = *srcInput.Commit
	}
	srcSpec := model.SourceSpec{
		Type:      &srcInput.Type,
		Namespace: &srcInput.Namespace,
		Name:      &srcInput.Name,
		Tag:       &tag,
		Commit:    &commit,
	}
	return &srcSpec
}

// TODO: maybe use generics for ArtifactInputSpec and ArtifactSpec?
func ConvertArtInputSpecToArtSpec(artInput *model.ArtifactInputSpec) *model.ArtifactSpec {
	artSpec := model.ArtifactSpec{
		Algorithm: &artInput.Algorithm,
		Digest:    &artInput.Digest,
	}
	return &artSpec
}

func ConvertBuilderInputSpecToBuilderSpec(input *model.BuilderInputSpec) *model.BuilderSpec {
	uri := input.URI
	output := model.BuilderSpec{
		URI: &uri,
	}
	return &output
}

func ConvertLicenseInputSpecToLicenseSpec(licenseInput *model.LicenseInputSpec) *model.LicenseSpec {
	return &model.LicenseSpec{
		Name:        &licenseInput.Name,
		Inline:      licenseInput.Inline,
		ListVersion: licenseInput.ListVersion,
	}
}
