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

// Transformer function transforms input specification to specification.
type Transformer[Input any, Output any] func(input *Input) *Output

// ConvertPkgInputSpecToPkgSpec is a function that transforms PkgInputSpec to PkgSpec.
var ConvertPkgInputSpecToPkgSpec Transformer[model.PkgInputSpec, model.PkgSpec] = func(input *model.PkgInputSpec) *model.PkgSpec {
	qualifiers := convertSlice(input.Qualifiers, convertQualifierInputToQualifierSpec)
	matchEmpty := len(qualifiers) == 0
	version := ptrOrNil(input.Version)
	subpath := ptrOrNil(input.Subpath)

	return &model.PkgSpec{
		Type:                     &input.Type,
		Namespace:                input.Namespace,
		Name:                     &input.Name,
		Version:                  version,
		Subpath:                  subpath,
		Qualifiers:               qualifiers,
		MatchOnlyEmptyQualifiers: &matchEmpty,
	}
}

// ConvertSrcInputSpecToSrcSpec is a function that transforms SourceInputSpec to SourceSpec.
var ConvertSrcInputSpecToSrcSpec Transformer[model.SourceInputSpec, model.SourceSpec] = func(input *model.SourceInputSpec) *model.SourceSpec {
	tag := ptrOrNil(input.Tag)
	commit := ptrOrNil(input.Commit)

	return &model.SourceSpec{
		Type:      &input.Type,
		Namespace: &input.Namespace,
		Name:      &input.Name,
		Tag:       tag,
		Commit:    commit,
	}
}

// ConvertArtInputSpecToArtSpec is a function that transforms ArtifactInputSpec to ArtifactSpec.
var ConvertArtInputSpecToArtSpec Transformer[model.ArtifactInputSpec, model.ArtifactSpec] = func(input *model.ArtifactInputSpec) *model.ArtifactSpec {
	return &model.ArtifactSpec{
		Algorithm: &input.Algorithm,
		Digest:    &input.Digest,
	}
}

// ConvertLicenseInputSpecToLicenseSpec is a function that transforms LicenseInputSpec to LicenseSpec.
var ConvertLicenseInputSpecToLicenseSpec Transformer[model.LicenseInputSpec, model.LicenseSpec] = func(input *model.LicenseInputSpec) *model.LicenseSpec {
	return &model.LicenseSpec{
		Name:        &input.Name,
		Inline:      input.Inline,
		ListVersion: input.ListVersion,
	}
}

// ptrOrNil is a function that checks if a pointer is nil.
// If the pointer is nil, it returns a pointer to an empty value of the same type.
// If the pointer is not nil, it returns the original pointer.
func ptrOrNil[T any](ptr *T) *T {
	if ptr == nil {
		var empty T
		return &empty
	}
	return ptr
}

// convertSlice is a function that transforms an input slice to an output slice using a provided converter function.
func convertSlice[Input any, Output any](inputSlice []*Input, converter Transformer[Input, Output]) []*Output {
	outputSlice := make([]*Output, len(inputSlice))
	for i, input := range inputSlice {
		outputSlice[i] = converter(input)
	}
	return outputSlice
}

// convertQualifierInputToQualifierSpec is a function that transforms PackageQualifierInputSpec to PackageQualifierSpec.
var convertQualifierInputToQualifierSpec Transformer[model.PackageQualifierInputSpec, model.PackageQualifierSpec] = func(input *model.PackageQualifierInputSpec) *model.PackageQualifierSpec {
	return &model.PackageQualifierSpec{
		Key:   input.Key,
		Value: &input.Value,
	}
}
