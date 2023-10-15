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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestConvertQualifierInputToQualifierSpec(t *testing.T) {
	input := &model.PackageQualifierInputSpec{
		Key:   "testKey",
		Value: "testValue",
	}

	output := convertQualifierInputToQualifierSpec(input)

	if output.Key != input.Key || *output.Value != input.Value {
		t.Errorf("convertQualifierInputToQualifierSpec failed, expected %v, got %v", input, output)
	}
}

func TestConvertSlice(t *testing.T) {
	transformer := func(input *int) *int {
		*input *= 2
		return input
	}

	testCases := []struct {
		name        string
		inputSlice  []*int
		transformer Transformer[int, int]
		expected    []*int
	}{
		{
			name:        "Test with empty slice",
			inputSlice:  []*int{},
			transformer: transformer,
			expected:    []*int{},
		},
		{
			name:        "Test with non-empty slice",
			inputSlice:  []*int{new(int), new(int), new(int)},
			transformer: transformer,
			expected:    []*int{new(int), new(int), new(int)},
		},
	}

	// Assign values to the pointers
	*testCases[1].inputSlice[0] = 1
	*testCases[1].inputSlice[1] = 2
	*testCases[1].inputSlice[2] = 3

	*testCases[1].expected[0] = 2
	*testCases[1].expected[1] = 4
	*testCases[1].expected[2] = 6

	// Run the test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := convertSlice(tc.inputSlice, tc.transformer)
			if diff := cmp.Diff(tc.expected, result); diff != "" {
				t.Errorf("Mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPtrOrNil(t *testing.T) {
	tests := []struct {
		name string
		ptr  *int
		want *int
	}{
		{
			name: "Nil pointer",
			ptr:  nil,
			want: new(int), // Pointer to zero value for int
		},
		{
			name: "Non-nil pointer",
			ptr:  func() *int { v := 5; return &v }(),
			want: func() *int { v := 5; return &v }(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ptrOrNil(tt.ptr); !cmp.Equal(got, tt.want) {
				t.Errorf("ptrOrNil() = %v, want %v", *got, *tt.want)
			}
		})
	}
}

func TestConvertPkgInputSpecToPkgSpec(t *testing.T) {
	nameSpace := "testNamespace"
	f := true
	input := &model.PkgInputSpec{
		Type:       "inputType",
		Namespace:  &nameSpace,
		Name:       "inputName",
		Version:    nil,
		Subpath:    nil,
		Qualifiers: nil,
	}
	expected := &model.PkgSpec{
		Type:                     &input.Type,
		Namespace:                input.Namespace,
		Name:                     &input.Name,
		Version:                  new(string),
		Subpath:                  new(string),
		Qualifiers:               []*model.PackageQualifierSpec{},
		MatchOnlyEmptyQualifiers: &f,
	}

	output := ConvertPkgInputSpecToPkgSpec(input)

	if diff := cmp.Diff(expected, output); diff != "" {
		t.Errorf("ConvertPkgInputSpecToPkgSpec() mismatch (-want +got):\n%s", diff)
	}
}

func TestConvertSrcInputSpecToSrcSpec(t *testing.T) {
	input := &model.SourceInputSpec{
		Type:      "git",
		Namespace: "namespace",
		Name:      "name",
		Tag:       StringToPtr("tag"),
		Commit:    StringToPtr("commit"),
	}
	expected := &model.SourceSpec{
		Type:      &input.Type,
		Namespace: &input.Namespace,
		Name:      &input.Name,
		Tag:       input.Tag,
		Commit:    input.Commit,
	}

	result := ConvertSrcInputSpecToSrcSpec(input)
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("ConvertSrcInputSpecToSrcSpec() mismatch (-want +got):\n%s", diff)
	}
}

func TestConvertArtInputSpecToArtSpec(t *testing.T) {
	input := &model.ArtifactInputSpec{
		Algorithm: "sha256",
		Digest:    "digest",
	}
	expected := &model.ArtifactSpec{
		Algorithm: &input.Algorithm,
		Digest:    &input.Digest,
	}

	result := ConvertArtInputSpecToArtSpec(input)
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("ConvertArtInputSpecToArtSpec() mismatch (-want +got):\n%s", diff)
	}
}

func TestConvertLicenseInputSpecToLicenseSpec(t *testing.T) {
	input := &model.LicenseInputSpec{
		Name:        "MIT",
		Inline:      StringToPtr("inline"),
		ListVersion: StringToPtr("listVersion"),
	}
	expected := &model.LicenseSpec{
		Name:        &input.Name,
		Inline:      input.Inline,
		ListVersion: input.ListVersion,
	}

	result := ConvertLicenseInputSpecToLicenseSpec(input)
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("ConvertLicenseInputSpecToLicenseSpec() mismatch (-want +got):\n%s", diff)
	}
}

func StringToPtr(s string) *string {
	return &s
}
