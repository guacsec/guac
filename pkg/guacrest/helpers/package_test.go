//
// Copyright 2024 The GUAC Authors.
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

package helpers_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	test_helpers "github.com/guacsec/guac/internal/testing/graphqlClients"
	gql "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/guacrest/helpers"
	"github.com/guacsec/guac/pkg/guacrest/pagination"
	"github.com/guacsec/guac/pkg/logging"
)

func Test_GetVersionsOfPackagesResponse(t *testing.T) {
	tests := []struct {
		testName string
		input    []gql.PackagesPackagesPackage
		expected []gql.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion
	}{
		{
			testName: "No package version nodes",
			input: []gql.PackagesPackagesPackage{{AllPkgTree: gql.AllPkgTree{
				Id:   "0",
				Type: "golang",
				Namespaces: []gql.AllPkgTreeNamespacesPackageNamespace{{
					Id:        "1",
					Namespace: "",
					Names: []gql.AllPkgTreeNamespacesPackageNamespaceNamesPackageName{{
						Id:   "2",
						Name: "foo",
					}},
				}},
			}}},
		},
		{
			testName: "Returns all package version nodes nested in one name node",
			input: []gql.PackagesPackagesPackage{{AllPkgTree: gql.AllPkgTree{
				Id:   "0",
				Type: "golang",
				Namespaces: []gql.AllPkgTreeNamespacesPackageNamespace{{
					Id:        "1",
					Namespace: "",
					Names: []gql.AllPkgTreeNamespacesPackageNamespaceNamesPackageName{{
						Id:   "2",
						Name: "foo",
						Versions: []gql.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion{
							{
								Id:      "3",
								Version: "v1",
							},
							{
								Id:      "4",
								Version: "v2",
							},
						},
					}},
				}},
			}}},
			expected: []gql.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion{
				{
					Id:      "3",
					Version: "v1",
				},
				{
					Id:      "4",
					Version: "v2",
				},
			},
		},
	}

	for _, tt := range tests {
		actual := helpers.GetVersionsOfPackagesResponse(tt.input)
		if !cmp.Equal(tt.expected, actual, cmpopts.EquateEmpty()) {
			t.Errorf("Got %v, wanted %v", actual, tt.expected)
		}
	}
}

func Test_FindPackageWithPurl(t *testing.T) {
	ctx := logging.WithLogger(context.Background())

	tests := []struct {
		testName string
		input    string
		wantErr  bool

		ingestedPkgToExpect  *gql.PkgInputSpec // this package is ingested, and its ID is the expected output
		otherPackageToIngest *gql.PkgInputSpec // other packages to ingest
	}{
		{
			testName:            "Matched ID of version node, package does not have version",
			input:               "pkg:guac/bar",
			ingestedPkgToExpect: &gql.PkgInputSpec{Type: "guac", Name: "bar"},
		},
		{
			testName:            "Matched ID of version node, package has version",
			input:               "pkg:guac/bar@v1",
			ingestedPkgToExpect: &gql.PkgInputSpec{Type: "guac", Name: "bar", Version: pagination.PointerOf("v1")},
		},
		{
			testName:             "Matched the less specific (without version) package",
			input:                "pkg:guac/bar",
			ingestedPkgToExpect:  &gql.PkgInputSpec{Type: "guac", Name: "bar"},
			otherPackageToIngest: &gql.PkgInputSpec{Type: "guac", Name: "bar", Version: pagination.PointerOf("v1")},
		},
		{
			testName:            "Matched the less specific (without qualifiers) package",
			input:               "pkg:guac/bar",
			ingestedPkgToExpect: &gql.PkgInputSpec{Type: "guac", Name: "bar"},
			otherPackageToIngest: &gql.PkgInputSpec{
				Type: "guac", Name: "bar",
				Qualifiers: []gql.PackageQualifierInputSpec{{Key: "key", Value: "val"}}},
		},
		{
			testName:             "Matched the more specific (with version) package",
			input:                "pkg:guac/bar@v1",
			ingestedPkgToExpect:  &gql.PkgInputSpec{Type: "guac", Name: "bar", Version: pagination.PointerOf("v1")},
			otherPackageToIngest: &gql.PkgInputSpec{Type: "guac", Name: "bar"},
		},
		{
			testName: "Matched the more specific (with qualifiers) package",
			input:    "pkg:guac/bar?key=val",
			ingestedPkgToExpect: &gql.PkgInputSpec{
				Type: "guac", Name: "bar",
				Qualifiers: []gql.PackageQualifierInputSpec{{Key: "key", Value: "val"}},
			},
			otherPackageToIngest: &gql.PkgInputSpec{Type: "guac", Name: "bar"},
		},
		{
			testName: "Same qualifier key in both packages",
			input:    "pkg:guac/bar?key=val-1",
			ingestedPkgToExpect: &gql.PkgInputSpec{
				Type: "guac", Name: "bar",
				Qualifiers: []gql.PackageQualifierInputSpec{{Key: "key", Value: "val-1"}},
			},
			otherPackageToIngest: &gql.PkgInputSpec{
				Type: "guac", Name: "bar",
				Qualifiers: []gql.PackageQualifierInputSpec{{Key: "key", Value: "val-2"}}},
		},
		{
			testName: "Common qualifiers in both packages",
			input:    "pkg:guac/bar?a=b&c=d",
			ingestedPkgToExpect: &gql.PkgInputSpec{
				Type: "guac", Name: "bar",
				Qualifiers: []gql.PackageQualifierInputSpec{{Key: "a", Value: "b"}, {Key: "c", Value: "d"}},
			},
			otherPackageToIngest: &gql.PkgInputSpec{
				Type: "guac", Name: "bar",
				Qualifiers: []gql.PackageQualifierInputSpec{{Key: "a", Value: "b"}, {Key: "c", Value: "e"}}},
		},
		{
			testName: "Input without qualifiers does not match package with qualifiers",
			input:    "pkg:guac/bar",
			otherPackageToIngest: &gql.PkgInputSpec{
				Type: "guac", Name: "bar",
				Qualifiers: []gql.PackageQualifierInputSpec{{Key: "a", Value: "b"}}},
			wantErr: true,
		},
		{
			testName:             "Input with qualifiers does not match package without qualifiers",
			input:                "pkg:guac/bar?a=b",
			otherPackageToIngest: &gql.PkgInputSpec{Type: "guac", Name: "bar"},
			wantErr:              true,
		},
		{
			testName:             "Input without version does not match package with version",
			input:                "pkg:guac/bar",
			otherPackageToIngest: &gql.PkgInputSpec{Type: "guac", Name: "bar", Version: pagination.PointerOf("v1")},
			wantErr:              true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			gqlClient := test_helpers.SetupTest(t)

			// ingest the expected output package and get its ID
			var expected *gql.IngestPackageResponse
			var err error
			if tt.ingestedPkgToExpect != nil {
				inputSpec := gql.IDorPkgInput{PackageInput: tt.ingestedPkgToExpect}
				expected, err = gql.IngestPackage(ctx, gqlClient, inputSpec)
				if err != nil {
					t.Errorf("Error setting up test: %s", err)
				}
			}

			// ingest the other package
			if tt.otherPackageToIngest != nil {
				inputSpec := gql.IDorPkgInput{PackageInput: tt.otherPackageToIngest}
				_, err = gql.IngestPackage(ctx, gqlClient, inputSpec)
				if err != nil {
					t.Errorf("Error setting up test: %s", err)
				}
			}

			// call the endpoint and check the output
			res, err := helpers.FindPackageWithPurl(ctx, gqlClient, tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("tt.wantErr is %v, but err is %s", tt.wantErr, err)
			}
			if !tt.wantErr && res.GetId() != expected.IngestPackage.PackageVersionID {
				t.Errorf("Got %s, but expected %s", res, expected.IngestPackage.PackageVersionID)
			}
		})
	}
}
