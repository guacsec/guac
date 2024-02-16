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

package backend_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestPkgEqual(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	type call struct {
		P1 *model.PkgInputSpec
		P2 *model.PkgInputSpec
		HE *model.PkgEqualInputSpec
	}
	tests := []struct {
		Name                string
		InPkg               []*model.PkgInputSpec
		Calls               []call
		Query               *model.PkgEqualSpec
		ExpHE               []*model.PkgEqual
		QueryID             bool
		QueryPkgID          bool
		QuerySecondaryPkgID bool
		ExpIngestErr        bool
		ExpQueryErr         bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{testdata.P1out, testdata.P2out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest same, different order",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: testdata.P2,
					P2: testdata.P1,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{testdata.P1out, testdata.P2out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Justification",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification one",
					},
				},
				{
					P1: testdata.P1,
					P2: testdata.P2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Justification: ptrfrom.String("test justification one"),
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{testdata.P1out, testdata.P2out},
					Justification: "test justification one",
				},
			},
		},
		{
			Name:  "Query on pkg ID",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification one",
					},
				},
				{
					P1: testdata.P1,
					P2: testdata.P2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification two",
					},
				},
			},
			QueryPkgID: true,
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{testdata.P1out, testdata.P2out},
					Justification: "test justification two",
				},
				{
					Packages:      []*model.Package{testdata.P1out, testdata.P2out},
					Justification: "test justification one",
				},
				{
					Packages:      []*model.Package{testdata.P1out, testdata.P2out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on secondary pkg ID",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification one",
					},
				},
				{
					P1: testdata.P1,
					P2: testdata.P2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification two",
					},
				},
			},
			QuerySecondaryPkgID: true,
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{testdata.P1out, testdata.P2out},
					Justification: "test justification two",
				},
				{
					Packages:      []*model.Package{testdata.P1out, testdata.P2out},
					Justification: "test justification one",
				},
				{
					Packages:      []*model.Package{testdata.P1out, testdata.P2out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on pkg",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: testdata.P1,
					P2: testdata.P3,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{{
					Type:                     ptrfrom.String("pypi"),
					Name:                     ptrfrom.String("tensorflow"),
					Version:                  ptrfrom.String("2.11.1"),
					Subpath:                  ptrfrom.String("saved_model_cli.py"),
					MatchOnlyEmptyQualifiers: ptrfrom.Bool(true),
				}},
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{testdata.P3out, testdata.P1out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on pkg details",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: testdata.P1,
					P2: testdata.P3,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{{
					Version: ptrfrom.String("2.11.1"),
					Subpath: ptrfrom.String(""),
				}},
				Justification: ptrfrom.String("test justification"),
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{testdata.P2out, testdata.P1out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on pkg algo and pkg",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: testdata.P1,
					P2: testdata.P3,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{{
					Type:      ptrfrom.String("pypi"),
					Namespace: ptrfrom.String(""),
					Name:      ptrfrom.String("tensorflow"),
					Subpath:   ptrfrom.String(""),
					Version:   ptrfrom.String("2.11.1"),
				}},
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{testdata.P2out, testdata.P1out},
					Justification: "test justification two",
				},
				{
					Packages:      []*model.Package{testdata.P2out, testdata.P1out},
					Justification: "test justification one",
				},
				{
					Packages:      []*model.Package{testdata.P2out, testdata.P1out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on both pkgs",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: testdata.P2,
					P2: testdata.P3,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{
					{
						Subpath: ptrfrom.String("saved_model_cli.py"),
					},
					{
						Name:                     ptrfrom.String("tensorflow"),
						Version:                  ptrfrom.String("2.11.1"),
						MatchOnlyEmptyQualifiers: ptrfrom.Bool(true),
					},
				},
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{testdata.P3out, testdata.P2out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on both pkgs, one filter",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: testdata.P2,
					P2: testdata.P3,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: testdata.P1,
					P2: testdata.P3,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{
					{
						Version: ptrfrom.String(""),
					},
					{
						Version: ptrfrom.String("2.11.1"),
						Subpath: ptrfrom.String("saved_model_cli.py"),
					},
				},
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{testdata.P1out, testdata.P3out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on both pkgs, match qualifiers",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P5},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P5,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{
					{
						Version:                  ptrfrom.String(""),
						MatchOnlyEmptyQualifiers: ptrfrom.Bool(true),
					},
					{
						MatchOnlyEmptyQualifiers: ptrfrom.Bool(false),
						Qualifiers: []*model.PackageQualifierSpec{{
							Key:   "test",
							Value: ptrfrom.String("test"),
						}},
					},
				},
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{testdata.P1out, testdata.P5out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on both pkgs, match qualifiers",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P5},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P5,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{
					{
						Version: ptrfrom.String(""),
					},
					{
						Type:      ptrfrom.String("conan"),
						Namespace: ptrfrom.String("openssl.org"),
						Qualifiers: []*model.PackageQualifierSpec{{
							Key:   "test",
							Value: ptrfrom.String("test"),
						}},
					},
				},
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{testdata.P1out, testdata.P5out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query none",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: testdata.P2,
					P2: testdata.P3,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: testdata.P1,
					P2: testdata.P3,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{
					{
						Version: ptrfrom.String("1.2.3"),
					},
				},
			},
			ExpHE: nil,
		},
		{
			Name:  "Query on ID",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: testdata.P2,
					P2: testdata.P3,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: testdata.P1,
					P2: testdata.P3,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			QueryID: true,
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{testdata.P1out, testdata.P3out},
					Justification: "test justification",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			var collectedPkgIDs []*model.PackageIDs
			for _, a := range test.InPkg {
				if pkgIDs, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: a}); err != nil {
					t.Fatalf("Could not ingest pkg: %v", err)
				} else {
					collectedPkgIDs = append(collectedPkgIDs, pkgIDs)
				}
			}
			for _, o := range test.Calls {
				peID, err := b.IngestPkgEqual(ctx, model.IDorPkgInput{PackageInput: o.P1}, model.IDorPkgInput{PackageInput: o.P2}, *o.HE)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.PkgEqualSpec{
						ID: ptrfrom.String(peID),
					}
				}
				if test.QueryPkgID {
					test.Query = &model.PkgEqualSpec{
						Packages: []*model.PkgSpec{{
							ID: ptrfrom.String(collectedPkgIDs[0].PackageVersionID),
						}},
					}
				}
				if test.QuerySecondaryPkgID {
					test.Query = &model.PkgEqualSpec{
						Packages: []*model.PkgSpec{
							{
								ID: ptrfrom.String(collectedPkgIDs[0].PackageVersionID),
							},
							{
								ID: ptrfrom.String(collectedPkgIDs[1].PackageVersionID),
							},
						},
					}
				}
			}
			fmt.Println(test.Query)
			got, err := b.PkgEqual(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpHE, got, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestPkgEquals(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	type call struct {
		P1 []*model.IDorPkgInput
		P2 []*model.IDorPkgInput
		PE []*model.PkgEqualInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		Calls        []call
		Query        *model.PkgEqualSpec
		ExpHE        []*model.PkgEqual
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					P1: []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P1}},
					P2: []*model.IDorPkgInput{{PackageInput: testdata.P2}, {PackageInput: testdata.P2}},
					PE: []*model.PkgEqualInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{testdata.P1out, testdata.P2out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest same, different order",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					P1: []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P2}},
					P2: []*model.IDorPkgInput{{PackageInput: testdata.P2}, {PackageInput: testdata.P1}},
					PE: []*model.PkgEqualInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{testdata.P1out, testdata.P2out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on pkg details",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3},
			Calls: []call{
				{
					P1: []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P1}},
					P2: []*model.IDorPkgInput{{PackageInput: testdata.P2}, {PackageInput: testdata.P3}},
					PE: []*model.PkgEqualInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{{
					Version: ptrfrom.String("2.11.1"),
					Subpath: ptrfrom.String(""),
				}},
				Justification: ptrfrom.String("test justification"),
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{testdata.P2out, testdata.P1out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on pkg algo and pkg",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3},
			Calls: []call{
				{
					P1: []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P1}},
					P2: []*model.IDorPkgInput{{PackageInput: testdata.P2}, {PackageInput: testdata.P3}},
					PE: []*model.PkgEqualInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{{
					Type:      ptrfrom.String("pypi"),
					Namespace: ptrfrom.String(""),
					Name:      ptrfrom.String("tensorflow"),
					Subpath:   ptrfrom.String(""),
					Version:   ptrfrom.String("2.11.1"),
				}},
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{testdata.P2out, testdata.P1out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on both pkgs, one filter",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3},
			Calls: []call{
				{
					P1: []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P1}},
					P2: []*model.IDorPkgInput{{PackageInput: testdata.P2}, {PackageInput: testdata.P3}},
					PE: []*model.PkgEqualInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{
					{
						Version: ptrfrom.String(""),
					},
					{
						Version: ptrfrom.String("2.11.1"),
						Subpath: ptrfrom.String("saved_model_cli.py"),
					},
				},
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{testdata.P1out, testdata.P3out},
					Justification: "test justification",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: p}); err != nil {
					t.Fatalf("Could not ingest pkg: %v", err)
				}
			}

			for _, o := range test.Calls {
				_, err := b.IngestPkgEquals(ctx, o.P1, o.P2, o.PE)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.PkgEqual(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpHE, got, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
