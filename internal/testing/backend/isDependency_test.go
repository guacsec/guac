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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestIsDependency(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	type call struct {
		P1 *model.PkgInputSpec
		P2 *model.PkgInputSpec
		MF model.MatchFlags
		ID *model.IsDependencyInputSpec
	}
	tests := []struct {
		Name          string
		InPkg         []*model.PkgInputSpec
		Calls         []call
		Query         *model.IsDependencySpec
		QueryID       bool
		QueryPkgID    bool
		QueryDepPkgID bool
		ExpID         []*model.IsDependency
		ExpIngestErr  bool
		ExpQueryErr   bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.IsDependencySpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P1out,
					DependencyPackage: testdata.P2outName,
					Justification:     "test justification",
				},
			},
		},
		{
			Name:  "Ingest same",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: testdata.P1,
					P2: testdata.P2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.IsDependencySpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P1out,
					DependencyPackage: testdata.P2outName,
					Justification:     "test justification",
				},
			},
		},
		{
			Name:  "Ingest same, different version",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: testdata.P1,
					P2: testdata.P3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.IsDependencySpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P1out,
					DependencyPackage: testdata.P2outName,
					Justification:     "test justification",
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
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification one",
					},
				},
				{
					P1: testdata.P1,
					P2: testdata.P2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification two",
					},
				},
			},
			Query: &model.IsDependencySpec{
				Justification: ptrfrom.String("test justification one"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P1out,
					DependencyPackage: testdata.P2outName,
					Justification:     "test justification one",
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
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: testdata.P2,
					P2: testdata.P3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				Package: &model.PkgSpec{
					Name:    ptrfrom.String("tensorflow"),
					Version: ptrfrom.String("2.11.1"),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P2out,
					DependencyPackage: testdata.P2outName,
				},
			},
		},
		{
			Name:  "Query on dep pkg",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P4},
			Calls: []call{
				{
					P1: testdata.P2,
					P2: testdata.P4,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: testdata.P2,
					P2: testdata.P1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				DependencyPackage: &model.PkgSpec{
					Name: ptrfrom.String("openssl"),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P2out,
					DependencyPackage: testdata.P4outName,
				},
			},
		},
		{
			Name:  "Query on dep pkg - type",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P4},
			Calls: []call{
				{
					P1: testdata.P2,
					P2: testdata.P4,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: testdata.P2,
					P2: testdata.P1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				DependencyPackage: &model.PkgSpec{
					Type: ptrfrom.String("conan"),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P2out,
					DependencyPackage: testdata.P4outName,
				},
			},
		},
		{
			Name:  "Query on dep pkg - namespace",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P4},
			Calls: []call{
				{
					P1: testdata.P2,
					P2: testdata.P4,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: testdata.P2,
					P2: testdata.P1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				DependencyPackage: &model.PkgSpec{
					Namespace: ptrfrom.String("openssl.org"),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P2out,
					DependencyPackage: testdata.P4outName,
				},
			},
		},
		{
			Name:  "Query on dep pkg - version",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P4},
			Calls: []call{
				{
					P1: testdata.P2,
					P2: testdata.P4,
					MF: mSpecific,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: testdata.P2,
					P2: testdata.P1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				DependencyPackage: &model.PkgSpec{
					Version: ptrfrom.String("3.0.3"),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P2out,
					DependencyPackage: testdata.P4out,
				},
			},
		},
		{
			Name:  "Query on dep pkg - subpath",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P4},
			Calls: []call{
				{
					P1: testdata.P2,
					P2: testdata.P3,
					MF: mSpecific,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: testdata.P2,
					P2: testdata.P1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				DependencyPackage: &model.PkgSpec{
					Subpath: ptrfrom.String("saved_model_cli.py"),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P2out,
					DependencyPackage: testdata.P3out,
				},
			},
		},
		{
			Name:  "Query on dep pkg - match empty qualifiers",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P4},
			Calls: []call{
				{
					P1: testdata.P2,
					P2: testdata.P4,
					MF: mSpecific,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: testdata.P2,
					P2: testdata.P1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				DependencyPackage: &model.PkgSpec{
					MatchOnlyEmptyQualifiers: ptrfrom.Bool(true),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P2out,
					DependencyPackage: testdata.P4out,
				},
				{
					Package:           testdata.P2out,
					DependencyPackage: testdata.P3out,
				},
			},
		},
		{
			Name:  "Query on dep pkg - match empty qualifiers false",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P5},
			Calls: []call{
				{
					P1: testdata.P2,
					P2: testdata.P5,
					MF: mSpecific,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: testdata.P2,
					P2: testdata.P1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				DependencyPackage: &model.PkgSpec{
					MatchOnlyEmptyQualifiers: ptrfrom.Bool(false),
					Qualifiers: []*model.PackageQualifierSpec{
						{
							Key:   "test",
							Value: ptrfrom.String("test"),
						},
					},
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P2out,
					DependencyPackage: testdata.P5out,
				},
			},
		},
		{
			Name:  "Query on dep pkg - match qualifiers",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P5},
			Calls: []call{
				{
					P1: testdata.P2,
					P2: testdata.P5,
					MF: mSpecific,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: testdata.P2,
					P2: testdata.P1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				DependencyPackage: &model.PkgSpec{
					Qualifiers: []*model.PackageQualifierSpec{
						{
							Key:   "test",
							Value: ptrfrom.String("test"),
						},
					},
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P2out,
					DependencyPackage: testdata.P5out,
				},
			},
		},
		{
			Name:  "Query on pkg - match empty qualifiers false",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P5},
			Calls: []call{
				{
					P1: testdata.P5,
					P2: testdata.P2,
					MF: mSpecific,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: testdata.P2,
					P2: testdata.P1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				Package: &model.PkgSpec{
					MatchOnlyEmptyQualifiers: ptrfrom.Bool(false),
					Qualifiers: []*model.PackageQualifierSpec{
						{
							Key:   "test",
							Value: ptrfrom.String("test"),
						},
					},
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P5out,
					DependencyPackage: testdata.P2out,
				},
			},
		},
		{
			Name:  "Query on pkg multiple",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: testdata.P3,
					P2: testdata.P2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				Package: &model.PkgSpec{
					Name:    ptrfrom.String("tensorflow"),
					Subpath: ptrfrom.String("saved_model_cli.py"),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P3out,
					DependencyPackage: testdata.P1outName,
				},
			},
		},
		{
			Name:  "Query on both pkgs",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3, testdata.P4},
			Calls: []call{
				{
					P1: testdata.P2,
					P2: testdata.P1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: testdata.P3,
					P2: testdata.P4,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				Package: &model.PkgSpec{
					Subpath: ptrfrom.String("saved_model_cli.py"),
				},
				DependencyPackage: &model.PkgSpec{
					Name: ptrfrom.String("openssl"),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P3out,
					DependencyPackage: testdata.P4outName,
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
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: testdata.P2,
					P2: testdata.P3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: testdata.P1,
					P2: testdata.P3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				Package: &model.PkgSpec{
					Subpath: ptrfrom.String("asdf"),
				},
			},
			ExpID: nil,
		},
		{
			Name:  "Query on ID",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: testdata.P2,
					P2: testdata.P3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: testdata.P1,
					P2: testdata.P3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			QueryID: true,
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P1out,
					DependencyPackage: testdata.P2outName,
				},
			},
		},
		{
			Name:  "Query on Range",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						VersionRange: "1-3",
					},
				},
				{
					P1: testdata.P2,
					P2: testdata.P1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						VersionRange: "4-5",
					},
				},
			},
			Query: &model.IsDependencySpec{
				VersionRange: ptrfrom.String("1-3"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P1out,
					DependencyPackage: testdata.P1outName,
					VersionRange:      "1-3",
				},
			},
		},
		{
			Name:  "Query on DependencyType",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						DependencyType: model.DependencyTypeDirect,
					},
				},
				{
					P1: testdata.P2,
					P2: testdata.P1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						DependencyType: model.DependencyTypeIndirect,
					},
				},
			},
			Query: &model.IsDependencySpec{
				DependencyType: (*model.DependencyType)(ptrfrom.String(string(model.DependencyTypeIndirect))),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P2out,
					DependencyPackage: testdata.P1outName,
					DependencyType:    model.DependencyTypeIndirect,
				},
			},
		},
		{
			Name:  "IsDep from version to version",
			InPkg: []*model.PkgInputSpec{testdata.P2, testdata.P3},
			Calls: []call{
				{
					P1: testdata.P3,
					P2: testdata.P2,
					MF: mSpecific,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.IsDependencySpec{
				Package: &model.PkgSpec{
					Name:    ptrfrom.String("tensorflow"),
					Subpath: ptrfrom.String("saved_model_cli.py"),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P3out,
					DependencyPackage: testdata.P2out,
					Justification:     "test justification",
				},
				{
					Package:           testdata.P3out,
					DependencyPackage: testdata.P4outName,
				},
				{
					Package:           testdata.P3out,
					DependencyPackage: testdata.P1outName,
				},
			},
		},
		{
			Name:  "IsDep from version to name",
			InPkg: []*model.PkgInputSpec{testdata.P4, testdata.P3},
			Calls: []call{
				{
					P1: testdata.P3,
					P2: testdata.P4,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification name only",
					},
				},
			},
			Query: &model.IsDependencySpec{
				DependencyPackage: &model.PkgSpec{
					Name: ptrfrom.String("openssl"),
				},
				Justification: ptrfrom.String("test justification name only"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P3out,
					DependencyPackage: testdata.P4outName,
					Justification:     "test justification name only",
				},
			},
		},
		{
			Name:  "IsDep from version to name and version",
			InPkg: []*model.PkgInputSpec{testdata.P2, testdata.P3},
			Calls: []call{
				{
					P1: testdata.P3,
					P2: testdata.P2,
					MF: mSpecific,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification return specific",
					},
				},
				{
					P1: testdata.P3,
					P2: testdata.P2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification return specific",
					},
				},
			},
			Query: &model.IsDependencySpec{
				Justification: ptrfrom.String("test justification return specific"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P3out,
					DependencyPackage: testdata.P2out,
					Justification:     "test justification return specific",
				},
				{
					Package:           testdata.P3out,
					DependencyPackage: testdata.P2outName,
					Justification:     "test justification return specific",
				},
			},
		},
		{
			Name:  "Query on pkg ID",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P4},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					MF: mSpecific,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: testdata.P4,
					P2: testdata.P2,
					MF: mSpecific,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			QueryPkgID: true,
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P4out,
					DependencyPackage: testdata.P2out,
				},
			},
		},
		{
			Name:  "Query on dep pkg ID",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P4},
			Calls: []call{
				{
					P1: testdata.P2,
					P2: testdata.P1,
					MF: mSpecific,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: testdata.P2,
					P2: testdata.P4,
					MF: mSpecific,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			QueryDepPkgID: true,
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P2out,
					DependencyPackage: testdata.P4out,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, a := range test.InPkg {
				if pkgIDs, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: a}); err != nil {
					t.Fatalf("Could not ingest pkg: %v", err)
				} else {
					if test.QueryPkgID {
						test.Query = &model.IsDependencySpec{
							Package: &model.PkgSpec{
								ID: ptrfrom.String(pkgIDs.PackageVersionID),
							},
						}
					}
					if test.QueryDepPkgID {
						test.Query = &model.IsDependencySpec{
							DependencyPackage: &model.PkgSpec{
								ID: ptrfrom.String(pkgIDs.PackageVersionID),
							},
						}
					}
				}
			}
			for _, o := range test.Calls {
				depID, err := b.IngestDependency(ctx, model.IDorPkgInput{PackageInput: o.P1}, model.IDorPkgInput{PackageInput: o.P2}, o.MF, *o.ID)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.IsDependencySpec{
						ID: ptrfrom.String(depID),
					}
				}
			}
			got, err := b.IsDependency(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpID, got, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIsDependencies(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	type call struct {
		P1s []*model.IDorPkgInput
		P2s []*model.IDorPkgInput
		MF  model.MatchFlags
		IDs []*model.IsDependencyInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		Calls        []call
		ExpID        []*model.IsDependency
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3, testdata.P4},
			Calls: []call{{
				P1s: []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P2}},
				P2s: []*model.IDorPkgInput{{PackageInput: testdata.P2}, {PackageInput: testdata.P4}},
				MF:  mAll,
				IDs: []*model.IsDependencyInputSpec{
					{
						Justification: "test justification",
					},
					{
						Justification: "test justification",
					},
				},
			}},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P1out,
					DependencyPackage: testdata.P2outName,
					Justification:     "test justification",
				},
			},
		},
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3, testdata.P4},
			Calls: []call{{
				P1s: []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P2}},
				P2s: []*model.IDorPkgInput{{PackageInput: testdata.P2}, {PackageInput: testdata.P4}},
				MF:  mSpecific,
				IDs: []*model.IsDependencyInputSpec{
					{
						Justification: "test justification",
					},
					{
						Justification: "test justification",
					},
				},
			}},
			ExpID: []*model.IsDependency{
				{
					Package:           testdata.P1out,
					DependencyPackage: testdata.P2out,
					Justification:     "test justification",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, a := range test.InPkg {
				if _, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: a}); err != nil {
					t.Fatalf("Could not ingest pkg: %v", err)
				}
			}
			for _, o := range test.Calls {
				depID, err := b.IngestDependencies(ctx, o.P1s, o.P2s, o.MF, o.IDs)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				got, err := b.IsDependency(ctx, &model.IsDependencySpec{ID: ptrfrom.String(depID[0])})
				if (err != nil) != test.ExpQueryErr {
					t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
				}
				if err != nil {
					return
				}
				if diff := cmp.Diff(test.ExpID, got, commonOpts); diff != "" {
					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
				}
			}
		})
	}
}
