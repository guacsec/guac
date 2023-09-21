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

//go:build integration

package arangodb

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

var (
	mAll      = model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}
	mSpecific = model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}
)

func TestIsDependency(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
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
			Name:  "Query bad ID",
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
				ID: ptrfrom.String("asdf"),
			},
			ExpQueryErr: false,
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
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, a := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *a); err != nil {
					t.Fatalf("Could not ingest pkg: %v", err)
				}
			}
			for _, o := range test.Calls {
				found, err := b.IngestDependency(ctx, *o.P1, *o.P2, o.MF, *o.ID)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.IsDependencySpec{
						ID: ptrfrom.String(found.ID),
					}
				}
				if test.QueryPkgID {
					test.Query = &model.IsDependencySpec{
						Package: &model.PkgSpec{
							ID: ptrfrom.String(found.Package.Namespaces[0].Names[0].Versions[0].ID),
						},
					}
				}
				if test.QueryDepPkgID {
					test.Query = &model.IsDependencySpec{
						DependencyPackage: &model.PkgSpec{
							ID: ptrfrom.String(found.DependencyPackage.Namespaces[0].Names[0].Versions[0].ID),
						},
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
			if diff := cmp.Diff(test.ExpID, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIsDependencies(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	type call struct {
		P1s []*model.PkgInputSpec
		P2s []*model.PkgInputSpec
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
				P1s: []*model.PkgInputSpec{testdata.P1, testdata.P2},
				P2s: []*model.PkgInputSpec{testdata.P2, testdata.P4},
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
				{
					Package:           testdata.P2out,
					DependencyPackage: testdata.P4outName,
					Justification:     "test justification",
				},
			},
		},
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3, testdata.P4},
			Calls: []call{{
				P1s: []*model.PkgInputSpec{testdata.P1, testdata.P2},
				P2s: []*model.PkgInputSpec{testdata.P2, testdata.P4},
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
				{
					Package:           testdata.P2out,
					DependencyPackage: testdata.P4out,
					Justification:     "test justification",
				},
			},
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, a := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *a); err != nil {
					t.Fatalf("Could not ingest pkg: %v", err)
				}
			}
			for _, o := range test.Calls {
				got, err := b.IngestDependencies(ctx, o.P1s, o.P2s, o.MF, o.IDs)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if diff := cmp.Diff(test.ExpID, got, ignoreID); diff != "" {
					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
				}
			}

		})
	}
}

// TODO (pxp928): add tests back in when implemented

// func TestIsDependencyNeighbors(t *testing.T) {
// 	type call struct {
// 		P1 *model.PkgInputSpec
// 		P2 *model.PkgInputSpec
// 		MF model.MatchFlags
// 		ID *model.IsDependencyInputSpec
// 	}
// 	tests := []struct {
// 		Name         string
// 		InPkg        []*model.PkgInputSpec
// 		Calls        []call
// 		ExpNeighbors map[string][]string
// 	}{
// 		{
// 			Name:  "HappyPath",
// 			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
// 			Calls: []call{
// 				{
// 					P1: testdata.P1,
// 					P2: testdata.P2,
// 					MF: mAll,
// 					ID: &model.IsDependencyInputSpec{},
// 				},
// 			},
// 			ExpNeighbors: map[string][]string{
// 				"3": []string{"1", "1", "1", "6"}, // testdata.P1/testdata.P2 name
// 				"4": []string{"1", "6"},           // testdata.P1 version
// 				"5": []string{"1"},                // testdata.P2 version
// 				"6": []string{"1", "1"},           // isDep
// 			},
// 		},
// 		{
// 			Name:  "Multiple",
// 			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P4},
// 			Calls: []call{
// 				{
// 					P1: testdata.P1,
// 					P2: testdata.P4,
// 					MF: mAll,
// 					ID: &model.IsDependencyInputSpec{
// 						Justification: "test justification",
// 					},
// 				},
// 				{
// 					P1: testdata.P2,
// 					P2: testdata.P4,
// 					MF: mAll,
// 					ID: &model.IsDependencyInputSpec{
// 						Justification: "test justification",
// 					},
// 				},
// 			},
// 			ExpNeighbors: map[string][]string{
// 				"3":  []string{"1", "1", "1"},        // testdata.P1/testdata.P2 name, 1 up, 2 down
// 				"4":  []string{"1", "10"},            // testdata.P1 version, 1 up, isdep
// 				"5":  []string{"1", "11"},            // testdata.P2 version, 1 up, isdep
// 				"8":  []string{"6", "6", "10", "11"}, // testdata.P4 name, 1 up, 1 down, 2 isdeps
// 				"10": []string{"1", "6"},             // isdep 1
// 				"11": []string{"1", "6"},             // isdep 2
// 			},
// 		},
// 	}
// 	ctx := context.Background()
// 	for _, test := range tests {
// 		t.Run(test.Name, func(t *testing.T) {
// 			b, err := inmem.getBackend(nil)
// 			if err != nil {
// 				t.Fatalf("Could not instantiate testing backend: %v", err)
// 			}
// 			for _, a := range test.InPkg {
// 				if _, err := b.IngestPackage(ctx, *a); err != nil {
// 					t.Fatalf("Could not ingest pkg: %v", err)
// 				}
// 			}
// 			for _, o := range test.Calls {
// 				if _, err := b.IngestDependency(ctx, *o.P1, *o.P2, o.MF, *o.ID); err != nil {
// 					t.Fatalf("Could not ingest IsDependency: %v", err)
// 				}
// 			}
// 			for q, r := range test.ExpNeighbors {
// 				got, err := b.Neighbors(ctx, q, nil)
// 				if err != nil {
// 					t.Fatalf("Could not query neighbors: %s", err)
// 				}
// 				gotIDs := convNodes(got)
// 				slices.Sort(r)
// 				slices.Sort(gotIDs)
// 				if diff := cmp.Diff(r, gotIDs); diff != "" {
// 					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
// 				}
// 			}
// 		})
// 	}
// }
