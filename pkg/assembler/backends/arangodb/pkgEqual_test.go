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
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestPkgEqual(t *testing.T) {
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
		{
			Name:  "Query bad ID",
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
				ID: ptrfrom.String("asdf"),
			},
			ExpQueryErr: true,
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
				found, err := b.IngestPkgEqual(ctx, *o.P1, *o.P2, *o.HE)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.PkgEqualSpec{
						ID: ptrfrom.String(found.ID),
					}
				}
				if test.QueryPkgID {
					test.Query = &model.PkgEqualSpec{
						Packages: []*model.PkgSpec{{
							ID: ptrfrom.String(found.Packages[0].Namespaces[0].Names[0].Versions[0].ID),
						}},
					}
				}
				if test.QuerySecondaryPkgID {
					test.Query = &model.PkgEqualSpec{
						Packages: []*model.PkgSpec{
							{
								ID: ptrfrom.String(found.Packages[0].Namespaces[0].Names[0].Versions[0].ID),
							},
							{
								ID: ptrfrom.String(found.Packages[1].Namespaces[0].Names[0].Versions[0].ID),
							},
						},
					}
				}
			}
			got, err := b.PkgEqual(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpHE, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestPkgEquals(t *testing.T) {
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
		P1 []*model.PkgInputSpec
		P2 []*model.PkgInputSpec
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
					P1: []*model.PkgInputSpec{testdata.P1, testdata.P1},
					P2: []*model.PkgInputSpec{testdata.P2, testdata.P2},
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
					P1: []*model.PkgInputSpec{testdata.P1, testdata.P2},
					P2: []*model.PkgInputSpec{testdata.P2, testdata.P1},
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
					P1: []*model.PkgInputSpec{testdata.P1, testdata.P1},
					P2: []*model.PkgInputSpec{testdata.P2, testdata.P3},
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
					P1: []*model.PkgInputSpec{testdata.P1, testdata.P1},
					P2: []*model.PkgInputSpec{testdata.P2, testdata.P3},
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
					P1: []*model.PkgInputSpec{testdata.P1, testdata.P1},
					P2: []*model.PkgInputSpec{testdata.P2, testdata.P3},
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
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if _, err := b.IngestPackages(ctx, test.InPkg); err != nil {
				t.Fatalf("Could not ingest pkg: %v", err)
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
			if diff := cmp.Diff(test.ExpHE, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func pkg(typ, namespace, name, version, subpath string, qualifiers map[string]string) *model.PkgInputSpec {
	var pQualifiers []*model.PackageQualifierInputSpec
	for k, v := range qualifiers {
		pQualifiers = append(pQualifiers, &model.PackageQualifierInputSpec{
			Key:   k,
			Value: v,
		})
	}

	p := &model.PkgInputSpec{
		Type:       typ,
		Namespace:  &namespace,
		Name:       name,
		Version:    &version,
		Subpath:    &subpath,
		Qualifiers: pQualifiers,
	}

	return p
}

func TestPkgInputSpecToPurl(t *testing.T) {
	testCases := []struct {
		expectedPurlUri string
		input           *model.PkgInputSpec
	}{
		{
			// alpine
			expectedPurlUri: "pkg:alpm/arch/pacman@6.0.1-1?arch=x86_64",
			input: pkg("alpm", "arch", "pacman", "6.0.1-1", "", map[string]string{
				"arch": "x86_64",
			}),
		}, {
			expectedPurlUri: "pkg:apk/alpine/curl@7.83.0-r0?arch=x86",
			input: pkg("apk", "alpine", "curl", "7.83.0-r0", "", map[string]string{
				"arch": "x86",
			}),
		}, {
			expectedPurlUri: "pkg:bitbucket/birkenfeld/pygments-main@244fd47e07d1014f0aed9c",
			input:           pkg("bitbucket", "birkenfeld", "pygments-main", "244fd47e07d1014f0aed9c", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:cocoapods/ShareKit@2.0#Twitter",
			input:           pkg("cocoapods", "", "ShareKit", "2.0", "Twitter", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:cargo/rand@0.7.2",
			input:           pkg("cargo", "", "rand", "0.7.2", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:composer/laravel/laravel@5.5.0",
			input:           pkg("composer", "laravel", "laravel", "5.5.0", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:conan/openssl.org/openssl@3.0.3?channel=stable&user=bincrafters",
			input: pkg("conan", "openssl.org", "openssl", "3.0.3", "", map[string]string{
				"user":    "bincrafters",
				"channel": "stable",
			}),
		}, {
			expectedPurlUri: "pkg:conda/absl-py@0.4.1?build=py36h06a4308_0&channel=main&subdir=linux-64&type=tar.bz2",
			input: pkg("conda", "", "absl-py", "0.4.1", "", map[string]string{
				"build":   "py36h06a4308_0",
				"channel": "main",
				"subdir":  "linux-64",
				"type":    "tar.bz2",
			}),
		}, {
			expectedPurlUri: "pkg:cran/A3@1.0.0",
			input:           pkg("cran", "", "A3", "1.0.0", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:deb/debian/dpkg@1.19.0.4?arch=amd64&distro=stretch",
			input: pkg("deb", "debian", "dpkg", "1.19.0.4", "", map[string]string{
				"arch":   "amd64",
				"distro": "stretch",
			}),
		}, {
			// The following are for docker PURLs
			expectedPurlUri: "pkg:docker/dockerimage@sha256%3A244fd47e07d10?repository_url=gcr.io%2Fcustomer",
			input:           pkg("docker", "gcr.io/customer", "dockerimage", "sha256:244fd47e07d10", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:docker/debian@dc437cc87d10?repository_url=smartentry",
			input:           pkg("docker", "smartentry", "debian", "dc437cc87d10", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:docker/cassandra@latest",
			input:           pkg("docker", "", "cassandra", "latest", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:gem/ruby-advisory-db-check@0.12.4",
			input:           pkg("gem", "", "ruby-advisory-db-check", "0.12.4", "", map[string]string{}),
		}, {
			// TODO (Issue #635): url path escapes here? Will this be an issue when searching via purl in osv or deps.dev?
			expectedPurlUri: "pkg:generic/openssl@1.1.10g?checksum=sha256%3Ade4d501267da&download_url=https%3A%2F%2Fopenssl.org%2Fsource%2Fopenssl-1.1.0g.tar.gz",
			input: pkg("generic", "", "openssl", "1.1.10g", "", map[string]string{
				"download_url": "https://openssl.org/source/openssl-1.1.0g.tar.gz",
				"checksum":     "sha256:de4d501267da",
			}),
		}, {
			expectedPurlUri: "pkg:generic/bitwarderl?vcs_url=git%2Bhttps%3A%2F%2Fgit.fsfe.org%2Fdxtr%2Fbitwarderl%40cc55108da32",
			input: pkg("generic", "", "bitwarderl", "", "", map[string]string{
				"vcs_url": "git+https://git.fsfe.org/dxtr/bitwarderl@cc55108da32",
			}),
		}, {
			expectedPurlUri: "pkg:github/package-url/purl-spec@244fd47e07d1004#everybody/loves/dogs",
			input:           pkg("github", "package-url", "purl-spec", "244fd47e07d1004", "everybody/loves/dogs", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:golang/github.com/gorilla/context@234fd47e07d1004f0aed9c#api",
			input:           pkg("golang", "github.com/gorilla", "context", "234fd47e07d1004f0aed9c", "api", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:hackage/3d-graphics-examples@0.0.0.2",
			input:           pkg("hackage", "", "3d-graphics-examples", "0.0.0.2", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:hex/bar@1.2.3?repository_url=https%3A%2F%2Fmyrepo.example.com",
			input: pkg("hex", "", "bar", "1.2.3", "", map[string]string{
				"repository_url": "https://myrepo.example.com",
			}),
		}, {
			expectedPurlUri: "pkg:hex/jason@1.1.2",
			input:           pkg("hex", "", "jason", "1.1.2", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:huggingface/distilbert-base-uncased@043235d6088ecd3dd5fb5ca3592b6913fd516027",
			input:           pkg("huggingface", "", "distilbert-base-uncased", "043235d6088ecd3dd5fb5ca3592b6913fd516027", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?classifier=dist&type=zip",
			input: pkg("maven", "org.apache.xmlgraphics", "batik-anim", "1.9.1", "", map[string]string{
				"type":       "zip",
				"classifier": "dist",
			}),
		}, {
			expectedPurlUri: "pkg:mlflow/trafficsigns@10?model_uuid=36233173b22f4c89b451f1228d700d49&repository_url=https%3A%2F%2Fadb-5245952564735461.0.azuredatabricks.net%2Fapi%2F2.0%2Fmlflow&run_id=410a3121-2709-4f88-98dd-dba0ef056b0a",
			input: pkg("mlflow", "", "trafficsigns", "10", "", map[string]string{
				"model_uuid":     "36233173b22f4c89b451f1228d700d49",
				"run_id":         "410a3121-2709-4f88-98dd-dba0ef056b0a",
				"repository_url": "https://adb-5245952564735461.0.azuredatabricks.net/api/2.0/mlflow",
			}),
		}, {
			expectedPurlUri: "pkg:npm/foobar@12.3.1",
			input:           pkg("npm", "", "foobar", "12.3.1", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:npm/%40angular/animation@12.3.1",
			input:           pkg("npm", "@angular", "animation", "12.3.1", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:nuget/EnterpriseLibrary.Common@6.0.1304",
			input:           pkg("nuget", "", "EnterpriseLibrary.Common", "6.0.1304", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:qpkg/blackberry/com.qnx.sdp@7.0.0.SGA201702151847",
			input:           pkg("qpkg", "blackberry", "com.qnx.sdp", "7.0.0.SGA201702151847", "", map[string]string{}),
		}, {
			// Special OCI case
			expectedPurlUri: "pkg:oci/debian@sha256%3A244fd47e07d10?arch=amd64&repository_url=docker.io%2Flibrary&tag=latest",
			input: pkg("oci", "docker.io/library", "debian", "sha256:244fd47e07d10", "", map[string]string{
				"arch": "amd64",
				"tag":  "latest",
			}),
		}, {
			expectedPurlUri: "pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=ghcr.io&tag=bullseye",
			input: pkg("oci", "ghcr.io", "debian", "sha256:244fd47e07d10", "", map[string]string{
				"tag": "bullseye",
			}),
		}, {
			expectedPurlUri: "pkg:oci/hello-wasm@sha256%3A244fd47e07d10?tag=v1",
			input: pkg("oci", "", "hello-wasm", "sha256:244fd47e07d10", "", map[string]string{
				"tag": "v1",
			}),
		}, {
			expectedPurlUri: "pkg:pub/characters@1.2.0",
			input:           pkg("pub", "", "characters", "1.2.0", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:pypi/django-allauth@12.23",
			input:           pkg("pypi", "", "django-allauth", "12.23", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
			input: pkg("rpm", "fedora", "curl", "7.50.3-1.fc25", "", map[string]string{
				"arch":   "i386",
				"distro": "fedora-25",
			}),
		}, {
			expectedPurlUri: "pkg:swid/Acme/example.com/Enterprise%2BServer@1.0.0?tag_id=75b8c285-fa7b-485b-b199-4745e3004d0d",
			input: pkg("swid", "Acme/example.com", "Enterprise+Server", "1.0.0", "", map[string]string{
				"tag_id": "75b8c285-fa7b-485b-b199-4745e3004d0d",
			}),
		}, {
			expectedPurlUri: "pkg:swift/github.com/RxSwiftCommunity/RxFlow@2.12.4",
			input:           pkg("swift", "github.com/RxSwiftCommunity", "RxFlow", "2.12.4", "", map[string]string{}),
		},
	}
	for _, tt := range testCases {
		t.Run(fmt.Sprintf("processing %v", tt.expectedPurlUri), func(t *testing.T) {
			got := pkgInputSpecToPurl(tt.input)
			if got != tt.expectedPurlUri {
				t.Errorf("purl mismatch wanted: %s, got: %s", tt.expectedPurlUri, got)
				return
			}
		})
	}
}

func Test_buildPkgEqualByID(t *testing.T) {
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
		HE *model.PkgEqualInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		Calls        []call
		Query        *model.PkgEqualSpec
		ExpHE        *model.PkgEqual
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "Query on pkg ID",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification two",
					},
				},
			},
			ExpHE: &model.PkgEqual{
				Packages:      []*model.Package{testdata.P1out, testdata.P2out},
				Justification: "test justification two",
			},
		},
		{
			Name:  "Query on ID",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P3},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P3,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpHE: &model.PkgEqual{
				Packages:      []*model.Package{testdata.P1out, testdata.P3out},
				Justification: "test justification",
			},
		},
		{
			Name:  "Query bad ID",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P3},
			Calls: []call{
				{
					P1: testdata.P1,
					P2: testdata.P3,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PkgEqualSpec{
				ID: ptrfrom.String("asdf"),
			},
			ExpQueryErr: true,
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
				found, err := b.IngestPkgEqual(ctx, *o.P1, *o.P2, *o.HE)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				got, err := b.(*arangoClient).buildPkgEqualByID(ctx, found.ID, test.Query)
				if (err != nil) != test.ExpQueryErr {
					t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
				}
				if err != nil {
					return
				}
				if diff := cmp.Diff(test.ExpHE, got, ignoreID); diff != "" {
					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
				}
			}

		})
	}
}

// TODO (pxp928): add tests back in when implemented

// func TestPkgEqualNeighbors(t *testing.T) {
// 	type call struct {
// 		P1 *model.PkgInputSpec
// 		P2 *model.PkgInputSpec
// 		HE *model.PkgEqualInputSpec
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
// 					HE: &model.PkgEqualInputSpec{
// 						Justification: "test justification",
// 					},
// 				},
// 			},
// 			ExpNeighbors: map[string][]string{
// 				"4": []string{"1", "6"}, // testdata.P1
// 				"5": []string{"1", "6"}, // testdata.P2
// 				"6": []string{"1", "1"}, // pkgequal
// 			},
// 		},
// 		{
// 			Name:  "Multiple",
// 			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P3},
// 			Calls: []call{
// 				{
// 					P1: testdata.P1,
// 					P2: testdata.P2,
// 					HE: &model.PkgEqualInputSpec{
// 						Justification: "test justification",
// 					},
// 				},
// 				{
// 					P1: testdata.P1,
// 					P2: testdata.P3,
// 					HE: &model.PkgEqualInputSpec{
// 						Justification: "test justification",
// 					},
// 				},
// 			},
// 			ExpNeighbors: map[string][]string{
// 				"4": []string{"1", "7", "8"}, // testdata.P1
// 				"5": []string{"1", "7"},      // testdata.P2
// 				"6": []string{"1", "8"},      // testdata.P3
// 				"7": []string{"1", "1"},      // pkgequal 1
// 				"8": []string{"1", "1"},      // pkgequal 2
// 			},
// 		},
// 	}
// 	ctx := context.Background()
// 	for _, test := range tests {
// 		t.Run(test.Name, func(t *testing.T) {
// 			b, err := backends.Get("inmem", nil, nil)
// 			if err != nil {
// 				t.Fatalf("Could not instantiate testing backend: %v", err)
// 			}
// 			for _, a := range test.InPkg {
// 				if _, err := b.IngestPackage(ctx, *a); err != nil {
// 					t.Fatalf("Could not ingest pkg: %v", err)
// 				}
// 			}
// 			for _, o := range test.Calls {
// 				if _, err := b.IngestPkgEqual(ctx, *o.P1, *o.P2, *o.HE); err != nil {
// 					t.Fatalf("Could not ingest PkgEqual: %v", err)
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
