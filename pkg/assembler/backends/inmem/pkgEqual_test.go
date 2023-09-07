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

package inmem_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"golang.org/x/exp/slices"
)

func TestPkgEqual(t *testing.T) {
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
		ExpHE        []*model.PkgEqual
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
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
					Packages:      []*model.Package{p1out, p2out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest same, different order",
			InPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: p2,
					P2: p1,
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
					Packages:      []*model.Package{p1out, p2out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Justification",
			InPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification one",
					},
				},
				{
					P1: p1,
					P2: p2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification two",
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Justification: ptrfrom.String("test justification one"),
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{p1out, p2out},
					Justification: "test justification one",
				},
			},
		},
		{
			Name:  "Query on pkg",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					HE: &model.PkgEqualInputSpec{},
				},
				{
					P1: p1,
					P2: p3,
					HE: &model.PkgEqualInputSpec{},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{{
					ID: ptrfrom.String("6"),
				}},
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages: []*model.Package{p1out, p3out},
				},
			},
		},
		{
			Name:  "Query on pkg multiple",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					HE: &model.PkgEqualInputSpec{},
				},
				{
					P1: p1,
					P2: p3,
					HE: &model.PkgEqualInputSpec{},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{{
					ID: ptrfrom.String("4"),
				}},
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages: []*model.Package{p1out, p2out},
				},
				{
					Packages: []*model.Package{p1out, p3out},
				},
			},
		},
		{
			Name:  "Query on pkg details",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					HE: &model.PkgEqualInputSpec{},
				},
				{
					P1: p1,
					P2: p3,
					HE: &model.PkgEqualInputSpec{},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{{
					Version: ptrfrom.String("2.11.1"),
					Subpath: ptrfrom.String(""),
				}},
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages: []*model.Package{p1out, p2out},
				},
			},
		},
		{
			Name:  "Query on pkg algo and pkg",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					HE: &model.PkgEqualInputSpec{},
				},
				{
					P1: p1,
					P2: p3,
					HE: &model.PkgEqualInputSpec{},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{{
					Type:      ptrfrom.String("pypi"),
					Namespace: ptrfrom.String(""),
					Name:      ptrfrom.String("tensorflow"),
					Version:   ptrfrom.String("2.11.1"),
				}},
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages: []*model.Package{p1out, p2out},
				},
			},
		},
		{
			Name:  "Query on both pkgs",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					HE: &model.PkgEqualInputSpec{},
				},
				{
					P1: p2,
					P2: p3,
					HE: &model.PkgEqualInputSpec{},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{
					{
						Subpath: ptrfrom.String("saved_model_cli.py"),
					},
					{
						ID: ptrfrom.String("6"),
					},
				},
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages: []*model.Package{p2out, p3out},
				},
			},
		},
		{
			Name:  "Query on both pkgs, one filter",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					HE: &model.PkgEqualInputSpec{},
				},
				{
					P1: p2,
					P2: p3,
					HE: &model.PkgEqualInputSpec{},
				},
				{
					P1: p1,
					P2: p3,
					HE: &model.PkgEqualInputSpec{},
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
					Packages: []*model.Package{p1out, p3out},
				},
			},
		},
		{
			Name:  "Query none",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					HE: &model.PkgEqualInputSpec{},
				},
				{
					P1: p2,
					P2: p3,
					HE: &model.PkgEqualInputSpec{},
				},
				{
					P1: p1,
					P2: p3,
					HE: &model.PkgEqualInputSpec{},
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
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					HE: &model.PkgEqualInputSpec{},
				},
				{
					P1: p2,
					P2: p3,
					HE: &model.PkgEqualInputSpec{},
				},
				{
					P1: p1,
					P2: p3,
					HE: &model.PkgEqualInputSpec{},
				},
			},
			Query: &model.PkgEqualSpec{
				ID: ptrfrom.String("8"),
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages: []*model.Package{p2out, p3out},
				},
			},
		},
		{
			Name:  "Ingest no P1",
			InPkg: []*model.PkgInputSpec{p2},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					HE: &model.PkgEqualInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Ingest no P2",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					HE: &model.PkgEqualInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Query bad ID",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					HE: &model.PkgEqualInputSpec{},
				},
				{
					P1: p2,
					P2: p3,
					HE: &model.PkgEqualInputSpec{},
				},
				{
					P1: p1,
					P2: p3,
					HE: &model.PkgEqualInputSpec{},
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
	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b, err := backends.Get("inmem", nil, nil)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			for _, a := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *a); err != nil {
					t.Fatalf("Could not ingest pkg: %v", err)
				}
			}
			for _, o := range test.Calls {
				_, err := b.IngestPkgEqual(ctx, *o.P1, *o.P2, *o.HE)
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
			// less := func(a, b *model.Package) bool { return a.Version < b.Version }
			// for _, he := range got {
			// 	slices.SortFunc(he.Packages, less)
			// }
			// for _, he := range test.ExpHE {
			// 	slices.SortFunc(he.Packages, less)
			// }
			if diff := cmp.Diff(test.ExpHE, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestPkgEquals(t *testing.T) {
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
			InPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: []*model.PkgInputSpec{p1, p1},
					P2: []*model.PkgInputSpec{p2, p2},
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
					Packages:      []*model.Package{p1out, p2out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest same, different order",
			InPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: []*model.PkgInputSpec{p1, p2},
					P2: []*model.PkgInputSpec{p2, p1},
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
					Packages:      []*model.Package{p1out, p2out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on pkg details",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: []*model.PkgInputSpec{p1, p1},
					P2: []*model.PkgInputSpec{p2, p3},
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
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{p1out, p2out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on pkg algo and pkg",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: []*model.PkgInputSpec{p1, p1},
					P2: []*model.PkgInputSpec{p2, p3},
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
					Version:   ptrfrom.String("2.11.1"),
				}},
			},
			ExpHE: []*model.PkgEqual{
				{
					Packages:      []*model.Package{p1out, p2out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on both pkgs, one filter",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: []*model.PkgInputSpec{p1, p1},
					P2: []*model.PkgInputSpec{p2, p3},
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
					Packages:      []*model.Package{p1out, p3out},
					Justification: "test justification",
				},
			},
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b, err := backends.Get("inmem", nil, nil)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
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

func TestPkgEqualNeighbors(t *testing.T) {
	type call struct {
		P1 *model.PkgInputSpec
		P2 *model.PkgInputSpec
		HE *model.PkgEqualInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		Calls        []call
		ExpNeighbors map[string][]string
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpNeighbors: map[string][]string{
				"4": []string{"1", "6"}, // p1
				"5": []string{"1", "6"}, // p2
				"6": []string{"1", "1"}, // pkgequal
			},
		},
		{
			Name:  "Multiple",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: p1,
					P2: p3,
					HE: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpNeighbors: map[string][]string{
				"4": []string{"1", "7", "8"}, // p1
				"5": []string{"1", "7"},      // p2
				"6": []string{"1", "8"},      // p3
				"7": []string{"1", "1"},      // pkgequal 1
				"8": []string{"1", "1"},      // pkgequal 2
			},
		},
	}
	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b, err := backends.Get("inmem", nil, nil)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			for _, a := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *a); err != nil {
					t.Fatalf("Could not ingest pkg: %v", err)
				}
			}
			for _, o := range test.Calls {
				if _, err := b.IngestPkgEqual(ctx, *o.P1, *o.P2, *o.HE); err != nil {
					t.Fatalf("Could not ingest PkgEqual: %v", err)
				}
			}
			for q, r := range test.ExpNeighbors {
				got, err := b.Neighbors(ctx, q, nil)
				if err != nil {
					t.Fatalf("Could not query neighbors: %s", err)
				}
				gotIDs := convNodes(got)
				slices.Sort(r)
				slices.Sort(gotIDs)
				if diff := cmp.Diff(r, gotIDs); diff != "" {
					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
				}
			}
		})
	}
}
