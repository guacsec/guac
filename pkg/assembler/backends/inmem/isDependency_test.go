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
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

var (
	mAll      = model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}
	mSpecific = model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}
)

func TestIsDependency(t *testing.T) {
	type call struct {
		P1 *model.PkgInputSpec
		P2 *model.PkgInputSpec
		MF model.MatchFlags
		ID *model.IsDependencyInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		Calls        []call
		Query        *model.IsDependencySpec
		ExpID        []*model.IsDependency
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
					Package:           p1out,
					DependencyPackage: p2outName,
					Justification:     "test justification",
				},
			},
		},
		{
			Name:  "Ingest same",
			InPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: p1,
					P2: p2,
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
					Package:           p1out,
					DependencyPackage: p2outName,
					Justification:     "test justification",
				},
			},
		},
		{
			Name:  "Ingest same, different version",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: p1,
					P2: p3,
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
					Package:           p1out,
					DependencyPackage: p2outName,
					Justification:     "test justification",
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
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification one",
					},
				},
				{
					P1: p1,
					P2: p2,
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
					Package:           p1out,
					DependencyPackage: p2outName,
					Justification:     "test justification one",
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
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p2,
					P2: p3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				Package: &model.PkgSpec{
					ID: ptrfrom.String("4"),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p1out,
					DependencyPackage: p2outName,
				},
			},
		},
		{
			Name:  "Query on dep pkg",
			InPkg: []*model.PkgInputSpec{p1, p2, p4},
			Calls: []call{
				{
					P1: p2,
					P2: p4,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p2,
					P2: p1,
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
					Package:           p2out,
					DependencyPackage: p4outName,
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
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p3,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				Package: &model.PkgSpec{
					Type: ptrfrom.String("pypi"),
				},
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p1out,
					DependencyPackage: p1outName,
				},
				{
					Package:           p3out,
					DependencyPackage: p1outName,
				},
			},
		},
		{
			Name:  "Query on both pkgs",
			InPkg: []*model.PkgInputSpec{p1, p2, p3, p4},
			Calls: []call{
				{
					P1: p2,
					P2: p1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p3,
					P2: p4,
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
					Package:           p3out,
					DependencyPackage: p4outName,
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
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p2,
					P2: p3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p1,
					P2: p3,
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
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p2,
					P2: p3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p1,
					P2: p3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				ID: ptrfrom.String("8"),
			},
			ExpID: []*model.IsDependency{
				{
					Package:           p2out,
					DependencyPackage: p1outName,
				},
			},
		},
		{
			Name:  "Query on Range",
			InPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: p1,
					P2: p1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						VersionRange: "1-3",
					},
				},
				{
					P1: p2,
					P2: p1,
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
					Package:           p1out,
					DependencyPackage: p1outName,
					VersionRange:      "1-3",
				},
			},
		},
		{
			Name:  "Query on DependencyType",
			InPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: p1,
					P2: p1,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						DependencyType: model.DependencyTypeDirect,
					},
				},
				{
					P1: p2,
					P2: p1,
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
					Package:           p2out,
					DependencyPackage: p1outName,
					DependencyType:    model.DependencyTypeIndirect,
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
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
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
					P2: p4,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
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
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p2,
					P2: p3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
				{
					P1: p1,
					P2: p3,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			Query: &model.IsDependencySpec{
				ID: ptrfrom.String("asdf"),
			},
			ExpQueryErr: true,
		},
		{
			Name:  "IsDep from version to version",
			InPkg: []*model.PkgInputSpec{p2, p3},
			Calls: []call{
				{
					P1: p3,
					P2: p2,
					MF: mSpecific,
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
					Package:           p3out,
					DependencyPackage: p2out,
					Justification:     "test justification",
				},
			},
		},
		{
			Name:  "IsDep from version to name",
			InPkg: []*model.PkgInputSpec{p2, p3},
			Calls: []call{
				{
					P1: p3,
					P2: p2,
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
					Package:           p3out,
					DependencyPackage: p2outName,
					Justification:     "test justification",
				},
			},
		},
		{
			Name:  "IsDep from version to name and version",
			InPkg: []*model.PkgInputSpec{p2, p3},
			Calls: []call{
				{
					P1: p3,
					P2: p2,
					MF: mSpecific,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: p3,
					P2: p2,
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
					Package:           p3out,
					DependencyPackage: p2out,
					Justification:     "test justification",
				},
				{
					Package:           p3out,
					DependencyPackage: p2outName,
					Justification:     "test justification",
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
			for _, a := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *a); err != nil {
					t.Fatalf("Could not ingest pkg: %v", err)
				}
			}
			for _, o := range test.Calls {
				_, err := b.IngestDependency(ctx, *o.P1, *o.P2, o.MF, *o.ID)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.IsDependency(ctx, test.Query)
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
			// for _, he := range test.ExpID {
			// 	slices.SortFunc(he.Packages, less)
			// }
			if diff := cmp.Diff(test.ExpID, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIsDependencies(t *testing.T) {
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
			InPkg: []*model.PkgInputSpec{p1, p2, p3, p4},
			Calls: []call{{
				P1s: []*model.PkgInputSpec{p1, p2},
				P2s: []*model.PkgInputSpec{p2, p4},
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
					Package:           p1out,
					DependencyPackage: p2outName,
					Justification:     "test justification",
				},
				{
					Package:           p2out,
					DependencyPackage: p4outName,
					Justification:     "test justification",
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

func TestIsDependencyNeighbors(t *testing.T) {
	type call struct {
		P1 *model.PkgInputSpec
		P2 *model.PkgInputSpec
		MF model.MatchFlags
		ID *model.IsDependencyInputSpec
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
					MF: mAll,
					ID: &model.IsDependencyInputSpec{},
				},
			},
			ExpNeighbors: map[string][]string{
				"3": {"1", "1", "1", "6"}, // p1/p2 name
				"4": {"1", "6"},           // p1 version
				"5": {"1"},                // p2 version
				"6": {"1", "1"},           // isDep
			},
		},
		{
			Name:  "Multiple",
			InPkg: []*model.PkgInputSpec{p1, p2, p4},
			Calls: []call{
				{
					P1: p1,
					P2: p4,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: p2,
					P2: p4,
					MF: mAll,
					ID: &model.IsDependencyInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpNeighbors: map[string][]string{
				"3":  {"1", "1", "1"},        // p1/p2 name, 1 up, 2 down
				"4":  {"1", "10"},            // p1 version, 1 up, isdep
				"5":  {"1", "11"},            // p2 version, 1 up, isdep
				"8":  {"6", "6", "10", "11"}, // p4 name, 1 up, 1 down, 2 isdeps
				"10": {"1", "6"},             // isdep 1
				"11": {"1", "6"},             // isdep 2
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
				if _, err := b.IngestDependency(ctx, *o.P1, *o.P2, o.MF, *o.ID); err != nil {
					t.Fatalf("Could not ingest IsDependency: %v", err)
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
