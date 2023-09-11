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

package backend

import (
	"encoding/json"
	"strconv"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"golang.org/x/exp/slices"
)

func (s *Suite) TestPkgEqual() {
	type call struct {
		P1       *model.PkgInputSpec
		P2       *model.PkgInputSpec
		PkgEqual *model.PkgEqualInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		Calls        []call
		Query        *model.PkgEqualSpec
		ExpPkgEqual  []*model.PkgEqual
		ExpInserts   int
		ExpIngestErr bool
		ExpQueryErr  bool
		Only         bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					PkgEqual: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpPkgEqual: []*model.PkgEqual{
				{
					Packages:      []*model.Package{p1out, p2out},
					Justification: "test justification",
				},
			},
		},
		{
			// Only:       true,
			Name:       "Ingest same, different order",
			InPkg:      []*model.PkgInputSpec{p1, p2},
			ExpInserts: 1,
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					PkgEqual: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1: p2,
					P2: p1,
					PkgEqual: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpPkgEqual: []*model.PkgEqual{
				{
					Packages:      []*model.Package{p1out, p2out},
					Justification: "test justification",
				},
			},
		},
		{
			Name: "Query on Justification",
			// Only:       true,
			InPkg:      []*model.PkgInputSpec{p1, p2},
			ExpInserts: 2,
			Calls: []call{
				{
					P1: p1,
					P2: p2,
					PkgEqual: &model.PkgEqualInputSpec{
						Justification: "test justification one",
					},
				},
				{
					P1: p1,
					P2: p2,
					PkgEqual: &model.PkgEqualInputSpec{
						Justification: "test justification two",
					},
				},
			},
			Query: &model.PkgEqualSpec{
				Justification: ptrfrom.String("test justification two"),
			},
			ExpPkgEqual: []*model.PkgEqual{
				{
					Packages:      []*model.Package{p1out, p2out},
					Justification: "test justification two",
				},
			},
		},
		{
			Name:  "Query on pkg",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1:       p1,
					P2:       p2,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
				{
					P1:       p1,
					P2:       p3,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{{
					ID: ptrfrom.String("2"), // index of p3
				}},
			},
			ExpPkgEqual: []*model.PkgEqual{
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
					P1:       p1,
					P2:       p2,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
				{
					P1:       p1,
					P2:       p3,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{{
					ID: ptrfrom.String("0"),
				}},
			},
			ExpPkgEqual: []*model.PkgEqual{
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
					P1:       p1,
					P2:       p2,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
				{
					P1:       p1,
					P2:       p3,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{{
					Version: ptrfrom.String("2.11.1"),
					Subpath: ptrfrom.String(""),
				}},
			},
			ExpPkgEqual: []*model.PkgEqual{
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
					PkgEqual: &model.PkgEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					P1:       p1,
					P2:       p3,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{{
					Type:      ptrfrom.String("pypi"),
					Namespace: ptrfrom.String(""),
					Name:      ptrfrom.String("tensorflow"),
					Version:   ptrfrom.String("2.11.1"),
					Subpath:   ptrfrom.String(""),
				}},
			},
			ExpPkgEqual: []*model.PkgEqual{
				{
					Justification: "test justification",
					Packages:      []*model.Package{p1out, p2out},
				},
			},
		},
		{
			// Only:  true,
			Name:  "Query on both pkgs",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1:       p1,
					P2:       p2,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
				{
					P1:       p2,
					P2:       p3,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{
					{
						Subpath: ptrfrom.String("saved_model_cli.py"),
					},
					{
						ID: ptrfrom.String("1"),
					},
				},
			},
			ExpPkgEqual: []*model.PkgEqual{
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
					P1:       p1,
					P2:       p2,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
				{
					P1:       p2,
					P2:       p3,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
				{
					P1:       p1,
					P2:       p3,
					PkgEqual: &model.PkgEqualInputSpec{},
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
			ExpPkgEqual: []*model.PkgEqual{
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
					P1:       p1,
					P2:       p2,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
				{
					P1:       p2,
					P2:       p3,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
				{
					P1:       p1,
					P2:       p3,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
			},
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{
					{
						Version: ptrfrom.String("1.2.3"),
					},
				},
			},
			ExpPkgEqual: nil,
		},
		{
			Name:  "Query on ID",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1:       p1,
					P2:       p2,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
				{
					P1:       p2,
					P2:       p3,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
				{
					P1:       p1,
					P2:       p3,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
			},
			Query: &model.PkgEqualSpec{
				ID: ptrfrom.String("1"),
			},
			ExpPkgEqual: []*model.PkgEqual{
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
					P1:       p1,
					P2:       p2,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Ingest no P2",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					P1:       p1,
					P2:       p2,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		// {
		// 	Name:  "Query three",
		// 	InPkg: []*model.PkgInputSpec{p1, p2, p3},
		// 	Calls: []call{
		// 		{
		// 			P1:       p1,
		// 			P2:       p2,
		// 			PkgEqual: &model.PkgEqualInputSpec{},
		// 		},
		// 		{
		// 			P1:       p2,
		// 			P2:       p3,
		// 			PkgEqual: &model.PkgEqualInputSpec{},
		// 		},
		// 		{
		// 			P1:       p1,
		// 			P2:       p3,
		// 			PkgEqual: &model.PkgEqualInputSpec{},
		// 		},
		// 	},
		// 	Query: &model.PkgEqualSpec{
		// 		Packages: []*model.PkgSpec{
		// 			{
		// 				Name: ptrfrom.String("somename"),
		// 			},
		// 			{
		// 				Version: ptrfrom.String("1.2.3"),
		// 			},
		// 			{
		// 				Type: ptrfrom.String("asdf"),
		// 			},
		// 		},
		// 	},
		// 	ExpQueryErr: true,
		// },
		{
			Name:  "Query bad ID",
			InPkg: []*model.PkgInputSpec{p1, p2, p3},
			Calls: []call{
				{
					P1:       p1,
					P2:       p2,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
				{
					P1:       p2,
					P2:       p3,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
				{
					P1:       p1,
					P2:       p3,
					PkgEqual: &model.PkgEqualInputSpec{},
				},
			},
			Query: &model.PkgEqualSpec{
				ID: ptrfrom.String("asdf"),
			},
			ExpQueryErr: true,
		},
	}

	ctx := s.Ctx
	hasOnly := false
	for _, t := range tests {
		if t.Only {
			hasOnly = true
			break
		}
	}

	for _, test := range tests {
		if hasOnly && !test.Only {
			continue
		}
		s.Run(test.Name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			pkgIDs := make([]string, len(test.InPkg))
			for i, a := range test.InPkg {
				if v, err := b.IngestPackage(ctx, *a); err != nil {
					t.Fatalf("Could not ingest pkg: %v", err)
				} else {
					pkgIDs[i] = v.Namespaces[0].Names[0].Versions[0].ID
				}
			}

			if test.Query != nil {
				for i, pkg := range test.Query.Packages {
					if pkg.ID == nil {
						continue
					}
					idIdx, err := strconv.Atoi(*pkg.ID)
					if err == nil {
						if idIdx >= len(pkgIDs) {
							s.T().Fatalf("ID index out of range, want: %d, got: %d", len(pkgIDs), idIdx)
						}
						test.Query.Packages[i].ID = &pkgIDs[idIdx]
					}
				}
			}

			ids := make([]string, len(test.Calls))
			for i, o := range test.Calls {
				v, err := b.IngestPkgEqual(ctx, *o.P1, *o.P2, *o.PkgEqual)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}

				ids[i] = v.ID
			}
			afterCount := s.Client.PkgEqual.Query().CountX(ctx)

			if test.ExpInserts > 0 {
				if want, got := test.ExpInserts, afterCount; want != got {
					t.Errorf("unexpected number of inserts, want: %d, got: %d", want, got)
				}
			}

			if test.Query != nil && test.Query.ID != nil {
				idIdx, err := strconv.Atoi(*test.Query.ID)
				if err == nil {
					if idIdx >= len(ids) {
						s.T().Fatalf("ID index out of range, want: %d, got: %d", len(ids), idIdx)
					}
					test.Query.ID = &ids[idIdx]
				}
			}

			got, err := b.PkgEqual(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}

			if diff := cmp.Diff(test.ExpPkgEqual, got, ignoreID, ignoreEmptySlices); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func (s *Suite) TestIngestPkgEquals() {
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
					Subpath:   ptrfrom.String(""),
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
	ctx := s.Ctx
	for _, test := range tests {
		s.Run(test.Name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
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

func (s *Suite) TestPkgEqualNeighbors() {
	s.T().Skip()

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
				"5": []string{"2", "7"}, // p1
				"6": []string{"2", "7"}, // p2
				"7": []string{"2", "2"}, // pkgequal
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
				"5": []string{"2", "8", "9"}, // p1
				"6": []string{"2", "8"},      // p2
				"7": []string{"2", "9"},      // p3
				"8": []string{"2", "2"},      // pkgequal 1
				"9": []string{"2", "2"},      // pkgequal 2
			},
		},
	}
	ctx := s.Ctx
	for _, test := range tests {
		s.Run(test.Name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
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

func convNode(n model.Node) hasID {
	// All nodes have a json "id"
	// Only getting top-level id however
	var h hasID
	b, _ := json.Marshal(n)
	_ = json.Unmarshal(b, &h)
	return h
}

func convNodes(ns []model.Node) []string {
	var ids []string
	for _, n := range ns {
		h := convNode(n)
		ids = append(ids, h.ID)
	}
	return ids
}

type hasID struct {
	ID string `json:"id"`
}
