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

package keyvalue_test

import (
	"context"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/stablememmap"
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

var (
	mAll      = model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}
	mSpecific = model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}
)

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
			store := stablememmap.GetStore()
			b, err := backends.Get("keyvalue", nil, store)
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
