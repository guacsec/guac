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
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/inmem"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"golang.org/x/exp/slices"
)

func TestHasSourceAt(t *testing.T) {
	testTime := time.Unix(1e9+5, 0)
	type call struct {
		Pkg   *model.PkgInputSpec
		Src   *model.SourceInputSpec
		Match *model.MatchFlags
		HSA   *model.HasSourceAtInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		Calls        []call
		Query        *model.HasSourceAtSpec
		ExpHSA       []*model.HasSourceAt
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{p1},
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:       p1out,
					Source:        s1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "HappyPath All Versions",
			InPkg: []*model.PkgInputSpec{p1},
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:       p1outName,
					Source:        s1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest Same Twice",
			InPkg: []*model.PkgInputSpec{p1},
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification",
					},
				},
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:       p1out,
					Source:        s1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query On Justification",
			InPkg: []*model.PkgInputSpec{p1},
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification one",
					},
				},
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification two",
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Justification: ptrfrom.String("test justification two"),
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:       p1out,
					Source:        s1out,
					Justification: "test justification two",
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{p1, p2},
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
				{
					Pkg: p2,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			Query: &model.HasSourceAtSpec{
				Package: &model.PkgSpec{
					Version: ptrfrom.String("2.11.1"),
				},
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package: p2out,
					Source:  s1out,
				},
			},
		},
		{
			Name:  "Query on Source",
			InPkg: []*model.PkgInputSpec{p1},
			InSrc: []*model.SourceInputSpec{s1, s2},
			Calls: []call{
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
				{
					Pkg: p1,
					Src: s2,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			Query: &model.HasSourceAtSpec{
				Source: &model.SourceSpec{
					Name: ptrfrom.String("myrepo"),
				},
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package: p1out,
					Source:  s1out,
				},
			},
		},
		{
			Name:  "Query on KnownSince",
			InPkg: []*model.PkgInputSpec{p1},
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						KnownSince: time.Unix(1e9, 0),
					},
				},
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						KnownSince: testTime,
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				KnownSince: &testTime,
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:    p1out,
					Source:     s1out,
					KnownSince: testTime,
				},
			},
		},
		{
			Name:  "Query Multiple",
			InPkg: []*model.PkgInputSpec{p1, p2},
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification one",
					},
				},
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification two",
					},
				},
				{
					Pkg: p2,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification two",
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Justification: ptrfrom.String("test justification two"),
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:       p1out,
					Source:        s1out,
					Justification: "test justification two",
				},
				{
					Package:       p2out,
					Source:        s1out,
					Justification: "test justification two",
				},
			},
		},
		{
			Name:  "Query None",
			InPkg: []*model.PkgInputSpec{p1},
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification one",
					},
				},
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification two",
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Justification: ptrfrom.String("test justification three"),
			},
			ExpHSA: nil,
		},
		{
			Name:  "Query ID",
			InPkg: []*model.PkgInputSpec{p1},
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification one",
					},
				},
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification two",
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				ID: ptrfrom.String("10"),
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:       p1out,
					Source:        s1out,
					Justification: "test justification two",
				},
			},
		},
		{
			Name:  "Query Name and Version",
			InPkg: []*model.PkgInputSpec{p1, p2},
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
				{
					Pkg: p2,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			Query: &model.HasSourceAtSpec{
				Package: &model.PkgSpec{
					Version: ptrfrom.String(""),
				},
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package: p1out,
					Source:  s1out,
				},
				{
					Package: p1outName,
					Source:  s1out,
				},
			},
		},
		{
			Name:  "Ingest no pkg",
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Ingest no src",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Query bad ID",
			InPkg: []*model.PkgInputSpec{p1},
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			Query: &model.HasSourceAtSpec{
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
			b, err := inmem.GetBackend(nil)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, s := range test.InSrc {
				if _, err := b.IngestSource(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, o := range test.Calls {
				_, err := b.IngestHasSourceAt(ctx, *o.Pkg, *o.Match, *o.Src, *o.HSA)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.HasSourceAt(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpHSA, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHasSourceAtNeighbors(t *testing.T) {
	type call struct {
		Pkg   *model.PkgInputSpec
		Src   *model.SourceInputSpec
		Match *model.MatchFlags
		HSA   *model.HasSourceAtInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		Calls        []call
		ExpNeighbors map[string][]string
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{p1},
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpNeighbors: map[string][]string{
				"5": []string{"2", "9"}, // Package Version
				"8": []string{"6", "9"}, // Source Name
				"9": []string{"2", "6"}, // HSA
			},
		},
		{
			Name:  "Package Name and Version",
			InPkg: []*model.PkgInputSpec{p1},
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSA: &model.HasSourceAtInputSpec{
						Justification: "test justification",
					},
				},
				{
					Pkg: p1,
					Src: s1,
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					HSA: &model.HasSourceAtInputSpec{},
				},
			},
			ExpNeighbors: map[string][]string{
				"4":  []string{"2", "2", "10"}, // Package Name
				"5":  []string{"2", "9"},       // Package Version
				"8":  []string{"6", "9", "10"}, // Source Name
				"9":  []string{"2", "6"},       // HSA -> Version
				"10": []string{"2", "6"},       // HSA -> Name
			},
		},
	}
	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b, err := inmem.GetBackend(nil)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, s := range test.InSrc {
				if _, err := b.IngestSource(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, o := range test.Calls {
				if _, err := b.IngestHasSourceAt(ctx, *o.Pkg, *o.Match, *o.Src, *o.HSA); err != nil {
					t.Fatalf("Could not ingest HasSourceAt: %v", err)
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
