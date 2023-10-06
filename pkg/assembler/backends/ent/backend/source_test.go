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
	"strconv"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (s *Suite) TestSources() {
	ctx := s.Ctx
	tests := []struct {
		name       string
		srcInput   []*model.SourceInputSpec
		srcFilter  *model.SourceSpec
		idInFilter bool
		want       []*model.Source
		wantErr    bool
		expInserts int
	}{
		{
			name:     "myrepo with tag",
			srcInput: []*model.SourceInputSpec{s1},
			srcFilter: &model.SourceSpec{
				Name: ptrfrom.String("myrepo"),
			},
			idInFilter: false,
			want:       []*model.Source{s1out},
			wantErr:    false,
			expInserts: 1,
		},
		{
			name:     "myrepo with tag, ID search",
			srcInput: []*model.SourceInputSpec{s1},
			srcFilter: &model.SourceSpec{
				Name: ptrfrom.String("myrepo"),
			},
			idInFilter: true,
			want:       []*model.Source{s1out},
			wantErr:    false,
			expInserts: 1,
		},
		{
			name:     "bobsrepo with commit",
			srcInput: []*model.SourceInputSpec{s2},
			srcFilter: &model.SourceSpec{
				Namespace: ptrfrom.String("github.com/bob"),
				Commit:    ptrfrom.String("5e7c41f"),
			},
			want:       []*model.Source{s2out},
			expInserts: 1,
		},
		{
			name:     "ingest same twice",
			srcInput: []*model.SourceInputSpec{s1, s1},
			srcFilter: &model.SourceSpec{
				Name: ptrfrom.String("myrepo"),
			},
			want:       []*model.Source{s1out},
			expInserts: 1,
		},
		{
			name:     "bobsrepo with commit, type search",
			srcInput: []*model.SourceInputSpec{s2},
			srcFilter: &model.SourceSpec{
				Type:      ptrfrom.String("git"),
				Namespace: ptrfrom.String("github.com/bob"),
				Commit:    ptrfrom.String("5e7c41f"),
			},
			idInFilter: false,
			want:       []*model.Source{s2out},
			wantErr:    false,
			expInserts: 1,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			t := s.T()
			be, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("GetBackend() error = %v", err)
			}
			ingestedPkg, err := be.IngestSources(ctx, tt.srcInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestSource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if count := s.Client.SourceName.Query().CountX(ctx); count != tt.expInserts {
				t.Errorf("Expected %d inserts, got %d", tt.expInserts, count)
			}

			if tt.idInFilter {
				tt.srcFilter.ID = &ingestedPkg[0].Namespaces[0].Names[0].ID
			}
			got, err := be.Sources(ctx, tt.srcFilter)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.Sources() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func (s *Suite) TestHasSourceAt() {
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
		Only         bool
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
				ID: ptrfrom.String("1"),
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

	hasOnly := false
	for _, test := range tests {
		if test.Only {
			hasOnly = true
			break
		}
	}

	ctx := s.Ctx
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
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}

			_, err = b.IngestSources(ctx, test.InSrc)
			s.NoError(err, "Could not ingest sources")

			// for _, s := range test.InSrc {
			// if _, err := b.IngestSource(ctx, *s); err != nil {
			// 	t.Fatalf("Could not ingest source: %v", err)
			// }
			// }

			ids := make([]string, len(test.Calls))
			for i, o := range test.Calls {
				v, err := b.IngestHasSourceAt(ctx, *o.Pkg, *o.Match, *o.Src, *o.HSA)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				ids[i] = v.ID
			}

			if test.Query.ID != nil {
				idIdx, err := strconv.Atoi(*test.Query.ID)
				if err == nil {
					if idIdx >= len(ids) {
						s.T().Fatalf("ID index out of range, want: %d, got: %d", len(ids), idIdx)
					}
					test.Query.ID = ptrfrom.String(ids[idIdx])
				}
			}

			got, err := b.HasSourceAt(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpHSA, got, ignoreID, ignoreEmptySlices); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func (s *Suite) TestIngestHasSourceAts() {
	testTime := time.Unix(1e9+5, 0)
	type call struct {
		Pkgs  []*model.PkgInputSpec
		Srcs  []*model.SourceInputSpec
		Match *model.MatchFlags
		HSAs  []*model.HasSourceAtInputSpec
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
					Pkgs: []*model.PkgInputSpec{p1},
					Srcs: []*model.SourceInputSpec{s1},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSAs: []*model.HasSourceAtInputSpec{
						{
							Justification: "test justification",
						},
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
					Pkgs: []*model.PkgInputSpec{p1},
					Srcs: []*model.SourceInputSpec{s1},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					HSAs: []*model.HasSourceAtInputSpec{
						{
							Justification: "test justification",
						},
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
					Pkgs: []*model.PkgInputSpec{p1, p1},
					Srcs: []*model.SourceInputSpec{s1, s1},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSAs: []*model.HasSourceAtInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
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
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{p1, p2},
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Pkgs: []*model.PkgInputSpec{p1, p2},
					Srcs: []*model.SourceInputSpec{s1, s1},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSAs: []*model.HasSourceAtInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Package: &model.PkgSpec{
					Version: ptrfrom.String("2.11.1"),
				},
			},
			ExpHSA: []*model.HasSourceAt{
				{
					Package:       p2out,
					Source:        s1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Source",
			InPkg: []*model.PkgInputSpec{p1},
			InSrc: []*model.SourceInputSpec{s1, s2},
			Calls: []call{
				{
					Pkgs: []*model.PkgInputSpec{p1, p1},
					Srcs: []*model.SourceInputSpec{s1, s2},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSAs: []*model.HasSourceAtInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasSourceAtSpec{
				Source: &model.SourceSpec{
					Name: ptrfrom.String("myrepo"),
				},
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
			Name:  "Query on KnownSince",
			InPkg: []*model.PkgInputSpec{p1},
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Pkgs: []*model.PkgInputSpec{p1, p1},
					Srcs: []*model.SourceInputSpec{s1, s1},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HSAs: []*model.HasSourceAtInputSpec{
						{
							KnownSince: time.Unix(1e9, 0),
						},
						{
							KnownSince: testTime,
						},
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
	}
	ctx := s.Ctx
	for _, test := range tests {
		s.Run(test.Name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
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
				_, err := b.IngestHasSourceAts(ctx, o.Pkgs, o.Match, o.Srcs, o.HSAs)
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
