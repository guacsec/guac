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

var b1 = &model.BuilderInputSpec{
	URI: "asdf",
}
var b1out = &model.Builder{
	URI: "asdf",
}

var b2 = &model.BuilderInputSpec{
	URI: "qwer",
}

func (s *Suite) TestHasSLSA() {
	testTime := time.Unix(1e9+5, 0)
	testTime2 := time.Unix(1e9, 0)
	type call struct {
		Sub       *model.ArtifactInputSpec
		BuiltFrom []*model.ArtifactInputSpec
		Builder   *model.BuilderInputSpec
		SLSA      *model.SLSAInputSpec
	}
	tests := []struct {
		Name         string
		InArt        []*model.ArtifactInputSpec
		InBld        []*model.BuilderInputSpec
		Calls        []call
		Query        *model.HasSLSASpec
		ExpHS        []*model.HasSlsa
		ExpIngestErr bool
		ExpQueryErr  bool
		Only         bool
	}{
		{
			Name:  "HappyPath",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			InBld: []*model.BuilderInputSpec{b1},
			Calls: []call{
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b1,
					SLSA: &model.SLSAInputSpec{
						BuildType: "test type",
					},
				},
			},
			Query: &model.HasSLSASpec{
				BuildType: ptrfrom.String("test type"),
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: a1out,
					Slsa: &model.Slsa{
						BuiltBy:   b1out,
						BuiltFrom: []*model.Artifact{a2out},
						BuildType: "test type",
					},
				},
			},
		},
		{
			Name:  "Ingest twice",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			InBld: []*model.BuilderInputSpec{b1},
			Calls: []call{
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b1,
					SLSA: &model.SLSAInputSpec{
						BuildType: "test type",
					},
				},
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b1,
					SLSA: &model.SLSAInputSpec{
						BuildType: "test type",
					},
				},
			},
			Query: &model.HasSLSASpec{
				BuildType: ptrfrom.String("test type"),
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: a1out,
					Slsa: &model.Slsa{
						BuiltBy:   b1out,
						BuiltFrom: []*model.Artifact{a2out},
						BuildType: "test type",
					},
				},
			},
		},
		{
			Name:  "Query on Build Type",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			InBld: []*model.BuilderInputSpec{b1},
			Calls: []call{
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b1,
					SLSA: &model.SLSAInputSpec{
						BuildType: "test type one",
					},
				},
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b1,
					SLSA: &model.SLSAInputSpec{
						BuildType: "test type two",
					},
				},
			},
			Query: &model.HasSLSASpec{
				BuildType: ptrfrom.String("test type one"),
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: a1out,
					Slsa: &model.Slsa{
						BuiltBy:   b1out,
						BuiltFrom: []*model.Artifact{a2out},
						BuildType: "test type one",
					},
				},
			},
		},
		{
			Name:  "Query on Version",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			InBld: []*model.BuilderInputSpec{b1},
			Calls: []call{
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b1,
					SLSA: &model.SLSAInputSpec{
						SlsaVersion: "test type two",
					},
				},
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b1,
					SLSA: &model.SLSAInputSpec{
						SlsaVersion: "test type one",
					},
				},
			},
			Query: &model.HasSLSASpec{
				SlsaVersion: ptrfrom.String("test type two"),
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: a1out,
					Slsa: &model.Slsa{
						BuiltBy:     b1out,
						BuiltFrom:   []*model.Artifact{a2out},
						SlsaVersion: "test type two",
					},
				},
			},
		},
		{
			Name:  "Query on Time",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			InBld: []*model.BuilderInputSpec{b1},
			Calls: []call{
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b1,
					SLSA: &model.SLSAInputSpec{
						StartedOn: &testTime2,
					},
				},
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b1,
					SLSA: &model.SLSAInputSpec{
						StartedOn: &testTime,
					},
				},
			},
			Query: &model.HasSLSASpec{
				StartedOn: &testTime,
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: a1out,
					Slsa: &model.Slsa{
						BuiltBy:   b1out,
						BuiltFrom: []*model.Artifact{a2out},
						StartedOn: &testTime,
					},
				},
			},
		},
		{
			Name:  "Query on Subject",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3},
			InBld: []*model.BuilderInputSpec{b1},
			Calls: []call{
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b1,
					SLSA:      &model.SLSAInputSpec{},
				},
				{
					Sub:       a3,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b1,
					SLSA:      &model.SLSAInputSpec{},
				},
			},
			Query: &model.HasSLSASpec{
				Subject: &model.ArtifactSpec{
					Algorithm: ptrfrom.String("sha256"),
				},
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: a1out,
					Slsa: &model.Slsa{
						BuiltBy:   b1out,
						BuiltFrom: []*model.Artifact{a2out},
					},
				},
			},
		},
		{
			Name:  "Query on Materials",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3, a4},
			InBld: []*model.BuilderInputSpec{b1},
			Calls: []call{
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b1,
					SLSA:      &model.SLSAInputSpec{},
				},
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2, a3},
					Builder:   b1,
					SLSA:      &model.SLSAInputSpec{},
				},
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a4},
					Builder:   b1,
					SLSA:      &model.SLSAInputSpec{},
				},
			},
			Query: &model.HasSLSASpec{
				BuiltFrom: []*model.ArtifactSpec{{
					Digest: ptrfrom.String("7A8F47318E4676DACB0142AFA0B83029CD7BEFD9"),
				}},
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: a1out,
					Slsa: &model.Slsa{
						BuiltBy:   b1out,
						BuiltFrom: []*model.Artifact{a2out},
					},
				},
				{
					Subject: a1out,
					Slsa: &model.Slsa{
						BuiltBy:   b1out,
						BuiltFrom: []*model.Artifact{a2out, a3out},
					},
				},
			},
		},
		{
			Name:  "Query on Builder",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			InBld: []*model.BuilderInputSpec{b1, b2},
			Calls: []call{
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b1,
					SLSA:      &model.SLSAInputSpec{},
				},
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b2,
					SLSA:      &model.SLSAInputSpec{},
				},
			},
			Query: &model.HasSLSASpec{
				BuiltBy: &model.BuilderSpec{
					URI: ptrfrom.String("asdf"),
				},
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: a1out,
					Slsa: &model.Slsa{
						BuiltBy:   b1out,
						BuiltFrom: []*model.Artifact{a2out},
					},
				},
			},
		},
		{
			Name:  "Query on ID",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			InBld: []*model.BuilderInputSpec{b1, b2},
			Calls: []call{
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b1,
					SLSA:      &model.SLSAInputSpec{},
				},
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b2,
					SLSA:      &model.SLSAInputSpec{},
				},
			},
			Query: &model.HasSLSASpec{
				ID: ptrfrom.String("0"),
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: a1out,
					Slsa: &model.Slsa{
						BuiltBy:   b1out,
						BuiltFrom: []*model.Artifact{a2out},
					},
				},
			},
		},
		{
			Name:  "Query none",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			InBld: []*model.BuilderInputSpec{b1, b2},
			Calls: []call{
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b1,
					SLSA:      &model.SLSAInputSpec{},
				},
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b2,
					SLSA:      &model.SLSAInputSpec{},
				},
			},
			Query: &model.HasSLSASpec{
				BuiltBy: &model.BuilderSpec{
					URI: ptrfrom.String("poiu"),
				},
			},
			ExpHS: nil,
		},
		{
			Name:  "Ingest no Materials 1",
			InArt: []*model.ArtifactInputSpec{a1},
			InBld: []*model.BuilderInputSpec{b1},
			Calls: []call{
				{
					Sub:       a1,
					BuiltFrom: nil,
					Builder:   b2,
					SLSA:      &model.SLSAInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Ingest no Materials 2",
			InArt: []*model.ArtifactInputSpec{a1},
			InBld: []*model.BuilderInputSpec{b1},
			Calls: []call{
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{},
					Builder:   b2,
					SLSA:      &model.SLSAInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Ingest no Sub",
			InArt: []*model.ArtifactInputSpec{a2},
			InBld: []*model.BuilderInputSpec{b2},
			Calls: []call{
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b2,
					SLSA:      &model.SLSAInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Ingest no matrials found",
			InArt: []*model.ArtifactInputSpec{a1},
			InBld: []*model.BuilderInputSpec{b2},
			Calls: []call{
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b2,
					SLSA:      &model.SLSAInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Ingest no builder found",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			Calls: []call{
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b2,
					SLSA:      &model.SLSAInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Query bad ID",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			InBld: []*model.BuilderInputSpec{b1, b2},
			Calls: []call{
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b1,
					SLSA:      &model.SLSAInputSpec{},
				},
				{
					Sub:       a1,
					BuiltFrom: []*model.ArtifactInputSpec{a2},
					Builder:   b2,
					SLSA:      &model.SLSAInputSpec{},
				},
			},
			Query: &model.HasSLSASpec{
				ID: ptrfrom.Any("asdf"),
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
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, bld := range test.InBld {
				if _, err := b.IngestBuilder(ctx, bld); err != nil {
					t.Fatalf("Could not ingest builder: %v", err)
				}
			}

			ids := make([]string, len(test.Calls))
			for i, o := range test.Calls {
				v, err := b.IngestSLSA(ctx, *o.Sub, o.BuiltFrom, *o.Builder, *o.SLSA)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				ids[i] = v.ID
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

			got, err := b.HasSlsa(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpHS, got, ignoreID, ignoreEmptySlices); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func (s *Suite) TestIngestHasSLSAs() {
	type call struct {
		Sub  []*model.ArtifactInputSpec
		BF   [][]*model.ArtifactInputSpec
		BB   []*model.BuilderInputSpec
		SLSA []*model.SLSAInputSpec
	}
	tests := []struct {
		Name         string
		InArt        []*model.ArtifactInputSpec
		InBld        []*model.BuilderInputSpec
		Calls        []call
		Query        *model.HasSLSASpec
		ExpHS        []*model.HasSlsa
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			InBld: []*model.BuilderInputSpec{b1},
			Calls: []call{
				{
					Sub: []*model.ArtifactInputSpec{a1},
					BF:  [][]*model.ArtifactInputSpec{[]*model.ArtifactInputSpec{a2}},
					BB:  []*model.BuilderInputSpec{b1},
					SLSA: []*model.SLSAInputSpec{
						{
							BuildType: "test type",
						},
					},
				},
			},
			Query: &model.HasSLSASpec{
				BuildType: ptrfrom.String("test type"),
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: a1out,
					Slsa: &model.Slsa{
						BuiltBy:   b1out,
						BuiltFrom: []*model.Artifact{a2out},
						BuildType: "test type",
					},
				},
			},
		},
		{
			Name:  "Ingest twice",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			InBld: []*model.BuilderInputSpec{b1},
			Calls: []call{
				{
					Sub: []*model.ArtifactInputSpec{a1, a1},
					BF:  [][]*model.ArtifactInputSpec{[]*model.ArtifactInputSpec{a2}, []*model.ArtifactInputSpec{a2}},
					BB:  []*model.BuilderInputSpec{b1, b1},
					SLSA: []*model.SLSAInputSpec{
						{
							BuildType: "test type",
						},
						{
							BuildType: "test type",
						},
					},
				},
			},
			Query: &model.HasSLSASpec{
				BuildType: ptrfrom.String("test type"),
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: a1out,
					Slsa: &model.Slsa{
						BuiltBy:   b1out,
						BuiltFrom: []*model.Artifact{a2out},
						BuildType: "test type",
					},
				},
			},
		},
		{
			Name:  "Query on Build Type",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			InBld: []*model.BuilderInputSpec{b1},
			Calls: []call{
				{
					Sub: []*model.ArtifactInputSpec{a1, a1},
					BF:  [][]*model.ArtifactInputSpec{[]*model.ArtifactInputSpec{a2}, []*model.ArtifactInputSpec{a2}},
					BB:  []*model.BuilderInputSpec{b1, b1},
					SLSA: []*model.SLSAInputSpec{
						{
							BuildType: "test type one",
						},
						{
							BuildType: "test type two",
						},
					},
				},
			},
			Query: &model.HasSLSASpec{
				BuildType: ptrfrom.String("test type one"),
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: a1out,
					Slsa: &model.Slsa{
						BuiltBy:   b1out,
						BuiltFrom: []*model.Artifact{a2out},
						BuildType: "test type one",
					},
				},
			},
		},
		{
			Name:  "Query on Subject",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3},
			InBld: []*model.BuilderInputSpec{b1},
			Calls: []call{
				{
					Sub: []*model.ArtifactInputSpec{a1, a3},
					BF:  [][]*model.ArtifactInputSpec{[]*model.ArtifactInputSpec{a2}, []*model.ArtifactInputSpec{a2}},
					BB:  []*model.BuilderInputSpec{b1, b1},
					SLSA: []*model.SLSAInputSpec{
						{},
						{},
					},
				},
			},
			Query: &model.HasSLSASpec{
				Subject: &model.ArtifactSpec{
					Algorithm: ptrfrom.String("sha256"),
				},
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: a1out,
					Slsa: &model.Slsa{
						BuiltBy:   b1out,
						BuiltFrom: []*model.Artifact{a2out},
					},
				},
			},
		},
		{
			Name:  "Query on Materials",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3, a4},
			InBld: []*model.BuilderInputSpec{b1},
			Calls: []call{
				{
					Sub: []*model.ArtifactInputSpec{a1, a1, a1},
					BF:  [][]*model.ArtifactInputSpec{[]*model.ArtifactInputSpec{a2}, []*model.ArtifactInputSpec{a2, a3}, []*model.ArtifactInputSpec{a4}},
					BB:  []*model.BuilderInputSpec{b1, b1, b1},
					SLSA: []*model.SLSAInputSpec{
						{},
						{},
						{},
					},
				},
			},
			Query: &model.HasSLSASpec{
				BuiltFrom: []*model.ArtifactSpec{{
					Digest: ptrfrom.String("7A8F47318E4676DACB0142AFA0B83029CD7BEFD9"),
				}},
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: a1out,
					Slsa: &model.Slsa{
						BuiltBy:   b1out,
						BuiltFrom: []*model.Artifact{a2out},
					},
				},
				{
					Subject: a1out,
					Slsa: &model.Slsa{
						BuiltBy:   b1out,
						BuiltFrom: []*model.Artifact{a2out, a3out},
					},
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
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, bld := range test.InBld {
				if _, err := b.IngestBuilder(ctx, bld); err != nil {
					t.Fatalf("Could not ingest builder: %v", err)
				}
			}
			for _, o := range test.Calls {
				_, err := b.IngestSLSAs(ctx, o.Sub, o.BF, o.BB, o.SLSA)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.HasSlsa(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpHS, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
