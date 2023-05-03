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

var b1 = &model.BuilderInputSpec{
	URI: "asdf",
}
var b1out = &model.Builder{
	URI: "asdf",
}

var b2 = &model.BuilderInputSpec{
	URI: "qwer",
}

func TestHasSLSA(t *testing.T) {
	testTime := time.Unix(1e9+5, 0)
	type call struct {
		Sub  *model.ArtifactInputSpec
		BF   []*model.ArtifactInputSpec
		BB   *model.BuilderInputSpec
		SLSA *model.SLSAInputSpec
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
					Sub: a1,
					BF:  []*model.ArtifactInputSpec{a2},
					BB:  b1,
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
					Sub: a1,
					BF:  []*model.ArtifactInputSpec{a2},
					BB:  b1,
					SLSA: &model.SLSAInputSpec{
						BuildType: "test type",
					},
				},
				{
					Sub: a1,
					BF:  []*model.ArtifactInputSpec{a2},
					BB:  b1,
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
					Sub: a1,
					BF:  []*model.ArtifactInputSpec{a2},
					BB:  b1,
					SLSA: &model.SLSAInputSpec{
						BuildType: "test type one",
					},
				},
				{
					Sub: a1,
					BF:  []*model.ArtifactInputSpec{a2},
					BB:  b1,
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
					Sub: a1,
					BF:  []*model.ArtifactInputSpec{a2},
					BB:  b1,
					SLSA: &model.SLSAInputSpec{
						SlsaVersion: "test type one",
					},
				},
				{
					Sub: a1,
					BF:  []*model.ArtifactInputSpec{a2},
					BB:  b1,
					SLSA: &model.SLSAInputSpec{
						SlsaVersion: "test type two",
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
					Sub: a1,
					BF:  []*model.ArtifactInputSpec{a2},
					BB:  b1,
					SLSA: &model.SLSAInputSpec{
						StartedOn: time.Unix(1e9, 0),
					},
				},
				{
					Sub: a1,
					BF:  []*model.ArtifactInputSpec{a2},
					BB:  b1,
					SLSA: &model.SLSAInputSpec{
						StartedOn: testTime,
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
						StartedOn: testTime,
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
					Sub:  a1,
					BF:   []*model.ArtifactInputSpec{a2},
					BB:   b1,
					SLSA: &model.SLSAInputSpec{},
				},
				{
					Sub:  a3,
					BF:   []*model.ArtifactInputSpec{a2},
					BB:   b1,
					SLSA: &model.SLSAInputSpec{},
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
					Sub:  a1,
					BF:   []*model.ArtifactInputSpec{a2},
					BB:   b1,
					SLSA: &model.SLSAInputSpec{},
				},
				{
					Sub:  a1,
					BF:   []*model.ArtifactInputSpec{a2, a3},
					BB:   b1,
					SLSA: &model.SLSAInputSpec{},
				},
				{
					Sub:  a1,
					BF:   []*model.ArtifactInputSpec{a4},
					BB:   b1,
					SLSA: &model.SLSAInputSpec{},
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
					Sub:  a1,
					BF:   []*model.ArtifactInputSpec{a2},
					BB:   b1,
					SLSA: &model.SLSAInputSpec{},
				},
				{
					Sub:  a1,
					BF:   []*model.ArtifactInputSpec{a2},
					BB:   b2,
					SLSA: &model.SLSAInputSpec{},
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
					Sub:  a1,
					BF:   []*model.ArtifactInputSpec{a2},
					BB:   b1,
					SLSA: &model.SLSAInputSpec{},
				},
				{
					Sub:  a1,
					BF:   []*model.ArtifactInputSpec{a2},
					BB:   b2,
					SLSA: &model.SLSAInputSpec{},
				},
			},
			Query: &model.HasSLSASpec{
				ID: ptrfrom.String("6"),
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
					Sub:  a1,
					BF:   []*model.ArtifactInputSpec{a2},
					BB:   b1,
					SLSA: &model.SLSAInputSpec{},
				},
				{
					Sub:  a1,
					BF:   []*model.ArtifactInputSpec{a2},
					BB:   b2,
					SLSA: &model.SLSAInputSpec{},
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
					Sub:  a1,
					BF:   nil,
					BB:   b2,
					SLSA: &model.SLSAInputSpec{},
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
					Sub:  a1,
					BF:   []*model.ArtifactInputSpec{},
					BB:   b2,
					SLSA: &model.SLSAInputSpec{},
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
					Sub:  a1,
					BF:   []*model.ArtifactInputSpec{a2},
					BB:   b2,
					SLSA: &model.SLSAInputSpec{},
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
					Sub:  a1,
					BF:   []*model.ArtifactInputSpec{a2},
					BB:   b2,
					SLSA: &model.SLSAInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Ingest no builder found",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			Calls: []call{
				{
					Sub:  a1,
					BF:   []*model.ArtifactInputSpec{a2},
					BB:   b2,
					SLSA: &model.SLSAInputSpec{},
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
					Sub:  a1,
					BF:   []*model.ArtifactInputSpec{a2},
					BB:   b1,
					SLSA: &model.SLSAInputSpec{},
				},
				{
					Sub:  a1,
					BF:   []*model.ArtifactInputSpec{a2},
					BB:   b2,
					SLSA: &model.SLSAInputSpec{},
				},
			},
			Query: &model.HasSLSASpec{
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
				_, err := b.IngestSLSA(ctx, *o.Sub, o.BF, *o.BB, *o.SLSA)
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

func TestHasSLSANeighbors(t *testing.T) {
	type call struct {
		Sub  *model.ArtifactInputSpec
		BF   []*model.ArtifactInputSpec
		BB   *model.BuilderInputSpec
		SLSA *model.SLSAInputSpec
	}
	tests := []struct {
		Name         string
		InArt        []*model.ArtifactInputSpec
		InBld        []*model.BuilderInputSpec
		Calls        []call
		ExpNeighbors map[string][]string
	}{
		{
			Name:  "HappyPath",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			InBld: []*model.BuilderInputSpec{b1},
			Calls: []call{
				{
					Sub: a1,
					BF:  []*model.ArtifactInputSpec{a2},
					BB:  b1,
					SLSA: &model.SLSAInputSpec{
						BuildType: "test type",
					},
				},
			},
			ExpNeighbors: map[string][]string{
				"2": []string{"5"},           // a1
				"3": []string{"5"},           // a2
				"4": []string{"5"},           // b1
				"5": []string{"2", "3", "4"}, // hasSBOM
			},
		},
		{
			Name:  "Multiple",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3, a4},
			InBld: []*model.BuilderInputSpec{b1},
			Calls: []call{
				{
					Sub: a1,
					BF:  []*model.ArtifactInputSpec{a2},
					BB:  b1,
					SLSA: &model.SLSAInputSpec{
						BuildType: "test type",
					},
				},
				{
					Sub: a3,
					BF:  []*model.ArtifactInputSpec{a4},
					BB:  b1,
					SLSA: &model.SLSAInputSpec{
						BuildType: "test type",
					},
				},
			},
			ExpNeighbors: map[string][]string{
				"2": []string{"7"},           // a1
				"3": []string{"7"},           // a2
				"4": []string{"8"},           // a3
				"5": []string{"8"},           // a4
				"6": []string{"7", "8"},      // b1
				"7": []string{"2", "3", "6"}, // hasSBOM 1
				"8": []string{"4", "5", "6"}, // hasSBOM 2
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
				if _, err := b.IngestSLSA(ctx, *o.Sub, o.BF, *o.BB, *o.SLSA); err != nil {
					t.Fatalf("Could not ingest HasSLSA: %v", err)
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
