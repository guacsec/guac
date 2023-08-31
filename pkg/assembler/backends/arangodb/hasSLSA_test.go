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

package arangodb

// import (
// 	"context"
// 	"strings"
// 	"testing"
// 	"time"

// 	"github.com/google/go-cmp/cmp"
// 	"github.com/guacsec/guac/internal/testing/ptrfrom"
// 	"github.com/guacsec/guac/internal/testing/testdata"
// 	"github.com/guacsec/guac/pkg/assembler/graphql/model"
// )

// var b1 = &model.BuilderInputSpec{
// 	URI: "asdf",
// }
// var b1out = &model.Builder{
// 	URI: "asdf",
// }

// var b2 = &model.BuilderInputSpec{
// 	URI: "qwer",
// }

// func TestHasSLSA(t *testing.T) {
// 	ctx := context.Background()
// 	arangArg := getArangoConfig()
// 	err := deleteDatabase(ctx, arangArg)
// 	if err != nil {
// 		t.Fatalf("error deleting arango database: %v", err)
// 	}
// 	b, err := GetBackend(ctx, arangArg)
// 	if err != nil {
// 		t.Fatalf("error creating arango backend: %v", err)
// 	}
// 	testTime := time.Unix(1e9+5, 0)
// 	testTime2 := time.Unix(1e9, 0)
// 	type call struct {
// 		Sub  *model.ArtifactInputSpec
// 		BF   []*model.ArtifactInputSpec
// 		BB   *model.BuilderInputSpec
// 		SLSA *model.SLSAInputSpec
// 	}
// 	tests := []struct {
// 		Name         string
// 		InArt        []*model.ArtifactInputSpec
// 		InBld        []*model.BuilderInputSpec
// 		Calls        []call
// 		Query        *model.HasSLSASpec
// 		ExpHS        []*model.HasSlsa
// 		ExpIngestErr bool
// 		ExpQueryErr  bool
// 	}{
// 		{
// 			Name:  "HappyPath",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			InBld: []*model.BuilderInputSpec{b1},
// 			Calls: []call{
// 				{
// 					Sub: testdata.A1,
// 					BF:  []*model.ArtifactInputSpec{testdata.A2},
// 					BB:  b1,
// 					SLSA: &model.SLSAInputSpec{
// 						BuildType: "test type",
// 					},
// 				},
// 			},
// 			Query: &model.HasSLSASpec{
// 				BuildType: ptrfrom.String("test type"),
// 			},
// 			ExpHS: []*model.HasSlsa{
// 				{
// 					Subject: testdata.A1out,
// 					Slsa: &model.Slsa{
// 						BuiltBy:   b1out,
// 						BuiltFrom: []*model.Artifact{testdata.A2out},
// 						BuildType: "test type",
// 					},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Ingest twice",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			InBld: []*model.BuilderInputSpec{b1},
// 			Calls: []call{
// 				{
// 					Sub: testdata.A1,
// 					BF:  []*model.ArtifactInputSpec{testdata.A2},
// 					BB:  b1,
// 					SLSA: &model.SLSAInputSpec{
// 						BuildType: "test type",
// 					},
// 				},
// 				{
// 					Sub: testdata.A1,
// 					BF:  []*model.ArtifactInputSpec{testdata.A2},
// 					BB:  b1,
// 					SLSA: &model.SLSAInputSpec{
// 						BuildType: "test type",
// 					},
// 				},
// 			},
// 			Query: &model.HasSLSASpec{
// 				BuildType: ptrfrom.String("test type"),
// 			},
// 			ExpHS: []*model.HasSlsa{
// 				{
// 					Subject: testdata.A1out,
// 					Slsa: &model.Slsa{
// 						BuiltBy:   b1out,
// 						BuiltFrom: []*model.Artifact{testdata.A2out},
// 						BuildType: "test type",
// 					},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Build Type",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			InBld: []*model.BuilderInputSpec{b1},
// 			Calls: []call{
// 				{
// 					Sub: testdata.A1,
// 					BF:  []*model.ArtifactInputSpec{testdata.A2},
// 					BB:  b1,
// 					SLSA: &model.SLSAInputSpec{
// 						BuildType: "test type one",
// 					},
// 				},
// 				{
// 					Sub: testdata.A1,
// 					BF:  []*model.ArtifactInputSpec{testdata.A2},
// 					BB:  b1,
// 					SLSA: &model.SLSAInputSpec{
// 						BuildType: "test type two",
// 					},
// 				},
// 			},
// 			Query: &model.HasSLSASpec{
// 				BuildType: ptrfrom.String("test type one"),
// 			},
// 			ExpHS: []*model.HasSlsa{
// 				{
// 					Subject: testdata.A1out,
// 					Slsa: &model.Slsa{
// 						BuiltBy:   b1out,
// 						BuiltFrom: []*model.Artifact{testdata.A2out},
// 						BuildType: "test type one",
// 					},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Version",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			InBld: []*model.BuilderInputSpec{b1},
// 			Calls: []call{
// 				{
// 					Sub: testdata.A1,
// 					BF:  []*model.ArtifactInputSpec{testdata.A2},
// 					BB:  b1,
// 					SLSA: &model.SLSAInputSpec{
// 						SlsaVersion: "test type one",
// 					},
// 				},
// 				{
// 					Sub: testdata.A1,
// 					BF:  []*model.ArtifactInputSpec{testdata.A2},
// 					BB:  b1,
// 					SLSA: &model.SLSAInputSpec{
// 						SlsaVersion: "test type two",
// 					},
// 				},
// 			},
// 			Query: &model.HasSLSASpec{
// 				SlsaVersion: ptrfrom.String("test type two"),
// 			},
// 			ExpHS: []*model.HasSlsa{
// 				{
// 					Subject: testdata.A1out,
// 					Slsa: &model.Slsa{
// 						BuiltBy:     b1out,
// 						BuiltFrom:   []*model.Artifact{testdata.A2out},
// 						SlsaVersion: "test type two",
// 					},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Time",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			InBld: []*model.BuilderInputSpec{b1},
// 			Calls: []call{
// 				{
// 					Sub: testdata.A1,
// 					BF:  []*model.ArtifactInputSpec{testdata.A2},
// 					BB:  b1,
// 					SLSA: &model.SLSAInputSpec{
// 						StartedOn: &testTime2,
// 					},
// 				},
// 				{
// 					Sub: testdata.A1,
// 					BF:  []*model.ArtifactInputSpec{testdata.A2},
// 					BB:  b1,
// 					SLSA: &model.SLSAInputSpec{
// 						StartedOn: &testTime,
// 					},
// 				},
// 			},
// 			Query: &model.HasSLSASpec{
// 				StartedOn: &testTime,
// 			},
// 			ExpHS: []*model.HasSlsa{
// 				{
// 					Subject: testdata.A1out,
// 					Slsa: &model.Slsa{
// 						BuiltBy:   b1out,
// 						BuiltFrom: []*model.Artifact{testdata.A2out},
// 						StartedOn: &testTime,
// 					},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Subject",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2, testdata.A3},
// 			InBld: []*model.BuilderInputSpec{b1},
// 			Calls: []call{
// 				{
// 					Sub:  testdata.A1,
// 					BF:   []*model.ArtifactInputSpec{testdata.A2},
// 					BB:   b1,
// 					SLSA: &model.SLSAInputSpec{},
// 				},
// 				{
// 					Sub:  testdata.A3,
// 					BF:   []*model.ArtifactInputSpec{testdata.A2},
// 					BB:   b1,
// 					SLSA: &model.SLSAInputSpec{},
// 				},
// 			},
// 			Query: &model.HasSLSASpec{
// 				Subject: &model.ArtifactSpec{
// 					Algorithm: ptrfrom.String("sha256"),
// 				},
// 			},
// 			ExpHS: []*model.HasSlsa{
// 				{
// 					Subject: testdata.A1out,
// 					Slsa: &model.Slsa{
// 						BuiltBy:   b1out,
// 						BuiltFrom: []*model.Artifact{testdata.A2out},
// 					},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Materials",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2, testdata.A3, testdata.A4},
// 			InBld: []*model.BuilderInputSpec{b1},
// 			Calls: []call{
// 				{
// 					Sub:  testdata.A1,
// 					BF:   []*model.ArtifactInputSpec{testdata.A2},
// 					BB:   b1,
// 					SLSA: &model.SLSAInputSpec{},
// 				},
// 				{
// 					Sub:  testdata.A1,
// 					BF:   []*model.ArtifactInputSpec{testdata.A2, testdata.A3},
// 					BB:   b1,
// 					SLSA: &model.SLSAInputSpec{},
// 				},
// 				{
// 					Sub:  testdata.A1,
// 					BF:   []*model.ArtifactInputSpec{testdata.A4},
// 					BB:   b1,
// 					SLSA: &model.SLSAInputSpec{},
// 				},
// 			},
// 			Query: &model.HasSLSASpec{
// 				BuiltFrom: []*model.ArtifactSpec{{
// 					Digest: ptrfrom.String("7A8F47318E4676DACB0142AFA0B83029CD7BEFD9"),
// 				}},
// 			},
// 			ExpHS: []*model.HasSlsa{
// 				{
// 					Subject: testdata.A1out,
// 					Slsa: &model.Slsa{
// 						BuiltBy:   b1out,
// 						BuiltFrom: []*model.Artifact{testdata.A2out},
// 					},
// 				},
// 				{
// 					Subject: testdata.A1out,
// 					Slsa: &model.Slsa{
// 						BuiltBy:   b1out,
// 						BuiltFrom: []*model.Artifact{testdata.A2out, testdata.A3out},
// 					},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Builder",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			InBld: []*model.BuilderInputSpec{b1, b2},
// 			Calls: []call{
// 				{
// 					Sub:  testdata.A1,
// 					BF:   []*model.ArtifactInputSpec{testdata.A2},
// 					BB:   b1,
// 					SLSA: &model.SLSAInputSpec{},
// 				},
// 				{
// 					Sub:  testdata.A1,
// 					BF:   []*model.ArtifactInputSpec{testdata.A2},
// 					BB:   b2,
// 					SLSA: &model.SLSAInputSpec{},
// 				},
// 			},
// 			Query: &model.HasSLSASpec{
// 				BuiltBy: &model.BuilderSpec{
// 					URI: ptrfrom.String("asdf"),
// 				},
// 			},
// 			ExpHS: []*model.HasSlsa{
// 				{
// 					Subject: testdata.A1out,
// 					Slsa: &model.Slsa{
// 						BuiltBy:   b1out,
// 						BuiltFrom: []*model.Artifact{testdata.A2out},
// 					},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on ID",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			InBld: []*model.BuilderInputSpec{b1, b2},
// 			Calls: []call{
// 				{
// 					Sub:  testdata.A1,
// 					BF:   []*model.ArtifactInputSpec{testdata.A2},
// 					BB:   b1,
// 					SLSA: &model.SLSAInputSpec{},
// 				},
// 				{
// 					Sub:  testdata.A1,
// 					BF:   []*model.ArtifactInputSpec{testdata.A2},
// 					BB:   b2,
// 					SLSA: &model.SLSAInputSpec{},
// 				},
// 			},
// 			Query: &model.HasSLSASpec{
// 				ID: ptrfrom.String("5"),
// 			},
// 			ExpHS: []*model.HasSlsa{
// 				{
// 					Subject: testdata.A1out,
// 					Slsa: &model.Slsa{
// 						BuiltBy:   b1out,
// 						BuiltFrom: []*model.Artifact{testdata.A2out},
// 					},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query none",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			InBld: []*model.BuilderInputSpec{b1, b2},
// 			Calls: []call{
// 				{
// 					Sub:  testdata.A1,
// 					BF:   []*model.ArtifactInputSpec{testdata.A2},
// 					BB:   b1,
// 					SLSA: &model.SLSAInputSpec{},
// 				},
// 				{
// 					Sub:  testdata.A1,
// 					BF:   []*model.ArtifactInputSpec{testdata.A2},
// 					BB:   b2,
// 					SLSA: &model.SLSAInputSpec{},
// 				},
// 			},
// 			Query: &model.HasSLSASpec{
// 				BuiltBy: &model.BuilderSpec{
// 					URI: ptrfrom.String("poiu"),
// 				},
// 			},
// 			ExpHS: nil,
// 		},
// 		{
// 			Name:  "Ingest no Materials 1",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1},
// 			InBld: []*model.BuilderInputSpec{b1},
// 			Calls: []call{
// 				{
// 					Sub:  testdata.A1,
// 					BF:   nil,
// 					BB:   b2,
// 					SLSA: &model.SLSAInputSpec{},
// 				},
// 			},
// 			ExpIngestErr: true,
// 		},
// 		{
// 			Name:  "Ingest no Materials 2",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1},
// 			InBld: []*model.BuilderInputSpec{b1},
// 			Calls: []call{
// 				{
// 					Sub:  testdata.A1,
// 					BF:   []*model.ArtifactInputSpec{},
// 					BB:   b2,
// 					SLSA: &model.SLSAInputSpec{},
// 				},
// 			},
// 			ExpIngestErr: true,
// 		},
// 		{
// 			Name:  "Ingest no Sub",
// 			InArt: []*model.ArtifactInputSpec{testdata.A2},
// 			InBld: []*model.BuilderInputSpec{b2},
// 			Calls: []call{
// 				{
// 					Sub:  testdata.A1,
// 					BF:   []*model.ArtifactInputSpec{testdata.A2},
// 					BB:   b2,
// 					SLSA: &model.SLSAInputSpec{},
// 				},
// 			},
// 			ExpIngestErr: true,
// 		},
// 		{
// 			Name:  "Ingest no matrials found",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1},
// 			InBld: []*model.BuilderInputSpec{b2},
// 			Calls: []call{
// 				{
// 					Sub:  testdata.A1,
// 					BF:   []*model.ArtifactInputSpec{testdata.A2},
// 					BB:   b2,
// 					SLSA: &model.SLSAInputSpec{},
// 				},
// 			},
// 			ExpIngestErr: true,
// 		},
// 		{
// 			Name:  "Ingest no builder found",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			Calls: []call{
// 				{
// 					Sub:  testdata.A1,
// 					BF:   []*model.ArtifactInputSpec{testdata.A2},
// 					BB:   b2,
// 					SLSA: &model.SLSAInputSpec{},
// 				},
// 			},
// 			ExpIngestErr: true,
// 		},
// 		{
// 			Name:  "Query bad ID",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			InBld: []*model.BuilderInputSpec{b1, b2},
// 			Calls: []call{
// 				{
// 					Sub:  testdata.A1,
// 					BF:   []*model.ArtifactInputSpec{testdata.A2},
// 					BB:   b1,
// 					SLSA: &model.SLSAInputSpec{},
// 				},
// 				{
// 					Sub:  testdata.A1,
// 					BF:   []*model.ArtifactInputSpec{testdata.A2},
// 					BB:   b2,
// 					SLSA: &model.SLSAInputSpec{},
// 				},
// 			},
// 			Query: &model.HasSLSASpec{
// 				ID: ptrfrom.String("asdf"),
// 			},
// 			ExpQueryErr: true,
// 		},
// 	}
// 	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
// 		return strings.Compare(".ID", p[len(p)-1].String()) == 0
// 	}, cmp.Ignore())
// 	for _, test := range tests {
// 		t.Run(test.Name, func(t *testing.T) {
// 			for _, a := range test.InArt {
// 				if _, err := b.IngestArtifact(ctx, a); err != nil {
// 					t.Fatalf("Could not ingest artifact: %v", err)
// 				}
// 			}
// 			for _, bld := range test.InBld {
// 				if _, err := b.IngestBuilder(ctx, bld); err != nil {
// 					t.Fatalf("Could not ingest builder: %v", err)
// 				}
// 			}
// 			for _, o := range test.Calls {
// 				_, err := b.IngestSLSA(ctx, *o.Sub, o.BF, *o.BB, *o.SLSA)
// 				if (err != nil) != test.ExpIngestErr {
// 					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
// 				}
// 				if err != nil {
// 					return
// 				}
// 			}
// 			got, err := b.HasSlsa(ctx, test.Query)
// 			if (err != nil) != test.ExpQueryErr {
// 				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
// 			}
// 			if err != nil {
// 				return
// 			}
// 			if diff := cmp.Diff(test.ExpHS, got, ignoreID); diff != "" {
// 				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
// 			}
// 		})
// 	}
// }

// func TestIngestHasSLSAs(t *testing.T) {
// 	ctx := context.Background()
// 	arangArg := getArangoConfig()
// 	err := deleteDatabase(ctx, arangArg)
// 	if err != nil {
// 		t.Fatalf("error deleting arango database: %v", err)
// 	}
// 	b, err := GetBackend(ctx, arangArg)
// 	if err != nil {
// 		t.Fatalf("error creating arango backend: %v", err)
// 	}
// 	type call struct {
// 		Sub  []*model.ArtifactInputSpec
// 		BF   [][]*model.ArtifactInputSpec
// 		BB   []*model.BuilderInputSpec
// 		SLSA []*model.SLSAInputSpec
// 	}
// 	tests := []struct {
// 		Name         string
// 		InArt        []*model.ArtifactInputSpec
// 		InBld        []*model.BuilderInputSpec
// 		Calls        []call
// 		Query        *model.HasSLSASpec
// 		ExpHS        []*model.HasSlsa
// 		ExpIngestErr bool
// 		ExpQueryErr  bool
// 	}{
// 		{
// 			Name:  "HappyPath",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			InBld: []*model.BuilderInputSpec{b1},
// 			Calls: []call{
// 				{
// 					Sub: []*model.ArtifactInputSpec{testdata.A1},
// 					BF:  [][]*model.ArtifactInputSpec{{testdata.A2}},
// 					BB:  []*model.BuilderInputSpec{b1},
// 					SLSA: []*model.SLSAInputSpec{
// 						{
// 							BuildType: "test type",
// 						},
// 					},
// 				},
// 			},
// 			Query: &model.HasSLSASpec{
// 				BuildType: ptrfrom.String("test type"),
// 			},
// 			ExpHS: []*model.HasSlsa{
// 				{
// 					Subject: testdata.A1out,
// 					Slsa: &model.Slsa{
// 						BuiltBy:   b1out,
// 						BuiltFrom: []*model.Artifact{testdata.A2out},
// 						BuildType: "test type",
// 					},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Ingest twice",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			InBld: []*model.BuilderInputSpec{b1},
// 			Calls: []call{
// 				{
// 					Sub: []*model.ArtifactInputSpec{testdata.A1, testdata.A1},
// 					BF:  [][]*model.ArtifactInputSpec{{testdata.A2}, {testdata.A2}},
// 					BB:  []*model.BuilderInputSpec{b1, b1},
// 					SLSA: []*model.SLSAInputSpec{
// 						{
// 							BuildType: "test type",
// 						},
// 						{
// 							BuildType: "test type",
// 						},
// 					},
// 				},
// 			},
// 			Query: &model.HasSLSASpec{
// 				BuildType: ptrfrom.String("test type"),
// 			},
// 			ExpHS: []*model.HasSlsa{
// 				{
// 					Subject: testdata.A1out,
// 					Slsa: &model.Slsa{
// 						BuiltBy:   b1out,
// 						BuiltFrom: []*model.Artifact{testdata.A2out},
// 						BuildType: "test type",
// 					},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Build Type",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			InBld: []*model.BuilderInputSpec{b1},
// 			Calls: []call{
// 				{
// 					Sub: []*model.ArtifactInputSpec{testdata.A1, testdata.A1},
// 					BF:  [][]*model.ArtifactInputSpec{{testdata.A2}, {testdata.A2}},
// 					BB:  []*model.BuilderInputSpec{b1, b1},
// 					SLSA: []*model.SLSAInputSpec{
// 						{
// 							BuildType: "test type one",
// 						},
// 						{
// 							BuildType: "test type two",
// 						},
// 					},
// 				},
// 			},
// 			Query: &model.HasSLSASpec{
// 				BuildType: ptrfrom.String("test type one"),
// 			},
// 			ExpHS: []*model.HasSlsa{
// 				{
// 					Subject: testdata.A1out,
// 					Slsa: &model.Slsa{
// 						BuiltBy:   b1out,
// 						BuiltFrom: []*model.Artifact{testdata.A2out},
// 						BuildType: "test type one",
// 					},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Subject",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2, testdata.A3},
// 			InBld: []*model.BuilderInputSpec{b1},
// 			Calls: []call{
// 				{
// 					Sub: []*model.ArtifactInputSpec{testdata.A1, testdata.A3},
// 					BF:  [][]*model.ArtifactInputSpec{{testdata.A2}, {testdata.A2}},
// 					BB:  []*model.BuilderInputSpec{b1, b1},
// 					SLSA: []*model.SLSAInputSpec{
// 						{},
// 						{},
// 					},
// 				},
// 			},
// 			Query: &model.HasSLSASpec{
// 				Subject: &model.ArtifactSpec{
// 					Algorithm: ptrfrom.String("sha256"),
// 				},
// 			},
// 			ExpHS: []*model.HasSlsa{
// 				{
// 					Subject: testdata.A1out,
// 					Slsa: &model.Slsa{
// 						BuiltBy:   b1out,
// 						BuiltFrom: []*model.Artifact{testdata.A2out},
// 					},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Materials",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2, testdata.A3, testdata.A4},
// 			InBld: []*model.BuilderInputSpec{b1},
// 			Calls: []call{
// 				{
// 					Sub: []*model.ArtifactInputSpec{testdata.A1, testdata.A1, testdata.A1},
// 					BF:  [][]*model.ArtifactInputSpec{{testdata.A2}, {testdata.A2, testdata.A3}, {testdata.A4}},
// 					BB:  []*model.BuilderInputSpec{b1, b1, b1},
// 					SLSA: []*model.SLSAInputSpec{
// 						{},
// 						{},
// 						{},
// 					},
// 				},
// 			},
// 			Query: &model.HasSLSASpec{
// 				BuiltFrom: []*model.ArtifactSpec{{
// 					Digest: ptrfrom.String("7A8F47318E4676DACB0142AFA0B83029CD7BEFD9"),
// 				}},
// 			},
// 			ExpHS: []*model.HasSlsa{
// 				{
// 					Subject: testdata.A1out,
// 					Slsa: &model.Slsa{
// 						BuiltBy:   b1out,
// 						BuiltFrom: []*model.Artifact{testdata.A2out},
// 					},
// 				},
// 				{
// 					Subject: testdata.A1out,
// 					Slsa: &model.Slsa{
// 						BuiltBy:   b1out,
// 						BuiltFrom: []*model.Artifact{testdata.A2out, testdata.A3out},
// 					},
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Ingest no Materials 1",
// 			InArt: []*model.ArtifactInputSpec{testdata.A1},
// 			InBld: []*model.BuilderInputSpec{b1},
// 			Calls: []call{
// 				{
// 					Sub: []*model.ArtifactInputSpec{testdata.A1},
// 					BF:  [][]*model.ArtifactInputSpec{{}},
// 					BB:  []*model.BuilderInputSpec{b1},
// 					SLSA: []*model.SLSAInputSpec{
// 						{},
// 					},
// 				},
// 			},
// 			ExpIngestErr: true,
// 		},
// 	}
// 	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
// 		return strings.Compare(".ID", p[len(p)-1].String()) == 0
// 	}, cmp.Ignore())
// 	for _, test := range tests {
// 		t.Run(test.Name, func(t *testing.T) {
// 			for _, a := range test.InArt {
// 				if _, err := b.IngestArtifact(ctx, a); err != nil {
// 					t.Fatalf("Could not ingest artifact: %v", err)
// 				}
// 			}
// 			for _, bld := range test.InBld {
// 				if _, err := b.IngestBuilder(ctx, bld); err != nil {
// 					t.Fatalf("Could not ingest builder: %v", err)
// 				}
// 			}
// 			for _, o := range test.Calls {
// 				_, err := b.IngestSLSAs(ctx, o.Sub, o.BF, o.BB, o.SLSA)
// 				if (err != nil) != test.ExpIngestErr {
// 					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
// 				}
// 				if err != nil {
// 					return
// 				}
// 			}
// 			got, err := b.HasSlsa(ctx, test.Query)
// 			if (err != nil) != test.ExpQueryErr {
// 				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
// 			}
// 			if err != nil {
// 				return
// 			}
// 			if diff := cmp.Diff(test.ExpHS, got, ignoreID); diff != "" {
// 				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
// 			}
// 		})
// 	}
// }

// // TODO (pxp928): add tests back in when implemented

// // func TestHasSLSANeighbors(t *testing.T) {
// // 	type call struct {
// // 		Sub  *model.ArtifactInputSpec
// // 		BF   []*model.ArtifactInputSpec
// // 		BB   *model.BuilderInputSpec
// // 		SLSA *model.SLSAInputSpec
// // 	}
// // 	tests := []struct {
// // 		Name         string
// // 		InArt        []*model.ArtifactInputSpec
// // 		InBld        []*model.BuilderInputSpec
// // 		Calls        []call
// // 		ExpNeighbors map[string][]string
// // 	}{
// // 		{
// // 			Name:  "HappyPath",
// // 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// // 			InBld: []*model.BuilderInputSpec{b1},
// // 			Calls: []call{
// // 				{
// // 					Sub: testdata.A1,
// // 					BF:  []*model.ArtifactInputSpec{testdata.A2},
// // 					BB:  b1,
// // 					SLSA: &model.SLSAInputSpec{
// // 						BuildType: "test type",
// // 					},
// // 				},
// // 			},
// // 			ExpNeighbors: map[string][]string{
// // 				"1": []string{"4"},           // testdata.A1
// // 				"2": []string{"4"},           // testdata.A2
// // 				"3": []string{"4"},           // b1
// // 				"4": []string{"1", "2", "3"}, // hasSBOM
// // 			},
// // 		},
// // 		{
// // 			Name:  "Multiple",
// // 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2, testdata.A3, testdata.A4},
// // 			InBld: []*model.BuilderInputSpec{b1},
// // 			Calls: []call{
// // 				{
// // 					Sub: testdata.A1,
// // 					BF:  []*model.ArtifactInputSpec{testdata.A2},
// // 					BB:  b1,
// // 					SLSA: &model.SLSAInputSpec{
// // 						BuildType: "test type",
// // 					},
// // 				},
// // 				{
// // 					Sub: testdata.A3,
// // 					BF:  []*model.ArtifactInputSpec{testdata.A4},
// // 					BB:  b1,
// // 					SLSA: &model.SLSAInputSpec{
// // 						BuildType: "test type",
// // 					},
// // 				},
// // 			},
// // 			ExpNeighbors: map[string][]string{
// // 				"1": []string{"6"},           // testdata.A1
// // 				"2": []string{"6"},           // testdata.A2
// // 				"3": []string{"7"},           // testdata.A3
// // 				"4": []string{"7"},           // testdata.A4
// // 				"5": []string{"6", "7"},      // b1
// // 				"6": []string{"1", "2", "5"}, // hasSBOM 1
// // 				"7": []string{"3", "4", "5"}, // hasSBOM 2
// // 			},
// // 		},
// // 	}
// // 	ctx := context.Background()
// // 	for _, test := range tests {
// // 		t.Run(test.Name, func(t *testing.T) {
// // 			b, err := inmem.GetBackend(nil)
// // 			if err != nil {
// // 				t.Fatalf("Could not instantiate testing backend: %v", err)
// // 			}
// // 			for _, a := range test.InArt {
// // 				if _, err := b.IngestArtifact(ctx, a); err != nil {
// // 					t.Fatalf("Could not ingest artifact: %v", err)
// // 				}
// // 			}
// // 			for _, bld := range test.InBld {
// // 				if _, err := b.IngestBuilder(ctx, bld); err != nil {
// // 					t.Fatalf("Could not ingest builder: %v", err)
// // 				}
// // 			}
// // 			for _, o := range test.Calls {
// // 				if _, err := b.IngestSLSA(ctx, *o.Sub, o.BF, *o.BB, *o.SLSA); err != nil {
// // 					t.Fatalf("Could not ingest HasSLSA: %v", err)
// // 				}
// // 			}
// // 			for q, r := range test.ExpNeighbors {
// // 				got, err := b.Neighbors(ctx, q, nil)
// // 				if err != nil {
// // 					t.Fatalf("Could not query neighbors: %s", err)
// // 				}
// // 				gotIDs := convNodes(got)
// // 				slices.Sort(r)
// // 				slices.Sort(gotIDs)
// // 				if diff := cmp.Diff(r, gotIDs); diff != "" {
// // 					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
// // 				}
// // 			}
// // 		})
// // 	}
// // }
