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
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestHasSLSA(t *testing.T) {
	ctx := context.Background()
	arangoArgs := getArangoConfig()
	err := DeleteDatabase(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	testTime := time.Unix(1e9+5, 0)
	testTime2 := time.Unix(1e9, 0)
	startTime := time.Now()
	finishTime := time.Now().Add(10 * time.Second)
	inputPredicate := []*model.SLSAPredicateInputSpec{
		{
			Key:   "buildDefinition.externalParameters.repository",
			Value: "https://github.com/octocat/hello-world",
		},
		{
			Key:   "buildDefinition.externalParameters.ref",
			Value: "refs/heads/main",
		},
		{
			Key:   "buildDefinition.resolvedDependencies.uri",
			Value: "git+https://github.com/octocat/hello-world@refs/heads/main",
		},
	}

	slsaPredicate := []*model.SLSAPredicate{
		{
			Key:   "buildDefinition.externalParameters.ref",
			Value: "refs/heads/main",
		},
		{
			Key:   "buildDefinition.externalParameters.repository",
			Value: "https://github.com/octocat/hello-world",
		},
		{
			Key:   "buildDefinition.resolvedDependencies.uri",
			Value: "git+https://github.com/octocat/hello-world@refs/heads/main",
		},
	}
	type call struct {
		Sub  *model.ArtifactInputSpec
		BF   []*model.ArtifactInputSpec
		BB   *model.BuilderInputSpec
		SLSA *model.SLSAInputSpec
	}
	tests := []struct {
		Name           string
		InArt          []*model.ArtifactInputSpec
		InBld          []*model.BuilderInputSpec
		Calls          []call
		Query          *model.HasSLSASpec
		QueryID        bool
		QuerySubjectID bool
		QueryBuilderID bool
		ExpHS          []*model.HasSlsa
		ExpIngestErr   bool
		ExpQueryErr    bool
	}{
		{
			Name: "unknown",
			InArt: []*model.ArtifactInputSpec{
				{
					Digest:    "5a787865sd676dacb0142afa0b83029cd7befd9",
					Algorithm: "sha1",
				},
				{
					Digest:    "0123456789abcdef0000000fedcba9876543210",
					Algorithm: "sha1",
				},
			},
			InBld: []*model.BuilderInputSpec{
				{
					URI: "https://github.com/BuildPythonWheel/HubHostedActions@v1",
				},
			},
			Calls: []call{
				{
					Sub: &model.ArtifactInputSpec{
						Digest:    "5a787865sd676dacb0142afa0b83029cd7befd9",
						Algorithm: "sha1",
					},
					BF: []*model.ArtifactInputSpec{{
						Digest:    "0123456789abcdef0000000fedcba9876543210",
						Algorithm: "sha1",
					}},
					BB: &model.BuilderInputSpec{
						URI: "https://github.com/BuildPythonWheel/HubHostedActions@v1",
					},
					SLSA: &model.SLSAInputSpec{
						BuildType:     "Test:SLSA",
						SlsaPredicate: inputPredicate,
						SlsaVersion:   "v1",
						StartedOn:     &startTime,
						FinishedOn:    &finishTime,
						Origin:        "Demo ingestion",
						Collector:     "Demo ingestion",
					},
				},
			},
			Query: &model.HasSLSASpec{
				BuildType: ptrfrom.String("Test:SLSA"),
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: &model.Artifact{
						Digest:    "5a787865sd676dacb0142afa0b83029cd7befd9",
						Algorithm: "sha1",
					},
					Slsa: &model.Slsa{
						BuiltBy: &model.Builder{
							URI: "https://github.com/BuildPythonWheel/HubHostedActions@v1",
						},
						BuiltFrom: []*model.Artifact{{
							Digest:    "0123456789abcdef0000000fedcba9876543210",
							Algorithm: "sha1",
						}},
						BuildType:     "Test:SLSA",
						SlsaPredicate: slsaPredicate,
						SlsaVersion:   "v1",
						StartedOn:     &startTime,
						FinishedOn:    &finishTime,
						Origin:        "Demo ingestion",
						Collector:     "Demo ingestion",
					},
				},
			},
		},
		{
			Name:  "HappyPath",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InBld: []*model.BuilderInputSpec{testdata.B1},
			Calls: []call{
				{
					Sub: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					BF:  []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:  &model.IDorBuilderInput{BuilderInput: testdata.B1},
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
					Subject: testdata.A1out,
					Slsa: &model.Slsa{
						BuiltBy:   testdata.B1out,
						BuiltFrom: []*model.Artifact{testdata.A2out},
						BuildType: "test type",
					},
				},
			},
		},
		{
			Name:  "Ingest twice",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InBld: []*model.BuilderInputSpec{testdata.B1},
			Calls: []call{
				{
					Sub: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					BF:  []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:  &model.IDorBuilderInput{BuilderInput: testdata.B1},
					SLSA: &model.SLSAInputSpec{
						BuildType: "test type",
					},
				},
				{
					Sub: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					BF:  []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:  &model.IDorBuilderInput{BuilderInput: testdata.B1},
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
					Subject: testdata.A1out,
					Slsa: &model.Slsa{
						BuiltBy:   testdata.B1out,
						BuiltFrom: []*model.Artifact{testdata.A2out},
						BuildType: "test type",
					},
				},
			},
		},
		{
			Name:  "Query on Build Type",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InBld: []*model.BuilderInputSpec{testdata.B1},
			Calls: []call{
				{
					Sub: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					BF:  []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:  &model.IDorBuilderInput{BuilderInput: testdata.B1},
					SLSA: &model.SLSAInputSpec{
						BuildType: "test type one",
					},
				},
				{
					Sub: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					BF:  []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:  &model.IDorBuilderInput{BuilderInput: testdata.B1},
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
					Subject: testdata.A1out,
					Slsa: &model.Slsa{
						BuiltBy:   testdata.B1out,
						BuiltFrom: []*model.Artifact{testdata.A2out},
						BuildType: "test type one",
					},
				},
			},
		},
		{
			Name:  "Query on Version",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InBld: []*model.BuilderInputSpec{testdata.B1},
			Calls: []call{
				{
					Sub: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					BF:  []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:  &model.IDorBuilderInput{BuilderInput: testdata.B1},
					SLSA: &model.SLSAInputSpec{
						SlsaVersion: "test type one",
					},
				},
				{
					Sub: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					BF:  []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:  &model.IDorBuilderInput{BuilderInput: testdata.B1},
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
					Subject: testdata.A1out,
					Slsa: &model.Slsa{
						BuiltBy:     testdata.B1out,
						BuiltFrom:   []*model.Artifact{testdata.A2out},
						SlsaVersion: "test type two",
					},
				},
			},
		},
		{
			Name:  "Query on Time",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InBld: []*model.BuilderInputSpec{testdata.B1},
			Calls: []call{
				{
					Sub: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					BF:  []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:  &model.IDorBuilderInput{BuilderInput: testdata.B1},
					SLSA: &model.SLSAInputSpec{
						StartedOn: &testTime2,
					},
				},
				{
					Sub: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					BF:  []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:  &model.IDorBuilderInput{BuilderInput: testdata.B1},
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
					Subject: testdata.A1out,
					Slsa: &model.Slsa{
						BuiltBy:   testdata.B1out,
						BuiltFrom: []*model.Artifact{testdata.A2out},
						StartedOn: &testTime,
					},
				},
			},
		},
		{
			Name:  "Query on Time",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InBld: []*model.BuilderInputSpec{testdata.B1},
			Calls: []call{
				{
					Sub: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					BF:  []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:  &model.IDorBuilderInput{BuilderInput: testdata.B1},
					SLSA: &model.SLSAInputSpec{
						FinishedOn: &testTime2,
					},
				},
				{
					Sub: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					BF:  []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:  &model.IDorBuilderInput{BuilderInput: testdata.B1},
					SLSA: &model.SLSAInputSpec{
						FinishedOn: &testTime,
					},
				},
			},
			Query: &model.HasSLSASpec{
				FinishedOn: &testTime,
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: testdata.A1out,
					Slsa: &model.Slsa{
						BuiltBy:    testdata.B1out,
						BuiltFrom:  []*model.Artifact{testdata.A2out},
						FinishedOn: &testTime,
					},
				},
			},
		},
		{
			Name:  "Query on Subject",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2, testdata.A3},
			InBld: []*model.BuilderInputSpec{testdata.B1},
			Calls: []call{
				{
					Sub:  testdata.A1,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B1,
					SLSA: &model.SLSAInputSpec{},
				},
				{
					Sub:  testdata.A3,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B1,
					SLSA: &model.SLSAInputSpec{},
				},
			},
			Query: &model.HasSLSASpec{
				Subject: &model.ArtifactSpec{
					Algorithm: ptrfrom.String("sha256"),
					Digest:    ptrfrom.String("6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"),
				},
				SlsaVersion: ptrfrom.String("test type one"),
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: testdata.A1out,
					Slsa: &model.Slsa{
						BuiltBy:     testdata.B1out,
						BuiltFrom:   []*model.Artifact{testdata.A2out},
						SlsaVersion: "test type one",
					},
				},
			},
		},
		{
			Name:  "Query on Subject ID",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2, testdata.A3},
			InBld: []*model.BuilderInputSpec{testdata.B1},
			Calls: []call{
				{
					Sub:  testdata.A1,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B1,
					SLSA: &model.SLSAInputSpec{},
				},
				{
					Sub:  testdata.A3,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B1,
					SLSA: &model.SLSAInputSpec{},
				},
			},
			QuerySubjectID: true,
			ExpHS: []*model.HasSlsa{
				{
					Subject: testdata.A3out,
					Slsa: &model.Slsa{
						BuiltBy:   testdata.B1out,
						BuiltFrom: []*model.Artifact{testdata.A2out},
					},
				},
			},
		},
		{
			Name:  "Query on Materials",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2, testdata.A3, testdata.A4},
			InBld: []*model.BuilderInputSpec{testdata.B1},
			Calls: []call{
				{
					Sub:  testdata.A1,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B1,
					SLSA: &model.SLSAInputSpec{},
				},
				{
					Sub:  testdata.A1,
					BF:   []*model.ArtifactInputSpec{testdata.A2, testdata.A3},
					BB:   testdata.B1,
					SLSA: &model.SLSAInputSpec{},
				},
				{
					Sub:  testdata.A1,
					BF:   []*model.ArtifactInputSpec{testdata.A4},
					BB:   testdata.B1,
					SLSA: &model.SLSAInputSpec{},
				},
			},
			Query: &model.HasSLSASpec{
				BuiltFrom: []*model.ArtifactSpec{{
					Digest: ptrfrom.String("5a787865sd676dacb0142afa0b83029cd7befd9"),
				}},
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: testdata.A1out,
					Slsa: &model.Slsa{
						BuiltBy:   testdata.B1out,
						BuiltFrom: []*model.Artifact{testdata.A4out},
					},
				},
			},
		},
		{
			Name:  "Query on Builder",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InBld: []*model.BuilderInputSpec{testdata.B1, testdata.B2},
			Calls: []call{
				{
					Sub:  testdata.A1,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B1,
					SLSA: &model.SLSAInputSpec{},
				},
				{
					Sub:  testdata.A1,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B2,
					SLSA: &model.SLSAInputSpec{},
				},
			},
			Query: &model.HasSLSASpec{
				BuiltBy: &model.BuilderSpec{
					URI: ptrfrom.String("qwer"),
				},
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: testdata.A1out,
					Slsa: &model.Slsa{
						BuiltBy:   testdata.B2out,
						BuiltFrom: []*model.Artifact{testdata.A2out},
					},
				},
			},
		},
		{
			Name:  "Query on Builder ID",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2, testdata.A3},
			InBld: []*model.BuilderInputSpec{testdata.B1, testdata.B2},
			Calls: []call{
				{
					Sub:  testdata.A1,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B1,
					SLSA: &model.SLSAInputSpec{},
				},
				{
					Sub:  testdata.A3,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B2,
					SLSA: &model.SLSAInputSpec{},
				},
			},
			QueryBuilderID: true,
			ExpHS: []*model.HasSlsa{
				{
					Subject: testdata.A1out,
					Slsa: &model.Slsa{
						BuiltBy:   testdata.B2out,
						BuiltFrom: []*model.Artifact{testdata.A2out},
					},
				},
				{
					Subject: testdata.A3out,
					Slsa: &model.Slsa{
						BuiltBy:   testdata.B2out,
						BuiltFrom: []*model.Artifact{testdata.A2out},
					},
				},
			},
		},
		{
			Name:  "Query on ID",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InBld: []*model.BuilderInputSpec{testdata.B1, testdata.B2},
			Calls: []call{
				{
					Sub:  testdata.A1,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B1,
					SLSA: &model.SLSAInputSpec{},
				},
				{
					Sub:  testdata.A1,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B2,
					SLSA: &model.SLSAInputSpec{},
				},
			},
			QueryID: true,
			ExpHS: []*model.HasSlsa{
				{
					Subject: testdata.A1out,
					Slsa: &model.Slsa{
						BuiltBy:   testdata.B2out,
						BuiltFrom: []*model.Artifact{testdata.A2out},
					},
				},
			},
		},
		{
			Name:  "Query none",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InBld: []*model.BuilderInputSpec{testdata.B1, testdata.B2},
			Calls: []call{
				{
					Sub:  testdata.A1,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B1,
					SLSA: &model.SLSAInputSpec{},
				},
				{
					Sub:  testdata.A1,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B2,
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
			Name:  "Query bad ID",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InBld: []*model.BuilderInputSpec{testdata.B1, testdata.B2},
			Calls: []call{
				{
					Sub:  testdata.A1,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B1,
					SLSA: &model.SLSAInputSpec{},
				},
				{
					Sub:  testdata.A1,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B2,
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
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, a := range test.InArt {
				if artID, err := b.IngestArtifact(ctx, &model.IDorArtifactInput{ArtifactInput: a}); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				} else {
					if test.QuerySubjectID {
						test.Query = &model.HasSLSASpec{
							Subject: &model.ArtifactSpec{
								ID: ptrfrom.String(artID),
							},
						}
					}
				}
			}
			for _, bld := range test.InBld {
				if buildID, err := b.IngestBuilder(ctx, bld); err != nil {
					t.Fatalf("Could not ingest builder: %v", err)
				} else {
					if test.QueryBuilderID {
						test.Query = &model.HasSLSASpec{
							BuiltBy: &model.BuilderSpec{
								ID: ptrfrom.String(buildID),
							},
						}
					}
				}
			}
			for _, o := range test.Calls {
				slsaID, err := b.IngestSLSA(ctx, *o.Sub, o.BF, *o.BB, *o.SLSA)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.HasSLSASpec{
						ID: ptrfrom.String(slsaID),
					}
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

func TestIngestHasSLSAs(t *testing.T) {
	ctx := context.Background()
	arangoArgs := getArangoConfig()
	err := DeleteDatabase(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
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
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InBld: []*model.BuilderInputSpec{testdata.B1},
			Calls: []call{
				{
					Sub: []*model.ArtifactInputSpec{testdata.A1},
					BF:  [][]*model.ArtifactInputSpec{{testdata.A2}},
					BB:  []*model.BuilderInputSpec{testdata.B1},
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
					Subject: testdata.A1out,
					Slsa: &model.Slsa{
						BuiltBy:   testdata.B1out,
						BuiltFrom: []*model.Artifact{testdata.A2out},
						BuildType: "test type",
					},
				},
			},
		},
		{
			Name:  "Ingest twice",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InBld: []*model.BuilderInputSpec{testdata.B1},
			Calls: []call{
				{
					Sub: []*model.ArtifactInputSpec{testdata.A1, testdata.A1},
					BF:  [][]*model.ArtifactInputSpec{{testdata.A2}, {testdata.A2}},
					BB:  []*model.BuilderInputSpec{testdata.B1, testdata.B1},
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
					Subject: testdata.A1out,
					Slsa: &model.Slsa{
						BuiltBy:   testdata.B1out,
						BuiltFrom: []*model.Artifact{testdata.A2out},
						BuildType: "test type",
					},
				},
			},
		},
		{
			Name:  "Query on Build Type",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InBld: []*model.BuilderInputSpec{testdata.B1},
			Calls: []call{
				{
					Sub: []*model.ArtifactInputSpec{testdata.A1, testdata.A1},
					BF:  [][]*model.ArtifactInputSpec{{testdata.A2}, {testdata.A2}},
					BB:  []*model.BuilderInputSpec{testdata.B1, testdata.B1},
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
					Subject: testdata.A1out,
					Slsa: &model.Slsa{
						BuiltBy:   testdata.B1out,
						BuiltFrom: []*model.Artifact{testdata.A2out},
						BuildType: "test type one",
					},
				},
			},
		},
		{
			Name:  "Query on Subject",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2, testdata.A3},
			InBld: []*model.BuilderInputSpec{testdata.B1},
			Calls: []call{
				{
					Sub: []*model.ArtifactInputSpec{testdata.A1, testdata.A3},
					BF:  [][]*model.ArtifactInputSpec{{testdata.A2}, {testdata.A2}},
					BB:  []*model.BuilderInputSpec{testdata.B1, testdata.B1},
					SLSA: []*model.SLSAInputSpec{
						{SlsaVersion: "test type one"},
						{},
					},
				},
			},
			Query: &model.HasSLSASpec{
				Subject: &model.ArtifactSpec{
					Algorithm: ptrfrom.String("sha256"),
					Digest:    ptrfrom.String("6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"),
				},
				SlsaVersion: ptrfrom.String("test type one"),
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: testdata.A1out,
					Slsa: &model.Slsa{
						BuiltBy:     testdata.B1out,
						BuiltFrom:   []*model.Artifact{testdata.A2out},
						SlsaVersion: "test type one",
					},
				},
			},
		},
		{
			Name:  "Query on Materials",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2, testdata.A3, testdata.A4},
			InBld: []*model.BuilderInputSpec{testdata.B1},
			Calls: []call{
				{
					Sub: []*model.ArtifactInputSpec{testdata.A1, testdata.A1, testdata.A1},
					BF:  [][]*model.ArtifactInputSpec{{testdata.A2}, {testdata.A2, testdata.A3}, {testdata.A4}},
					BB:  []*model.BuilderInputSpec{testdata.B1, testdata.B1, testdata.B1},
					SLSA: []*model.SLSAInputSpec{
						{},
						{},
						{},
					},
				},
			},
			Query: &model.HasSLSASpec{
				BuiltFrom: []*model.ArtifactSpec{{
					Digest: ptrfrom.String("5a787865sd676dacb0142afa0b83029cd7befd9"),
				}},
			},
			ExpHS: []*model.HasSlsa{
				{
					Subject: testdata.A1out,
					Slsa: &model.Slsa{
						BuiltBy:   testdata.B1out,
						BuiltFrom: []*model.Artifact{testdata.A4out},
					},
				},
			},
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, &model.IDorArtifactInput{ArtifactInput: a}); err != nil {
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

func Test_buildHasSlsaByID(t *testing.T) {
	ctx := context.Background()
	arangoArgs := getArangoConfig()
	err := DeleteDatabase(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangoArgs)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
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
		ExpHS        *model.HasSlsa
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "Query on Subject",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InBld: []*model.BuilderInputSpec{testdata.B1},
			Calls: []call{
				{
					Sub: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					BF:  []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:  &model.IDorBuilderInput{BuilderInput: testdata.B1},
					SLSA: &model.SLSAInputSpec{
						BuildType: "test type one",
					},
				},
			},
			Query: &model.HasSLSASpec{
				Subject: &model.ArtifactSpec{
					Algorithm: ptrfrom.String("sha256"),
					Digest:    ptrfrom.String("6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"),
				},
				BuildType: ptrfrom.String("test type one"),
			},
			ExpHS: &model.HasSlsa{
				Subject: testdata.A1out,
				Slsa: &model.Slsa{
					BuiltBy:   testdata.B1out,
					BuiltFrom: []*model.Artifact{testdata.A2out},
					BuildType: "test type one",
				},
			},
		},
		{
			Name:  "Query on Subject ID",
			InArt: []*model.ArtifactInputSpec{testdata.A2, testdata.A3},
			InBld: []*model.BuilderInputSpec{testdata.B1},
			Calls: []call{
				{
					Sub:  testdata.A3,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B1,
					SLSA: &model.SLSAInputSpec{},
				},
			},
			ExpHS: &model.HasSlsa{
				Subject: testdata.A3out,
				Slsa: &model.Slsa{
					BuiltBy:   testdata.B1out,
					BuiltFrom: []*model.Artifact{testdata.A2out},
				},
			},
		},
		{
			Name:  "Query on Materials",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A4},
			InBld: []*model.BuilderInputSpec{testdata.B1},
			Calls: []call{
				{
					Sub:  testdata.A1,
					BF:   []*model.ArtifactInputSpec{testdata.A4},
					BB:   testdata.B1,
					SLSA: &model.SLSAInputSpec{},
				},
			},
			Query: &model.HasSLSASpec{
				BuiltFrom: []*model.ArtifactSpec{{
					Digest: ptrfrom.String("5a787865sd676dacb0142afa0b83029cd7befd9"),
				}},
			},
			ExpHS: &model.HasSlsa{
				Subject: testdata.A1out,
				Slsa: &model.Slsa{
					BuiltBy:   testdata.B1out,
					BuiltFrom: []*model.Artifact{testdata.A4out},
				},
			},
		},
		{
			Name:  "Query on Builder",
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			InBld: []*model.BuilderInputSpec{testdata.B2},
			Calls: []call{
				{
					Sub:  testdata.A1,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B2,
					SLSA: &model.SLSAInputSpec{},
				},
			},
			Query: &model.HasSLSASpec{
				BuiltBy: &model.BuilderSpec{
					URI: ptrfrom.String("qwer"),
				},
			},
			ExpHS: &model.HasSlsa{
				Subject: testdata.A1out,
				Slsa: &model.Slsa{
					BuiltBy:   testdata.B2out,
					BuiltFrom: []*model.Artifact{testdata.A2out},
				},
			},
		},
		{
			Name:  "Query on Builder ID",
			InArt: []*model.ArtifactInputSpec{testdata.A2, testdata.A3},
			InBld: []*model.BuilderInputSpec{testdata.B2},
			Calls: []call{
				{
					Sub:  testdata.A3,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B2,
					SLSA: &model.SLSAInputSpec{},
				},
			},
			ExpHS: &model.HasSlsa{
				Subject: testdata.A3out,
				Slsa: &model.Slsa{
					BuiltBy:   testdata.B2out,
					BuiltFrom: []*model.Artifact{testdata.A2out},
				},
			},
		},
		{
			Name:  "Query on ID",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InBld: []*model.BuilderInputSpec{testdata.B1, testdata.B2},
			Calls: []call{
				{
					Sub:  testdata.A1,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B2,
					SLSA: &model.SLSAInputSpec{},
				},
			},
			ExpHS: &model.HasSlsa{
				Subject: testdata.A1out,
				Slsa: &model.Slsa{
					BuiltBy:   testdata.B2out,
					BuiltFrom: []*model.Artifact{testdata.A2out},
				},
			},
		},
		{
			Name:  "Query bad ID",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InBld: []*model.BuilderInputSpec{testdata.B2},
			Calls: []call{
				{
					Sub:  testdata.A1,
					BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					BB:   testdata.B2,
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
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, &model.IDorArtifactInput{ArtifactInput: a}); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, bld := range test.InBld {
				if _, err := b.IngestBuilder(ctx, bld); err != nil {
					t.Fatalf("Could not ingest builder: %v", err)
				}
			}
			for _, o := range test.Calls {
				slsaID, err := b.IngestSLSA(ctx, *o.Sub, o.BF, *o.BB, *o.SLSA)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				got, err := b.(*arangoClient).buildHasSlsaByID(ctx, slsaID, test.Query)
				if (err != nil) != test.ExpQueryErr {
					t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
				}
				if err != nil {
					return
				}
				if diff := cmp.Diff(test.ExpHS, got, ignoreID); diff != "" {
					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
				}
			}

		})
	}
}
