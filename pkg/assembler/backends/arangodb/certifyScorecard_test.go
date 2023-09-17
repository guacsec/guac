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

func TestCertifyScorecard(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	testTime := time.Unix(1e9+5, 0)
	type call struct {
		Src *model.SourceInputSpec
		SC  *model.ScorecardInputSpec
	}
	tests := []struct {
		Name          string
		InSrc         []*model.SourceInputSpec
		Calls         []call
		Query         *model.CertifyScorecardSpec
		QueryID       bool
		QuerySourceID bool
		ExpSC         []*model.CertifyScorecard
		ExpIngestErr  bool
		ExpQueryErr   bool
	}{
		{
			Name:  "HappyPath",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						Origin: "test origin",
					},
				},
			},
			Query: &model.CertifyScorecardSpec{
				Origin: ptrfrom.String("test origin"),
			},
			ExpSC: []*model.CertifyScorecard{
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks: []*model.ScorecardCheck{},
						Origin: "test origin",
					},
				},
			},
		},
		{
			Name:  "Ingest same",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						Origin: "test origin",
					},
				},
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						Origin: "test origin",
					},
				},
			},
			Query: &model.CertifyScorecardSpec{
				Origin: ptrfrom.String("test origin"),
			},
			ExpSC: []*model.CertifyScorecard{
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks: []*model.ScorecardCheck{},
						Origin: "test origin",
					},
				},
			},
		},
		{
			Name:  "Query on Source ID",
			InSrc: []*model.SourceInputSpec{testdata.S1, testdata.S2},
			Calls: []call{
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						Origin: "test origin",
					},
				},
				{
					Src: testdata.S2,
					SC: &model.ScorecardInputSpec{
						Origin: "test origin",
					},
				},
			},
			QuerySourceID: true,
			ExpSC: []*model.CertifyScorecard{
				{
					Source: testdata.S2out,
					Scorecard: &model.Scorecard{
						Checks: []*model.ScorecardCheck{},
						Origin: "test origin",
					},
				},
			},
		},
		{
			Name:  "Query multiple",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						Origin: "test origin one",
					},
				},
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						AggregateScore: 4.4,
						Origin:         "test origin two",
					},
				},
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						AggregateScore: 4.9,
						Origin:         "test origin two",
					},
				},
			},
			Query: &model.CertifyScorecardSpec{
				Origin: ptrfrom.String("test origin two"),
			},
			ExpSC: []*model.CertifyScorecard{
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks:         []*model.ScorecardCheck{},
						AggregateScore: 4.4,
						Origin:         "test origin two",
					},
				},
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks:         []*model.ScorecardCheck{},
						AggregateScore: 4.9,
						Origin:         "test origin two",
					},
				},
			},
		},
		{
			Name:  "Query Source",
			InSrc: []*model.SourceInputSpec{testdata.S1, testdata.S2},
			Calls: []call{
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						Origin: "test origin",
					},
				},
				{
					Src: testdata.S2,
					SC: &model.ScorecardInputSpec{
						Origin: "test origin",
					},
				},
			},
			Query: &model.CertifyScorecardSpec{
				Source: &model.SourceSpec{
					Namespace: ptrfrom.String("github.com/jeff"),
				},
			},
			ExpSC: []*model.CertifyScorecard{
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks:         []*model.ScorecardCheck{},
						AggregateScore: 4.9,
						Origin:         "test origin two",
					},
				},
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks:         []*model.ScorecardCheck{},
						AggregateScore: 4.4,
						Origin:         "test origin two",
					},
				},
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks: []*model.ScorecardCheck{},
						Origin: "test origin one",
					},
				},
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks: []*model.ScorecardCheck{},
						Origin: "test origin",
					},
				},
			},
		},
		{
			Name:  "Query Time",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						AggregateScore:   1.5,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						AggregateScore:   1.5,
						TimeScanned:      testTime,
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
			},
			Query: &model.CertifyScorecardSpec{
				TimeScanned: &testTime,
			},
			ExpSC: []*model.CertifyScorecard{
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks:           []*model.ScorecardCheck{},
						AggregateScore:   1.5,
						TimeScanned:      testTime,
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
			},
		},
		{
			Name:  "Query Score",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						AggregateScore:   1.5,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						AggregateScore:   5.7,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
			},
			Query: &model.CertifyScorecardSpec{
				AggregateScore: ptrfrom.Float64(57.0 / 10),
			},
			ExpSC: []*model.CertifyScorecard{
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks:           []*model.ScorecardCheck{},
						AggregateScore:   5.7,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
			},
		},
		{
			Name:  "Query Checks",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						Checks: []*model.ScorecardCheckInputSpec{
							{
								Check: "check one",
								Score: 5,
							},
						},
						ScorecardVersion: "123",
					},
				},
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						Checks: []*model.ScorecardCheckInputSpec{
							{
								Check: "check one",
								Score: 5,
							},
							{
								Check: "check two",
								Score: 6,
							},
						},
						ScorecardVersion: "456",
					},
				},
			},
			Query: &model.CertifyScorecardSpec{
				Checks: []*model.ScorecardCheckSpec{
					{
						Check: "check one",
						Score: 5,
					},
				},
			},
			ExpSC: []*model.CertifyScorecard{
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks: []*model.ScorecardCheck{
							{
								Check: "check one",
								Score: 5,
							},
						},
						ScorecardVersion: "123",
					},
				},
			},
		},
		{
			Name:  "Query None",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						AggregateScore:   1.5,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						AggregateScore:   5.7,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
			},
			Query: &model.CertifyScorecardSpec{
				ScorecardVersion: ptrfrom.String("853"),
			},
			ExpSC: nil,
		},
		{
			Name:  "Query commit",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						AggregateScore:   1.5,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						AggregateScore:   5.7,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
			},
			Query: &model.CertifyScorecardSpec{
				ScorecardCommit: ptrfrom.String("abc"),
			},
			ExpSC: []*model.CertifyScorecard{
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks:           []*model.ScorecardCheck{},
						AggregateScore:   1.5,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks:           []*model.ScorecardCheck{},
						AggregateScore:   1.5,
						TimeScanned:      testTime,
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks:           []*model.ScorecardCheck{},
						AggregateScore:   5.7,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
			},
		},
		{
			Name:  "Query ID",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						AggregateScore:   1.5,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
			},
			QueryID: true,
			ExpSC: []*model.CertifyScorecard{
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks:           []*model.ScorecardCheck{},
						AggregateScore:   1.5,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
			},
		},
		{
			Name:  "Query bad ID",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Src: testdata.S1,
					SC: &model.ScorecardInputSpec{
						AggregateScore:   1.5,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
			},
			Query: &model.CertifyScorecardSpec{
				ID: ptrfrom.String("4294967296"),
			},
			ExpQueryErr: false,
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, s := range test.InSrc {
				if _, err := b.IngestSource(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, o := range test.Calls {
				found, err := b.IngestScorecard(ctx, *o.Src, *o.SC)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.CertifyScorecardSpec{
						ID: ptrfrom.String(found.ID),
					}
				}
				if test.QuerySourceID {
					test.Query = &model.CertifyScorecardSpec{
						Source: &model.SourceSpec{
							ID: ptrfrom.String(found.Source.Namespaces[0].Names[0].ID),
						},
					}

				}
			}
			got, err := b.Scorecards(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpSC, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestScorecards(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	type call struct {
		Src []*model.SourceInputSpec
		SC  []*model.ScorecardInputSpec
	}
	tests := []struct {
		Name         string
		InSrc        []*model.SourceInputSpec
		Calls        []call
		Query        *model.CertifyScorecardSpec
		ExpSC        []*model.CertifyScorecard
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Src: []*model.SourceInputSpec{testdata.S1},
					SC: []*model.ScorecardInputSpec{
						{
							Origin: "test origin",
						},
					},
				},
			},
			Query: &model.CertifyScorecardSpec{
				Origin: ptrfrom.String("test origin"),
			},
			ExpSC: []*model.CertifyScorecard{
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks: []*model.ScorecardCheck{},
						Origin: "test origin",
					},
				},
			},
		},
		{
			Name:  "Ingest same",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Src: []*model.SourceInputSpec{testdata.S1, testdata.S1},
					SC: []*model.ScorecardInputSpec{
						{
							Origin: "test origin",
						},
						{
							Origin: "test origin",
						},
					},
				},
			},
			Query: &model.CertifyScorecardSpec{
				Origin: ptrfrom.String("test origin"),
			},
			ExpSC: []*model.CertifyScorecard{
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks: []*model.ScorecardCheck{},
						Origin: "test origin",
					},
				},
			},
		},
		{
			Name:  "Query multiple",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Src: []*model.SourceInputSpec{testdata.S1, testdata.S1, testdata.S1},
					SC: []*model.ScorecardInputSpec{
						{
							Origin: "test origin one",
						},
						{
							AggregateScore: 4.4,
							Origin:         "test origin two",
						},
						{
							AggregateScore: 4.9,
							Origin:         "test origin two",
						},
					},
				},
			},
			Query: &model.CertifyScorecardSpec{
				Origin: ptrfrom.String("test origin two"),
			},
			ExpSC: []*model.CertifyScorecard{
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks:         []*model.ScorecardCheck{},
						AggregateScore: 4.4,
						Origin:         "test origin two",
					},
				},
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks:         []*model.ScorecardCheck{},
						AggregateScore: 4.9,
						Origin:         "test origin two",
					},
				},
			},
		},
		{
			Name:  "Query Source",
			InSrc: []*model.SourceInputSpec{testdata.S1, testdata.S2},
			Calls: []call{
				{
					Src: []*model.SourceInputSpec{testdata.S1, testdata.S2},
					SC: []*model.ScorecardInputSpec{
						{
							Origin: "test origin",
						},
						{
							Origin: "test origin",
						},
					},
				},
			},
			Query: &model.CertifyScorecardSpec{
				Source: &model.SourceSpec{
					Namespace: ptrfrom.String("github.com/jeff"),
				},
			},
			ExpSC: []*model.CertifyScorecard{
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks:         []*model.ScorecardCheck{},
						AggregateScore: 4.9,
						Origin:         "test origin two",
					},
				},
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks:         []*model.ScorecardCheck{},
						AggregateScore: 4.4,
						Origin:         "test origin two",
					},
				},
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks: []*model.ScorecardCheck{},
						Origin: "test origin one",
					},
				},
				{
					Source: testdata.S1out,
					Scorecard: &model.Scorecard{
						Checks: []*model.ScorecardCheck{},
						Origin: "test origin",
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
			for _, s := range test.InSrc {
				if _, err := b.IngestSource(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, o := range test.Calls {
				_, err := b.IngestScorecards(ctx, o.Src, o.SC)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.Scorecards(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpSC, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

// TODO (pxp928): add tests back in when implemented

// func TestCertifyScorecardNeighbors(t *testing.T) {
// 	type call struct {
// 		Src *model.SourceInputSpec
// 		SC  *model.ScorecardInputSpec
// 	}
// 	tests := []struct {
// 		Name         string
// 		InSrc        []*model.SourceInputSpec
// 		Calls        []call
// 		ExpNeighbors map[string][]string
// 	}{
// 		{
// 			Name:  "HappyPath",
// 			InSrc: []*model.SourceInputSpec{testdata.S1},
// 			Calls: []call{
// 				{
// 					Src: testdata.S1,
// 					SC: &model.ScorecardInputSpec{
// 						Origin: "test origin",
// 					},
// 				},
// 			},
// 			ExpNeighbors: map[string][]string{
// 				"3": []string{"1", "4"}, // src name
// 				"4": []string{"1"},      // SC
// 			},
// 		},
// 		{
// 			Name:  "Multiple",
// 			InSrc: []*model.SourceInputSpec{testdata.S1, testdata.S2},
// 			Calls: []call{
// 				{
// 					Src: testdata.S1,
// 					SC: &model.ScorecardInputSpec{
// 						Origin: "test origin",
// 					},
// 				},
// 				{
// 					Src: testdata.S2,
// 					SC: &model.ScorecardInputSpec{
// 						Origin: "test origin",
// 					},
// 				},
// 				{
// 					Src: testdata.S2,
// 					SC: &model.ScorecardInputSpec{
// 						Origin: "test origin two",
// 					},
// 				},
// 			},
// 			ExpNeighbors: map[string][]string{
// 				// test sources are all type git, id:2
// 				"3": []string{"1", "6"},      // src name 1 -> src namespace, SC1
// 				"5": []string{"1", "7", "8"}, // src name 2 -> src namespace, SC2, SC3
// 				"6": []string{"1"},           // SC 1
// 				"7": []string{"1"},           // SC 2
// 				"8": []string{"1"},           // SC 3
// 			},
// 		},
// 	}
// 	ctx := context.Background()
// 	for _, test := range tests {
// 		t.Run(test.Name, func(t *testing.T) {
// 			b, err := inmem.getBackend(nil)
// 			if err != nil {
// 				t.Fatalf("Could not instantiate testing backend: %v", err)
// 			}
// 			for _, s := range test.InSrc {
// 				if _, err := b.IngestSource(ctx, *s); err != nil {
// 					t.Fatalf("Could not ingest source: %v", err)
// 				}
// 			}
// 			for _, o := range test.Calls {
// 				if _, err := b.IngestScorecard(ctx, *o.Src, *o.SC); err != nil {
// 					t.Fatalf("Could not ingest CertifyScorecard: %v", err)
// 				}
// 			}
// 			for q, r := range test.ExpNeighbors {
// 				got, err := b.Neighbors(ctx, q, nil)
// 				if err != nil {
// 					t.Fatalf("Could not query neighbors: %s", err)
// 				}
// 				gotIDs := convNodes(got)
// 				slices.Sort(r)
// 				slices.Sort(gotIDs)
// 				if diff := cmp.Diff(r, gotIDs); diff != "" {
// 					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
// 				}
// 			}
// 		})
// 	}
// }
