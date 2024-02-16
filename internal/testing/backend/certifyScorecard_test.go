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

package backend_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestCertifyScorecard(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
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
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, s := range test.InSrc {
				if srcID, err := b.IngestSource(ctx, model.IDorSourceInput{SourceInput: s}); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				} else {
					if test.QuerySourceID {
						test.Query = &model.CertifyScorecardSpec{
							Source: &model.SourceSpec{
								ID: ptrfrom.String(srcID.SourceNameID),
							},
						}

					}
				}
			}
			for _, o := range test.Calls {
				scoreID, err := b.IngestScorecard(ctx, model.IDorSourceInput{SourceInput: o.Src}, *o.SC)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.CertifyScorecardSpec{
						ID: ptrfrom.String(scoreID),
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
			if diff := cmp.Diff(test.ExpSC, got, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestScorecards(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	type call struct {
		Src []*model.IDorSourceInput
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
					Src: []*model.IDorSourceInput{{SourceInput: testdata.S1}},
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
					Src: []*model.IDorSourceInput{{SourceInput: testdata.S1}, {SourceInput: testdata.S1}},
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
					Src: []*model.IDorSourceInput{{SourceInput: testdata.S1}, {SourceInput: testdata.S1}, {SourceInput: testdata.S1}},
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
					Src: []*model.IDorSourceInput{{SourceInput: testdata.S1}, {SourceInput: testdata.S2}},
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
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, s := range test.InSrc {
				if _, err := b.IngestSource(ctx, model.IDorSourceInput{SourceInput: s}); err != nil {
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
			if diff := cmp.Diff(test.ExpSC, got, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
