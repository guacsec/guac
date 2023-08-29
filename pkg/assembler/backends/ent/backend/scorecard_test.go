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

//go:build integrationEnt

package backend

import (
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (s *Suite) TestCertifyScorecard() {
	testTime := time.Unix(1e9+5, 0)
	type call struct {
		Src *model.SourceInputSpec
		SC  *model.ScorecardInputSpec
	}
	tests := []struct {
		Name         string
		InSrc        []*model.SourceInputSpec
		Calls        []call
		Query        *model.CertifyScorecardSpec
		ExpSC        []*model.CertifyScorecard
		ExpIngestErr bool
		ExpQueryErr  bool
		Only         bool
	}{
		{
			Name:  "HappyPath",
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Src: s1,
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
					Source: s1out,
					Scorecard: &model.Scorecard{
						Checks: []*model.ScorecardCheck{},
						Origin: "test origin",
					},
				},
			},
		},
		{
			Name:  "Ingest same",
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Src: s1,
					SC: &model.ScorecardInputSpec{
						Origin: "test origin",
					},
				},
				{
					Src: s1,
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
					Source: s1out,
					Scorecard: &model.Scorecard{
						Checks: []*model.ScorecardCheck{},
						Origin: "test origin",
					},
				},
			},
		},
		{
			Name:  "Query multiple",
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Src: s1,
					SC: &model.ScorecardInputSpec{
						Origin: "test origin one",
					},
				},
				{
					Src: s1,
					SC: &model.ScorecardInputSpec{
						AggregateScore: 4.4,
						Origin:         "test origin two",
					},
				},
				{
					Src: s1,
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
					Source: s1out,
					Scorecard: &model.Scorecard{
						Checks:         []*model.ScorecardCheck{},
						AggregateScore: 4.4,
						Origin:         "test origin two",
					},
				},
				{
					Source: s1out,
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
			Only:  true,
			InSrc: []*model.SourceInputSpec{s1, s2},
			Calls: []call{
				{
					Src: s1,
					SC: &model.ScorecardInputSpec{
						Origin: "test origin",
					},
				},
				{
					Src: s2,
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
					Source: s1out,
					Scorecard: &model.Scorecard{
						Checks: []*model.ScorecardCheck{},
						Origin: "test origin",
					},
				},
			},
		},
		{
			Name:  "Query Time",
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Src: s1,
					SC: &model.ScorecardInputSpec{
						AggregateScore:   1.5,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
				{
					Src: s1,
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
					Source: s1out,
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
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Src: s1,
					SC: &model.ScorecardInputSpec{
						AggregateScore:   1.5,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
				{
					Src: s1,
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
					Source: s1out,
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
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Src: s1,
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
					Src: s1,
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
					Source: s1out,
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
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Src: s1,
					SC: &model.ScorecardInputSpec{
						AggregateScore:   1.5,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
				{
					Src: s1,
					SC: &model.ScorecardInputSpec{
						AggregateScore:   5.7,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
			},
			Query: &model.CertifyScorecardSpec{
				ScorecardVersion: ptrfrom.String("456"),
			},
			ExpSC: nil,
		},
		{
			Name:  "Query ID",
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Src: s1,
					SC: &model.ScorecardInputSpec{
						AggregateScore:   1.5,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
			},
			Query: &model.CertifyScorecardSpec{
				ID: ptrfrom.String("5"),
			},
			ExpSC: []*model.CertifyScorecard{
				{
					Source: s1out,
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
			Name: "Ingest error",
			Calls: []call{
				{
					Src: s1,
					SC: &model.ScorecardInputSpec{
						AggregateScore:   1.5,
						TimeScanned:      time.Unix(1e9, 0),
						ScorecardVersion: "123",
						ScorecardCommit:  "abc",
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Query bad ID",
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Src: s1,
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
			for _, s := range test.InSrc {
				if _, err := b.IngestSource(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, o := range test.Calls {
				_, err := b.IngestScorecard(ctx, *o.Src, *o.SC)
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
