//
// Copyright 2022 The GUAC Authors.
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

package scorecard

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func Test_scorecardParser(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name           string
		doc            *processor.Document
		wantPredicates *assembler.PlaceholderStruct
		wantErr        bool
	}{{
		name: "testing",
		doc: &processor.Document{
			Blob:              testdata.ScorecardExample,
			Type:              processor.DocumentScorecard,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		wantPredicates: &assembler.PlaceholderStruct{
			CertifyScorecard: []assembler.CertifyScorecardIngest{
				{
					Source: &model.SourceInputSpec{
						Type:      "git",
						Namespace: "github.com/kubernetes",
						Name:      "kubernetes",
						Commit:    strP("5835544ca568b757a8ecae5c153f317e5736700e"),
					},
					Scorecard: &model.ScorecardInputSpec{
						Checks: []*model.ScorecardCheckInputSpec{
							{Check: "Binary-Artifacts", Score: 10},
							{Check: "CI-Tests", Score: 10},
							{Check: "Code-Review", Score: 7},
							{Check: "Dangerous-Workflow", Score: 10},
							{Check: "License", Score: 10},
							{Check: "Pinned-Dependencies", Score: 2},
							{Check: "Security-Policy", Score: 10},
							{Check: "Token-Permissions", Score: 10},
							{Check: "Vulnerabilities", Score: 10},
						},
						AggregateScore:   8.9,
						TimeScanned:      "2022-10-06",
						ScorecardVersion: "v4.7.0",
						ScorecardCommit:  "7cd6406aef0b80a819402e631919293d5eb6adcf",
					},
				},
			},
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScorecardParser()
			if err := s.Parse(ctx, tt.doc); (err != nil) != tt.wantErr {
				t.Errorf("scorecard.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			preds := s.GetPredicates(ctx)
			if d := cmp.Diff(tt.wantPredicates, preds); len(d) != 0 {
				t.Errorf("scorecard.GetPredicate mismatch values (+got, -expected): %s", d)
			}
		})
	}
}

func strP(s string) *string {
	return &s
}
