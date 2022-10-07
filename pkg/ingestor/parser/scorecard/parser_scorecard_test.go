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
	"reflect"
	"testing"

	testdata_ing "github.com/guacsec/guac/internal/testing/ingestor/testdata"
	testdata "github.com/guacsec/guac/internal/testing/processor"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func Test_scorecardParser(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name      string
		doc       *processor.Document
		wantNodes []assembler.GuacNode
		wantEdges []assembler.GuacEdge
		wantErr   bool
	}{{
		name: "testing",
		doc: &processor.Document{
			Blob:              testdata.ScorecardExample,
			Type:              processor.DocumentScorecard,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		wantNodes: []assembler.GuacNode{
			assembler.ScorecardNode{
				MetadataType:            "scorecard",
				Repo:                    "github.com/kubernetes/kubernetes",
				Commit:                  "sha1:5835544ca568b757a8ecae5c153f317e5736700e",
				ScorecardVersion:        "v4.7.0",
				ScorecardCommit:         "sha1:7cd6406aef0b80a819402e631919293d5eb6adcf",
				Score:                   8.9,
				CheckBinaryArtifact:     10,
				CheckCITests:            10,
				CheckCodeReview:         7,
				CheckDangerousWorkflow:  10,
				CheckLicense:            10,
				CheckPinnedDependencies: 2,
				CheckSecurityPolicy:     10,
				CheckTokenPermissions:   10,
				CheckVulnerabilities:    10,
			},
			assembler.ArtifactNode{
				Name:   "github.com/kubernetes/kubernetes",
				Digest: "sha1:5835544ca568b757a8ecae5c153f317e5736700e",
			},
		},
		wantEdges: []assembler.GuacEdge{
			assembler.MetadataForEdge{
				MetadataScorecard: assembler.ScorecardNode{
					MetadataType:            "scorecard",
					Repo:                    "github.com/kubernetes/kubernetes",
					Commit:                  "sha1:5835544ca568b757a8ecae5c153f317e5736700e",
					ScorecardVersion:        "v4.7.0",
					ScorecardCommit:         "sha1:7cd6406aef0b80a819402e631919293d5eb6adcf",
					Score:                   8.9,
					CheckBinaryArtifact:     10,
					CheckCITests:            10,
					CheckCodeReview:         7,
					CheckDangerousWorkflow:  10,
					CheckLicense:            10,
					CheckPinnedDependencies: 2,
					CheckSecurityPolicy:     10,
					CheckTokenPermissions:   10,
					CheckVulnerabilities:    10,
				},
				ForArtifact: assembler.ArtifactNode{
					Name:   "github.com/kubernetes/kubernetes",
					Digest: "sha1:5835544ca568b757a8ecae5c153f317e5736700e",
				},
			},
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScorecardParser()
			if err := s.Parse(ctx, tt.doc); (err != nil) != tt.wantErr {
				t.Errorf("slsa.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if nodes := s.CreateNodes(ctx); !reflect.DeepEqual(nodes, tt.wantNodes) {
				t.Errorf("slsa.CreateNodes() = %v, want %v", nodes, tt.wantNodes)
			}
			if edges := s.CreateEdges(ctx, []assembler.IdentityNode{testdata_ing.Ident}); !reflect.DeepEqual(edges, tt.wantEdges) {
				t.Errorf("slsa.CreateEdges() = %v, want %v", edges, tt.wantEdges)
			}
		})
	}
}
