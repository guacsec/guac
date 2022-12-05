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

	"github.com/guacsec/guac/internal/testing/testdata"
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
			assembler.MetadataNode{
				MetadataType: "scorecard",
				MetadataID:   "github.com/kubernetes/kubernetes:5835544ca568b757a8ecae5c153f317e5736700e",
				Details: map[string]interface{}{
					"repo":                "git+https://github.com/kubernetes/kubernetes",
					"commit":              "sha1:5835544ca568b757a8ecae5c153f317e5736700e",
					"scorecard_version":   "v4.7.0",
					"scorecard_commit":    "sha1:7cd6406aef0b80a819402e631919293d5eb6adcf",
					"score":               8.9,
					"Binary_Artifacts":    10,
					"CI_Tests":            10,
					"Code_Review":         7,
					"Dangerous_Workflow":  10,
					"License":             10,
					"Pinned_Dependencies": 2,
					"Security_Policy":     10,
					"Token_Permissions":   10,
					"Vulnerabilities":     10,
				},
			},
			assembler.ArtifactNode{
				Name:   "git+https://github.com/kubernetes/kubernetes",
				Digest: "sha1:5835544ca568b757a8ecae5c153f317e5736700e",
			},
		},
		wantEdges: []assembler.GuacEdge{
			assembler.MetadataForEdge{
				MetadataNode: assembler.MetadataNode{
					MetadataType: "scorecard",
					MetadataID:   "github.com/kubernetes/kubernetes:5835544ca568b757a8ecae5c153f317e5736700e",
					Details: map[string]interface{}{
						"repo":                "git+https://github.com/kubernetes/kubernetes",
						"commit":              "sha1:5835544ca568b757a8ecae5c153f317e5736700e",
						"scorecard_version":   "v4.7.0",
						"scorecard_commit":    "sha1:7cd6406aef0b80a819402e631919293d5eb6adcf",
						"score":               8.9,
						"Binary_Artifacts":    10,
						"CI_Tests":            10,
						"Code_Review":         7,
						"Dangerous_Workflow":  10,
						"License":             10,
						"Pinned_Dependencies": 2,
						"Security_Policy":     10,
						"Token_Permissions":   10,
						"Vulnerabilities":     10,
					},
				},
				ForArtifact: assembler.ArtifactNode{
					Name:   "git+https://github.com/kubernetes/kubernetes",
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
				t.Errorf("scorecard.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if nodes := s.CreateNodes(ctx); !reflect.DeepEqual(nodes, tt.wantNodes) {
				t.Errorf("scorecard.CreateNodes() = %v, want %v", nodes, tt.wantNodes)
			}
			if edges := s.CreateEdges(ctx, []assembler.IdentityNode{testdata.Ident}); !reflect.DeepEqual(edges, tt.wantEdges) {
				t.Errorf("scorecard.CreateEdges() = %v, want %v", edges, tt.wantEdges)
			}
		})
	}
}
