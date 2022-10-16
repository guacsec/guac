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

package crev

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

var (
	artNode = assembler.ArtifactNode{
		Name:   "git://github.com/kubernetes/kubernetes",
		Digest: "sha1:5835544ca568b757a8ecae5c153f317e5736700e",
	}
	attNode = assembler.AttestationNode{
		FilePath:        "TestSource",
		Digest:          "sha256:eeb3bad2cc7858680fb537be28ecfa5e7f1b10460a2ef5f39dd171238044c3ce",
		AttestationType: attestationType,
		Payload: map[string]interface{}{
			"review-id_id-Type": "crev",
			"review-id_id":      "",
			"review-id_url":     "person@example.com",
			"date":              "2022-10-03 12:00:00 +0000 UTC",
			"thoroughness":      "high",
			"understanding":     "high",
			"rating":            "positive",
			"comment":           "N/A",
		},
	}
)

func Test_crevParser(t *testing.T) {
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
			Blob:   testdata.ITE6CREVExample,
			Type:   processor.DocumentITE6CREV,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantNodes: []assembler.GuacNode{artNode, attNode},
		wantEdges: []assembler.GuacEdge{
			assembler.IdentityForEdge{
				IdentityNode:    testdata_ing.Ident,
				AttestationNode: attNode,
			},
			assembler.AttestationForEdge{
				AttestationNode: attNode,
				ArtifactNode:    artNode,
			},
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCrevParser()
			if err := c.Parse(ctx, tt.doc); (err != nil) != tt.wantErr {
				t.Errorf("crev.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if nodes := c.CreateNodes(ctx); !reflect.DeepEqual(nodes, tt.wantNodes) {
				t.Errorf("crev.CreateNodes() = %v, want %v", nodes, tt.wantNodes)
			}
			if edges := c.CreateEdges(ctx, []assembler.IdentityNode{testdata_ing.Ident}); !reflect.DeepEqual(edges, tt.wantEdges) {
				t.Errorf("crev.CreateEdges() = %v, want %v", edges, tt.wantEdges)
			}
		})
	}
}
