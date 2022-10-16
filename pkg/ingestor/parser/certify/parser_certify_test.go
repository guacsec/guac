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

package certify

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
		Digest:          "sha256:8b895a8289dcb53080a9b41744a82224d5b6862d979167d3494bf85371ddaf9e",
		AttestationType: attestationType,
		Payload: map[string]interface{}{
			"certifier_name":   "John Doe",
			"certifier_sig":    "",
			"certifier_pubKey": "",
			"certifier_url":    "person@example.com",
			"data":             "2022-10-03 12:00:00 +0000 UTC",
			"full_review":      "https://github.com/kubernetes/kubernetes/pull/112078#pullrequestreview-1088153270",
		},
	}
)

func Test_certifyParser(t *testing.T) {
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
			Blob:   testdata.ITE6ReviewExample,
			Type:   processor.DocumentITE6CERTIFY,
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
			c := NewCerifyParser()
			if err := c.Parse(ctx, tt.doc); (err != nil) != tt.wantErr {
				t.Errorf("cerify.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if nodes := c.CreateNodes(ctx); !reflect.DeepEqual(nodes, tt.wantNodes) {
				t.Errorf("cerify.CreateNodes() = %v, want %v", nodes, tt.wantNodes)
			}
			if edges := c.CreateEdges(ctx, []assembler.IdentityNode{testdata_ing.Ident}); !reflect.DeepEqual(edges, tt.wantEdges) {
				t.Errorf("cerify.CreateEdges() = %v, want %v", edges, tt.wantEdges)
			}
		})
	}
}
