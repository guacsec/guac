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

package parser

import (
	"context"
	"testing"

	"github.com/guacsec/guac/internal/testing/mockverifier"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/verifier"
	"github.com/guacsec/guac/pkg/logging"
)

var (
	dsseDocTree = processor.DocumentNode{
		Document: &processor_data.Ite6DSSEDoc,
		Children: []*processor.DocumentNode{
			{
				Document: &processor_data.Ite6SLSADoc,
				Children: []*processor.DocumentNode{},
			},
		},
	}

	spdxDocTree = processor.DocumentNode{
		Document: &processor.Document{
			Blob:   testdata.SpdxExampleAlpine,
			Format: processor.FormatJSON,
			Type:   processor.DocumentSPDX,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		Children: []*processor.DocumentNode{},
	}

	graphInput = []assembler.AssemblerInput{{
		Nodes: testdata.DsseNodes,
		Edges: testdata.DsseEdges,
	}, {
		Nodes: testdata.SlsaNodes,
		Edges: testdata.SlsaEdges,
	}}

	spdxGraphInput = []assembler.AssemblerInput{{
		Nodes: testdata.SpdxNodes,
		Edges: testdata.SpdxEdges,
	}}
)

func TestParseDocumentTree(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	err := verifier.RegisterVerifier(mockverifier.NewMockSigstoreVerifier(), "sigstore")
	if err != nil {
		t.Errorf("verifier.RegisterVerifier() failed with error: %v", err)
	}
	tests := []struct {
		name    string
		tree    processor.DocumentTree
		want    []assembler.AssemblerInput
		wantErr bool
	}{{
		name:    "testing",
		tree:    processor.DocumentTree(&dsseDocTree),
		want:    graphInput,
		wantErr: false,
	}, {
		name:    "valid big SPDX document",
		tree:    processor.DocumentTree(&spdxDocTree),
		want:    spdxGraphInput,
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDocumentTree(ctx, tt.tree)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDocumentTree() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("ParseDocumentTree() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				compare(t, got[i].Edges, tt.want[i].Edges, got[i].Nodes, tt.want[i].Nodes)
			}
		})
	}
}

func compare(t *testing.T, gotEdges, wantEdges []assembler.GuacEdge, gotNodes, wantNodes []assembler.GuacNode) {
	if !testdata.GuacEdgeSliceEqual(gotEdges, wantEdges) {
		t.Errorf("ParseDocumentTree() = %v, want %v", gotEdges, wantEdges)
	}
	if !testdata.GuacNodeSliceEqual(gotNodes, wantNodes) {
		t.Errorf("ParseDocumentTree() = %v, want %v", gotNodes, wantNodes)
	}
}
