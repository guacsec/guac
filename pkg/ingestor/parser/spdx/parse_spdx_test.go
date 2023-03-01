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

package spdx

// TODO(bulldozer): freeze test until next implementation
/*
import (
	"context"
	"testing"

	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func Test_spdxParser(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name      string
		doc       *processor.Document
		wantNodes []assembler.GuacNode
		wantEdges []assembler.GuacEdge
		wantErr   bool
	}{{
		name: "valid big SPDX document",
		doc: &processor.Document{
			Blob:   testdata.SpdxExampleAlpine,
			Format: processor.FormatJSON,
			Type:   processor.DocumentSPDX,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantNodes: testdata.SpdxNodes,
		wantEdges: testdata.SpdxEdges,
		wantErr:   false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSpdxParser()
			err := s.Parse(ctx, tt.doc)
			if (err != nil) != tt.wantErr {
				t.Errorf("spdxParser.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if nodes := s.CreateNodes(ctx); !testdata.GuacNodeSliceEqual(nodes, tt.wantNodes) {
				t.Errorf("spdxParser.CreateNodes() = %v, want %v", nodes, tt.wantNodes)
			}
			if edges := s.CreateEdges(ctx, nil); !testdata.GuacEdgeSliceEqual(edges, tt.wantEdges) {
				t.Errorf("spdxParser.CreateEdges() = %v, want %v", edges, tt.wantEdges)
			}
		})
	}
}
*/
