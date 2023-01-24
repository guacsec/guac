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
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/guacsec/guac/internal/testing/mockverifier"
	nats_test "github.com/guacsec/guac/internal/testing/nats"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/verifier"
	"github.com/guacsec/guac/pkg/logging"
)

var (
	dsseDocTree = processor.DocumentNode{
		Document: &testdata.Ite6DSSEDoc,
		Children: []*processor.DocumentNode{
			{
				Document: &testdata.Ite6SLSADoc,
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
		if !strings.Contains(err.Error(), "the verification provider is being overwritten") {
			t.Errorf("unexpected error: %v", err)
		}
	}

	tests := []struct {
		name    string
		tree    processor.DocumentTree
		want    []assembler.AssemblerInput
		wantErr bool
	}{{
		name:    "valid dsse",
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

func Test_ParserSubscribe(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	err := verifier.RegisterVerifier(mockverifier.NewMockSigstoreVerifier(), "sigstore")
	if err != nil {
		if !strings.Contains(err.Error(), "the verification provider is being overwritten") {
			t.Errorf("unexpected error: %v", err)
		}
	}

	natsTest := nats_test.NewNatsTestServer()
	url, err := natsTest.EnableJetStreamForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer natsTest.Shutdown()

	testCases := []struct {
		name       string
		tree       processor.DocumentTree
		want       []assembler.AssemblerInput
		wantErr    bool
		errMessage error
	}{{
		name:       "valid dsse",
		tree:       processor.DocumentTree(&dsseDocTree),
		want:       graphInput,
		wantErr:    true,
		errMessage: context.DeadlineExceeded,
	}, {
		name:       "valid big SPDX document",
		tree:       processor.DocumentTree(&spdxDocTree),
		want:       spdxGraphInput,
		wantErr:    true,
		errMessage: context.DeadlineExceeded,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			jetStream := emitter.NewJetStream(url, "", "")
			ctx, err = jetStream.JetStreamInit(ctx)
			if err != nil {
				t.Fatalf("unexpected error initializing jetstream: %v", err)
			}
			err = jetStream.RecreateStream(ctx)
			if err != nil {
				t.Fatalf("unexpected error recreating jetstream: %v", err)
			}
			defer jetStream.Close()
			err := testPublish(ctx, tt.tree)
			if err != nil {
				t.Fatalf("unexpected error on emit: %v", err)
			}
			var cancel context.CancelFunc

			ctx, cancel = context.WithTimeout(ctx, time.Second)
			defer cancel()

			transportFunc := func(d []assembler.Graph) error {
				if len(d) != len(tt.want) {
					t.Errorf("ParseDocumentTree() = %v, want %v", d, tt.want)
				}
				for i := range d {
					compare(t, d[i].Edges, tt.want[i].Edges, d[i].Nodes, tt.want[i].Nodes)
				}
				return nil
			}

			err = Subscribe(ctx, transportFunc)
			if (err != nil) != tt.wantErr {
				t.Errorf("nats emitter Subscribe test errored = %v, want %v", err, tt.wantErr)
			}
			if err != nil {
				if !errors.Is(err, tt.errMessage) {
					t.Errorf("nats emitter Subscribe test errored = %v, want %v", err, tt.errMessage)
				}
			}
		})
	}
}

func testPublish(ctx context.Context, documentTree processor.DocumentTree) error {
	docTreeJSON, err := json.Marshal(documentTree)
	if err != nil {
		return err
	}
	err = emitter.Publish(ctx, emitter.SubjectNameDocProcessed, docTreeJSON)
	if err != nil {
		return err
	}
	return nil
}
