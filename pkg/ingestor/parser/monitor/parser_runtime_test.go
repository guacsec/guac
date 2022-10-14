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

package monitor

import (
	"context"
	"reflect"
	"testing"

	"github.com/guacsec/guac/internal/testing/ingestor/testdata"
	processor_data "github.com/guacsec/guac/internal/testing/processor"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

var (
	art = assembler.ArtifactNode{
		Name:   "ttl.sh/testin123",
		Digest: "sha256:def2bdf8cee687d5889d51923d7907c441f1a61958f1e5dfb07f53041c83745f",
	}

	att = assembler.AttestationNode{
		FilePath:        "TestSource",
		AttestationType: "runtime",
		Digest:          "sha256:66e5f99f14ba199652e142b132a410e2d0b7c44a73ff05246b4c28826bbd55ff",
	}

	build = assembler.BuilderNode{
		BuilderType: "https://tekton.dev/attestations/chains@v2",
		BuilderId:   "https://tekton.dev/chains/v2",
	}

	runtime = assembler.RuntimeNode{
		RuntimeNodeType: "https://tetragon",
		RuntimeNodeId:   "https://tetragon",
	}

	runtimeNodes = []assembler.GuacNode{art, att, build, runtime}
	runtimeEdges = []assembler.GuacEdge{
		assembler.IdentityForEdge{
			IdentityNode:    testdata.Ident,
			AttestationNode: att,
		},
		assembler.BuiltByEdge{
			ArtifactNode: art,
			BuilderNode:  build,
		},
		assembler.AttestationForEdge{
			AttestationNode: att,
			ArtifactNode:    art,
		},
		assembler.RuntimeByEdge{
			ArtifactNode: art,
			RuntimeNode:  runtime,
		},
	}
)

func Test_runtimeParser(t *testing.T) {
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
			Blob:   processor_data.RuntimeExample,
			Format: processor.FormatJSON,
			Type:   processor.DocumentITE6Runtime,
			SourceInformation: processor.SourceInformation{
				Source:    "TestSource",
				Collector: "TestCollector",
			},
		},
		wantNodes: runtimeNodes,
		wantEdges: runtimeEdges,
		wantErr:   false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRuntimeParser()
			err := r.Parse(ctx, tt.doc)
			if (err != nil) != tt.wantErr {
				t.Errorf("runtime.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if nodes := r.CreateNodes(ctx); !reflect.DeepEqual(nodes, tt.wantNodes) {
				t.Errorf("runtime.CreateNodes() = %v, want %v", nodes, tt.wantNodes)
			}
			if edges := r.CreateEdges(ctx, []assembler.IdentityNode{testdata.Ident}); !reflect.DeepEqual(edges, tt.wantEdges) {
				t.Errorf("runtime.CreateEdges() = %v, want %v", edges, tt.wantEdges)
			}
		})
	}
}
