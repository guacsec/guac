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

package dsse

import (
	"reflect"
	"testing"

	"github.com/guacsec/guac/internal/testing/ingestor/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/verifier"
)

func Test_DsseParser(t *testing.T) {
	err := verifier.RegisterVerifier(testdata.NewMockSigstoreVerifier(), "sigstore")
	if err != nil {
		t.Errorf("verifier.RegisterVerifier() failed with error: %v", err)
	}
	tests := []struct {
		name    string
		doc     *processor.Document
		wantErr bool
	}{{
		name:    "testing",
		doc:     &testdata.Ite6DSSEDoc,
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDSSEParser()
			if err := d.Parse(tt.doc); (err != nil) != tt.wantErr {
				t.Errorf("slsa.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if nodes := d.CreateNodes(); !reflect.DeepEqual(nodes, testdata.DsseNodes) {
				t.Errorf("slsa.CreateNodes() = %v, want %v", nodes, testdata.DsseNodes)
			}
			if edges := d.CreateEdges([]assembler.IdentityNode{testdata.Ident}); !reflect.DeepEqual(edges, testdata.DsseEdges) {
				t.Errorf("slsa.CreateEdges() = %v, want %v", edges, testdata.DsseEdges)
			}
			if identity := d.GetIdentities(); !reflect.DeepEqual(identity, []assembler.IdentityNode{testdata.Ident}) {
				t.Errorf("slsa.GetDocType() = %v, want %v", identity, []assembler.IdentityNode{testdata.Ident})
			}
		})
	}
}
