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

package slsa

import (
	"reflect"
	"testing"

	"github.com/guacsec/guac/internal/testing/ingestor/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func Test_slsaParser(t *testing.T) {
	tests := []struct {
		name    string
		doc     *processor.Document
		wantErr bool
	}{{
		name:    "testing",
		doc:     &testdata.Ite6SLSADoc,
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSLSAParser()
			if err := s.Parse(tt.doc); (err != nil) != tt.wantErr {
				t.Errorf("slsa.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if nodes := s.CreateNodes(); !reflect.DeepEqual(nodes, testdata.SlsaNodes) {
				t.Errorf("slsa.CreateNodes() = %v, want %v", nodes, testdata.SlsaNodes)
			}
			if edges := s.CreateEdges([]assembler.IdentityNode{testdata.Ident}); !reflect.DeepEqual(edges, testdata.SlsaEdges) {
				t.Errorf("slsa.CreateEdges() = %v, want %v", edges, testdata.SlsaEdges)
			}
		})
	}
}
