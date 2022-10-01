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

import (
	"reflect"
	"testing"

	"github.com/guacsec/guac/internal/testing/ingestor/testdata"
	processor_data "github.com/guacsec/guac/internal/testing/processor"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func Test_spdxParser(t *testing.T) {
	tests := []struct {
		name    string
		doc     *processor.Document
		wantErr bool
	}{{
		name: "valid big SPDX document",
		doc: &processor.Document{
			Blob:              processor_data.SpdxExampleAlpine,
			Format:            processor.FormatJSON,
			Type:              processor.DocumentSPDX,
			SourceInformation: processor.SourceInformation{},
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSpdxParser()
			if err := s.Parse(tt.doc); (err != nil) != tt.wantErr {
				t.Errorf("spdxParser.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if nodes := s.CreateNodes(); !testdata.GuacNodeSliceEqual(nodes, testdata.SpdxNodes) {
				t.Errorf("spdxParser.CreateNodes() = %v, want %v", nodes, testdata.SpdxNodes)
			}
			if edges := s.CreateEdges(nil); !reflect.DeepEqual(edges, testdata.SpdxEdges) {
				t.Errorf("spdxParser.CreateEdges() = %v, want %v", edges, testdata.SpdxEdges)
			}
			if docType := s.GetDocType(); !reflect.DeepEqual(docType, processor.DocumentSPDX) {
				t.Errorf("spdxParser.GetDocType() = %v, want %v", docType, processor.DocumentSPDX)
			}
		})
	}
}
