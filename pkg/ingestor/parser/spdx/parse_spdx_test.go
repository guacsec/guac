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
	_ "embed"
	"reflect"
	"testing"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/spdx/tools-golang/spdx/v2_2"
)

var (
	// based off https://github.com/spdx/spdx-examples/blob/master/example7/spdx/example7-third-party-modules.spdx.json
	//go:embed testdata/spdx_alpine.json
	spdxExampleAlpine []byte
)

func Test_spdxParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		doc     *processor.Document
		wantErr bool
	}{{
		name: "valid big SPDX document",
		doc: &processor.Document{
			Blob:              spdxExampleAlpine,
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
		})
	}
}

func Test_spdxParser_CreateNodes(t *testing.T) {
	type fields struct {
		packages map[string][]assembler.PackageNode
		files    map[string][]assembler.ArtifactNode
		spdxDoc  *v2_2.Document
	}
	tests := []struct {
		name   string
		fields fields
		want   []assembler.GuacNode
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &spdxParser{
				packages: tt.fields.packages,
				files:    tt.fields.files,
				spdxDoc:  tt.fields.spdxDoc,
			}
			if got := s.CreateNodes(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("spdxParser.CreateNodes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_spdxParser_CreateEdges(t *testing.T) {
	type fields struct {
		packages map[string][]assembler.PackageNode
		files    map[string][]assembler.ArtifactNode
		spdxDoc  *v2_2.Document
	}
	type args struct {
		foundIdentities []assembler.IdentityNode
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []assembler.GuacEdge
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &spdxParser{
				packages: tt.fields.packages,
				files:    tt.fields.files,
				spdxDoc:  tt.fields.spdxDoc,
			}
			if got := s.CreateEdges(tt.args.foundIdentities); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("spdxParser.CreateEdges() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_spdxParser_GetDocType(t *testing.T) {
	type fields struct {
		packages map[string][]assembler.PackageNode
		files    map[string][]assembler.ArtifactNode
		spdxDoc  *v2_2.Document
	}
	tests := []struct {
		name   string
		fields fields
		want   processor.DocumentType
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &spdxParser{
				packages: tt.fields.packages,
				files:    tt.fields.files,
				spdxDoc:  tt.fields.spdxDoc,
			}
			if got := s.GetDocType(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("spdxParser.GetDocType() = %v, want %v", got, tt.want)
			}
		})
	}
}
