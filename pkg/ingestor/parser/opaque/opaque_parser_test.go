//
// Copyright 2024 The GUAC Authors.
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

package opaque

import (
	"context"
	"reflect"
	"testing"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

func Test_parser_Parse(t *testing.T) {
	type args struct {
		ctx context.Context
		doc *processor.Document
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "json lines document",
			args: args{
				ctx: context.Background(),
				doc: &processor.Document{
					Blob:   []byte(`{"key": "value"}\n{"key": "value"}`),
					Format: processor.FormatUnknown,
					Type:   processor.DocumentUnknown,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		p := NewOpaqueParser()
		t.Run(tt.name, func(t *testing.T) {
			err := p.Parse(tt.args.ctx, tt.args.doc)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_parser_GetPredicates(t *testing.T) {
	ctx := context.Background()
	p := NewOpaqueParser()
	err := p.Parse(ctx, &processor.Document{
		Blob: []byte("some data"),
	})
	if err != nil {
		t.Errorf("Parse() error = %v, want nil", err)
	}
	got := p.GetPredicates(ctx)
	if got == nil {
		t.Errorf("GetPredicates() = nil, want empty IngestPredicates")
	} else if !reflect.DeepEqual(got, &assembler.IngestPredicates{}) {
		t.Errorf("GetPredicates() = %v, want empty IngestPredicates", got)
	}
}

func Test_parser_GetIdentities(t *testing.T) {
	ctx := context.Background()
	p := NewOpaqueParser()
	err := p.Parse(ctx, &processor.Document{
		Blob: []byte("some data"),
	})
	if err != nil {
		t.Errorf("Parse() error = %v, want nil", err)
	}
	got := p.GetIdentities(ctx)
	if got == nil {
		t.Errorf("GetIdentities() = nil, want empty slice")
	} else if len(got) != 0 {
		t.Errorf("GetIdentities() = %v, want empty slice", got)
	}
}

func Test_parser_GetIdentifiers(t *testing.T) {
	ctx := context.Background()
	p := NewOpaqueParser()
	err := p.Parse(ctx, &processor.Document{
		Blob: []byte("some data"),
	})
	if err != nil {
		t.Errorf("Parse() error = %v, want nil", err)
	}
	got, err := p.GetIdentifiers(ctx)
	if err != nil {
		t.Errorf("GetIdentifiers() error = %v, want nil", err)
	}
	if got == nil {
		t.Errorf("GetIdentifiers() = nil, want empty IdentifierStrings")
	} else if !reflect.DeepEqual(got, &common.IdentifierStrings{}) {
		t.Errorf("GetIdentifiers() = %v, want empty IdentifierStrings", got)
	}
}
