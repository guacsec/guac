//
// Copyright 2023 The GUAC Authors.
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

package open_vex

import (
	"context"
	"reflect"
	"testing"

	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/openvex/go-vex/pkg/vex"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func Test_openVEXParser_Parse(t *testing.T) {
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
			name: "test",
			args: args{
				ctx: context.Background(),
				doc: &processor.Document{Blob: testdata.NotAffectedOpenVEXExample},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newParser := NewOpenVEXParser()
			if err := newParser.Parse(tt.args.ctx, tt.args.doc); (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_openVEXParser_GetPredicates(t *testing.T) {
	type fields struct {
		doc *processor.Document
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *assembler.IngestPredicates
	}{
		{
			name: "status not affected",
			fields: fields{
				doc: &processor.Document{
					Blob:   testdata.NotAffectedOpenVEXExample,
					Format: processor.FormatJSON,
					Type:   processor.DocumentOpenVEX,
					SourceInformation: processor.SourceInformation{
						Collector: "TestCollector",
						Source:    "TestSource",
					},
				},
			},
			args: args{
				ctx: context.Background(),
			},
			want: &assembler.IngestPredicates{
				Vex: testdata.NotAffectedOpenVexIngest,
			},
		},
		{
			name: "status affected",
			fields: fields{
				doc: &processor.Document{
					Blob:   testdata.AffectedOpenVex,
					Format: processor.FormatJSON,
					Type:   processor.DocumentOpenVEX,
					SourceInformation: processor.SourceInformation{
						Collector: "TestCollector",
						Source:    "TestSource",
					},
				},
			},
			args: args{
				ctx: context.Background(),
			},
			want: &assembler.IngestPredicates{
				Vex:         testdata.AffectedOpenVexIngest,
				CertifyVuln: testdata.AffectedOpenVEXCertifyVulnIngest,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewOpenVEXParser()

			err := c.Parse(tt.args.ctx, tt.fields.doc)
			if err != nil {
				t.Errorf("Parse() error = %v, wantErr %v", err, false)
				return
			}

			got := c.GetPredicates(tt.args.ctx)

			if d := cmp.Diff(tt.want, got, testdata.IngestPredicatesCmpOpts...); len(d) != 0 {
				t.Errorf("csaf.GetPredicate mismatch values (+got, -expected): %s", d)
			}
		})
	}
}

func Test_openVEXParser_GetIdentities(t *testing.T) {
	type fields struct {
		doc               *processor.Document
		identifierStrings *common.IdentifierStrings
		openVex           *vex.VEX
	}
	type args struct {
		ctx context.Context
	}
	test := struct {
		name   string
		fields fields
		args   args
		want   []common.TrustInformation
	}{
		name: "default case",
		want: nil,
	}
	c := &openVEXParser{
		doc:               test.fields.doc,
		identifierStrings: test.fields.identifierStrings,
		openVex:           test.fields.openVex,
	}
	if got := c.GetIdentities(test.args.ctx); !reflect.DeepEqual(got, test.want) {
		t.Errorf("GetIdentities() = %v, want %v", got, test.want)
	}
}

func Test_openVEXParser_GetIdentifiers(t *testing.T) {
	type fields struct {
		doc               *processor.Document
		identifierStrings *common.IdentifierStrings
	}
	test := struct {
		name    string
		fields  fields
		ctx     context.Context
		want    *common.IdentifierStrings
		wantErr bool
	}{
		name: "default case",
		fields: fields{
			doc: &processor.Document{
				Blob:   testdata.NotAffectedOpenVEXExample,
				Format: processor.FormatJSON,
				Type:   processor.DocumentOpenVEX,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			},
			identifierStrings: &common.IdentifierStrings{},
		},
		ctx: context.Background(),
		want: &common.IdentifierStrings{
			PurlStrings: []string{
				"pkg:oci/git@sha256:23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb",
			},
		},
		wantErr: true,
	}

	c := NewOpenVEXParser()

	err := c.Parse(test.ctx, test.fields.doc)
	if err != nil {
		t.Errorf("Parse() error = %v, wantErr %v", err, false)
		return
	}

	_ = c.GetPredicates(test.ctx)

	got, err := c.GetIdentifiers(test.ctx)
	if (err != nil) != test.wantErr {
		t.Errorf("GetIdentifiers() error = %v, wantErr %v", err, test.wantErr)
		return
	}
	if d := cmp.Diff(test.want, got, testdata.IngestPredicatesCmpOpts...); len(d) != 0 {
		t.Errorf("csaf.GetPredicate mismatch values (+got, -expected): %s", d)
	}
	//if !reflect.DeepEqual(got, test.want) {
	//	t.Errorf("GetIdentifiers() got = %v, want %v", got, test.want)
	//}
}
