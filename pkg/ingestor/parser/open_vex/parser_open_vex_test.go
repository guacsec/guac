package open_vex

import (
	"context"
	"testing"

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
				doc: &processor.Document{Blob: testdata.ValidOpenVEXExample},
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
			name: "default",
			fields: fields{
				doc: &processor.Document{
					Blob:   testdata.ValidOpenVEXExample,
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
				Vex: testdata.OpenVEXExample,
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
