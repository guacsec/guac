package open_vex

import (
	"reflect"
	"testing"

	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func TestOpenVEXProcessor_ValidateSchema(t *testing.T) {
	type args struct {
		d *processor.Document
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "default OpenVEX document",
			args: args{
				d: &processor.Document{
					Blob:   testdata.ValidOpenVEXExample,
					Type:   processor.DocumentOpenVEX,
					Format: processor.FormatJSON,
				},
			},
			wantErr: false,
		},
		{
			name: "incorrect type",
			args: args{
				d: &processor.Document{
					Blob:   testdata.ValidOpenVEXExample,
					Type:   processor.DocumentUnknown,
					Format: processor.FormatJSON,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid OpenVEX document",
			args: args{
				d: &processor.Document{
					Blob:   []byte("invalid"),
					Type:   processor.DocumentOpenVEX,
					Format: processor.FormatJSON,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid OpenVEX document format",
			args: args{
				d: &processor.Document{
					Blob:   testdata.ValidOpenVEXExample,
					Type:   processor.DocumentOpenVEX,
					Format: processor.FormatUnknown,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &OpenVEXProcessor{}
			if err := p.ValidateSchema(tt.args.d); (err != nil) != tt.wantErr {
				t.Errorf("ValidateSchema() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOpenVEXProcessor_Unpack(t *testing.T) {
	type args struct {
		d *processor.Document
	}
	tests := []struct {
		name    string
		args    args
		want    []*processor.Document
		wantErr bool
	}{
		{
			name: "OpenVEX document",
			args: args{
				d: &processor.Document{
					Type: processor.DocumentOpenVEX,
				},
			},
			want: []*processor.Document{},
		},
		{
			name: "Incorrect type",
			args: args{
				d: &processor.Document{
					Type: processor.DocumentUnknown,
				},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &OpenVEXProcessor{}
			got, err := p.Unpack(tt.args.d)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unpack() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Unpack() got = %v, want %v", got, tt.want)
			}
		})
	}
}
