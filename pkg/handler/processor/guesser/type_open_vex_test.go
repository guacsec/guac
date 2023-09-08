package guesser

import (
	"testing"

	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func Test_openVexTypeGuesser_GuessDocumentType(t *testing.T) {
	type args struct {
		blob   []byte
		format processor.FormatType
	}
	tests := []struct {
		name string
		args args
		want processor.DocumentType
	}{
		{
			name: "invalid openvex Document",
			args: args{
				blob: []byte(`{
					"abc": "def"
				}`),
				format: processor.FormatJSON,
			},
			want: processor.DocumentUnknown,
		},
		{
			name: "valid openvex Document",
			args: args{
				blob:   testdata.ValidOpenVEXExample,
				format: processor.FormatJSON,
			},
			want: processor.DocumentOpenVEX,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := &openVexTypeGuesser{}
			if got := op.GuessDocumentType(tt.args.blob, tt.args.format); got != tt.want {
				t.Errorf("GuessDocumentType() = %v, want %v", got, tt.want)
			}
		})
	}
}
