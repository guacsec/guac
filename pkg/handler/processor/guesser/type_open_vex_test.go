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
				blob:   testdata.NotAffectedOpenVEXExample,
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
