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

package guesser

import (
	"testing"

	"github.com/guacsec/guac/pkg/handler/processor"
)

func Test_Ite6TypeGuesser(t *testing.T) {
	testCases := []struct {
		name     string
		blob     []byte
		expected processor.DocumentType
	}{{
		name:     "invalid ITE6 Document",
		blob:     []byte(`{ "abc": "def"}`),
		expected: processor.DocumentUnknown,
	}, {
		name:     "valid ITE6 Document",
		blob:     []byte(`{"_type": "https://in-toto.io/Statement/v0.1"}`),
		expected: processor.DocumentITE6Unknown,
	}, {
		name:     "valid SLSA ITE6 Document",
		blob:     []byte(`{"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://slsa.dev/provenance/v0.2"}`),
		expected: processor.DocumentITE6SLSA,
	}, {
		name:     "valid SLSA ITE6 Document with different versions",
		blob:     []byte(`{"_type": "https://in-toto.io/Statement/v1.1", "predicateType": "https://slsa.dev/provenance/v1.0"}`),
		expected: processor.DocumentITE6SLSA,
	}}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			guesser := &ite6TypeGuesser{}
			f := guesser.GuessDocumentType(tt.blob, processor.FormatJSON)
			if f != tt.expected {
				t.Errorf("got the wrong format, got %v, expected %v", f, tt.expected)
			}
		})
	}

}
