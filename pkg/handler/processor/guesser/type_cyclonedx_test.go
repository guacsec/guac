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

	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func Test_cyclonedxTypeGuesser_GuessDocumentType(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name     string
		blob     []byte
		format   processor.FormatType
		expected processor.DocumentType
	}{
		{
			name:     "invalid cyclonedx Document",
			blob:     []byte(`{"abc": "def"}`),
			format:   processor.FormatJSON,
			expected: processor.DocumentUnknown,
		},
		{
			name:     "invalid cyclonedx Document",
			blob:     testdata.CycloneDXInvalidExample,
			format:   processor.FormatJSON,
			expected: processor.DocumentUnknown,
		},
		{
			name:     "invalid xml cyclonedx Document",
			blob:     testdata.CycloneDXInvalidExampleXML,
			format:   processor.FormatXML,
			expected: processor.DocumentUnknown,
		},
		{
			name:     "valid small cyclonedx Document",
			blob:     testdata.CycloneDXBusyboxExample,
			format:   processor.FormatJSON,
			expected: processor.DocumentCycloneDX,
		},
		{
			name:     "valid distroless cyclonedx Document",
			blob:     testdata.CycloneDXDistrolessExample,
			format:   processor.FormatJSON,
			expected: processor.DocumentCycloneDX,
		},
		{
			name:     "valid alpine cyclonedx Document",
			blob:     testdata.CycloneDXExampleAlpine,
			format:   processor.FormatJSON,
			expected: processor.DocumentCycloneDX,
		},
		{
			name:     "valid xml cyclonedx Document",
			blob:     testdata.CycloneDXExampleLaravelXML,
			format:   processor.FormatXML,
			expected: processor.DocumentCycloneDX,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			guesser := &cycloneDXTypeGuesser{}
			f := guesser.GuessDocumentType(tt.blob, tt.format)
			if f != tt.expected {
				t.Errorf("got the wrong format, got %v, expected %v", f, tt.expected)
			}
		})
	}
}
