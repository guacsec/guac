//
// Copyright 2026 The GUAC Authors.
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

func TestSRACTypeGuesser(t *testing.T) {
	g := &sracTypeGuesser{}
	for _, tc := range []struct {
		input  string
		format processor.FormatType
		want   processor.DocumentType
	}{
		{`{"schemaVersion":"0.2-draft","documentId":"a","assertions":[]}`, processor.FormatJSON, processor.DocumentSRAC},
		{`{"schemaVersion":"unsupported","documentId":"a","assertions":null}`, processor.FormatJSON, processor.DocumentSRAC},
		{`{"schemaVersion":"0.2-draft","documentId":"a","assertions":[]}`, processor.FormatXML, processor.DocumentUnknown},
		{`{"schemaVersion":"1.0","bomFormat":"CycloneDX"}`, processor.FormatJSON, processor.DocumentUnknown},
		{`invalid json`, processor.FormatJSON, processor.DocumentUnknown},
	} {
		if got := g.GuessDocumentType([]byte(tc.input), tc.format); got != tc.want {
			t.Errorf("guess %s = %s, want %s", tc.input, got, tc.want)
		}
	}
}
