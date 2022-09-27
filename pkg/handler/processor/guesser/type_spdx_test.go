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
	_ "embed"
	"testing"

	"github.com/guacsec/guac/pkg/handler/processor"
)

var (
	// based off https://github.com/spdx/spdx-examples/blob/master/example7/spdx/example7-third-party-modules.spdx.json
	//go:embed testdata/small-spdx.json
	spdxExampleSmall []byte

	//go:embed testdata/alpine-spdx.json
	spdxExampleBig []byte

	// Invalid types for field spdxVersion
	//go:embed testdata/invalid-spdx.json
	spdxInvalidExample []byte
)

func Test_spdxTypeGuesser_GuessDocumentType(t *testing.T) {
	testCases := []struct {
		name     string
		blob     []byte
		expected processor.DocumentType
	}{{
		name:     "invalid spdx Document",
		blob:     spdxInvalidExample,
		expected: processor.DocumentUnknown,
	}, {
		name:     "valid small spdx Document",
		blob:     spdxExampleSmall,
		expected: processor.DocumentSPDX,
	}, {
		name:     "valid big spdx Document",
		blob:     spdxExampleBig,
		expected: processor.DocumentSPDX,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			guesser := &spdxTypeGuesser{}
			f := guesser.GuessDocumentType(tt.blob, processor.FormatJSON)
			if f != tt.expected {
				t.Errorf("got the wrong format, got %v, expected %v", f, tt.expected)
			}
		})
	}
}
