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

func Test_XMLGuesser(t *testing.T) {
	testCases := []struct {
		name     string
		blob     []byte
		expected processor.FormatType
	}{{
		name:     "simple XML",
		blob:     []byte(`<a>value</a>`),
		expected: processor.FormatXML,
	}, {
		name:     "invalid XML",
		blob:     []byte(`{ "abc": "def"}`),
		expected: processor.FormatUnknown,
	}}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			guesser := &xmlFormatGuesser{}
			f := guesser.GuessFormat(tt.blob)
			if f != tt.expected {
				t.Errorf("got the wrong format, got %v, expected %v", f, tt.expected)
			}
		})
	}

}
