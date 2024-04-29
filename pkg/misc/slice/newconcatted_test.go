//
// Copyright 2024 The GUAC Authors.
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

package slice

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConcatted(t *testing.T) {
	tests := []struct {
		name  string
		input [][]uint
		want  []uint
	}{
		{
			name: "no input",
		},
		{
			name:  "one nil input",
			input: [][]uint{nil},
			want:  []uint{},
		},
		{
			name:  "two nil inputs",
			input: [][]uint{nil},
			want:  []uint{},
		},
		{
			name:  "first input is one-el and second is nil",
			input: [][]uint{{0}, nil},
			want:  []uint{0},
		},
		{
			name:  "first input is nil and second is one-el",
			input: [][]uint{nil, {0}},
			want:  []uint{0},
		},
		{
			name:  "three one-el inputs",
			input: [][]uint{{0}, {1}, {2}},
			want:  []uint{0, 1, 2},
		},
		{
			name:  "three two-el inputs",
			input: [][]uint{{0, 1}, {2, 3}, {4, 5}},
			want:  []uint{0, 1, 2, 3, 4, 5},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wantLenAndCap := 0
			for _, inputEl := range test.input {
				wantLenAndCap += len(inputEl)
			}

			// ensure we don't unnecessarily resize (copy, reallocate) during an append() call
			checkBeforeLenAndCap := func(gotLen, gotCap int) {
				require.Equal(t, 0, gotLen, "before len")
				require.Equal(t, wantLenAndCap, gotCap, "before cap")
			}

			checkAfterLenAndCap := func(gotLen, gotCap int) {
				require.Equal(t, wantLenAndCap, gotLen, "after len")
				require.Equal(t, wantLenAndCap, gotCap, "after cap")
			}

			assert.Equal(t, test.want, newConcatted(checkBeforeLenAndCap, checkAfterLenAndCap, test.input...))
		})
	}
}
