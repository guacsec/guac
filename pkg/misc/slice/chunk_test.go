// Copyright 2024 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package slice

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChunk(t *testing.T) {
	t.Run("error case", func(t *testing.T) {
		wantErr := errors.New("some error")
		err := Chunk([]uint{0, 1, 2}, 2, func([]uint) error {
			return wantErr
		})

		assert.Equal(t, "error running chunk callback on input slice[0:2]: some error", err.Error())
		assert.True(t, errors.Is(err, wantErr))
	})

	tests := []struct {
		name  string
		input []uint
		want  [][]uint
	}{
		{},
		{
			name:  "nil slice",
			input: nil,
			want:  nil,
		},
		{
			name:  "empty slice",
			input: []uint{},
			want:  nil,
		},
		{
			name:  "one element slice",
			input: []uint{0},
			want:  [][]uint{{0}},
		},
		{
			name:  "two element slice",
			input: []uint{0, 1},
			want:  [][]uint{{0, 1}},
		},
		{
			name:  "three element slice",
			input: []uint{0, 1, 2},
			want:  [][]uint{{0, 1}, {2}},
		},
		{
			name:  "four element slice",
			input: []uint{0, 1, 2, 3},
			want:  [][]uint{{0, 1}, {2, 3}},
		},
		{
			name:  "five element slice",
			input: []uint{0, 1, 2, 3, 4},
			want:  [][]uint{{0, 1}, {2, 3}, {4}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got [][]uint
			err := Chunk(test.input, 2, func(subslice []uint) error {
				got = append(got, subslice)
				return nil
			})

			assert.NoError(t, err)

			assert.Equal(t, test.want, got)
		})
	}
}
