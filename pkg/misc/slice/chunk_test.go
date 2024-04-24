package slice

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChunk(t *testing.T) {
	t.Run("error case", func(t *testing.T) {
		err := Chunk([]uint{0, 1, 2}, 2, func([]uint) error {
			return errors.New("some error")
		})

		assert.Equal(t, errors.New("some error"), err)
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
