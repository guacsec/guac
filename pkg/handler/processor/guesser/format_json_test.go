package guesser

import (
	"testing"

	"github.com/guacsec/guac/pkg/handler/processor"
)

func Test_JsonGuesser(t *testing.T) {
	testCases := []struct {
		name     string
		blob     []byte
		expected processor.FormatType
	}{{
		name:     "simple JSON",
		blob:     []byte(`{ "abc": "def"}`),
		expected: processor.FormatJSON,
	}, {
		name:     "invalid JSON",
		blob:     []byte(`"abc": "def"`),
		expected: processor.FormatUnknown,
	}}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			guesser := &jsonFormatGuesser{}
			f := guesser.GuessFormat(tt.blob)
			if f != tt.expected {
				t.Errorf("got the wrong format, got %v, expected %v", f, tt.expected)
			}
		})
	}

}
