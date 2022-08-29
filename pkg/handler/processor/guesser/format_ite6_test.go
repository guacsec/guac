package guesser

import (
	"testing"

	"github.com/guacsec/guac/pkg/handler/processor"
)

func Test_Ite6Guesser(t *testing.T) {
	testCases := []struct {
		name     string
		blob     []byte
		expected processor.FormatType
	}{{
		name:     "invalid ITE6 Document",
		blob:     []byte(`{ "abc": "def"}`),
		expected: processor.FormatUnknown,
	}, {
		name:     "valid ITE6 Document",
		blob:     []byte(`{"_type": "https://in-toto.io/Statement/v0.1"}`),
		expected: processor.FormatITE6,
	}, {
		name:     "valid SLSA ITE6 Document",
		blob:     []byte(`{"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://slsa.dev/provenance/v0.2"}`),
		expected: processor.FormatSLSA,
	}}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			guesser := &ite6FormatGuesser{}
			f := guesser.GuessFormat(tt.blob)
			if f != tt.expected {
				t.Errorf("got the wrong format, got %v, expected %v", f, tt.expected)
			}
		})
	}

}
