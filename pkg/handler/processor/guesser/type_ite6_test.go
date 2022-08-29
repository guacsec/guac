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
		expected: processor.DocumentITE6,
	}, {
		name:     "valid SLSA ITE6 Document",
		blob:     []byte(`{"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://slsa.dev/provenance/v0.2"}`),
		expected: processor.DocumentSLSA,
	}, {
		name:     "valid SLSA ITE6 Document with different versions",
		blob:     []byte(`{"_type": "https://in-toto.io/Statement/v1.1", "predicateType": "https://slsa.dev/provenance/v1.0"}`),
		expected: processor.DocumentSLSA,
	}}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			guesser := &ite6TypeGusser{}
			f := guesser.GuessDocumentType(tt.blob, processor.FormatJSON)
			if f != tt.expected {
				t.Errorf("got the wrong format, got %v, expected %v", f, tt.expected)
			}
		})
	}

}
