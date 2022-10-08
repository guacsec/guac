package guesser

import (
	"testing"

	testdata "github.com/guacsec/guac/internal/testing/processor"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func Test_cyclonedxTypeGuesser_GuessDocumentType(t *testing.T) {
	testCases := []struct {
		name     string
		blob     []byte
		expected processor.DocumentType
	}{{
		name: "invalid cyclonedx Document",
		blob: []byte(`{
			"abc": "def"
		}`),
		expected: processor.DocumentUnknown,
	}, {
		name:     "invalid cyclonedx Document",
		blob:     testdata.CycloneDXInvalidExample,
		expected: processor.DocumentUnknown,
	}, {
		name:     "valid small cyclonedx Document",
		blob:     testdata.CycloneDXBusyboxExample,
		expected: processor.DocumentCycloneDX,
	}, {
		name:     "valid distroless cyclonedx Document",
		blob:     testdata.CycloneDXDistrolessExample,
		expected: processor.DocumentCycloneDX,
	}, {
		name:     "valid alpine cyclonedx Document",
		blob:     testdata.CycloneDXExampleAlpine,
		expected: processor.DocumentCycloneDX,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			guesser := &cycloneDXTypeGuesser{}
			f := guesser.GuessDocumentType(tt.blob, processor.FormatJSON)
			if f != tt.expected {
				t.Errorf("got the wrong format, got %v, expected %v", f, tt.expected)
			}
		})
	}
}
