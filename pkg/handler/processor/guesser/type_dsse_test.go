package guesser

import (
	"testing"

	"github.com/guacsec/guac/pkg/handler/processor"
)

func Test_DSSETypeGuesser(t *testing.T) {
	testCases := []struct {
		name     string
		blob     []byte
		expected processor.DocumentType
	}{{
		name:     "invalid DSSE Document",
		blob:     []byte(`{ "abc": "def"}`),
		expected: processor.DocumentUnknown,
	}, {
		name: "valid DSSE Document",
		blob: []byte(`
		{
			"payload": "aGVsbG8gd29ybGQ=",
			"payloadType": "http://example.com/HelloWorld",
			"signatures": [
				{
					"keyid": "4205d7b430cb1c84e6db1a43cc3e747e78702a0d56a43174ee17158aa92e9f5b",
					"sig": "A3JqsQGtVsJ2O2xqrI5IcnXip5GToJ3F+FnZ+O88SjtR6rDAajabZKciJTfUiHqJPcIAriEGAHTVeCUjW2JIZA=="
				}
			]
		}`),
		expected: processor.DocumentDSSE,
	}}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			guesser := &dsseTypeGuesser{}
			f := guesser.GuessDocumentType(tt.blob, processor.FormatJSON)
			if f != tt.expected {
				t.Errorf("got the wrong format, got %v, expected %v", f, tt.expected)
			}
		})
	}

}
