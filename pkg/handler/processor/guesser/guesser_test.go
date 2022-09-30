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
	"context"
	"testing"

	testdata "github.com/guacsec/guac/internal/testing/processor"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func Test_GuessDocument(t *testing.T) {
	testCases := []struct {
		name     string
		document *processor.Document
		expected processor.DocumentType
	}{{
		name: "DocumentUnknown",
		document: &processor.Document{
			Blob:              []byte(`{ "abc": "def"}`),
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expected: processor.DocumentUnknown,
	}, {
		name: "DocumentUnknown",
		document: &processor.Document{
			Blob:              testdata.SpdxInvalidExample,
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expected: processor.DocumentUnknown,
	}, {
		name: "valid small spdx Document",
		document: &processor.Document{
			Blob:              testdata.SpdxExampleSmall,
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expected: processor.DocumentSPDX,
	}, {
		name: "valid big spdx Document",
		document: &processor.Document{
			Blob:              testdata.SpdxExampleBig,
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expected: processor.DocumentSPDX,
	}, {
		name: "valid DSSE Document",
		document: &processor.Document{
			Blob: []byte(`
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
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expected: processor.DocumentDSSE,
	}, {
		name: "valid ITE6 Document",
		document: &processor.Document{
			Blob:              []byte(`{"_type": "https://in-toto.io/Statement/v0.1"}`),
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expected: processor.DocumentITE6Unknown,
	}, {
		name: "valid SLSA ITE6 Document",
		document: &processor.Document{
			Blob:              []byte(`{"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://slsa.dev/provenance/v0.2"}`),
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expected: processor.DocumentITE6SLSA,
	}, {
		name: "valid SLSA ITE6 Document with different versions",
		document: &processor.Document{
			Blob:              []byte(`{"_type": "https://in-toto.io/Statement/v1.1", "predicateType": "https://slsa.dev/provenance/v1.0"}`),
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expected: processor.DocumentITE6SLSA,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			documentType, _, err := GuessDocument(context.TODO(), tt.document)
			if err == nil && documentType != tt.expected {
				t.Errorf("got the wrong type, got %v, expected %v", documentType, tt.expected)
			}
		})
	}
}
