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

	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func Test_GuessDocument(t *testing.T) {
	testCases := []struct {
		name           string
		document       *processor.Document
		expectedType   processor.DocumentType
		expectedFormat processor.FormatType
	}{{
		name: "DocumentUnknown JSON",
		document: &processor.Document{
			Blob:              []byte(`{ "abc": "def"}`),
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectedType:   processor.DocumentUnknown,
		expectedFormat: processor.FormatJSON,
	}, {
		name: "DocumentUnknown empty JSON",
		document: &processor.Document{
			Blob:              []byte(``),
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		expectedType:   processor.DocumentUnknown,
		expectedFormat: processor.FormatJSON,
	}, {
		name: "DocumentUnknown, FormatUnknown",
		document: &processor.Document{
			Blob:              []byte(`unstructured text`),
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectedType:   processor.DocumentUnknown,
		expectedFormat: processor.FormatUnknown,
	}, {
		name: "valid small spdx Document",
		document: &processor.Document{
			Blob:              testdata.SpdxExampleSmall,
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectedType:   processor.DocumentSPDX,
		expectedFormat: processor.FormatJSON,
	}, {
		name: "valid big spdx Document",
		document: &processor.Document{
			Blob:              testdata.SpdxExampleBig,
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectedType:   processor.DocumentSPDX,
		expectedFormat: processor.FormatJSON,
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
		expectedType:   processor.DocumentDSSE,
		expectedFormat: processor.FormatJSON,
	}, {
		name: "valid ITE6 Document",
		document: &processor.Document{
			Blob:              []byte(`{"_type": "https://in-toto.io/Statement/v0.1"}`),
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectedType:   processor.DocumentITE6Generic,
		expectedFormat: processor.FormatJSON,
	}, {
		name: "valid SLSA ITE6 Document",
		document: &processor.Document{
			Blob:              []byte(`{"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://slsa.dev/provenance/v0.2"}`),
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectedType:   processor.DocumentITE6SLSA,
		expectedFormat: processor.FormatJSON,
	}, {
		name: "valid SLSA ITE6 Document with different versions",
		document: &processor.Document{
			Blob:              []byte(`{"_type": "https://in-toto.io/Statement/v1.1", "predicateType": "https://slsa.dev/provenance/v1.0"}`),
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectedType:   processor.DocumentITE6SLSA,
		expectedFormat: processor.FormatJSON,
	}, {
		name: "valid scorecard Document",
		document: &processor.Document{
			Blob:              testdata.ScorecardExample,
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectedType:   processor.DocumentScorecard,
		expectedFormat: processor.FormatJSON,
	}, {
		name: "valid big cyclonedx Document",
		document: &processor.Document{
			Blob:              testdata.CycloneDXBigExample,
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectedType:   processor.DocumentCycloneDX,
		expectedFormat: processor.FormatJSON,
	}, {
		name: "valid small cyclonedx Document",
		document: &processor.Document{
			Blob:              testdata.CycloneDXBusyboxExample,
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectedType:   processor.DocumentCycloneDX,
		expectedFormat: processor.FormatJSON,
	}, {
		name: "valid CREV ITE6 Document",
		document: &processor.Document{
			Blob:              testdata.ITE6CREVExample,
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectedType:   processor.DocumentITE6Generic,
		expectedFormat: processor.FormatJSON,
	}, {
		name: "valid Review ITE6 Document",
		document: &processor.Document{
			Blob:              testdata.ITE6ReviewExample,
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectedType:   processor.DocumentITE6Generic,
		expectedFormat: processor.FormatJSON,
	}, {
		name: "valid Vuln ITE6 Document",
		document: &processor.Document{
			Blob:              testdata.ITE6VulnExample,
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectedType:   processor.DocumentITE6Vul,
		expectedFormat: processor.FormatJSON,
	}, {
		name: "valid deps.dev Document",
		document: &processor.Document{
			Blob:              []byte(testdata.CollectedYargsParser),
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectedType:   processor.DocumentDepsDev,
		expectedFormat: processor.FormatJSON,
	}, {
		name: "valid CSAF Document",
		document: &processor.Document{
			Blob:              testdata.CsafExampleRedHat,
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectedType:   processor.DocumentCsaf,
		expectedFormat: processor.FormatJSON,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			documentType, documentFormat, err := GuessDocument(context.TODO(), tt.document)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			} else if documentType != tt.expectedType || documentFormat != tt.expectedFormat {
				t.Errorf("document type, format: got %v, %v, expected %v, %v", documentType, documentFormat, tt.expectedType, tt.expectedFormat)
			}
		})
	}
}
