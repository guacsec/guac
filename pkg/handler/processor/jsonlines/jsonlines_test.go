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

package jsonlines

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/guacsec/guac/pkg/handler/processor"
)

var (
	singleLineDSSE = strings.ReplaceAll(`{
		"payload": "aGVsbG8gd29ybGQ=",
		"payloadType": "http://example.com/HelloWorld",
		"signatures": [
			{
				"keyid": "4205d7b430cb1c84e6db1a43cc3e747e78702a0d56a43174ee17158aa92e9f5b",
				"sig": "A3JqsQGtVsJ2O2xqrI5IcnXip5GToJ3F+FnZ+O88SjtR6rDAajabZKciJTfUiHqJPcIAriEGAHTVeCUjW2JIZA=="
			}
		]
	}`, "\n", "")
	jsonLinesUnknownDSSEDoc = processor.Document{
		Blob:   []byte(fmt.Sprintf("%s\n%s", singleLineDSSE, singleLineDSSE)),
		Type:   processor.DocumentJsonLines,
		Format: processor.FormatJSONLines,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}
	decodedPayload, _               = base64.StdEncoding.DecodeString("aGVsbG8gd29ybGQ=")
	unpackedJsonLinesUnknownDSSEDoc = processor.Document{
		Blob:   decodedPayload,
		Type:   processor.DocumentUnknown,
		Format: processor.FormatUnknown,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}
	singleLineJson  = `{"a": "b"}`
	jsonLinesSimple = processor.Document{
		Blob:   []byte(fmt.Sprintf("%s\n%s", singleLineJson, singleLineJson)),
		Type:   processor.DocumentJsonLines,
		Format: processor.FormatJSONLines,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}
	unpackedJsonLinesSimple = processor.Document{
		Blob:   []byte(singleLineJson),
		Type:   processor.DocumentUnknown,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}
	incorrectTypeDoc = processor.Document{
		Blob:   []byte("not valid JSON Lines"),
		Type:   processor.DocumentUnknown,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}
)

func TestJsonLinesProcessor_Unpack(t *testing.T) {
	testCases := []struct {
		name      string
		doc       processor.Document
		expected  []*processor.Document
		expectErr bool
	}{{
		name:      "JSON Lines with DSSE Unknown Payload entries",
		doc:       jsonLinesUnknownDSSEDoc,
		expected:  []*processor.Document{&unpackedJsonLinesUnknownDSSEDoc, &unpackedJsonLinesUnknownDSSEDoc},
		expectErr: false,
	}, {
		name:      "JSON Lines with random json entries",
		doc:       jsonLinesSimple,
		expected:  []*processor.Document{&unpackedJsonLinesSimple, &unpackedJsonLinesSimple},
		expectErr: false,
	}, {
		name:      "Incorrect type",
		doc:       incorrectTypeDoc,
		expected:  nil,
		expectErr: true,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			d := JsonLinesProcessor{}
			actual, err := d.Unpack(&tt.doc)
			if (err != nil) != tt.expectErr {
				t.Errorf("JsonLinesProcessor.Unpack() error = %v, expectErr %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(actual, tt.expected) {
				t.Errorf("JsonLinesProcessor.Unpack() = %v, expected %v", actual, tt.expected)
			}
		})
	}
}

func TestDSSEProcessor_ValidateSchema(t *testing.T) {
	testCases := []struct {
		name      string
		doc       processor.Document
		expectErr bool
	}{{
		name:      "Valid JSON Lines",
		doc:       jsonLinesUnknownDSSEDoc,
		expectErr: false,
	}, {
		name:      "Invalid JSON Lines",
		doc:       incorrectTypeDoc,
		expectErr: true,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			d := JsonLinesProcessor{}
			err := d.ValidateSchema(&tt.doc)
			if (err != nil) != tt.expectErr {
				t.Errorf("JsonLinesProcessor.ValidateSchema() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}
