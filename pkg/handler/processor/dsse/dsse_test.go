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

package dsse

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

var (
	unknownDSSEDoc = processor.Document{
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
		Type:   processor.DocumentDSSE,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}
	decodedPayload, _      = base64.StdEncoding.DecodeString("aGVsbG8gd29ybGQ=")
	unpackedUnknownDSSEDoc = processor.Document{
		Blob:   decodedPayload,
		Type:   processor.DocumentUnknown,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}
	// Taken from: https://slsa.dev/provenance/v0.1#example
	ite6SLSA = `
	{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": [{"name": "_", "digest": {"sha256": "5678..."}}],
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
		  "buildType": "https://example.com/Makefile",
		  "builder": { "id": "mailto:person@example.com" },
		  "invocation": {
			"configSource": {
			  "uri": "https://example.com/example-1.2.3.tar.gz",
			  "digest": {"sha256": "1234..."},
			  "entryPoint": "src:foo",                
			},
			"parameters": {"CFLAGS": "-O3"}           
		  },
		  "materials": [{
			"uri": "https://example.com/example-1.2.3.tar.gz",
			"digest": {"sha256": "1234..."}
		  }]
		}
	}`
	b64ITE6SLSA    = base64.StdEncoding.EncodeToString([]byte(ite6SLSA))
	ite6Payload, _ = json.Marshal(dsse.Envelope{
		PayloadType: string(dsseITE6),
		Payload:     b64ITE6SLSA,
		Signatures: []dsse.Signature{{
			KeyID: "id1",
			Sig:   "test",
		}},
	})
	ite6DSSEDoc = processor.Document{
		Blob:   ite6Payload,
		Type:   processor.DocumentDSSE,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}
	ite6SLSADoc = processor.Document{
		Blob:   []byte(ite6SLSA),
		Type:   processor.DocumentITE6,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}
	incorrectTypeDoc = processor.Document{
		Blob:   []byte("not a DSSE Envelope"),
		Type:   processor.DocumentUnknown,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}
)

func TestDSSEProcessor_Unpack(t *testing.T) {
	testCases := []struct {
		name      string
		doc       processor.Document
		expected  []*processor.Document
		expectErr bool
	}{{
		name:      "DSSE Envelope with Unknown Payload",
		doc:       unknownDSSEDoc,
		expected:  []*processor.Document{&unpackedUnknownDSSEDoc},
		expectErr: false,
	}, {
		name:      "DSSE Envelope with ITE6",
		doc:       ite6DSSEDoc,
		expected:  []*processor.Document{&ite6SLSADoc},
		expectErr: false,
	}, {
		name:      "Incorrect type",
		doc:       incorrectTypeDoc,
		expected:  nil,
		expectErr: true,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			d := DSSEProcessor{}
			actual, err := d.Unpack(&tt.doc)
			if (err != nil) != tt.expectErr {
				t.Errorf("DSSEProcessor.Unpack() error = %v, expectErr %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(actual, tt.expected) {
				t.Errorf("DSSEProcessor.Unpack() = %v, expected %v", actual, tt.expected)
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
		name:      "Valid DSSE Envelope",
		doc:       unknownDSSEDoc,
		expectErr: false,
	}, {
		name:      "Invalid DSSE Envelope",
		doc:       incorrectTypeDoc,
		expectErr: true,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			d := DSSEProcessor{}
			err := d.ValidateSchema(&tt.doc)
			if (err != nil) != tt.expectErr {
				t.Errorf("DSSEProcessor.ValidateSchema() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}
