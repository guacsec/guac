//
// Copyright 2022 The AFF Authors.
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

package process

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/guacsec/guac/internal/testing/ingestor/simpledoc"
	"github.com/guacsec/guac/pkg/ingestor/processor"
	"github.com/sirupsen/logrus"
)

func Test_SimpleDocProcessTest(t *testing.T) {
	testCases := []struct {
		name      string
		doc       processor.Document
		expected  []processor.Document
		expectErr bool
	}{{

		name: "simple test",
		doc: processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:   simpledoc.SimpleDocType,
			Format: processor.FormatJSON,
			TrustInformation: processor.TrustInformation{
				IssuerUri: ptrStr("google.com"),
			},
			SourceInformation: processor.SourceInformation{},
		},
		expected: []processor.Document{
			{
				Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
				Type:   simpledoc.SimpleDocType,
				Format: processor.FormatJSON,
				TrustInformation: processor.TrustInformation{
					IssuerUri: ptrStr("google.com"),
				},
				SourceInformation: processor.SourceInformation{},
			},
		},
	}, {

		name: "unpack test",
		doc: processor.Document{
			Blob: []byte(`{
						 "issuer": "google.com",
						 "info": "this is a cool document",
						 "nested": [{
							 "issuer": "google.com",
							 "info": "this is a cooler nested doc 1"
						 },{
							 "issuer": "google.com",
							 "info": "this is a cooler nested doc 2"
						 }]
						}`),
			Type:   simpledoc.SimpleDocType,
			Format: processor.FormatJSON,
			TrustInformation: processor.TrustInformation{
				IssuerUri: ptrStr("google.com"),
			},
			SourceInformation: processor.SourceInformation{},
		},
		expected: []processor.Document{
			{
				Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cooler nested doc 1"
					}`),
				Type:   simpledoc.SimpleDocType,
				Format: processor.FormatJSON,
				TrustInformation: processor.TrustInformation{
					IssuerUri: ptrStr("google.com"),
				},
				SourceInformation: processor.SourceInformation{},
			}, {
				Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cooler nested doc 2"
					}`),
				Type:   simpledoc.SimpleDocType,
				Format: processor.FormatJSON,
				TrustInformation: processor.TrustInformation{
					IssuerUri: ptrStr("google.com"),
				},
				SourceInformation: processor.SourceInformation{},
			},
		},
	}, {

		name: "unpack twice test",
		doc: processor.Document{
			Blob: []byte(`{
						 "issuer": "google.com",
						 "info": "this is a cool document",
						 "nested": [{
							 "issuer": "google.com",
							 "info": "this is a cooler nested doc 1",
							 "nested": [{
							   "issuer": "google.com",
							   "info": "this is a cooler nested doc 3"
							 }]
						 },{
							 "issuer": "google.com",
							 "info": "this is a cooler nested doc 2",
							 "nested": [{
							   "issuer": "google.com",
							   "info": "this is a cooler nested doc 4"
							 }]
						 }]
						}`),
			Type:   simpledoc.SimpleDocType,
			Format: processor.FormatJSON,
			TrustInformation: processor.TrustInformation{
				IssuerUri: ptrStr("google.com"),
			},
			SourceInformation: processor.SourceInformation{},
		},
		expected: []processor.Document{
			{
				Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cooler nested doc 3"
					}`),
				Type:   simpledoc.SimpleDocType,
				Format: processor.FormatJSON,
				TrustInformation: processor.TrustInformation{
					IssuerUri: ptrStr("google.com"),
				},
				SourceInformation: processor.SourceInformation{},
			}, {
				Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cooler nested doc 4"
					}`),
				Type:   simpledoc.SimpleDocType,
				Format: processor.FormatJSON,
				TrustInformation: processor.TrustInformation{
					IssuerUri: ptrStr("google.com"),
				},
				SourceInformation: processor.SourceInformation{},
			},
		},
	}, {

		name: "unpack assymetric test",
		doc: processor.Document{
			Blob: []byte(`{
				 "issuer": "google.com",
				 "info": "this is a cool document",
				 "nested": [{
					 "issuer": "google.com",
					 "info": "this is a cooler nested doc 1"
				 },{
					 "issuer": "google.com",
					 "info": "this is a cooler nested doc 2",
					 "nested": [{
					   "issuer": "google.com",
					   "info": "this is a cooler nested doc 4"
					 }]
				 }]
				}`),
			Type:   simpledoc.SimpleDocType,
			Format: processor.FormatJSON,
			TrustInformation: processor.TrustInformation{
				IssuerUri: ptrStr("google.com"),
			},
			SourceInformation: processor.SourceInformation{},
		},
		expected: []processor.Document{
			{
				Blob: []byte(`{
				"issuer": "google.com",
				"info": "this is a cooler nested doc 1"
			}`),
				Type:   simpledoc.SimpleDocType,
				Format: processor.FormatJSON,
				TrustInformation: processor.TrustInformation{
					IssuerUri: ptrStr("google.com"),
				},
				SourceInformation: processor.SourceInformation{},
			}, {
				Blob: []byte(`{
				"issuer": "google.com",
				"info": "this is a cooler nested doc 4"
			}`),
				Type:   simpledoc.SimpleDocType,
				Format: processor.FormatJSON,
				TrustInformation: processor.TrustInformation{
					IssuerUri: ptrStr("google.com"),
				},
				SourceInformation: processor.SourceInformation{},
			},
		},
	}, {

		name: "bad format",
		doc: processor.Document{
			Blob: []byte(`{ NOT JSON YO
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:   simpledoc.SimpleDocType,
			Format: processor.FormatJSON,
			TrustInformation: processor.TrustInformation{
				IssuerUri: ptrStr("google.com"),
			},
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}, {

		name: "bad format type",
		doc: processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:   simpledoc.SimpleDocType,
			Format: "invalid-format",
			TrustInformation: processor.TrustInformation{
				IssuerUri: ptrStr("google.com"),
			},
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}, {

		name: "bad document schema",
		doc: processor.Document{
			// simpledoc requires issuer
			Blob: []byte(`{
                        "info": "this is a cool document"
                    }`),
			Type:   simpledoc.SimpleDocType,
			Format: processor.FormatJSON,
			TrustInformation: processor.TrustInformation{
				IssuerUri: ptrStr("google.com"),
			},
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}, {

		name: "bad schema type",
		doc: processor.Document{
			Blob: []byte(`{
                        "issuer": "google.com",
                        "info": "this is a cool document"
                    }`),
			Type:   "invalid-document-type",
			Format: processor.FormatJSON,
			TrustInformation: processor.TrustInformation{
				IssuerUri: ptrStr("google.com"),
			},
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}, {

		// validate trust
		name: "bad trust info",
		doc: processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:   simpledoc.SimpleDocType,
			Format: processor.FormatJSON,
			TrustInformation: processor.TrustInformation{
				IssuerUri: ptrStr("bing.com"),
			},
			SourceInformation: processor.SourceInformation{},
		},
		expected: []processor.Document{},
	}, {

		name: "bad nested trust info",
		doc: processor.Document{
			Blob: []byte(`{
						 "issuer": "google.com",
						 "info": "this is a cool document",
						 "nested": [{
							 "issuer": "bing.com",
							 "info": "this is a cooler nested doc 1"
						 },{
							 "issuer": "google.com",
							 "info": "this is a cooler nested doc 2"
						 }]
						}`),
			Type:   simpledoc.SimpleDocType,
			Format: processor.FormatJSON,
			TrustInformation: processor.TrustInformation{
				IssuerUri: ptrStr("google.com"),
			},
			SourceInformation: processor.SourceInformation{},
		},
		expected: []processor.Document{
			{
				Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cooler nested doc 2"
					}`),
				Type:   simpledoc.SimpleDocType,
				Format: processor.FormatJSON,
				TrustInformation: processor.TrustInformation{
					IssuerUri: ptrStr("google.com"),
				},
				SourceInformation: processor.SourceInformation{},
			},
		},
	}, {

		// misc
		name: "propagate source info",
		doc: processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:   simpledoc.SimpleDocType,
			Format: processor.FormatJSON,
			TrustInformation: processor.TrustInformation{
				IssuerUri: ptrStr("google.com"),
			},
			SourceInformation: processor.SourceInformation{
				Collector: "a-collector",
				Source:    "a-source",
			},
		},
		expected: []processor.Document{
			{
				Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
				Type:   simpledoc.SimpleDocType,
				Format: processor.FormatJSON,
				TrustInformation: processor.TrustInformation{
					IssuerUri: ptrStr("google.com"),
				},
				SourceInformation: processor.SourceInformation{
					Collector: "a-collector",
					Source:    "a-source",
				},
			},
		},
	}, {

		// misc
		name: "propagate nested source info",
		doc: processor.Document{
			Blob: []byte(`{
                         "issuer": "google.com",
                         "info": "this is a cool document",
                         "nested": [{
                             "issuer": "google.com",
                             "info": "this is a cooler nested doc 1"
                         },{
                             "issuer": "google.com",
                             "info": "this is a cooler nested doc 2"
                         }]
                        }`),
			Type:   simpledoc.SimpleDocType,
			Format: processor.FormatJSON,
			TrustInformation: processor.TrustInformation{
				IssuerUri: ptrStr("google.com"),
			},
			SourceInformation: processor.SourceInformation{
				Collector: "a-collector",
				Source:    "a-source",
			},
		},
		expected: []processor.Document{
			{
				Blob: []byte(`{
                        "issuer": "google.com",
                        "info": "this is a cooler nested doc 1"
                    }`),
				Type:   simpledoc.SimpleDocType,
				Format: processor.FormatJSON,
				TrustInformation: processor.TrustInformation{
					IssuerUri: ptrStr("google.com"),
				},
				SourceInformation: processor.SourceInformation{
					Collector: "a-collector",
					Source:    "a-source",
				},
			}, {
				Blob: []byte(`{
                        "issuer": "google.com",
                        "info": "this is a cooler nested doc 2"
                    }`),
				Type:   simpledoc.SimpleDocType,
				Format: processor.FormatJSON,
				TrustInformation: processor.TrustInformation{
					IssuerUri: ptrStr("google.com"),
				},
				SourceInformation: processor.SourceInformation{
					Collector: "a-collector",
					Source:    "a-source",
				},
			},
		},
	}}

	logrus.SetLevel(logrus.DebugLevel)
	// Register
	RegisterDocumentProcessor(&simpledoc.SimpleDocProc{}, simpledoc.SimpleDocType)
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			docs, err := Process(&tt.doc)
			if err != nil {
				if tt.expectErr {
					return
				}
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Compare docs
			if len(docs) != len(tt.expected) {
				t.Errorf("number of docs got %v, expected %v", len(docs), len(tt.expected))
				return
			}
			for _, d := range docs {
				if !existAndPop(tt.expected, *d) {
					t.Errorf("got doc but not expected: %v", d)
					return
				}
			}
		})
	}
}

func existAndPop(docs []processor.Document, d processor.Document) bool {
	for i, dd := range docs {
		d.Blob = consistentJsonBytes(d.Blob)
		dd.Blob = consistentJsonBytes(dd.Blob)
		if reflect.DeepEqual(d, dd) {
			docs = append(docs[:i], docs[i+1:]...)
			return true
		}
	}
	return false
}

func ptrStr(i string) *string {
	return &i
}

// consistentJsonBytes makes sure that the blob byte comparison
// does not differ due to whitespace in testing definitions.
func consistentJsonBytes(b []byte) []byte {
	var v interface{}
	err := json.Unmarshal(b, &v)
	if err != nil {
		panic(err)
	}
	out, _ := json.Marshal(v)
	return out
}
