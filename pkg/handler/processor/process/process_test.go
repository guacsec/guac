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

package process

import (
	"context"
	"strings"
	"testing"

	"github.com/guacsec/guac/internal/testing/dochelper"
	"github.com/guacsec/guac/internal/testing/simpledoc"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/guesser"
	"github.com/guacsec/guac/pkg/logging"
)

func Test_SimpleDocProcessTest(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	testCases := []struct {
		name      string
		doc       processor.Document
		expected  processor.DocumentTree
		expectErr bool
	}{{

		name: "simple test",
		doc: processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		expected: dochelper.DocNode(&processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		}),
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
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		expected: dochelper.DocNode(
			&processor.Document{ //root
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
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			},
			dochelper.DocNode(&processor.Document{ // child 1
				Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cooler nested doc 1"
					}`),
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			}),
			dochelper.DocNode(&processor.Document{ //child 2
				Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cooler nested doc 2"
					}`),
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			})),
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
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		expected: dochelper.DocNode(
			&processor.Document{ // root
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
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			},
			dochelper.DocNode(&processor.Document{
				Blob: []byte(`{
							"issuer": "google.com",
							 "info": "this is a cooler nested doc 1",
							 "nested": [{
							   "issuer": "google.com",
							   "info": "this is a cooler nested doc 3"
							 }]
							 }`),
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			},
				dochelper.DocNode(&processor.Document{
					Blob: []byte(`{
                        "issuer": "google.com",
                        "info": "this is a cooler nested doc 3"
                    }`),
					Type:              simpledoc.SimpleDocType,
					Format:            processor.FormatJSON,
					SourceInformation: processor.SourceInformation{},
				})),
			dochelper.DocNode(&processor.Document{
				Blob: []byte(`{
                              "issuer": "google.com",
                               "info": "this is a cooler nested doc 2",
                               "nested": [{
                                 "issuer": "google.com",
                                 "info": "this is a cooler nested doc 4"
                               }]
                               }`),
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			},
				dochelper.DocNode(&processor.Document{
					Blob: []byte(`{
                        "issuer": "google.com",
                        "info": "this is a cooler nested doc 4"
                    }`),
					Type:              simpledoc.SimpleDocType,
					Format:            processor.FormatJSON,
					SourceInformation: processor.SourceInformation{},
				}))),
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
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		expected: dochelper.DocNode(
			&processor.Document{ //root
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
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			},
			dochelper.DocNode(&processor.Document{ // child 1
				Blob: []byte(`{
				"issuer": "google.com",
				"info": "this is a cooler nested doc 1"
			}`),
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			}),
			dochelper.DocNode(&processor.Document{ // child 2
				Blob: []byte(`{
				"issuer": "google.com",
				"info": "this is a cooler nested doc 2",
				"nested": [{
				   "issuer": "google.com",
				   "info": "this is a cooler nested doc 4"
				 }]
				}`),
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			},
				dochelper.DocNode(&processor.Document{ // child 2.1
					Blob: []byte(`{
                  "issuer": "google.com",
                  "info": "this is a cooler nested doc 4"
                  }`),
					Type:              simpledoc.SimpleDocType,
					Format:            processor.FormatJSON,
					SourceInformation: processor.SourceInformation{},
				})),
		),
	}, {

		name: "bad format",
		doc: processor.Document{
			Blob: []byte(`{ NOT JSON YO
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
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
			Type:              simpledoc.SimpleDocType,
			Format:            "invalid-format",
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
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
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
			Type:              "invalid-document-type",
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}, {

		name: "unknown format",
		doc: processor.Document{
			Blob: []byte(`{ NOT JSON YO
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}, {

		name: "unknown document",
		doc: processor.Document{
			Blob: []byte(`{
						"abc": "def"
					}`),
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
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
			SourceInformation: processor.SourceInformation{
				Collector: "a-collector",
				Source:    "a-source",
			},
		},
		expected: dochelper.DocNode(&processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:   simpledoc.SimpleDocType,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector: "a-collector",
				Source:    "a-source",
			},
		}),
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
			SourceInformation: processor.SourceInformation{
				Collector: "a-collector",
				Source:    "a-source",
			},
		},
		expected: dochelper.DocNode(
			&processor.Document{ //root
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
				SourceInformation: processor.SourceInformation{
					Collector: "a-collector",
					Source:    "a-source",
				},
			},
			dochelper.DocNode(&processor.Document{ //child 1
				Blob: []byte(`{
                        "issuer": "google.com",
                        "info": "this is a cooler nested doc 1"
                    }`),
				Type:   simpledoc.SimpleDocType,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "a-collector",
					Source:    "a-source",
				},
			}),
			dochelper.DocNode(&processor.Document{ //child 2
				Blob: []byte(`{
                        "issuer": "google.com",
                        "info": "this is a cooler nested doc 2"
                    }`),
				Type:   simpledoc.SimpleDocType,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "a-collector",
					Source:    "a-source",
				},
			})),
	}, {

		// preprocessor tests
		name: "preprocessor on format JSON",
		doc: processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expected: dochelper.DocNode(&processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		}),
	}, {

		name: "preprocessor on simpledoc",
		doc: processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expected: dochelper.DocNode(&processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		}),
	},
	}

	// Register
	err := RegisterDocumentProcessor(&simpledoc.SimpleDocProc{}, simpledoc.SimpleDocType)
	if err != nil {
		if !strings.Contains(err.Error(), "the document processor is being overwritten") {
			t.Errorf("unexpected error: %v", err)
		}
	}
	err = guesser.RegisterDocumentTypeGuesser(&simpledoc.SimpleDocProc{}, "simple-doc-guesser")
	if err != nil {
		if !strings.Contains(err.Error(), "the document type guesser is being overwritten") {
			t.Errorf("unexpected error: %v", err)
		}
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			docTree, err := Process(ctx, &tt.doc)
			if err != nil {
				if tt.expectErr {
					return
				}
				t.Errorf("unexpected error: %v", err)
				return
			}

			if !dochelper.DocTreeEqual(docTree, tt.expected) {
				t.Errorf("doc tree did not match up, got\n%s, \nexpected\n%s", dochelper.StringTree(docTree), dochelper.StringTree(tt.expected))
			}

			/*
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
			*/
		})
	}
}

func Test_validateFormat(t *testing.T) {
	tests := []struct {
		name    string
		doc     processor.Document
		wantErr bool
	}{
		{
			name: "valid XML format document",
			doc: processor.Document{
				Blob:   []byte(testdata.CycloneDXExampleLaravelXML),
				Type:   processor.DocumentCycloneDX,
				Format: processor.FormatXML,
				SourceInformation: processor.SourceInformation{
					Collector: "a-collector",
					Source:    "a-source",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid XML format document",
			doc: processor.Document{
				Blob:   []byte(testdata.CycloneDXInvalidExampleXML),
				Type:   processor.DocumentCycloneDX,
				Format: processor.FormatXML,
				SourceInformation: processor.SourceInformation{
					Collector: "a-collector",
					Source:    "a-source",
				},
			},
			wantErr: true,
		},
		{
			name: "valid JSON document",
			doc: processor.Document{
				Blob:   []byte(testdata.SpdxExampleSmall),
				Type:   processor.DocumentSPDX,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "a-collector",
					Source:    "a-source",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateFormat(&tt.doc); (err != nil) != tt.wantErr {
				t.Errorf("validateFormat() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}



func Test_guessEncoding(t *testing.T) {
	tests := []struct {
		name    string
		doc     processor.Document
		wantErr bool
		wantMimeType string
	}{
		{
			name: "valid .bz2 format document",
			doc: processor.Document{
				Blob:   []byte(testdata.CycloneDXBz2Example),
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: "a-collector",
					Source:    "a-source",
				},
			},
			wantErr: false,
			wantMimeType: "application/x-bzip2",
		},
		{
			name: "valid .zst format document",
			doc: processor.Document{
				Blob:   []byte(testdata.CycloneDXZstdExample),
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: "a-collector",
					Source:    "a-source",
				},
			},
			wantErr: false,
			wantMimeType: "application/zstd",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mimeType, err := detectFileEncoding(&tt.doc)
			if (err != nil) != tt.wantErr {
				t.Errorf("detectFileEncoding() error = %v, wantErr %v", err, tt.wantErr)
			}
			if mimeType !=  tt.wantMimeType {
				t.Errorf("detectFileEncoding() incorrect mimeType = %v", mimeType)
			}
		})
	}
}

/*
// TODO: Fix tests to check for logger messages instead of err text
// https://github.com/guacsec/guac/issues/765
func Test_ProcessSubscribe(t *testing.T) {
	natsTest := nats_test.NewNatsTestServer()
	url, err := natsTest.EnableJetStreamForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer natsTest.Shutdown()

	testCases := []struct {
		name       string
		doc        processor.Document
		wantErr    bool
		expected   processor.DocumentTree
		errMessage string
	}{{
		name: "simple test",
		doc: processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		wantErr: true,
		expected: dochelper.DocNode(&processor.Document{
			Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		}),
		errMessage: "context deadline exceeded",
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
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		wantErr: true,
		expected: dochelper.DocNode(
			&processor.Document{ //root
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
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			},
			dochelper.DocNode(&processor.Document{ // child 1
				Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cooler nested doc 1"
					}`),
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			}),
			dochelper.DocNode(&processor.Document{ //child 2
				Blob: []byte(`{
						"issuer": "google.com",
						"info": "this is a cooler nested doc 2"
					}`),
				Type:              simpledoc.SimpleDocType,
				Format:            processor.FormatJSON,
				SourceInformation: processor.SourceInformation{},
			})),
		errMessage: "context deadline exceeded",
	}, {
		name: "bad format",
		doc: processor.Document{
			Blob: []byte(`{ NOT JSON YO
						"issuer": "google.com",
						"info": "this is a cool document"
					}`),
			Type:              simpledoc.SimpleDocType,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		wantErr:    true,
		errMessage: "failed process document: invalid JSON document",
	}}

	// Register
	err = RegisterDocumentProcessor(&simpledoc.SimpleDocProc{}, simpledoc.SimpleDocType)
	if err != nil {
		if !strings.Contains(err.Error(), "the document processor is being overwritten") {
			t.Errorf("unexpected error: %v", err)
		}
	}
	err = guesser.RegisterDocumentTypeGuesser(&simpledoc.SimpleDocProc{}, "simple-doc-guesser")
	if err != nil {
		if !strings.Contains(err.Error(), "the document type guesser is being overwritten") {
			t.Errorf("unexpected error: %v", err)
		}
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			jetStream := emitter.NewJetStream(url, "", "")
			ctx, err = jetStream.JetStreamInit(ctx)
			if err != nil {
				t.Fatalf("unexpected error initializing jetstream: %v", err)
			}
			err = jetStream.RecreateStream(ctx)
			if err != nil {
				t.Fatalf("unexpected error recreating jetstream: %v", err)
			}
			defer jetStream.Close()

			err := testPublish(ctx, &tt.doc)
			if err != nil {
				t.Fatalf("unexpected error on emit: %v", err)
			}
			var cancel context.CancelFunc

			ctx, cancel = context.WithTimeout(ctx, 1*time.Second)
			defer cancel()

			transportFunc := func(d processor.DocumentTree) error {
				if !dochelper.DocTreeEqual(d, tt.expected) {
					t.Errorf("doc tree did not match up, got\n%s, \nexpected\n%s", dochelper.StringTree(d), dochelper.StringTree(tt.expected))
				}
				return nil
			}

			err = Subscribe(ctx, transportFunc)
			if (err != nil) != tt.wantErr {
				t.Errorf("nats emitter Subscribe test errored = %v, want %v", err, tt.wantErr)
			}
			if err != nil {
				if !strings.Contains(err.Error(), tt.errMessage) {
					t.Errorf("nats emitter Subscribe test errored = %v, want %v", err, tt.errMessage)
				}
			}
		})
	}
}

func testPublish(ctx context.Context, d *processor.Document) error {
	docByte, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("failed marshal of document: %w", err)
	}
	err = emitter.Publish(ctx, emitter.SubjectNameDocCollected, docByte)
	if err != nil {
		return fmt.Errorf("failed to publish document on stream: %w", err)
	}
	return nil
}
*/
