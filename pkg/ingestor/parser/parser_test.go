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

package parser

import (
	"context"
	"errors"
	"testing"

	"github.com/guacsec/guac/internal/testing/mocks"

	"github.com/golang/mock/gomock"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

func TestParserHelper(t *testing.T) {
	tests := []struct {
		name         string
		registerArgs processor.DocumentType
		parseArg     *processor.Document
		isParseErr   bool
		wantErr      bool
	}{
		{
			name:         "default",
			registerArgs: processor.DocumentType("test"),
			parseArg: &processor.Document{
				Type: processor.DocumentType("test"),
			},
		},
		{
			name:         "invalid register",
			registerArgs: processor.DocumentType("test"),
			parseArg: &processor.Document{
				Type: processor.DocumentType("invalid"),
			},
			wantErr: true,
		},
		{
			name:         "parse error",
			registerArgs: processor.DocumentType("test"),
			parseArg: &processor.Document{
				Type: processor.DocumentType("test"),
			},
			isParseErr: true,
			wantErr:    true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockDocumentParser := mocks.NewMockDocumentParser(ctrl)
			ctx := context.Background()

			parser := common.DocumentParser(mockDocumentParser)

			f := func() common.DocumentParser {
				return parser
			}

			mockDocumentParser.EXPECT().Parse(ctx, test.parseArg).DoAndReturn(func(ctx context.Context, doc *processor.Document) error {
				if test.isParseErr {
					return errors.New("parse error")
				}
				return nil
			}).AnyTimes()
			mockDocumentParser.EXPECT().GetIdentities(ctx).Return([]common.TrustInformation{}).AnyTimes()

			_ = RegisterDocumentParser(f, test.registerArgs) // Ignoring error because it is mutating a global variable

			if _, err := parseHelper(ctx, test.parseArg); err != nil { // Ignoring the graphBuilder because the mock will always return an empty graphBuilder
				t.Logf("error parsing document: %v", err)
			}
		})
	}
}

func Test_docTreeBuilder_parse(t *testing.T) {
	type fields struct {
		identities    []common.TrustInformation
		graphBuilders []*common.GraphBuilder
	}
	tests := []struct {
		name            string
		fields          fields
		root            processor.DocumentTree
		registerDocType processor.DocumentType
		// The registerDocType is used to register the document parser, it is different from the roots own
		// processor.DocumentType so that we can test the error case
		makeOverflow bool
		// makeOverflow is used to know whether we should try to make the stack overflow.
		// The makeOverflow flag makes the roots child point back to the root so that it will overflow
		wantErr bool
	}{
		{
			name: "default",
			root: &processor.DocumentNode{
				Document: &processor.Document{
					Type: "test",
				},
				Children: []*processor.DocumentNode{
					{
						Document: &processor.Document{
							Type: "test",
						},
					},
					{
						Document: &processor.Document{
							Type: "test",
						},
					},
				},
			},
			registerDocType: "test",
		},
		{
			name: "parseHelper error",
			root: &processor.DocumentNode{
				Document: &processor.Document{
					Type: "invalid",
				},
			},
			registerDocType: "test",
			wantErr:         true,
		},
		{
			name: "parse children error",
			root: &processor.DocumentNode{
				Document: &processor.Document{
					Type: "test",
				},
				Children: []*processor.DocumentNode{
					{
						Document: &processor.Document{
							Type: "invalid",
						},
					},
				},
			},
			registerDocType: "test",
			wantErr:         true,
		},
		{
			name: "can overflow",
			root: &processor.DocumentNode{
				Document: &processor.Document{
					Type: processor.DocumentType("test"),
				},
			},
			registerDocType: "test",
			makeOverflow:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t1 *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockDocumentParser := mocks.NewMockDocumentParser(ctrl)
			ctx := context.Background()

			parser := common.DocumentParser(mockDocumentParser)

			f := func() common.DocumentParser {
				return parser
			}

			mockDocumentParser.EXPECT().Parse(ctx, test.root.Document).DoAndReturn(func(ctx context.Context, doc *processor.Document) error {
				return nil
			}).AnyTimes()
			mockDocumentParser.EXPECT().GetIdentities(ctx).Return([]common.TrustInformation{}).AnyTimes()

			_ = RegisterDocumentParser(f, test.registerDocType) // Ignoring error because it is mutating a global variable

			if test.makeOverflow {
				// make the roots child point back to the root so that it will overflow
				root := test.root
				root.Children = append(root.Children, &processor.DocumentNode{ // create child
					Document: &processor.Document{
						Type: test.root.Document.Type,
					},
				})
				root = root.Children[0]
				root.Children = append(root.Children, test.root) // make the child point back to the root
			}

			treeBuilder := &docTreeBuilder{
				identities:    test.fields.identities,
				graphBuilders: test.fields.graphBuilders,
			}
			if err := treeBuilder.parse(ctx, test.root, map[visitedKey]bool{}); (err != nil) != test.wantErr {
				t1.Errorf("parse() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
