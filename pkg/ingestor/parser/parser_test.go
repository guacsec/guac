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
	"github.com/golang/mock/gomock"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/ingestor/parser/internal/mock"
	"testing"
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

			if err := RegisterDocumentParser(f, test.registerArgs); (err != nil) != test.wantErr {
				t.Errorf("RegisterDocumentParser() error = %v, wantErr %v", err, test.wantErr)
			}

			if _, err := parseHelper(ctx, test.parseArg); err != nil { // Ignoring the graphBuilder because the mock will always return an empty graphBuilder
				t.Logf("error parsing document: %v", err)
			}
		})
	}
}
