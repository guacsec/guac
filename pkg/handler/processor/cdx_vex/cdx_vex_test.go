//
// Copyright 2023 The GUAC Authors.
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

package cdx_vex

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func Test_ValidateSchema(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name        string
		doc         processor.Document
		expectedErr error
	}{
		{
			name: "Incorrect document type",
			doc: processor.Document{
				Type: processor.DocumentCsaf,
			},
			expectedErr: fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentCdxVex, processor.DocumentCsaf),
		},
		{
			name: "Successful validation of cdx-vex document",
			doc: processor.Document{
				Type:   processor.DocumentCdxVex,
				Format: processor.FormatJSON,
				Blob:   testdata.CycloneDXExampleVEX,
			},
		},
		{
			name: "Invalid format for cdx-vex document",
			doc: processor.Document{
				Type:   processor.DocumentCdxVex,
				Format: processor.FormatXML,
				Blob:   testdata.CycloneDXExampleVEX,
			},
			expectedErr: fmt.Errorf("unable to support parsing of cdx-vex document format: %v", processor.FormatXML),
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			c := CdxVexProcessor{}
			err := c.ValidateSchema(&tt.doc)
			if err != nil && err.Error() != tt.expectedErr.Error() {
				t.Errorf("ValidateSchema() actual error = %v, expected error %v", err, tt.expectedErr)
			}
		})
	}
}

func Test_Unpack(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name        string
		doc         processor.Document
		expectedRes []*processor.Document
		expectedErr error
	}{
		{
			name: "Invalid document type",
			doc: processor.Document{
				Type: processor.DocumentCycloneDX,
			},
			expectedRes: nil,
			expectedErr: fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentCdxVex, processor.DocumentCycloneDX),
		},
		{
			name: "Successful unpacked cdx-vex document",
			doc: processor.Document{
				Type: processor.DocumentCdxVex,
			},
			expectedRes: []*processor.Document{},
			expectedErr: nil,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			c := CdxVexProcessor{}
			res, err := c.Unpack(&tt.doc)
			if err != nil && err.Error() != tt.expectedErr.Error() {
				t.Errorf("Unpack() actual error = %v, expected error %v", err, tt.expectedErr)
			}
			if !reflect.DeepEqual(res, tt.expectedRes) {
				t.Errorf("Unpack() actual result = %v, expected result  %v", res, tt.expectedRes)
			}
		})
	}
}
