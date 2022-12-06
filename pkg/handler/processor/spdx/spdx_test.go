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

package spdx

import (
	"reflect"
	"testing"

	testdata "github.com/guacsec/guac/internal/testing"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func TestSPDXProcessor_Unpack(t *testing.T) {
	testCases := []struct {
		name      string
		doc       processor.Document
		expected  []*processor.Document
		expectErr bool
	}{{
		name: "SPDX document",
		doc: processor.Document{
			Blob:   testdata.SpdxExampleSmall,
			Format: processor.FormatUnknown,
			Type:   processor.DocumentSPDX,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		expected:  []*processor.Document{},
		expectErr: false,
	}, {
		name: "Incorrect type",
		doc: processor.Document{
			Blob:   testdata.SpdxExampleSmall,
			Format: processor.FormatUnknown,
			Type:   processor.DocumentUnknown,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		expected:  nil,
		expectErr: true,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			d := SPDXProcessor{}
			actual, err := d.Unpack(&tt.doc)
			if (err != nil) != tt.expectErr {
				t.Errorf("SPDXProcessor.Unpack() error = %v, expectErr %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(actual, tt.expected) {
				t.Errorf("SPDXProcessor.Unpack() = %v, expected %v", actual, tt.expected)
			}
		})
	}
}

func TestSPDXProcessor_ValidateSchema(t *testing.T) {
	testCases := []struct {
		name      string
		doc       processor.Document
		expectErr bool
	}{{
		name: "valid small SPDX document",
		doc: processor.Document{
			Blob:              testdata.SpdxExampleSmall,
			Format:            processor.FormatJSON,
			Type:              processor.DocumentSPDX,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: false,
	}, {
		name: "valid big SPDX document",
		doc: processor.Document{
			Blob:              testdata.SpdxExampleBig,
			Format:            processor.FormatJSON,
			Type:              processor.DocumentSPDX,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: false,
	}, {
		name: "invalid SPDX document",
		doc: processor.Document{
			Blob:              testdata.SpdxInvalidExample,
			Format:            processor.FormatJSON,
			Type:              processor.DocumentSPDX,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}, {
		name: "invalid format supported",
		doc: processor.Document{
			Blob:              testdata.SpdxExampleSmall,
			Format:            processor.FormatUnknown,
			Type:              processor.DocumentSPDX,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			d := SPDXProcessor{}
			err := d.ValidateSchema(&tt.doc)
			if (err != nil) != tt.expectErr {
				t.Errorf("SPDXProcessor.ValidateSchema() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}
