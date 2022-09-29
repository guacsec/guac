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

package cyclonedx

import (
	"reflect"
	"testing"

	testdata "github.com/guacsec/guac/internal/testing/processor"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func TestCyloneDXProcessor_Unpack(t *testing.T) {
	testCases := []struct {
		name      string
		doc       processor.Document
		expected  []*processor.Document
		expectErr bool
	}{{
		name: "CycloneDX document",
		doc: processor.Document{
			Blob:              testdata.CycloneDXExampleJSONSmall,
			Format:            processor.FormatUnknown,
			Type:              processor.DocumentCycloneDX,
			SourceInformation: processor.SourceInformation{},
		},
		expected:  []*processor.Document{},
		expectErr: false,
	}, {
		name: "Incorrect type",
		doc: processor.Document{
			Blob:              testdata.CycloneDXExampleJSONSmall,
			Format:            processor.FormatUnknown,
			Type:              processor.DocumentUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expected:  nil,
		expectErr: true,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			d := CycloneDXProcessor{}
			actual, err := d.Unpack(&tt.doc)
			if (err != nil) != tt.expectErr {
				t.Errorf("CycloneDXProcessor.Unpack() error = %v, expectErr %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(actual, tt.expected) {
				t.Errorf("CycloneDXProcessor.Unpack() = %v, expected %v", actual, tt.expected)
			}
		})
	}
}

func TestCycloneDXProcessor_ValidateSchema(t *testing.T) {
	testCases := []struct {
		name      string
		doc       processor.Document
		expectErr bool
	}{{
		name: "valid small JSON CycloneDX document",
		doc: processor.Document{
			Blob:              testdata.CycloneDXExampleJSONSmall,
			Format:            processor.FormatJSON,
			Type:              processor.DocumentCycloneDX,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: false,
	}, {
		name: "valid big JSON CycloneDX document",
		doc: processor.Document{
			Blob:              testdata.CycloneDXExampleJSONBig,
			Format:            processor.FormatJSON,
			Type:              processor.DocumentCycloneDX,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: false,
	}, {
		name: "valid big XML CycloneDX document",
		doc: processor.Document{
			Blob:              testdata.CycloneDXExampleXMLBig,
			Format:            processor.FormatXML,
			Type:              processor.DocumentCycloneDX,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: false,
	}, {
		name: "invalid CycloneDX document",
		doc: processor.Document{
			Blob:              testdata.CycloneDXInvalidExample,
			Format:            processor.FormatJSON,
			Type:              processor.DocumentCycloneDX,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}, {
		name: "invalid format supported",
		doc: processor.Document{
			Blob:              testdata.CycloneDXExampleJSONSmall,
			Format:            processor.FormatUnknown,
			Type:              processor.DocumentCycloneDX,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}, {
		name: "invalid document type",
		doc: processor.Document{
			Blob:              testdata.CycloneDXExampleJSONSmall,
			Format:            processor.FormatUnknown,
			Type:              processor.DocumentUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			d := CycloneDXProcessor{}
			err := d.ValidateSchema(&tt.doc)
			if (err != nil) != tt.expectErr {
				t.Errorf("CycloneDXProcessor.ValidateSchema() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}
