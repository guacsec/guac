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
	_ "embed"
	"fmt"
	"reflect"
	"testing"

	"github.com/guacsec/guac/pkg/handler/processor"
)

var (
	// based off https://github.com/spdx/spdx-examples/blob/master/example7/spdx/example7-third-party-modules.spdx.json
	//go:embed testdata/small-spdx.json
	spdxExampleSmall []byte

	//go:embed testdata/alpine-spdx.json
	spdxExampleBig []byte

	// Invalid types for field spdxVersion
	//go:embed testdata/invalid-spdx.json
	spdxInvalidExample []byte
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
			Blob:              spdxExampleSmall,
			Format:            processor.FormatUnknown,
			Type:              processor.DocumentSPDX,
			SourceInformation: processor.SourceInformation{},
		},
		expected:  []*processor.Document{},
		expectErr: false,
	}, {
		name: "Incorrect type",
		doc: processor.Document{
			Blob:              spdxExampleSmall,
			Format:            processor.FormatUnknown,
			Type:              processor.DocumentUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expected:  nil,
		expectErr: true,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println(spdxExampleSmall)
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
			Blob:              spdxExampleSmall,
			Format:            processor.FormatJSON,
			Type:              processor.DocumentSPDX,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: false,
	}, {
		name: "valid big SPDX document",
		doc: processor.Document{
			Blob:              spdxExampleBig,
			Format:            processor.FormatJSON,
			Type:              processor.DocumentSPDX,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: false,
	}, {
		name: "invalid SPDX document",
		doc: processor.Document{
			Blob:              spdxInvalidExample,
			Format:            processor.FormatJSON,
			Type:              processor.DocumentSPDX,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}, {
		name: "invalid format supported",
		doc: processor.Document{
			Blob:              spdxExampleSmall,
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
