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

package deps_dev

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func TestDepsDev_ValidateSchema(t *testing.T) {
	testCases := []struct {
		name      string
		doc       processor.Document
		expectErr bool
	}{{
		name: "deps.dev document",
		doc: processor.Document{
			Blob:              []byte(testdata.CollectedYargsParser),
			Type:              processor.DocumentDepsDev,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: false,
	}, {
		name: "Incorrect type",
		doc: processor.Document{
			Blob:              []byte(testdata.CollectedYargsParser),
			Format:            processor.FormatUnknown,
			Type:              processor.DocumentUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			d := &DepsDev{}
			if err := d.ValidateSchema(&tt.doc); (err != nil) != tt.expectErr {
				t.Errorf("DepsDev.ValidateSchema() error = %v, wantErr %v", err, tt.expectErr)
			}
		})
	}
}

func TestDepsDev_Unpack(t *testing.T) {
	testCases := []struct {
		name      string
		doc       processor.Document
		expected  []*processor.Document
		expectErr bool
	}{{
		name: "deps.dev document",
		doc: processor.Document{
			Blob:              []byte(testdata.CollectedYargsParser),
			Type:              processor.DocumentDepsDev,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		expected:  []*processor.Document{},
		expectErr: false,
	}, {
		name: "Incorrect type",
		doc: processor.Document{
			Blob:              []byte(testdata.CollectedYargsParser),
			Format:            processor.FormatUnknown,
			Type:              processor.DocumentUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expected:  nil,
		expectErr: true,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println(testdata.SpdxExampleSmall)
			d := DepsDev{}
			actual, err := d.Unpack(&tt.doc)
			if (err != nil) != tt.expectErr {
				t.Errorf("DepsDev.Unpack() error = %v, expectErr %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(actual, tt.expected) {
				t.Errorf("DepsDev.Unpack() = %v, expected %v", actual, tt.expected)
			}
		})
	}
}
