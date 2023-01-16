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

package assembler

import (
	"reflect"
	"testing"

	"github.com/guacsec/guac/pkg/handler/processor"
)

func TestNewObjectMetadata(t *testing.T) {
	test := struct {
		name string
		s    processor.SourceInformation
		want *objectMetadata
	}{
		name: "test",
		s: processor.SourceInformation{
			Collector: "collector",
			Source:    "source",
		},
		want: &objectMetadata{
			sourceInfo:    "source",
			collectorInfo: "collector",
		},
	}
	if got := NewObjectMetadata(test.s); !reflect.DeepEqual(got, test.want) {
		t.Errorf("NewObjectMetadata() = %v, want %v", got, test.want)
	}
}

func Test_objectMetadata_addProperties(t *testing.T) {
	tests := []struct {
		name string
		o    *objectMetadata
		prop map[string]interface{}
	}{
		{
			name: "regular",
			o: &objectMetadata{
				sourceInfo:    "source",
				collectorInfo: "collector",
			},
			prop: map[string]interface{}{},
		},
		{
			name: "no change to prop",
			o: &objectMetadata{
				sourceInfo:    "",
				collectorInfo: "",
			},
			prop: map[string]interface{}{},
		},
		{
			name: "prop has keys of o.sourceInfo and o.collectorInfo",
			o: &objectMetadata{
				sourceInfo:    "source",
				collectorInfo: "collector",
			},
			prop: map[string]interface{}{
				"source":    "source",
				"collector": "collector",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prevProp := make(map[string]interface{})
			for k, v := range test.prop {
				prevProp[k] = v
			}
			diff := make(map[string]interface{})

			test.o.addProperties(test.prop)

			// finding the difference between prevProp and test.prop
			for k := range prevProp {
				_, ok := test.prop[k]
				if k == "source" || k == "collector" || !ok {
					diff = test.prop
				}
			}

			if _, ok := diff["source"]; ok && len(test.o.sourceInfo) > 0 && diff["source"] != test.o.sourceInfo {
				// We expect the source to be added to the properties
				t.Errorf("objectMetadata.addProperties() of prop[\"source\"] = %v, want %v", diff["source"], test.o.sourceInfo)
			}
			if _, ok := diff["collector"]; ok && len(test.o.collectorInfo) > 0 && diff["collector"] != test.o.collectorInfo {
				// We expect the collector to be added to the properties
				t.Errorf("objectMetadata.addProperties() of prop[\"collector\"] = %v, want %v", diff["collector"], test.o.collectorInfo)
			}

			for k, v := range diff {
				if (k != "source" && k != "collector") ||
					(k == "source" && len(test.o.sourceInfo) == 0 && prevProp[k] != v) ||
					(k == "collector" && len(test.o.collectorInfo) == 0 && prevProp[k] != v) {

					// first part of if: extra properties that aren't "source" or "collector"
					// second part of if: "source" property was added when it shouldn't have been
					// third part of if: "collector" property was added when it shouldn't have been

					t.Errorf("objectMetadata.addProperties() of prop[%v] = %v, want %v", k, v, nil)
				}
			}
		})
	}
}

func Test_objectMetadata_getProperties(t *testing.T) {
	test := struct {
		name string
		o    *objectMetadata
		want []string
	}{
		name: "test",
		o:    &objectMetadata{},
		want: []string{"source", "collector"},
	}
	if got := test.o.getProperties(); !reflect.DeepEqual(got, test.want) {
		t.Errorf("getProperties() = %v, want %v", got, test.want)
	}
}

func Test_isDefined(t *testing.T) {
	tests := []struct {
		name string
		v    interface{}
		want bool
	}{
		{
			name: "zero",
			v:    0,
			want: false,
		},
		{
			name: "empty string",
			v:    "",
			want: false,
		},
		{
			name: "empty struct",
			v:    struct{}{},
			want: false,
		},
		{
			name: "empty map",
			v:    map[string]string{},
			want: true,
		},
		{
			name: "string with value",
			v:    "test",
			want: true,
		},
		{
			name: "empty slice",
			v:    []string{},
			want: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isDefined(test.v); got != test.want {
				t.Errorf("isDefined() = %v, want %v", got, test.want)
			}
		})
	}
}

func Test_toLower(t *testing.T) {
	test := struct {
		name string
		v    []string
		want []string
	}{
		name: "test",
		v:    []string{"TEST", "rANDom---123!!"},
		want: []string{"test", "random---123!!"},
	}
	if got := toLower(test.v...); !reflect.DeepEqual(got, test.want) {
		t.Errorf("toLower() = %v, want %v", got, test.want)
	}
}
