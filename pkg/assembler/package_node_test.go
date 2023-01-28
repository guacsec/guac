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
)

var packageNode = PackageNode{
	Name: "test",
	Digest: []string{
		"test",
		"test2",
	},
	Version: "version",
	Purl:    "purl",
	CPEs:    []string{"cpe"},
	Tags:    []string{"tag"},
	NodeData: objectMetadata{
		sourceInfo:    "",
		collectorInfo: "",
	},
}

func TestPackageNode_Type(t *testing.T) {
	test := struct {
		name string
		want string
	}{
		name: "type",
		want: "Package",
	}
	t.Run(test.name, func(t *testing.T) {
		if got := packageNode.Type(); got != test.want {
			t.Errorf("Type() = %v, want %v", got, test.want)
		}
	})
}

func TestPackageNode_IdentifiablePropertyNames(t *testing.T) {
	test := struct {
		name string
		want []string
	}{
		name: "default property name",
		want: []string{"purl"},
	}
	t.Run(test.name, func(t *testing.T) {
		if got := packageNode.IdentifiablePropertyNames(); !reflect.DeepEqual(got, test.want) {
			t.Errorf("IdentifiablePropertyNames() = %v, want %v", got, test.want)
		}
	})
}

func TestPackageNode_Properties(t *testing.T) {
	test := struct {
		name string
		want map[string]interface{}
	}{
		name: "default property name",
		want: map[string]interface{}{
			packageName: "test",
			packageDigest: []string{
				"test",
				"test2",
			},
			packageVersion: "version",
			packagePurl:    "purl",
			packageCPEs:    []string{"cpe"},
			packageTags:    []string{"tag"},
		},
	}
	t.Run(test.name, func(t *testing.T) {
		if got := packageNode.Properties(); !reflect.DeepEqual(got, test.want) {
			t.Errorf("Properties() = %v, want %v", got, test.want)
		}
	})
}

func TestPackageNode_PropertyNames(t *testing.T) {
	test := struct {
		name string
		want []string
	}{
		name: "default property names",
		want: []string{packageName, packageDigest, packagePurl, packageCPEs, packageTags, packageVersion, "source", "collector"},
	}
	t.Run(test.name, func(t *testing.T) {
		if got := packageNode.PropertyNames(); !reflect.DeepEqual(got, test.want) {
			t.Errorf("PropertyNames() = %v, want %v", got, test.want)
		}
	})
}
