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

var artifactNode = ArtifactNode{
	Name:   "test",
	Digest: "TEST-Digest",
	Tags:   []string{"test-tags"},
	NodeData: objectMetadata{
		sourceInfo:    "",
		collectorInfo: "",
	},
}

func TestArtifactNode_IdentifiablePropertyNames(t *testing.T) {
	test := struct {
		name string
		want []string
	}{
		name: "test",
		want: []string{"digest"},
	}
	t.Run(test.name, func(t *testing.T) {
		if got := artifactNode.IdentifiablePropertyNames(); !reflect.DeepEqual(got, test.want) {
			t.Errorf("IdentifiablePropertyNames() = %v, want %v", got, test.want)
		}
	})
}

func TestArtifactNode_Properties(t *testing.T) {
	test := struct {
		name string
		want map[string]interface{}
	}{
		name: "test",
		want: map[string]interface{}{
			name:   "test",
			digest: "test-digest",
			tags:   []string{"test-tags"},
		},
	}
	t.Run(test.name, func(t *testing.T) {
		if got := artifactNode.Properties(); !reflect.DeepEqual(got, test.want) {
			t.Errorf("Properties() = %v, want %v", got, test.want)
		}
	})
}

func TestArtifactNode_PropertyNames(t *testing.T) {
	test := struct {
		name string
		want []string
	}{
		name: "test",
		want: []string{name, digest, tags, "source", "collector"},
	}
	t.Run(test.name, func(t *testing.T) {
		if got := artifactNode.PropertyNames(); !reflect.DeepEqual(got, test.want) {
			t.Errorf("PropertyNames() = %v, want %v", got, test.want)
		}
	})
}

func TestArtifactNode_Type(t *testing.T) {
	test := struct {
		name string
		want string
	}{
		name: "test",
		want: "Artifact",
	}
	t.Run(test.name, func(t *testing.T) {
		if got := artifactNode.Type(); got != test.want {
			t.Errorf("Type() = %v, want %v", got, test.want)
		}
	})
}
