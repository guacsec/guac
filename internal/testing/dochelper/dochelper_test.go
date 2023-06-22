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

package dochelper

import (
	"testing"

	"github.com/guacsec/guac/pkg/handler/processor"
)

func TestStringTree(t *testing.T) {
	type args struct {
		n            *processor.DocumentNode
		makeOverflow bool
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "regular",
			args: args{
				n: &processor.DocumentNode{
					Document: &processor.Document{
						Blob: []byte(`{"a": "b"}`),
						Type: "test2",
					},
					Children: []*processor.DocumentNode{
						{
							Document: &processor.Document{
								Blob: []byte(`{"c": "d"}`),
								Type: "test",
							},
						},
					},
				},
				makeOverflow: false,
			},
			want: " { doc: {\"a\":\"b\"}, , test2, { }}\n- { doc: {\"c\":\"d\"}, , test, { }}",
		},
		{
			name: "stack overflow",
			args: args{
				n: &processor.DocumentNode{
					Document: &processor.Document{
						Blob: []byte(`{"a": "b"}`),
						Type: "test1",
					},
					Children: []*processor.DocumentNode{
						{
							Document: &processor.Document{
								Blob: []byte(`{"c": "d"}`),
								Type: "test2",
							},
						},
					},
				},
				makeOverflow: true,
			},
			want: " { doc: {\"a\":\"b\"}, , test1, { }}\n- { doc: {\"c\":\"d\"}, , test2, { }}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.args.makeOverflow {
				tt.args.n.Children[0].Children = append(tt.args.n.Children[0].Children, &processor.DocumentNode{
					Document: tt.args.n.Document,
					Children: tt.args.n.Children,
				})
			}
			got := StringTree(tt.args.n)
			if got != tt.want {
				t.Errorf("want = %v, got = %v", tt.want, got)
			}
		})
	}
}
