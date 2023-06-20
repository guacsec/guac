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

package simpledoc

import "testing"

func Test_validateSimpleDoc(t *testing.T) {
	type args struct {
		pd SimpleDoc
	}
	tests := []struct {
		name              string
		args              args
		wantErr           bool
		wantStackOverflow bool
	}{
		{
			name: "valid",
			args: args{
				pd: SimpleDoc{
					Issuer: "1",
					Nested: []SimpleDoc{
						{
							Issuer: "2",
						},
						{
							Issuer: "3",
						},
					},
				},
			},
			wantErr:           false,
			wantStackOverflow: false,
		},
		{
			name: "invalid",
			args: args{
				pd: SimpleDoc{
					Issuer: "1",
					Nested: []SimpleDoc{
						{
							Issuer: "",
						},
						{
							Issuer: "2",
						},
					},
				},
			},
			wantErr:           true,
			wantStackOverflow: false,
		},
		{
			name: "stackoverflow",
			args: args{
				pd: SimpleDoc{
					Issuer: "1",
					Nested: []SimpleDoc{
						{
							Issuer: "2",
						},
						{
							Issuer: "3",
						},
					},
				},
			},
			wantErr:           false,
			wantStackOverflow: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantStackOverflow {
				// makes the simpledoc have itself as a child nested simpledoc (infinite recursion)
				tt.args.pd.Nested = append(tt.args.pd.Nested, tt.args.pd)
			}
			if err := validateSimpleDoc(tt.args.pd); (err != nil) != tt.wantErr {
				t.Errorf("validateSimpleDocHelper() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
