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

package guacanalytics

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/Khan/genqlient/graphql"
)

func TestTopoSortFromBfsNodeMap(t *testing.T) {
	type args struct {
		nodeMap map[string]BfsNode
	}
	tests := []struct {
		name    string
		args    args
		want    map[int][]string
		want1   []string
		wantErr bool
	}{
		{
			name: "default",
			args: args{
				/*
						1
					   / \
					  2   3
					 / \   \
					4   5   6
				*/
				nodeMap: map[string]BfsNode{
					"1": {Parents: []string{}},
					"2": {Parents: []string{"1"}},
					"3": {Parents: []string{"1"}},
					"4": {Parents: []string{"2"}},
					"5": {Parents: []string{"2"}},
					"6": {Parents: []string{"3"}},
				},
			},
			want: map[int][]string{
				0: {"1"},
				1: {"2", "3"},
				2: {"4", "5", "6"},
			},
			want1: *new([]string),
		},
		{
			name: "cycle error",
			args: args{
				/*
						1
					   / \
					  2 - 3
				*/
				nodeMap: map[string]BfsNode{
					"1": {Parents: []string{"3"}},
					"2": {Parents: []string{"1"}},
					"3": {Parents: []string{"2"}},
				},
			},
			wantErr: true,
		},
		{
			name: "infoNodes not empty",
			args: args{
				nodeMap: map[string]BfsNode{
					"1": {NotInBlastRadius: true},
				},
			},
			want:  map[int][]string{},
			want1: []string{"1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			gqlClient := graphql.NewClient("test", nil)
			got, got1, err := TopoSortFromBfsNodeMap(ctx, gqlClient, tt.args.nodeMap)
			if (err != nil) != tt.wantErr {
				t.Errorf("TopoSortFromBfsNodeMap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for k := range got {
				sort.Strings(got[k])
				sort.Strings(tt.want[k])
				if !reflect.DeepEqual(got[k], tt.want[k]) {
					t.Errorf("TopoSortFromBfsNodeMap() got = %v, want %v", got, tt.want)
				}
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("TopoSortFromBfsNodeMap() got1 = %v, want %v", got1, tt.want1)
			}

		})
	}
}
