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

package helper

import (
	"context"
	"reflect"
	"testing"

	"github.com/99designs/gqlgen/graphql"
)

func TestGetPreloads(t *testing.T) {
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetPreloads(tt.args.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPreloads() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getNestedPreloads(t *testing.T) {
	type args struct {
		ctx     *graphql.OperationContext
		fields  []graphql.CollectedField
		prefix  string
		visited map[string]bool
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getNestedPreloads(tt.args.ctx, tt.args.fields, tt.args.prefix, tt.args.visited); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getNestedPreloads() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getPreloadString(t *testing.T) {
	type args struct {
		prefix string
		name   string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getPreloadString(tt.args.prefix, tt.args.name); got != tt.want {
				t.Errorf("getPreloadString() = %v, want %v", got, tt.want)
			}
		})
	}
}
