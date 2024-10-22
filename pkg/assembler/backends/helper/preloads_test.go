//
// Copyright 2024 The GUAC Authors.
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
	"github.com/vektah/gqlparser/v2/ast"
)

func TestGetPreloads(t *testing.T) {
	t.Run("Context with fields", func(t *testing.T) {
		ctx := graphql.WithOperationContext(context.Background(), &graphql.OperationContext{})
		ctx = graphql.WithFieldContext(ctx, &graphql.FieldContext{
			Field: graphql.CollectedField{
				Selections: ast.SelectionSet{
					&ast.Field{
						Name: "field_1",
						SelectionSet: ast.SelectionSet{
							&ast.Field{
								Name: "field_a",
							},
						},
					},
					&ast.Field{
						Name: "field_2",
					},
				},
			},
		})
		result := GetPreloads(ctx)
		expected := []string{"field_1", "field_1.field_a", "field_2"}
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})
}
