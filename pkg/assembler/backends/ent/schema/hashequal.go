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

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// HashEqual holds the schema definition for the HashEqual entity.
type HashEqual struct {
	ent.Schema
}

// Fields of the HashEqual.
func (HashEqual) Fields() []ent.Field {
	return []ent.Field{
		field.String("origin"),
		field.String("collector"),
		field.String("justification"),
	}
}

// Edges of the HashEqual.
func (HashEqual) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("artifacts", Artifact.Type).Required(),
	}
}
