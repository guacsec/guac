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
	"entgo.io/ent/schema/index"
)

// SourceNamespace holds the schema definition for the SourceNamespace entity.
type SourceNamespace struct {
	ent.Schema
}

// Fields of the SourceNamespace.
func (SourceNamespace) Fields() []ent.Field {
	return []ent.Field{
		field.String("namespace"),
		field.Int("source_id"),
	}
}

// Edges of the SourceNamespace.
func (SourceNamespace) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("source_type", SourceType.Type).Unique().Required().Field("source_id"),
		edge.From("names", SourceName.Type).Ref("namespace"),
	}
}

// Indexes of the SourceNamespace.
func (SourceNamespace) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("namespace", "source_id").Unique(),
	}
}
