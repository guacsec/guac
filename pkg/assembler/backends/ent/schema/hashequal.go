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
	"github.com/google/uuid"
)

// HashEqual holds the schema definition for the HashEqual entity.
type HashEqual struct {
	ent.Schema
}

// Fields of the HashEqual.
func (HashEqual) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(getUUIDv7).
			Unique().
			Immutable(),
		field.UUID("art_id", getUUIDv7()),
		field.UUID("equal_art_id", getUUIDv7()),
		field.String("origin"),
		field.String("collector"),
		field.String("justification"),
		field.String("artifacts_hash").Comment("An opaque hash of the artifact IDs that are equal"),
	}
}

// Edges of the HashEqual.
func (HashEqual) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("artifact_a", Artifact.Type).Required().Field("art_id").Unique(),
		edge.To("artifact_b", Artifact.Type).Required().Field("equal_art_id").Unique(),
	}
}

// Indexes of the HashEqual.
func (HashEqual) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("art_id", "equal_art_id", "artifacts_hash", "origin", "justification", "collector").Unique(),
	}
}
