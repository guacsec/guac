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

// Builder holds the schema definition for the Builder entity.
type Builder struct {
	ent.Schema
}

// Fields of the Builder.
func (Builder) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Unique().
			Immutable(),
		field.String("uri").Unique().Immutable().Comment("The URI of the builder, used as a unique identifier in the graph query"),
	}
}

// Edges of the Builder.
func (Builder) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("slsa_attestations", SLSAAttestation.Type).Ref("built_by"),
	}
}

// Indexes of the BuilderNode.
func (Builder) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("uri").Unique(),
	}
}
