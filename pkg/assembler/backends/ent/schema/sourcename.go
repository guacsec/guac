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

// SourceName holds the schema definition for the SourceName entity.
type SourceName struct {
	ent.Schema
}

// Fields of the SourceName.
func (SourceName) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(getUUIDv7).
			Unique().
			Immutable(),
		field.String("type"),
		field.String("namespace"),
		field.String("name"),
		field.String("commit").Optional(),
		field.String("tag").Optional(),
	}
}

// Edges of the SourceName.
func (SourceName) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("occurrences", Occurrence.Type).Ref("source"),
		edge.From("has_source_at", HasSourceAt.Type).Ref("source"),
		edge.From("scorecard", CertifyScorecard.Type).Ref("source"),
		edge.From("certification", Certification.Type).Ref("source"),
		edge.From("metadata", HasMetadata.Type).Ref("source"),
		edge.From("poc", PointOfContact.Type).Ref("source"),
		edge.From("certify_legal", CertifyLegal.Type).Ref("source"),
	}
}

// Indexes of the SourceName.
func (SourceName) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("type", "namespace", "name", "commit", "tag").Unique(),
	}
}
