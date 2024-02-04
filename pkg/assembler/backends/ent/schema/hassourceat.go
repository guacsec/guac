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
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// HasSourceAt holds the schema definition for the HasSourceAt entity.
type HasSourceAt struct {
	ent.Schema
}

// Fields of the HasSourceAt.
func (HasSourceAt) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Unique().
			Immutable(),
		field.UUID("package_version_id", uuid.New()).Optional().Nillable(),
		field.UUID("package_name_id", uuid.New()).Optional().Nillable(),
		field.UUID("source_id", uuid.New()),
		field.Time("known_since"),
		field.String("justification"),
		field.String("origin"),
		field.String("collector"),
	}
}

// Edges of the HasSourceAt.
func (HasSourceAt) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("package_version", PackageVersion.Type).Field("package_version_id").Unique(),
		edge.To("all_versions", PackageName.Type).Field("package_name_id").Unique(),
		edge.To("source", SourceName.Type).Field("source_id").Unique().Required(),
	}
}

func (HasSourceAt) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("source_id", "package_version_id", "justification").Unique().Annotations(entsql.IndexWhere("package_version_id IS NOT NULL AND package_name_id IS NULL")),
		index.Fields("source_id", "package_name_id", "justification").Unique().Annotations(entsql.IndexWhere("package_name_id IS NOT NULL AND package_version_id IS NULL")),
		index.Fields("known_since"),
	}
}
