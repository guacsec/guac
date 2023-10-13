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
)

// PointOfContact holds the schema definition for the PointOfContact entity.
type PointOfContact struct {
	ent.Schema
}

// Fields of the PointOfContact.
func (PointOfContact) Fields() []ent.Field {
	return []ent.Field{
		field.Int("source_id").Optional().Nillable(),
		field.Int("package_version_id").Optional().Nillable(),
		field.Int("package_name_id").Optional().Nillable(),
		field.Int("artifact_id").Optional().Nillable(),
		field.String("email"),
		field.String("info"),
		field.Time("since"),
		field.String("justification"),
		field.String("origin"),
		field.String("collector"),
	}
}

// Edges of the PointOfContact.
func (PointOfContact) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("source", SourceName.Type).Unique().Field("source_id"),
		edge.To("package_version", PackageVersion.Type).Unique().Field("package_version_id"),
		edge.To("all_versions", PackageName.Type).Unique().Field("package_name_id"),
		edge.To("artifact", Artifact.Type).Unique().Field("artifact_id"),
	}
}

func (PointOfContact) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("since", "email", "info", "justification", "origin", "collector", "source_id").Unique().Annotations(entsql.IndexWhere("source_id IS NOT NULL AND package_version_id IS NULL AND package_name_id IS NULL AND artifact_id IS NULL")),
		index.Fields("since", "email", "info", "justification", "origin", "collector", "package_version_id").Unique().Annotations(entsql.IndexWhere("source_id IS NULL AND package_version_id IS NOT NULL AND package_name_id IS NULL AND artifact_id IS NULL")),
		index.Fields("since", "email", "info", "justification", "origin", "collector", "package_name_id").Unique().Annotations(entsql.IndexWhere("source_id IS NULL AND package_version_id IS NULL AND package_name_id IS NOT NULL AND artifact_id IS NULL")),
		index.Fields("since", "email", "info", "justification", "origin", "collector", "artifact_id").Unique().Annotations(entsql.IndexWhere("source_id IS NULL AND package_version_id IS NULL AND package_name_id IS NULL AND artifact_id IS NOT NULL")),
	}
}
