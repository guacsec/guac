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

// Certification holds the schema definition for the Certification entity.
type Certification struct {
	ent.Schema
}

// Fields of the Certification.
func (Certification) Fields() []ent.Field {
	return []ent.Field{
		// TODO: (ivanvanderbyl) We can reduce the index size by 3/4 if we use a single type field for the source, package_version, package_name, and artifact.
		field.Int("source_id").Optional().Nillable(),
		field.Int("package_version_id").Optional().Nillable(),
		field.Int("package_name_id").Optional().Nillable(),
		field.Int("artifact_id").Optional().Nillable(),
		field.Enum("type").Values("GOOD", "BAD").Default("GOOD"),
		field.String("justification"),
		field.String("origin"),
		field.String("collector"),
		field.Time("known_since"),
	}
}

// Edges of the Certification.
func (Certification) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("source", SourceName.Type).Unique().Field("source_id"),
		edge.To("package_version", PackageVersion.Type).Unique().Field("package_version_id"),
		edge.To("all_versions", PackageName.Type).Unique().Field("package_name_id"),
		edge.To("artifact", Artifact.Type).Unique().Field("artifact_id"),
	}
}

func (Certification) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("type", "justification", "origin", "collector", "source_id", "known_since").Unique().Annotations(entsql.IndexWhere("source_id IS NOT NULL AND package_version_id IS NULL AND package_name_id IS NULL AND artifact_id IS NULL")),
		index.Fields("type", "justification", "origin", "collector", "package_version_id", "known_since").Unique().Annotations(entsql.IndexWhere("source_id IS NULL AND package_version_id IS NOT NULL AND package_name_id IS NULL AND artifact_id IS NULL")),
		index.Fields("type", "justification", "origin", "collector", "package_name_id", "known_since").Unique().Annotations(entsql.IndexWhere("source_id IS NULL AND package_version_id IS NULL AND package_name_id IS NOT NULL AND artifact_id IS NULL")),
		index.Fields("type", "justification", "origin", "collector", "artifact_id", "known_since").Unique().Annotations(entsql.IndexWhere("source_id IS NULL AND package_version_id IS NULL AND package_name_id IS NULL AND artifact_id IS NOT NULL")),
	}
}
