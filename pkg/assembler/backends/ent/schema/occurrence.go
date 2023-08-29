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

// Occurrence holds the schema definition for the Occurrence entity.
type Occurrence struct {
	ent.Schema
}

// func (Occurrence) Annotations() []schema.Annotation {
// 	return []schema.Annotation{
// 		field.ID("subject_id", "artifact_id"),
// 	}
// }

// Fields of the Occurrence.
func (Occurrence) Fields() []ent.Field {
	return []ent.Field{
		field.Int("artifact_id").Comment("The artifact in the relationship"),
		field.String("justification").Comment("Justification for the attested relationship"),
		field.String("origin").Comment("Document from which this attestation is generated from"),
		field.String("collector").Comment("GUAC collector for the document"),
		field.Int("source_id").Optional().Nillable(),
		field.Int("package_id").Optional().Nillable(),
	}
}

// Edges of the Occurrence.
func (Occurrence) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("artifact", Artifact.Type).Field("artifact_id").Unique().Required(),
		edge.To("package", PackageVersion.Type).Unique().Field("package_id"),
		edge.To("source", SourceName.Type).Unique().Field("source_id"),
	}
}

// Indexes of the Occurrence.
func (Occurrence) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("justification", "origin", "collector").Edges("artifact", "package").Unique().
			Annotations(entsql.IndexWhere("package_id IS NOT NULL AND source_id IS NULL")).StorageKey("occurrence_unique_package"),
		index.Fields("justification", "origin", "collector").Edges("artifact", "source").Unique().
			Annotations(entsql.IndexWhere("package_id IS NULL AND source_id IS NOT NULL")).StorageKey("occurrence_unique_source"),

		// index.Fields("justification", "origin", "collector").Edges("source", "artifact").Unique().
		// Annotations(entsql.IndexWhere("source_id <> NULL AND package_id is NULL")).
		// StorageKey("occurrence_unique_source"),
		//index.Fields("justification", "origin", "collector").Edges("package", "source", "artifact").Unique(),
	}
}
