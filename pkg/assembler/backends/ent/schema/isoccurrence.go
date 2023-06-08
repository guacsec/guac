package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// IsOccurrence holds the schema definition for the IsOccurrence entity.
type IsOccurrence struct {
	ent.Schema
}

// Fields of the IsOccurrence.
func (IsOccurrence) Fields() []ent.Field {
	return []ent.Field{
		field.Int("package_id").Optional(),
		field.Int("source_id").Optional(),
		field.Int("artifact_id"),
		field.String("justification"),
		field.String("origin"),
		field.String("collector"),
	}
}

// Edges of the IsOccurrence.
func (IsOccurrence) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("package", PackageVersion.Type).Field("package_id").Unique(),
		//edge.To("source", SorceName.Type).Field("source_id").Unique(),
		edge.To("artifact", Artifact.Type).Field("artifact_id").Unique().Required(),
	}
}

// Indexes of the IsOccurrence.
func (IsOccurrence) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("justification", "origin", "collector").Edges("package", "artifact").Unique().Annotations(
			entsql.IndexWhere("package_id <> NULL OR source_id <> NULL"),
		),
		//index.Fields("justification", "origin", "collector").Edges("package", "source", "artifact").Unique(),
	}
}
