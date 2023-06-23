package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// OccurrenceSubject holds the schema definition for the OccurrenceSubject entity.
type OccurrenceSubject struct {
	ent.Schema
}

// Fields of the OccurrenceSubject.
func (OccurrenceSubject) Fields() []ent.Field {
	return []ent.Field{
		field.Int("source_id").Optional().Nillable(),
		field.Int("package_id").Optional().Nillable(),
	}
}

// Edges of the OccurrenceSubject.
func (OccurrenceSubject) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("occurrence", Occurrence.Type).Unique(),
		edge.To("package", PackageVersion.Type).Unique().Field("package_id"),
		edge.To("source", SourceName.Type).Unique().Field("source_id"),
	}
}
